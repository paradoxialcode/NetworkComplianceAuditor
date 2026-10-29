from __future__ import annotations

import re
from collections.abc import Iterable
from itertools import chain
from pathlib import Path
from typing import Final

import yaml
from jinja2 import StrictUndefined, TemplateError, meta
from jinja2.sandbox import SandboxedEnvironment
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from auditor.compliance.models import Check

MAX_TEMPLATE_BYTES: Final = 1_000_000
MAX_COMMAND_LEN: Final = 512
MAX_PARAM_LEN: Final = 128
CONTROL_CHARS: Final = re.compile(r"[\x00-\x1f\x7f]")
_VENDOR: Final = re.compile(r"^[a-z0-9_]{2,32}$")
_KEY: Final = re.compile(r"^[a-z0-9_]{3,64}$")
_PARAM_NAME: Final = re.compile(r"^[a-z][a-z0-9_]{0,31}$")

ENV: Final = SandboxedEnvironment(autoescape=False, undefined=StrictUndefined)


class TemplateLoadError(Exception):
    pass


class ParamSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    pattern: str = Field(min_length=1, max_length=128)
    default: str | None = None

    @model_validator(mode="after")
    def _validate(self) -> ParamSpec:
        try:
            re.compile(self.pattern)
        except re.error as exc:
            raise ValueError(f"invalid pattern: {exc}") from exc
        if self.default is not None and not self.accepts(self.default):
            raise ValueError("default does not match its own pattern")
        return self

    def accepts(self, value: str) -> bool:
        return (
            isinstance(value, str)
            and len(value) <= MAX_PARAM_LEN
            and not CONTROL_CHARS.search(value)
            and re.fullmatch(self.pattern, value) is not None
        )


class RemediationStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    title: str = Field(min_length=3, max_length=200)
    commands: tuple[str, ...] = Field(min_length=1, max_length=50)
    risk: str | None = Field(default=None, max_length=500)
    order: int = Field(default=50, ge=0, le=80)
    params: dict[str, ParamSpec] = Field(default_factory=dict)

    @field_validator("params")
    @classmethod
    def _param_names(cls, v: dict[str, ParamSpec]) -> dict[str, ParamSpec]:
        bad = [name for name in v if not _PARAM_NAME.fullmatch(name)]
        if bad:
            raise ValueError(f"invalid parameter names: {bad}")
        return v

    @model_validator(mode="after")
    def _validate_commands(self) -> RemediationStep:
        declared = set(self.params)
        for command in self.commands:
            if not command.strip() or len(command) > MAX_COMMAND_LEN or CONTROL_CHARS.search(command):
                raise ValueError("commands must be non-empty single lines without control characters")
            try:
                tree = ENV.parse(command)
            except TemplateError as exc:
                raise ValueError(f"template syntax error: {exc}") from exc
            undeclared = meta.find_undeclared_variables(tree) - declared
            if undeclared:
                raise ValueError(f"undeclared template variables: {sorted(undeclared)}")
        return self


class VendorTemplates(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    vendor: str
    steps: dict[str, RemediationStep] = Field(min_length=1)

    @field_validator("vendor")
    @classmethod
    def _vendor(cls, v: str) -> str:
        v = v.strip().lower()
        if not _VENDOR.fullmatch(v):
            raise ValueError("vendor must be 2-32 chars of a-z, 0-9, underscore")
        return v

    @field_validator("steps")
    @classmethod
    def _keys(cls, v: dict[str, RemediationStep]) -> dict[str, RemediationStep]:
        bad = [key for key in v if not _KEY.fullmatch(key)]
        if bad:
            raise ValueError(f"invalid remediation keys: {bad}")
        return v


def load_templates(directory: Path) -> dict[str, VendorTemplates]:
    files = sorted(p for p in chain(directory.glob("*.yaml"), directory.glob("*.yml")) if p.is_file())
    loaded: dict[str, VendorTemplates] = {}
    for path in files:
        if path.stat().st_size > MAX_TEMPLATE_BYTES:
            raise TemplateLoadError(f"{path.name}: file exceeds {MAX_TEMPLATE_BYTES} bytes")
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            templates = VendorTemplates.model_validate(doc)
        except (yaml.YAMLError, UnicodeDecodeError, ValidationError) as exc:
            raise TemplateLoadError(f"{path.name}: {exc}") from exc
        if templates.vendor in loaded:
            raise TemplateLoadError(f"{path.name}: duplicate templates for vendor {templates.vendor}")
        loaded[templates.vendor] = templates
    return loaded


def missing_templates(checks: Iterable[Check], templates: dict[str, VendorTemplates]) -> list[str]:
    problems: list[str] = []
    for check in checks:
        if check.remediation_key is None:
            continue
        for vendor in check.vendors or tuple(sorted(templates)):
            vendor_templates = templates.get(vendor)
            if vendor_templates is None:
                problems.append(f"{check.id}: no templates loaded for vendor {vendor!r}")
            elif check.remediation_key not in vendor_templates.steps:
                problems.append(f"{check.id}: {vendor} has no step {check.remediation_key!r}")
    return problems
