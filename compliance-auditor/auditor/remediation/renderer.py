from collections.abc import Iterable, Mapping
from enum import StrEnum
from typing import Final

from jinja2 import TemplateError
from pydantic import BaseModel, ConfigDict

from auditor.compliance.models import NONCOMPLIANT, CheckResult, Severity, Status

from .templates import CONTROL_CHARS, ENV, MAX_COMMAND_LEN, RemediationStep, VendorTemplates

_MANUAL_ORDER: Final = 90
_VERIFY_ORDER: Final = 100
_SEVERITY_RANK: Final = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}


class RemediationKind(StrEnum):
    COMMANDS = "commands"
    MANUAL = "manual"
    VERIFY = "verify"


class Remediation(BaseModel):
    model_config = ConfigDict(frozen=True)

    check_id: str
    check_title: str
    severity: Severity
    status: Status
    kind: RemediationKind
    step_title: str | None
    commands: tuple[str, ...]
    warning: str | None
    note: str | None
    order: int


def _build(
    result: CheckResult,
    kind: RemediationKind,
    order: int,
    *,
    step_title: str | None = None,
    commands: tuple[str, ...] = (),
    warning: str | None = None,
    note: str | None = None,
) -> Remediation:
    return Remediation(
        check_id=result.check_id,
        check_title=result.title,
        severity=result.severity,
        status=result.status,
        kind=kind,
        step_title=step_title,
        commands=commands,
        warning=warning,
        note=note,
        order=order,
    )


def _manual(result: CheckResult, note: str) -> Remediation:
    return _build(result, RemediationKind.MANUAL, _MANUAL_ORDER, note=note)


def _render_commands(step: RemediationStep, context: Mapping[str, str]) -> tuple[tuple[str, ...] | None, str | None]:
    values: dict[str, str] = {}
    for name, spec in step.params.items():
        value = context.get(name, spec.default)
        if value is None:
            return None, f"parameter {name!r} is required but was not provided"
        if not spec.accepts(value):
            return None, f"parameter {name!r} failed validation"
        values[name] = value
    lines: list[str] = []
    for template in step.commands:
        try:
            line = ENV.from_string(template).render(**values)
        except TemplateError:
            return None, "template could not be rendered"
        if not line.strip() or len(line) > MAX_COMMAND_LEN or CONTROL_CHARS.search(line):
            return None, "rendered command is not a valid single line"
        lines.append(line)
    return tuple(lines), None


def render_remediation(
    result: CheckResult,
    vendor: str | None,
    templates: Mapping[str, VendorTemplates],
    context: Mapping[str, str] | None = None,
) -> Remediation:
    if result.status not in NONCOMPLIANT:
        return _build(
            result,
            RemediationKind.VERIFY,
            _VERIFY_ORDER,
            note="Result could not be determined automatically; verify this setting manually.",
        )
    if result.remediation_key is None:
        return _manual(result, "No automated remediation is defined for this check.")
    vendor_templates = templates.get((vendor or "").strip().lower())
    if vendor_templates is None:
        return _manual(result, "No remediation templates are available for this vendor.")
    step = vendor_templates.steps.get(result.remediation_key)
    if step is None:
        return _manual(result, "No remediation template exists for this check on this vendor.")
    commands, error = _render_commands(step, context or {})
    if commands is None:
        return _manual(result, f"Remediation could not be generated: {error}.")
    return _build(
        result,
        RemediationKind.COMMANDS,
        step.order,
        step_title=step.title,
        commands=commands,
        warning=step.risk,
    )


def render_all(
    results: Iterable[CheckResult],
    vendor: str | None,
    templates: Mapping[str, VendorTemplates],
    contexts: Mapping[str, Mapping[str, str]] | None = None,
) -> list[Remediation]:
    items = [
        render_remediation(r, vendor, templates, (contexts or {}).get(r.check_id))
        for r in results
        if r.status in NONCOMPLIANT or r.status in (Status.UNKNOWN, Status.ERROR)
    ]
    return sorted(items, key=lambda x: (x.order, _SEVERITY_RANK[x.severity], x.check_id))
