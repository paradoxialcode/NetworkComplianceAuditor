from __future__ import annotations

from collections.abc import Iterable
from itertools import chain
from pathlib import Path
from typing import Final

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .models import FRAMEWORKS, Check

MAX_CATALOG_BYTES: Final = 2_000_000


class CatalogLoadError(Exception):
    pass


class Control(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._()/ -]{0,63}$")
    title: str = Field(min_length=1, max_length=300)


class Catalog(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    framework: str
    name: str = Field(min_length=1, max_length=200)
    version: str | None = None
    controls: tuple[Control, ...] = Field(min_length=1)

    @field_validator("framework")
    @classmethod
    def _known_framework(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in FRAMEWORKS:
            raise ValueError(f"unknown framework {v!r}")
        return v

    @model_validator(mode="after")
    def _unique_ids(self) -> Catalog:
        ids = [c.id.casefold() for c in self.controls]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate control ids")
        return self


def load_catalogs(directory: Path) -> dict[str, Catalog]:
    files = sorted(p for p in chain(directory.glob("*.yaml"), directory.glob("*.yml")) if p.is_file())
    catalogs: dict[str, Catalog] = {}
    for path in files:
        if path.stat().st_size > MAX_CATALOG_BYTES:
            raise CatalogLoadError(f"{path.name}: file exceeds {MAX_CATALOG_BYTES} bytes")
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            catalog = Catalog.model_validate(doc)
        except (yaml.YAMLError, UnicodeDecodeError, ValidationError) as exc:
            raise CatalogLoadError(f"{path.name}: {exc}") from exc
        if catalog.framework in catalogs:
            raise CatalogLoadError(f"{path.name}: duplicate catalog for {catalog.framework}")
        catalogs[catalog.framework] = catalog
    return catalogs


def unknown_mappings(checks: Iterable[Check], catalogs: dict[str, Catalog]) -> list[str]:
    known = {fw: {c.id.casefold() for c in cat.controls} for fw, cat in catalogs.items()}
    problems: list[str] = []
    for check in checks:
        for framework, ids in check.mappings.items():
            if framework not in known:
                continue
            problems.extend(
                f"{check.id}: {framework} control {cid!r} not in catalog"
                for cid in ids
                if cid.strip().casefold() not in known[framework]
            )
    return problems
