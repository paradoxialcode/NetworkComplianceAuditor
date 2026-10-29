from __future__ import annotations

from enum import StrEnum
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .operators import validate_operand

FRAMEWORKS: Final = ("cis", "stig", "nist", "iso27001", "soc2", "dpdp")


class Status(StrEnum):
    PASS = "pass"  # nosec B105
    FAIL = "fail"
    NOT_CONFIGURED = "not_configured"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"
    ERROR = "error"


NONCOMPLIANT: Final = frozenset({Status.FAIL, Status.NOT_CONFIGURED})


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Condition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    field: str | None = Field(default=None, pattern=r"^[a-z0-9_]+(\.[a-z0-9_]+)*$", max_length=128)
    op: str | None = None
    value: Any = None
    on_missing: Literal["pass", "fail", "not_configured"] = "fail"
    all_of: list[Condition] | None = None
    any_of: list[Condition] | None = None

    @model_validator(mode="after")
    def _validate_shape(self) -> Condition:
        leaf = self.field is not None or self.op is not None
        groups = [g for g in (self.all_of, self.any_of) if g is not None]
        if int(leaf) + len(groups) != 1:
            raise ValueError("condition must be exactly one of: field+op, all_of, any_of")
        if leaf:
            if self.field is None or self.op is None:
                raise ValueError("field and op must be given together")
            validate_operand(self.op, self.value)
        elif not groups[0]:
            raise ValueError("all_of/any_of must not be empty")
        return self


class Check(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[A-Z0-9][A-Z0-9_.-]{2,63}$")
    title: str = Field(min_length=3, max_length=200)
    severity: Severity
    condition: Condition
    vendors: tuple[str, ...] | None = None
    mappings: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    remediation_key: str | None = Field(default=None, pattern=r"^[a-z0-9_]{3,64}$")

    @field_validator("vendors")
    @classmethod
    def _normalize_vendors(cls, v: tuple[str, ...] | None) -> tuple[str, ...] | None:
        if v is None:
            return None
        if not v:
            raise ValueError("vendors must not be empty when given")
        return tuple(x.strip().lower() for x in v)

    @field_validator("mappings")
    @classmethod
    def _validate_mappings(cls, v: dict[str, tuple[str, ...]]) -> dict[str, tuple[str, ...]]:
        normalized = {k.strip().lower(): vals for k, vals in v.items()}
        unknown = set(normalized) - set(FRAMEWORKS)
        if unknown:
            raise ValueError(f"unknown framework(s): {sorted(unknown)}")
        return normalized


class CheckResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    check_id: str
    title: str
    severity: Severity
    status: Status
    evidence: dict[str, Any]
    mappings: dict[str, tuple[str, ...]]
    remediation_key: str | None
