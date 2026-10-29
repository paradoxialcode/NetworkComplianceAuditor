from collections import Counter
from collections.abc import Iterable, Sequence
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from .catalog import Catalog
from .models import NONCOMPLIANT, CheckResult, Severity, Status


class ControlStatus(StrEnum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    INDETERMINATE = "indeterminate"
    NOT_APPLICABLE = "not_applicable"
    NOT_ASSESSABLE = "not_assessable"


class ControlResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    control_id: str
    title: str
    status: ControlStatus
    check_ids: tuple[str, ...]


class FrameworkScore(BaseModel):
    model_config = ConfigDict(frozen=True)

    framework: str
    name: str
    total: int
    compliant: int
    non_compliant: int
    indeterminate: int
    not_applicable: int
    not_assessable: int
    coverage_pct: float
    pass_pct: float | None
    controls: tuple[ControlResult, ...]


class AuditSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    total: int
    by_status: dict[Status, int]
    failing_by_severity: dict[Severity, int]


def _control_status(statuses: Sequence[Status]) -> ControlStatus:
    if not statuses:
        return ControlStatus.NOT_ASSESSABLE
    applicable = [s for s in statuses if s is not Status.NOT_APPLICABLE]
    if not applicable:
        return ControlStatus.NOT_APPLICABLE
    if any(s in NONCOMPLIANT for s in applicable):
        return ControlStatus.NON_COMPLIANT
    if any(s in (Status.ERROR, Status.UNKNOWN) for s in applicable):
        return ControlStatus.INDETERMINATE
    return ControlStatus.COMPLIANT


def score_framework(catalog: Catalog, results: Iterable[CheckResult]) -> FrameworkScore:
    by_control: dict[str, list[CheckResult]] = {}
    for result in results:
        for control_id in result.mappings.get(catalog.framework, ()):
            by_control.setdefault(control_id.strip().casefold(), []).append(result)

    controls: list[ControlResult] = []
    for control in catalog.controls:
        mapped = by_control.get(control.id.casefold(), [])
        controls.append(
            ControlResult(
                control_id=control.id,
                title=control.title,
                status=_control_status([r.status for r in mapped]),
                check_ids=tuple(sorted({r.check_id for r in mapped})),
            )
        )

    counts = Counter(c.status for c in controls)
    compliant = counts[ControlStatus.COMPLIANT]
    non_compliant = counts[ControlStatus.NON_COMPLIANT]
    indeterminate = counts[ControlStatus.INDETERMINATE]
    not_applicable = counts[ControlStatus.NOT_APPLICABLE]
    assessed = compliant + non_compliant + indeterminate
    in_scope = len(controls) - not_applicable
    return FrameworkScore(
        framework=catalog.framework,
        name=catalog.name,
        total=len(controls),
        compliant=compliant,
        non_compliant=non_compliant,
        indeterminate=indeterminate,
        not_applicable=not_applicable,
        not_assessable=counts[ControlStatus.NOT_ASSESSABLE],
        coverage_pct=round(100 * assessed / in_scope, 1) if in_scope else 0.0,
        pass_pct=round(100 * compliant / assessed, 1) if assessed else None,
        controls=tuple(controls),
    )


def score_all(
    catalogs: dict[str, Catalog],
    results: Sequence[CheckResult],
    frameworks: Iterable[str] | None = None,
) -> dict[str, FrameworkScore]:
    selected = list(catalogs) if frameworks is None else [f.strip().lower() for f in frameworks]
    missing = [f for f in selected if f not in catalogs]
    if missing:
        raise KeyError(f"no catalog loaded for: {missing}")
    return {f: score_framework(catalogs[f], results) for f in selected}


def summarize(results: Sequence[CheckResult]) -> AuditSummary:
    by_status = Counter(r.status for r in results)
    failing = Counter(r.severity for r in results if r.status in NONCOMPLIANT)
    return AuditSummary(total=len(results), by_status=dict(by_status), failing_by_severity=dict(failing))
