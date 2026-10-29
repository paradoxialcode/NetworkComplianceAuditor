from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from auditor.compliance.catalog import Catalog, CatalogLoadError, load_catalogs, unknown_mappings
from auditor.compliance.engine import run_audit
from auditor.compliance.loader import CheckLoadError, load_checks
from auditor.compliance.models import Check, CheckResult
from auditor.compliance.scoring import AuditSummary, FrameworkScore, score_all, summarize
from auditor.compliance.validation import validate_check_fields
from auditor.remediation.renderer import Remediation, render_all
from auditor.remediation.templates import (
    TemplateLoadError,
    VendorTemplates,
    load_templates,
    missing_templates,
)
from auditor.schema.baseline import SecurityBaseline

from .store import persist_audit

_MAX_REPORTED_PROBLEMS = 50


class AuditError(Exception):
    pass


@dataclass(frozen=True)
class RuleSet:
    checks: tuple[Check, ...]
    catalogs: dict[str, Catalog]
    templates: dict[str, VendorTemplates]
    warnings: tuple[str, ...]


class AuditOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    audit_id: int | None
    baseline: SecurityBaseline
    frameworks: tuple[str, ...]
    results: list[CheckResult]
    scores: dict[str, FrameworkScore]
    summary: AuditSummary
    remediations: list[Remediation]


def _require_dir(path: Path) -> Path:
    if not path.is_dir():
        raise AuditError(f"rule directory not found: {path.name}")
    return path


def load_rule_set(data_dir: Path) -> RuleSet:
    try:
        checks = load_checks(_require_dir(data_dir / "checks"))
        catalogs = load_catalogs(_require_dir(data_dir / "frameworks"))
        templates = load_templates(_require_dir(data_dir / "remediation"))
    except (CheckLoadError, CatalogLoadError, TemplateLoadError) as exc:
        raise AuditError(str(exc)) from exc
    if not checks:
        raise AuditError("no checks were found in data/checks")
    if not catalogs:
        raise AuditError("no framework catalogs were found in data/frameworks")
    problems = validate_check_fields(checks, SecurityBaseline) + unknown_mappings(checks, catalogs)
    if problems:
        shown = problems[:_MAX_REPORTED_PROBLEMS]
        extra = len(problems) - len(shown)
        suffix = f"\n... and {extra} more" if extra > 0 else ""
        raise AuditError("rule set is inconsistent:\n" + "\n".join(shown) + suffix)
    return RuleSet(
        checks=tuple(checks),
        catalogs=catalogs,
        templates=templates,
        warnings=tuple(missing_templates(checks, templates)),
    )


def run_device_audit(
    baseline: SecurityBaseline,
    rules: RuleSet,
    frameworks: Iterable[str] | None = None,
    database: Path | str | None = None,
) -> AuditOutcome:
    results: Sequence[CheckResult] = run_audit(rules.checks, baseline)
    try:
        scores = score_all(rules.catalogs, results, frameworks)
    except KeyError as exc:
        raise AuditError(f"unknown framework selection: {exc.args[0]}") from exc
    summary = summarize(results)
    remediations = render_all(results, baseline.device.vendor.value, rules.templates)
    audit_id = persist_audit(database, baseline, results, scores, summary) if database is not None else None
    return AuditOutcome(
        audit_id=audit_id,
        baseline=baseline,
        frameworks=tuple(scores),
        results=list(results),
        scores=scores,
        summary=summary,
        remediations=remediations,
    )
