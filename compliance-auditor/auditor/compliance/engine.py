import logging
import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Final

from pydantic import BaseModel

from .models import Check, CheckResult, Condition, Status
from .operators import EXISTENCE_OPS, MISSING, OPERATORS

logger = logging.getLogger(__name__)

_SENSITIVE: Final = re.compile(r"passw|secret|psk|key|communit|token|credential|hash", re.IGNORECASE)
_MAX_EVIDENCE_LEN: Final = 200
_MAX_EVIDENCE_ITEMS: Final = 20
UNKNOWN_STATE: Final = "UNKNOWN"
_ON_MISSING: Final = {
    "pass": Status.PASS,
    "fail": Status.FAIL,
    "not_configured": Status.NOT_CONFIGURED,
}

Evidence = dict[str, Any]


def resolve(data: Mapping[str, Any], path: str) -> Any:
    current: Any = data
    for segment in path.split("."):
        if isinstance(current, Mapping):
            if segment not in current:
                return MISSING
            current = current[segment]
        elif isinstance(current, Sequence) and not isinstance(current, (str, bytes)):
            if segment.isdigit():
                index = int(segment)
                if index >= len(current):
                    return MISSING
                current = current[index]
            else:
                match = next((i for i in current if isinstance(i, Mapping) and i.get("key") == segment), None)
                if match is None:
                    return MISSING
                current = match
        else:
            return MISSING
    return current


def _evidence_value(path: str, value: Any) -> Any:
    if value is MISSING:
        return "<not configured>"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, (str, list, tuple, set, frozenset)):
        if _SENSITIVE.search(path):
            return "[REDACTED]"
        if isinstance(value, str):
            return value[:_MAX_EVIDENCE_LEN]
        return [_evidence_value(path, v) for v in list(value)[:_MAX_EVIDENCE_ITEMS]]
    return f"<{type(value).__name__}>"


def _all(statuses: set[Status]) -> Status:
    for status in (Status.FAIL, Status.NOT_CONFIGURED, Status.ERROR, Status.UNKNOWN):
        if status in statuses:
            return status
    return Status.PASS


def _any(statuses: set[Status]) -> Status:
    if Status.PASS in statuses:
        return Status.PASS
    if Status.ERROR in statuses:
        return Status.ERROR
    if Status.UNKNOWN in statuses:
        return Status.UNKNOWN
    if statuses == {Status.NOT_CONFIGURED}:
        return Status.NOT_CONFIGURED
    return Status.FAIL


def _eval_leaf(field: str, op: str, cond: Condition, data: Mapping[str, Any]) -> tuple[Status, Evidence]:
    actual = resolve(data, field)
    evidence = {field: _evidence_value(field, actual)}
    if actual is MISSING and op not in EXISTENCE_OPS:
        return _ON_MISSING[cond.on_missing], evidence
    if isinstance(actual, str) and actual == UNKNOWN_STATE:
        return Status.UNKNOWN, evidence
    try:
        matched = OPERATORS[op](actual, cond.value)
    except (TypeError, ValueError, re.error):
        return Status.ERROR, evidence
    return (Status.PASS if matched else Status.FAIL), evidence


def _eval(cond: Condition, data: Mapping[str, Any]) -> tuple[Status, Evidence]:
    if cond.field is not None and cond.op is not None:
        return _eval_leaf(cond.field, cond.op, cond, data)
    children = cond.all_of if cond.all_of is not None else cond.any_of
    results = [_eval(child, data) for child in children or []]
    evidence: Evidence = {}
    for _, child_evidence in results:
        evidence.update(child_evidence)
    statuses = {status for status, _ in results}
    combine = _all if cond.all_of is not None else _any
    return combine(statuses), evidence


def _result(check: Check, status: Status, evidence: Evidence) -> CheckResult:
    return CheckResult(
        check_id=check.id,
        title=check.title,
        severity=check.severity,
        status=status,
        evidence=evidence,
        mappings=check.mappings,
        remediation_key=check.remediation_key,
    )


def evaluate_check(check: Check, data: Mapping[str, Any], vendor: str | None = None) -> CheckResult:
    if check.vendors is not None and (vendor is None or vendor.strip().lower() not in check.vendors):
        return _result(check, Status.NOT_APPLICABLE, {})
    status, evidence = _eval(check.condition, data)
    return _result(check, status, evidence)


def _to_mapping(baseline: Mapping[str, Any] | BaseModel) -> Mapping[str, Any]:
    if isinstance(baseline, BaseModel):
        return baseline.model_dump(mode="json")
    if isinstance(baseline, Mapping):
        return baseline
    raise TypeError("baseline must be a mapping or a Pydantic model")


def run_audit(
    checks: Iterable[Check],
    baseline: Mapping[str, Any] | BaseModel,
    vendor: str | None = None,
) -> list[CheckResult]:
    data = _to_mapping(baseline)
    if vendor is None:
        device = data.get("device")
        if isinstance(device, Mapping) and isinstance(device.get("vendor"), str):
            vendor = device["vendor"]
    results: list[CheckResult] = []
    for check in checks:
        try:
            results.append(evaluate_check(check, data, vendor))
        except Exception:
            logger.exception("check %s failed to evaluate", check.id)
            results.append(_result(check, Status.ERROR, {}))
    return results
