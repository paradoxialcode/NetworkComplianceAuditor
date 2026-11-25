import pytest
from pydantic import ValidationError

from auditor.compliance.catalog import Catalog, Control, mapping_completeness
from auditor.compliance.engine import evaluate_check
from auditor.compliance.models import Check, Condition, Status
from auditor.compliance.validation import validate_check_fields
from auditor.schema.baseline import SecurityBaseline

PERMIT = {"field": "action", "op": "eq", "value": "permit"}


def _check(condition: dict, check_id: str = "TST-001", **extra) -> Check:
    return Check.model_validate(
        {"id": check_id, "title": "Test check", "severity": "low", "condition": condition, **extra}
    )


def _status(condition: dict, data: dict) -> Status:
    return evaluate_check(_check(condition), data).status


POLICIES = {"policies": [{"action": "permit"}, {"action": "deny"}]}


@pytest.mark.parametrize(
    "bad",
    [
        {"field": "policies", "any_match": PERMIT, "op": "eq", "value": 1},
        {"field": "policies", "any_match": PERMIT, "none_match": PERMIT},
        {"any_match": PERMIT},
        {"field": "policies", "any_match": PERMIT, "value": 1},
        {"field": "policies", "any_match": PERMIT, "all_of": [PERMIT]},
        {"field": "policies"},
        {"field": "policies", "any_match": {"field": "action"}},
    ],
)
def test_invalid_shapes_rejected(bad):
    with pytest.raises(ValidationError):
        Condition.model_validate(bad)


@pytest.mark.parametrize("key", ["any_match", "none_match"])
def test_valid_shape_accepted(key):
    Condition.model_validate({"field": "policies", key: PERMIT})


def test_any_match_pass_and_evidence_has_counts_only():
    result = evaluate_check(_check({"field": "policies", "any_match": PERMIT}), POLICIES)
    assert result.status is Status.PASS
    assert result.evidence == {"policies.count": 2, "policies.matched": 1}


def test_any_match_fail_when_nothing_matches():
    cond = {"field": "policies", "any_match": {"field": "action", "op": "eq", "value": "reject"}}
    assert _status(cond, POLICIES) is Status.FAIL


def test_none_match():
    assert _status({"field": "policies", "none_match": PERMIT}, POLICIES) is Status.FAIL
    cond = {"field": "policies", "none_match": {"field": "action", "op": "eq", "value": "reject"}}
    assert _status(cond, POLICIES) is Status.PASS


def test_empty_list():
    data = {"policies": []}
    assert _status({"field": "policies", "any_match": PERMIT}, data) is Status.FAIL
    assert _status({"field": "policies", "none_match": PERMIT}, data) is Status.PASS


@pytest.mark.parametrize(
    ("on_missing", "expected"),
    [(None, Status.FAIL), ("pass", Status.PASS), ("not_configured", Status.NOT_CONFIGURED)],
)
def test_missing_list_uses_on_missing(on_missing, expected):
    cond = {"field": "policies", "any_match": PERMIT}
    if on_missing:
        cond["on_missing"] = on_missing
    assert _status(cond, {}) is expected


def test_scalar_list_items_use_value_field():
    data = {"logging": {"destinations": ["10.0.0.1", "10.0.0.2"]}}
    hit = {"field": "logging.destinations", "any_match": {"field": "value", "op": "eq", "value": "10.0.0.2"}}
    miss = {"field": "logging.destinations", "any_match": {"field": "value", "op": "eq", "value": "10.9.9.9"}}
    assert _status(hit, data) is Status.PASS
    assert _status(miss, data) is Status.FAIL


def test_unknown_item_is_never_pass_or_fail():
    data = {"policies": [{"action": "UNKNOWN"}]}
    assert _status({"field": "policies", "any_match": PERMIT}, data) is Status.UNKNOWN
    assert _status({"field": "policies", "none_match": PERMIT}, data) is Status.UNKNOWN


def test_match_beats_unknown_for_any_and_none():
    data = {"policies": [{"action": "UNKNOWN"}, {"action": "permit"}]}
    assert _status({"field": "policies", "any_match": PERMIT}, data) is Status.PASS
    assert _status({"field": "policies", "none_match": PERMIT}, data) is Status.FAIL


def test_unknown_list_value_is_unknown():
    assert _status({"field": "policies", "any_match": PERMIT}, {"policies": "UNKNOWN"}) is Status.UNKNOWN


def test_non_list_field_is_error():
    assert _status({"field": "policies", "any_match": PERMIT}, {"policies": 5}) is Status.ERROR


def test_operator_type_error_in_item_is_error():
    cond = {"field": "policies", "any_match": {"field": "action", "op": "gt", "value": 1}}
    assert _status(cond, POLICIES) is Status.ERROR


def test_nested_all_of_inside_match():
    cond = {
        "field": "policies",
        "none_match": {
            "all_of": [PERMIT, {"field": "src", "op": "eq", "value": "any"}],
        },
    }
    safe = {"policies": [{"action": "permit", "src": "10.0.0.0/8"}, {"action": "deny", "src": "any"}]}
    risky = {"policies": [{"action": "permit", "src": "any"}]}
    assert _status(cond, safe) is Status.PASS
    assert _status(cond, risky) is Status.FAIL


def test_vendor_scoping_still_applies():
    check = _check({"field": "policies", "any_match": PERMIT}, vendors=["cisco"])
    assert evaluate_check(check, POLICIES, "fortinet").status is Status.NOT_APPLICABLE


def _validation_errors(condition: dict) -> list[str]:
    return validate_check_fields([_check(condition)], SecurityBaseline)


def test_validation_accepts_model_items_and_scalar_items():
    assert _validation_errors({"field": "policies", "none_match": PERMIT}) == []
    scalar = {"field": "logging.destinations", "any_match": {"field": "value", "op": "eq", "value": "x"}}
    assert _validation_errors(scalar) == []


def test_validation_rejects_bad_item_field():
    errors = _validation_errors({"field": "policies", "any_match": {"field": "nope", "op": "eq", "value": 1}})
    assert len(errors) == 1 and "nope" in errors[0]


def test_validation_rejects_non_list_field():
    errors = _validation_errors({"field": "device.hostname", "any_match": PERMIT})
    assert len(errors) == 1 and "requires a list" in errors[0]


def test_validation_rejects_unknown_list_field():
    assert _validation_errors({"field": "nope", "any_match": PERMIT})


def test_validation_rejects_numeric_op_on_string_item():
    cond = {"field": "policies", "any_match": {"field": "action", "op": "gt", "value": 1}}
    assert any("numeric operator" in e for e in _validation_errors(cond))


def test_validation_rejects_wrong_scalar_item_field():
    cond = {"field": "logging.destinations", "any_match": {"field": "name", "op": "eq", "value": "x"}}
    assert _validation_errors(cond)


def _catalog() -> dict[str, Catalog]:
    controls = tuple(Control(id=cid, title="t") for cid in ("AC-1", "AC-2", "AU-1"))
    return {"nist": Catalog(framework="nist", name="NIST", controls=controls)}


def test_mapping_completeness_all_and_by_vendor():
    cond = {"field": "a_b", "op": "present"}
    checks = [
        _check(cond, "TST-001", mappings={"nist": ["ac-1"]}),
        _check(cond, "TST-002", vendors=["cisco"], mappings={"nist": ["AU-1"]}),
    ]
    everything = mapping_completeness(checks, _catalog())["nist"]
    assert (everything.mapped, everything.total, everything.pct) == (2, 3, 66.7)
    assert everything.unmapped == ("AC-2",)
    forti = mapping_completeness(checks, _catalog(), "Fortinet")["nist"]
    assert forti.mapped == 1 and forti.unmapped == ("AC-2", "AU-1")
    cisco = mapping_completeness(checks, _catalog(), "cisco")["nist"]
    assert cisco.mapped == 2


def test_mapping_completeness_no_checks():
    item = mapping_completeness([], _catalog())["nist"]
    assert (item.mapped, item.pct) == (0, 0.0)
