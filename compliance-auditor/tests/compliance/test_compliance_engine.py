import pytest
from pydantic import BaseModel

from auditor.compliance import engine
from auditor.compliance.engine import evaluate_check, resolve, run_audit
from auditor.compliance.models import Check, Status

BASELINE = {
    "mgmt": {"telnet": {"enabled": False}, "ssh": {"version": 2}},
    "snmp": {"community": "public123", "communities": ["a", "b"]},
    "password": {"min_length": 8},
    "logging": {"hosts": ["10.0.0.5"]},
}


def chk(condition, check_id="CHK-TEST-01", **extra):
    return Check.model_validate(
        {"id": check_id, "title": "Test check", "severity": "high", "condition": condition, **extra}
    )


def status(condition, vendor=None, **extra):
    return evaluate_check(chk(condition, **extra), BASELINE, vendor).status


def test_resolve_paths():
    assert resolve(BASELINE, "mgmt.ssh.version") == 2
    assert resolve(BASELINE, "logging.hosts.0") == "10.0.0.5"
    assert resolve(BASELINE, "logging.hosts.5").name == "MISSING"
    assert resolve(BASELINE, "mgmt.ssh.version.deeper").name == "MISSING"
    assert resolve(BASELINE, "nothing").name == "MISSING"


def test_leaf_pass_and_fail():
    assert status({"field": "mgmt.ssh.version", "op": "eq", "value": 2}) is Status.PASS
    assert status({"field": "mgmt.ssh.version", "op": "eq", "value": 1}) is Status.FAIL
    assert status({"field": "password.min_length", "op": "gte", "value": 12}) is Status.FAIL


@pytest.mark.parametrize(
    ("on_missing", "expected"),
    [(None, Status.FAIL), ("pass", Status.PASS), ("fail", Status.FAIL), ("not_configured", Status.NOT_CONFIGURED)],
)
def test_missing_field_semantics(on_missing, expected):
    cond = {"field": "ntp.enabled", "op": "eq", "value": True}
    if on_missing:
        cond["on_missing"] = on_missing
    assert status(cond) is expected


def test_existence_operators_on_missing_field():
    assert status({"field": "telnet.stanza", "op": "absent"}) is Status.PASS
    assert status({"field": "telnet.stanza", "op": "present"}) is Status.FAIL
    assert status({"field": "mgmt.ssh.version", "op": "present"}) is Status.PASS


def test_type_mismatch_is_error_not_fail():
    assert status({"field": "snmp.community", "op": "gte", "value": 1}) is Status.ERROR


def test_all_of_and_any_of():
    good = {"field": "mgmt.ssh.version", "op": "eq", "value": 2}
    bad = {"field": "mgmt.telnet.enabled", "op": "eq", "value": True}
    assert status({"all_of": [good, good]}) is Status.PASS
    assert status({"all_of": [good, bad]}) is Status.FAIL
    assert status({"any_of": [bad, good]}) is Status.PASS
    assert status({"any_of": [bad, bad]}) is Status.FAIL
    erroring = {"field": "snmp.community", "op": "gte", "value": 1}
    assert status({"all_of": [good, erroring]}) is Status.ERROR
    assert status({"any_of": [bad, erroring]}) is Status.ERROR
    assert status({"any_of": [good, erroring]}) is Status.PASS


def test_any_of_all_not_configured():
    nc = {"field": "x.y", "op": "eq", "value": 1, "on_missing": "not_configured"}
    assert status({"any_of": [nc, nc]}) is Status.NOT_CONFIGURED


def test_vendor_applicability():
    cond = {"field": "mgmt.ssh.version", "op": "eq", "value": 2}
    assert status(cond, vendor="Cisco", vendors=["cisco", "junos"]) is Status.PASS
    assert status(cond, vendor="fortinet", vendors=["cisco"]) is Status.NOT_APPLICABLE
    assert status(cond, vendor=None, vendors=["cisco"]) is Status.NOT_APPLICABLE
    assert status(cond, vendor="anything") is Status.PASS


def test_evidence_redaction():
    cond = {
        "all_of": [
            {"field": "snmp.community", "op": "ne", "value": "public"},
            {"field": "snmp.communities", "op": "contains", "value": "a"},
            {"field": "password.min_length", "op": "gte", "value": 8},
            {"field": "mgmt.missing_thing", "op": "present"},
        ]
    }
    result = evaluate_check(chk(cond), BASELINE)
    assert result.evidence["snmp.community"] == "[REDACTED]"
    assert result.evidence["snmp.communities"] == "[REDACTED]"
    assert result.evidence["password.min_length"] == 8
    assert result.evidence["mgmt.missing_thing"] == "<not configured>"


def test_evidence_truncates_long_strings():
    long_value = {"banner": {"text": "x" * 1000}}
    cond = {"field": "banner.text", "op": "present"}
    result = evaluate_check(chk(cond), long_value)
    assert len(result.evidence["banner.text"]) == 200


def test_result_carries_metadata():
    check = chk(
        {"field": "mgmt.ssh.version", "op": "eq", "value": 2},
        mappings={"NIST": ["AC-17"], "cis": ["x"]},
        remediation_key="set_ssh_v2",
    )
    result = evaluate_check(check, BASELINE)
    assert result.mappings == {"nist": ("AC-17",), "cis": ("x",)}
    assert result.remediation_key == "set_ssh_v2"
    assert result.severity == "high"


def test_run_audit_accepts_pydantic_model():
    class Mgmt(BaseModel):
        ssh_version: int = 2

    class Baseline(BaseModel):
        mgmt: Mgmt = Mgmt()

    results = run_audit([chk({"field": "mgmt.ssh_version", "op": "eq", "value": 2})], Baseline())
    assert results[0].status is Status.PASS


def test_run_audit_rejects_bad_baseline():
    with pytest.raises(TypeError):
        run_audit([], ["not", "a", "mapping"])


def test_one_broken_check_does_not_abort_audit(monkeypatch):
    original = engine._eval

    def flaky(cond, data):
        if cond.value == 99:
            raise RuntimeError("boom")
        return original(cond, data)

    monkeypatch.setattr(engine, "_eval", flaky)
    checks = [
        chk({"field": "mgmt.ssh.version", "op": "eq", "value": 99}, check_id="CHK-BAD-01"),
        chk({"field": "mgmt.ssh.version", "op": "eq", "value": 2}, check_id="CHK-OK-01"),
    ]
    results = run_audit(checks, BASELINE)
    assert [r.status for r in results] == [Status.ERROR, Status.PASS]


@pytest.mark.parametrize(
    "bad",
    [
        {},
        {"field": "a.b"},
        {"op": "eq", "value": 1},
        {"field": "A.b", "op": "eq", "value": 1},
        {"field": "a..b", "op": "eq", "value": 1},
        {"field": "a.b", "op": "eq", "value": 1, "all_of": []},
        {"all_of": []},
        {"field": "a.b", "op": "bogus", "value": 1},
        {"field": "a.b", "op": "eq", "value": 1, "extra": 1},
    ],
)
def test_invalid_conditions_rejected(bad):
    with pytest.raises(ValueError):
        chk(bad)


def test_unknown_state_is_its_own_status():
    data = {"management": {"telnet": "UNKNOWN"}}
    cond = {"field": "management.telnet", "op": "eq", "value": "DISABLED", "on_missing": "pass"}
    assert evaluate_check(chk(cond), data).status is Status.UNKNOWN


def test_composite_precedence_with_unknown_and_error():
    ok = {"field": "mgmt.ssh.version", "op": "eq", "value": 2}
    bad = {"field": "mgmt.ssh.version", "op": "eq", "value": 1}
    unk = {"field": "state.x", "op": "eq", "value": "A"}
    err = {"field": "snmp.community", "op": "gte", "value": 1}
    data = {**BASELINE, "state": {"x": "UNKNOWN"}}

    def run(cond):
        return evaluate_check(chk(cond), data).status

    assert run({"all_of": [bad, unk]}) is Status.FAIL
    assert run({"all_of": [bad, err]}) is Status.FAIL
    assert run({"all_of": [ok, unk]}) is Status.UNKNOWN
    assert run({"any_of": [ok, unk]}) is Status.PASS
    assert run({"any_of": [bad, unk]}) is Status.UNKNOWN
    assert run({"any_of": [unk, err]}) is Status.ERROR


def test_keyed_list_lookup():
    data = {"facts": [{"key": "ssh_version", "value": 2}, {"key": "other", "value": "x"}]}
    assert resolve(data, "facts.ssh_version.value") == 2
    assert resolve(data, "facts.1.key") == "other"
    assert resolve(data, "facts.absent.value").name == "MISSING"


def test_non_empty_operator():
    data = {"logging": {"hosts": ["a"], "none": [], "name": ""}}
    assert evaluate_check(chk({"field": "logging.hosts", "op": "non_empty"}), data).status is Status.PASS
    assert evaluate_check(chk({"field": "logging.none", "op": "non_empty"}), data).status is Status.FAIL
    assert evaluate_check(chk({"field": "logging.name", "op": "non_empty"}), data).status is Status.FAIL
    assert evaluate_check(chk({"field": "logging.nothing", "op": "non_empty"}), data).status is Status.FAIL


def test_catastrophic_regex_in_a_rule_is_rejected_at_load():
    with pytest.raises(ValueError, match="too slow"):
        chk({"field": "banner.text", "op": "regex", "value": "(a|aa)+$"})


def test_slow_regex_gives_a_controlled_error_not_a_hang(monkeypatch):
    import time

    from auditor import regex_safety

    monkeypatch.setattr(regex_safety, "_PROBES", ())
    regex_safety.compile_pattern.cache_clear()
    try:
        check = chk({"field": "banner.text", "op": "regex", "value": "(a|aa)+$"})
        data = {"banner": {"text": "a" * 60 + "!"}}
        start = time.time()
        result = evaluate_check(check, data)
        elapsed = time.time() - start
    finally:
        regex_safety.compile_pattern.cache_clear()
    assert result.status is Status.ERROR
    assert elapsed < 1.0
