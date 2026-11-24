from pathlib import Path

import pytest

from auditor.audit.pipeline import audit_config_upload
from auditor.audit.service import load_rule_set
from auditor.compliance.models import Status
from auditor.parsers.normalizer import Vendor
from auditor.training.store import load_rules

DATA = Path(__file__).resolve().parents[2] / "data"
SAMPLES = DATA / "samples"
RULES = load_rule_set(DATA)
JUNOS_RULES = load_rules(SAMPLES / "junos" / "junos-demo-rules.json")


def run(relative: str, vendor: Vendor | None = None):
    path = SAMPLES / relative
    return audit_config_upload(path.read_bytes(), path.name, RULES, vendor=vendor, trained_rules=JUNOS_RULES)


def test_rule_set_is_consistent():
    assert RULES.warnings == ()
    assert set(RULES.catalogs) == {"nist", "cis", "iso27001"}
    assert len(RULES.checks) == 24
    assert all(set(check.mappings) == {"nist", "cis", "iso27001"} for check in RULES.checks)


@pytest.mark.parametrize("sample", ["cisco/edge-r1-hardened.cfg", "fortinet/fw-hq-hardened.conf"])
def test_hardened_samples_are_fully_compliant(sample):
    outcome = run(sample).outcome
    assert {r.status for r in outcome.results} <= {Status.PASS, Status.NOT_APPLICABLE}
    assert all(score.pass_pct == 100.0 for score in outcome.scores.values())
    assert outcome.remediations == []


@pytest.mark.parametrize("sample", ["cisco/edge-r1-weak.cfg", "fortinet/fw-hq-weak.conf"])
def test_weak_samples_fail_with_remediation(sample):
    outcome = run(sample).outcome
    failed = [r for r in outcome.results if r.status is Status.FAIL]
    assert len(failed) >= 14
    assert all(score.pass_pct < 10 for score in outcome.scores.values())
    assert sum(1 for item in outcome.remediations if item.commands) >= 14


def test_junos_samples_use_trained_rules():
    weak = run("junos/srx-branch-weak.set", Vendor.JUNOS)
    hardened = run("junos/srx-branch-hardened.set", Vendor.JUNOS)
    assert weak.parse.parser == "trained"
    status = {r.check_id: r.status for r in hardened.outcome.results}
    assert status["MGT-001"] is Status.PASS
    assert {r.check_id: r.status for r in weak.outcome.results}["MGT-001"] is Status.FAIL
