import io

import pytest
from pypdf import PdfReader

from auditor.audit.generic import build_generic_baseline
from auditor.audit.pipeline import (
    TRAINED_PARSER,
    UnsupportedVendorError,
    audit_config_upload,
    parse_config_upload,
)
from auditor.audit.service import RuleSet
from auditor.audit.trained import ABSENT_TEXT, MAX_RULE_ERRORS, build_trained_baseline
from auditor.compliance.catalog import Catalog
from auditor.compliance.models import Check, Status
from auditor.parsers.normalizer import Vendor
from auditor.reporting.pdf_builder import build_report_bytes
from auditor.schema import baseline as schema
from auditor.training.patterns import MatchMethod, PatternRule

HASH = "$6$salt$ThisIsAVeryLongSecretHashValue1234567890"
JUNOS = f"""set version 21.4R3-S3.4
set system host-name junos-fw-1
set system services ssh
set system services telnet
set system ntp server 10.0.0.1
set system ntp server 10.0.0.2
set system syslog host 192.0.2.10 any any
set system login user alice class super-user
set system login user alice authentication encrypted-password "{HASH}"
set interfaces ge-0/0/0 unit 0 family inet address 10.1.1.1/24
set chassis alarm management-ethernet link-down ignore
"""
JUNOS_NO_TELNET = JUNOS.replace("set system services telnet\n", "")


def mk(rule_id, method, expression, field, value, confidence=0.9, **extra):
    return PatternRule(
        rule_id=rule_id,
        vendor=extra.pop("vendor", Vendor.JUNOS),
        method=method,
        expression=expression,
        target_field=field,
        suggested_value=value,
        confidence=confidence,
        explanation="test rule",
        **extra,
    )


def junos_rules():
    return [
        mk("junos-telnet", MatchMethod.PREFIX, "set system services telnet", "telnet_enabled", True, absent_value=False),
        mk(
            "junos-http",
            MatchMethod.PREFIX,
            "set system services web-management http",
            "http_management_enabled",
            True,
            0.85,
            absent_value=False,
        ),
        mk("junos-host", MatchMethod.REGEX, r"set system host-name (\S+)", "hostname", None, capture_group=1),
        mk("junos-ntp", MatchMethod.REGEX, r"set system ntp server (\S+)", "ntp_servers", None, capture_group=1),
        mk(
            "junos-syslog",
            MatchMethod.REGEX,
            r"set system syslog host (\S+) .*",
            "syslog_servers",
            None,
            capture_group=1,
        ),
        mk(
            "junos-user",
            MatchMethod.REGEX,
            r"set system login user (\S+) class \S+",
            "local_users",
            None,
            capture_group=1,
        ),
    ]


def build(text=JUNOS, rules=None):
    return build_trained_baseline(text, junos_rules() if rules is None else rules, Vendor.JUNOS, filename="j.set")


def fact(baseline, key):
    return next((f for f in baseline.facts if f.key == key), None)


def test_present_line_overrides_with_rule_evidence():
    baseline = build().baseline
    assert baseline.management.telnet is schema.SecurityState.ENABLED
    evidence = fact(baseline, "telnet_enabled").evidence
    assert evidence.mapping_id == "trained:junos-telnet"
    assert evidence.confidence == 0.9
    assert evidence.line == 4
    assert evidence.text == "set system services telnet"


def test_absence_rule_sets_the_value_when_the_config_is_recognized():
    baseline = build(JUNOS_NO_TELNET).baseline
    assert baseline.management.telnet is schema.SecurityState.DISABLED
    assert baseline.management.http is schema.SecurityState.DISABLED
    evidence = fact(baseline, "telnet_enabled").evidence
    assert evidence.text == ABSENT_TEXT
    assert evidence.line is None
    assert evidence.mapping_id == "trained:junos-telnet"


def test_absence_is_ignored_when_no_rule_matched_the_file():
    result = build("set foo bar\nset baz qux\n")
    assert result.rules_matched == 0
    assert result.baseline.management.telnet is schema.SecurityState.UNKNOWN
    assert result.baseline.management.http is schema.SecurityState.UNKNOWN
    assert not any(f.evidence and f.evidence.mapping_id.startswith("trained:") for f in result.baseline.facts)


def test_captures_fill_text_fields():
    baseline = build().baseline
    assert baseline.device.hostname == "junos-fw-1"
    assert baseline.device.vendor is schema.Vendor.Juniper
    assert baseline.device.platform == "Junos (trained rules)"
    assert baseline.time_sync.servers == ["10.0.0.1", "10.0.0.2"]
    assert baseline.time_sync.enabled is schema.SecurityState.ENABLED
    assert baseline.logging.destinations == ["192.0.2.10"]
    assert fact(baseline, "local_users").value == ["alice"]
    assert baseline.auth.local is schema.SecurityState.ENABLED


def test_secrets_never_reach_the_baseline():
    baseline = build().baseline
    assert HASH not in repr(baseline)
    assert "ThisIsAVery" not in repr(baseline)


def test_capture_from_a_sensitive_line_is_skipped():
    rules = [
        mk(
            "junos-user-auth",
            MatchMethod.REGEX,
            r"set system login user (\S+) authentication .*",
            "local_users",
            None,
            capture_group=1,
        ),
        *junos_rules()[:1],
    ]
    result = build(rules=rules)
    assert fact(result.baseline, "local_users") is None
    assert HASH not in repr(result.baseline)


def test_boolean_rule_on_a_sensitive_line_uses_redacted_evidence():
    rules = [mk("junos-auth", MatchMethod.PREFIX, "set system login user alice authentication", "telnet_enabled", True)]
    baseline = build(rules=rules).baseline
    assert fact(baseline, "telnet_enabled").evidence.text == "<redacted>"
    assert HASH not in repr(baseline)


def test_low_confidence_rules_do_not_set_values():
    rules = [mk("junos-chassis", MatchMethod.REGEX, r"set chassis (\S+) .*", "hostname", None, 0.5, capture_group=1)]
    baseline = build(rules=rules).baseline
    assert baseline.device.hostname == "junos-fw-1"


def test_low_confidence_rules_leave_unknown_when_nothing_else_knows():
    rules = [mk("junos-x", MatchMethod.PREFIX, "set zzz", "telnet_enabled", True, 0.5)]
    baseline = build("set zzz yes\nset system host-name a\n", rules).baseline
    assert fact(baseline, "telnet_enabled") is None


def test_conflicting_rules_leave_the_state_unknown():
    rules = [
        mk("on", MatchMethod.PREFIX, "set system services telnet", "telnet_enabled", True),
        mk("off", MatchMethod.PREFIX, "set system services ssh", "telnet_enabled", False, 0.8),
    ]
    baseline = build(rules=rules).baseline
    assert baseline.management.telnet is schema.SecurityState.UNKNOWN
    assert fact(baseline, "telnet_enabled") is None
    assert any(item.reason == "conflict" for item in baseline.unrecognized)


def test_hostname_tie_between_different_values_is_a_conflict():
    rules = [
        mk("h1", MatchMethod.REGEX, r"set system host-name (\S+)", "hostname", None, capture_group=1),
        mk("h2", MatchMethod.REGEX, r"set chassis (\S+) .*", "hostname", None, capture_group=1),
    ]
    baseline = build(rules=rules).baseline
    assert baseline.device.hostname == "junos-fw-1"
    assert any(item.reason == "conflict" for item in baseline.unrecognized)


def test_lines_matched_by_rules_are_no_longer_unrecognized():
    base = build_generic_baseline(JUNOS).baseline
    trained = build().baseline
    assert len(trained.unrecognized) < len(base.unrecognized)
    locations = {item.location for item in trained.unrecognized}
    assert "line 5" not in locations


def test_other_vendor_rules_are_ignored_and_no_rules_is_an_error():
    cisco = mk("c", MatchMethod.EXACT, "ip http server", "http_management_enabled", True, vendor=Vendor.CISCO_IOS)
    with pytest.raises(ValueError, match="no trained rules"):
        build(rules=[cisco])
    with pytest.raises(TypeError):
        build(rules=["not a rule"])
    with pytest.raises(TypeError):
        build_trained_baseline(5, junos_rules(), Vendor.JUNOS)
    with pytest.raises(TypeError):
        build_trained_baseline("x", junos_rules(), "junos")


def test_slow_rule_is_disabled_after_repeated_timeouts():
    slow = mk("slow", MatchMethod.REGEX, r"set (x|xx)+y", "telnet_enabled", True)
    text = "\n".join(["set system host-name a", *["set " + "x" * 45] * (MAX_RULE_ERRORS + 2)])
    result = build_trained_baseline(text, [slow, *junos_rules()[:1]], Vendor.JUNOS)
    assert result.rule_errors == MAX_RULE_ERRORS
    assert any(item.reason == "rule error" and "slow" in item.text for item in result.baseline.unrecognized)


def test_completeness_counts_mapped_basics():
    result = build()
    assert result.total_basics == 10
    assert {"hostname", "telnet", "http", "ntp", "syslog", "ssh"} <= set(result.mapped)
    assert result.rules_total == 6
    assert result.rules_matched == 5


def test_trained_values_beat_generic_inference():
    text = "set system host-name from-generic\nset system services telnet\n"
    rules = [mk("never-telnet", MatchMethod.PREFIX, "set system services telnet", "telnet_enabled", False, 0.95)]
    assert build_generic_baseline(text).baseline.management.telnet is schema.SecurityState.ENABLED
    assert build(text, rules).baseline.management.telnet is schema.SecurityState.DISABLED


def test_brace_style_junos_matches_the_same_rules():
    brace = """version 21.4R3-S3.4;
system {
    host-name junos-fw-1;
    services {
        ssh;
    }
    ntp {
        server 10.0.0.1;
    }
}
"""
    baseline = build(brace).baseline
    assert baseline.device.hostname == "junos-fw-1"
    assert baseline.time_sync.servers == ["10.0.0.1"]
    assert baseline.management.telnet is schema.SecurityState.DISABLED


def test_pipeline_uses_trained_rules_for_a_vendor_without_a_parser():
    result = parse_config_upload(JUNOS.encode(), "j.set", vendor=Vendor.JUNOS, trained_rules=junos_rules())
    assert result.parser == TRAINED_PARSER
    assert result.vendor is Vendor.JUNOS
    assert result.vendor_detected is False
    assert result.baseline.device.sha256 == result.upload.sha256
    assert result.baseline.device.filename == "j.set"
    assert result.rules_matched == (5, 6)
    mapped, total = result.completeness
    assert total == 10 and mapped >= 6


@pytest.mark.parametrize("rules", [None, [], [mk("c", MatchMethod.EXACT, "ip http server", "http_management_enabled", True, vendor=Vendor.CISCO_IOS)]])
def test_pipeline_without_usable_rules_still_asks_for_training(rules):
    with pytest.raises(UnsupportedVendorError):
        parse_config_upload(JUNOS.encode(), "j.set", vendor=Vendor.JUNOS, trained_rules=rules)


def make_rule_set():
    checks = [
        Check.model_validate(
            {
                "id": "CHK-TELNET-OFF",
                "title": "Telnet must be disabled",
                "severity": "high",
                "condition": {"field": "management.telnet", "op": "eq", "value": "DISABLED"},
                "mappings": {"nist": ["AC-17"]},
            }
        )
    ]
    catalog = Catalog.model_validate(
        {"framework": "nist", "name": "NIST subset", "controls": [{"id": "AC-17", "title": "Remote Access"}]}
    )
    return RuleSet(checks=tuple(checks), catalogs={"nist": catalog}, templates={}, warnings=())


def test_end_to_end_audit_and_report_disclose_trained_values():
    on = audit_config_upload(JUNOS.encode(), "j.set", make_rule_set(), vendor=Vendor.JUNOS, trained_rules=junos_rules())
    off = audit_config_upload(
        JUNOS_NO_TELNET.encode(), "j.set", make_rule_set(), vendor=Vendor.JUNOS, trained_rules=junos_rules()
    )
    assert [r.status for r in on.outcome.results] == [Status.FAIL]
    assert [r.status for r in off.outcome.results] == [Status.PASS]
    text = " ".join(page.extract_text() for page in PdfReader(io.BytesIO(build_report_bytes(on.outcome))).pages)
    assert "trained mapping rules" in text
    assert HASH not in text
