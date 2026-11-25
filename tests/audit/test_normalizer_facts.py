from pathlib import Path

import pytest

from auditor.audit.pipeline import parse_config_upload
from auditor.compliance.engine import run_audit
from auditor.compliance.loader import load_checks
from auditor.compliance.models import Status
from auditor.parsers.normalizer import NamedFact, SecurityBaseline, Vendor, normalize
from auditor.parsers.tokenizers.fortinet import tokenize_fortinet
from auditor.parsers.tokenizers.indented import tokenize_indented
from tests.audit.samples_item3 import CISCO_BAD, CISCO_GOOD, FORTI_BAD, FORTI_GOOD

CHECKS = load_checks(Path(__file__).resolve().parents[2] / "data" / "checks")
SECRETS = (
    "SuperSecretHash",
    "AnotherHash",
    "RADIUSKEY123",
    "SECRETBANNER",
    "Xk39sLong",
    "AUTHPASS999",
    "PRIVPASS999",
    "SH2abcdefSECRETENC",
    "Zq81LongCommunity",
    "SNMPAUTHSECRET",
    "RADIUSSECRETENC",
    "FORTIBANNERTEXT",
    "plaintext1",
    "cisco123",
    "vtypass",
)


def cisco(text: str) -> dict[str, NamedFact]:
    baseline = normalize(tokenize_indented(text), Vendor.CISCO_IOS)
    return {fact.key: fact for fact in baseline.facts}


def forti(text: str) -> dict[str, NamedFact]:
    baseline = normalize(tokenize_fortinet(text), Vendor.FORTIOS)
    return {fact.key: fact for fact in baseline.facts}


def statuses(text: str) -> dict[str, Status]:
    parse = parse_config_upload(text.encode(), "device.cfg")
    return {result.check_id: result.status for result in run_audit(CHECKS, parse.baseline)}


def test_cisco_good_values():
    facts = cisco(CISCO_GOOD)
    expected = {
        "os_version": "17.9",
        "hardware_model": "C9300-24T",
        "serial_number": "FCW1234ABCD",
        "ssh_version": 2,
        "ssh_enabled": True,
        "aaa_enabled": True,
        "privileged_secret_set": True,
        "remote_auth_server_count": 1,
        "plaintext_password_count": 0,
        "max_login_attempts": 3,
        "timestamps_enabled": True,
        "trap_level_numeric": 6,
        "exec_timeout_minutes": 5,
        "snmp_default_community": False,
        "login_banner_present": True,
        "ip_source_route_enabled": False,
        "directed_broadcast_enabled": False,
        "icmp_redirects_enabled": False,
        "mgmt_access_restricted": True,
        "permit_any_any_count": 0,
        "antispoofing_enabled": True,
        "logging_enabled": True,
        "snmp_v3_configured": True,
    }
    assert {key: facts[key].value for key in expected} == expected


def test_cisco_bad_values():
    facts = cisco(CISCO_BAD)
    assert facts["plaintext_password_count"].value == 3
    assert facts["snmp_default_community"].value is True
    assert facts["ip_source_route_enabled"].value is True
    assert facts["directed_broadcast_enabled"].value is True
    assert facts["icmp_redirects_enabled"].value is True
    assert facts["mgmt_access_restricted"].value is False
    assert facts["permit_any_any_count"].value == 1
    assert facts["exec_timeout_minutes"].value == 99999
    assert facts["ssh_enabled"].value is False
    assert facts["privileged_secret_set"].value is False
    assert "antispoofing_enabled" not in facts
    assert "login_banner_present" not in facts


def test_forti_good_values():
    facts = forti(FORTI_GOOD)
    expected = {
        "hardware_model": "FGT60F",
        "os_version": "7.2.5",
        "ssh_enabled": True,
        "https_enabled": True,
        "ssh_version": 2,
        "exec_timeout_minutes": 5,
        "max_login_attempts": 3,
        "login_banner_present": True,
        "icmp_redirects_enabled": False,
        "snmp_default_community": False,
        "snmp_v3_configured": True,
        "remote_auth_server_count": 1,
        "aaa_enabled": True,
        "plaintext_password_count": 0,
        "trap_level_numeric": 6,
        "mgmt_access_restricted": True,
        "permit_any_any_count": 0,
        "antispoofing_enabled": True,
    }
    assert {key: facts[key].value for key in expected} == expected


def test_forti_bad_values():
    facts = forti(FORTI_BAD)
    assert facts["snmp_default_community"].value is True
    assert facts["icmp_redirects_enabled"].value is True
    assert facts["mgmt_access_restricted"].value is False
    assert facts["permit_any_any_count"].value == 1
    assert facts["exec_timeout_minutes"].value == 30
    assert "ssh_enabled" not in facts or facts["ssh_enabled"].value is False
    assert "ssh_version" not in facts


@pytest.mark.parametrize("text", [CISCO_GOOD, CISCO_BAD, FORTI_GOOD, FORTI_BAD])
def test_no_secret_in_baseline_or_schema(text):
    vendor = Vendor.FORTIOS if text.startswith("#config") else Vendor.CISCO_IOS
    tokens = tokenize_fortinet(text) if vendor is Vendor.FORTIOS else tokenize_indented(text)
    normalized = repr(normalize(tokens, vendor))
    schema_dump = parse_config_upload(text.encode(), "d.cfg").baseline.model_dump_json()
    for secret in SECRETS:
        assert secret not in normalized
        assert secret not in schema_dump


def test_good_cisco_passes_every_check():
    assert set(statuses(CISCO_GOOD).values()) == {Status.PASS}


def test_bad_cisco_fails_hardening_checks():
    result = statuses(CISCO_BAD)
    for check_id in ("AUTH-004", "MGT-001", "MGT-004", "MGT-005", "MGT-006", "NET-001", "NET-002", "NET-003", "NET-004", "NET-005"):
        assert result[check_id] is Status.FAIL, check_id


def test_forti_good_checks():
    result = statuses(FORTI_GOOD)
    for check_id in ("AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004", "AUTH-005", "LOG-001", "LOG-002", "LOG-004", "LOG-005"):
        assert result[check_id] is Status.PASS, check_id
    for check_id in ("MGT-001", "MGT-002", "MGT-003", "MGT-004", "MGT-005", "MGT-006", "MGT-007"):
        assert result[check_id] is Status.PASS, check_id
    for check_id in ("NET-003", "NET-004", "NET-005", "NET-006"):
        assert result[check_id] is Status.PASS, check_id


def test_bad_forti_fails_hardening_checks():
    result = statuses(FORTI_BAD)
    for check_id in ("MGT-001", "MGT-004", "MGT-005", "MGT-006", "NET-003", "NET-004", "NET-005"):
        assert result[check_id] is Status.FAIL, check_id


def test_schema_mapping_promotes_management_fields():
    baseline = parse_config_upload(CISCO_GOOD.encode(), "c.cfg").baseline
    assert baseline.management.ssh.value == "ENABLED"
    assert baseline.auth.aaa.value == "ENABLED"
    assert baseline.logging.enabled.value == "ENABLED"
    assert baseline.device.version == "17.9"
    keys = {fact.key for fact in baseline.facts}
    assert {"ntp_server_count", "serial_number", "hardware_model"} <= keys
    assert not keys & {"ssh_enabled", "https_enabled", "aaa_enabled", "logging_enabled", "os_version"}

    fortinet = parse_config_upload(FORTI_GOOD.encode(), "f.cfg").baseline
    assert fortinet.management.https.value == "ENABLED"
    assert fortinet.device.version == "7.2.5"


def test_evidence_lines_point_at_source():
    facts = cisco(CISCO_GOOD)
    lines = CISCO_GOOD.splitlines()
    for key in ("ssh_version", "trap_level_numeric", "max_login_attempts", "exec_timeout_minutes"):
        evidence = facts[key].evidence
        assert evidence is not None
        assert lines[evidence.line_number - 1].strip().startswith(evidence.raw.strip().split()[0])


def test_hostile_values_are_ignored():
    text = (
        "version " + "9" * 500 + "\n"
        "line vty 0 4\n exec-timeout 99999999999999 0\n"
        "login block-for 1 attempts notanumber within 1\n"
        "logging trap 99\n"
    )
    facts = cisco(text)
    assert len(str(facts["os_version"].value)) <= 64
    assert "exec_timeout_minutes" not in facts
    assert "max_login_attempts" not in facts
    assert "trap_level_numeric" not in facts


def test_named_fact_rejects_bad_keys():
    for key in ("", "Bad-Key", "1abc", "a" * 65):
        with pytest.raises(ValueError):
            NamedFact(key, True)
    with pytest.raises(ValueError):
        SecurityBaseline(vendor=Vendor.CISCO_IOS, facts=(NamedFact("a", 1), NamedFact("a", 2)))
