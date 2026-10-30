import pytest

from auditor.audit.adapter import to_schema_baseline
from auditor.audit.service import RuleSet, run_device_audit
from auditor.compliance.catalog import Catalog
from auditor.compliance.models import Check, Status
from auditor.parsers import normalizer as parsed
from auditor.schema import baseline as schema

SHA = "a" * 64


def ev(line=1, raw="line", redacted=False):
    return parsed.Evidence("router.cfg", line, line, raw, redacted)


def fact(value, line=1, raw="line"):
    return parsed.Fact(value, ev(line, raw))


def make_parsed(**overrides):
    base = {
        "vendor": parsed.Vendor.CISCO_IOS,
        "source_file": "C:\\configs\\router.cfg",
        "hostname": fact("edge-rtr-1", 1, "hostname edge-rtr-1"),
        "ntp_servers": (fact("10.0.0.1", 5), fact("10.0.0.2", 6)),
        "syslog_servers": (fact("10.0.0.9", 7),),
        "local_users": (fact("admin", 8), fact("ops", 9)),
        "interfaces": (
            parsed.InterfaceBaseline(fact("Gi0/1", 10), fact("uplink", 11), fact(False, 12)),
            parsed.InterfaceBaseline(fact("Gi0/2", 13), None, fact(True, 14)),
            parsed.InterfaceBaseline(fact("Gi0/3", 15)),
        ),
        "telnet_enabled": fact(False, 20, "no ip telnet"),
        "http_management_enabled": fact(True, 21, "ip http server"),
        "password_encryption": fact(True, 22, "service password-encryption"),
        "warnings": (parsed.NormalizationWarning("could not interpret block", 30),),
    }
    base.update(overrides)
    return parsed.SecurityBaseline(**base)


def test_device_identity():
    out = to_schema_baseline(make_parsed(), sha256=SHA)
    assert out.device.hostname == "edge-rtr-1"
    assert out.device.vendor is schema.Vendor.Cisco
    assert out.device.platform == "Cisco IOS"
    assert out.device.filename == "router.cfg"
    assert out.device.sha256 == SHA


def test_fortinet_vendor_mapping():
    out = to_schema_baseline(make_parsed(vendor=parsed.Vendor.FORTIOS))
    assert out.device.vendor is schema.Vendor.Fortinet
    assert out.device.platform == "FortiOS"


def test_filename_argument_overrides_and_is_reduced_to_basename():
    out = to_schema_baseline(make_parsed(), filename="../../uploads/evil name.cfg")
    assert out.device.filename == "evil name.cfg"


def test_missing_hostname_uses_fallback():
    assert to_schema_baseline(make_parsed(hostname=None)).device.hostname == "unknown-device"


def test_long_hostname_is_clipped():
    out = to_schema_baseline(make_parsed(hostname=fact("h" * 1000)))
    assert len(out.device.hostname) == 255


@pytest.mark.parametrize(
    ("value", "expected"),
    [(True, schema.SecurityState.ENABLED), (False, schema.SecurityState.DISABLED), (None, schema.SecurityState.UNKNOWN)],
)
def test_management_states(value, expected):
    fact_value = None if value is None else fact(value)
    out = to_schema_baseline(make_parsed(telnet_enabled=fact_value, http_management_enabled=fact_value))
    assert out.management.telnet is expected
    assert out.management.http is expected


def test_unmodelled_management_fields_are_unknown_not_guessed():
    out = to_schema_baseline(make_parsed())
    assert out.management.ssh is schema.SecurityState.UNKNOWN
    assert out.management.https is schema.SecurityState.UNKNOWN


def test_services():
    out = to_schema_baseline(make_parsed())
    assert out.time_sync.servers == ["10.0.0.1", "10.0.0.2"]
    assert out.time_sync.enabled is schema.SecurityState.ENABLED
    assert out.logging.destinations == ["10.0.0.9"]
    assert out.logging.enabled is schema.SecurityState.ENABLED
    assert out.auth.local is schema.SecurityState.ENABLED


def test_absence_is_unknown_not_disabled():
    out = to_schema_baseline(make_parsed(ntp_servers=(), syslog_servers=(), local_users=()))
    assert out.time_sync.enabled is schema.SecurityState.UNKNOWN
    assert out.logging.enabled is schema.SecurityState.UNKNOWN
    assert out.auth.local is None
    assert out.time_sync.servers == []
    assert out.logging.destinations == []


def test_interfaces():
    out = to_schema_baseline(make_parsed())
    names = {i.name: i for i in out.interfaces}
    assert names["Gi0/1"].admin_state is schema.SecurityState.ENABLED
    assert names["Gi0/1"].description == "uplink"
    assert names["Gi0/2"].admin_state is schema.SecurityState.DISABLED
    assert names["Gi0/3"].admin_state is schema.SecurityState.UNKNOWN


def test_facts_carry_evidence():
    out = to_schema_baseline(make_parsed())
    by_key = {f.key: f for f in out.facts}
    telnet = by_key["telnet_enabled"]
    assert telnet.value is False
    assert telnet.state is schema.SecurityState.DISABLED
    assert telnet.evidence.text == "no ip telnet"
    assert telnet.evidence.line == 20
    assert telnet.evidence.mapping_id == "builtin:cisco_ios"
    assert telnet.evidence.confidence == 1.0
    assert by_key["password_encryption"].value is True
    assert by_key["local_users"].value == ["admin", "ops"]


def test_facts_omitted_when_not_stated():
    out = to_schema_baseline(
        make_parsed(telnet_enabled=None, http_management_enabled=None, password_encryption=None, local_users=())
    )
    assert out.facts == []


def test_warnings_become_unrecognized_without_raw_lines():
    out = to_schema_baseline(make_parsed())
    assert len(out.unrecognized) == 1
    assert out.unrecognized[0].location == "line 30"
    assert out.unrecognized[0].vendor is schema.Vendor.Cisco


def test_empty_result_still_converts():
    out = to_schema_baseline(parsed.SecurityBaseline(vendor=parsed.Vendor.CISCO_IOS))
    assert out.device.hostname == "unknown-device"
    assert out.interfaces == []
    assert out.management.telnet is schema.SecurityState.UNKNOWN


def test_invalid_sha256_is_rejected():
    with pytest.raises(ValueError):
        to_schema_baseline(make_parsed(), sha256="not-a-hash")


@pytest.mark.parametrize("bad", [None, "text", {"vendor": "x"}, 5])
def test_wrong_input_type_is_rejected(bad):
    with pytest.raises(TypeError):
        to_schema_baseline(bad)


def test_adapter_output_flows_through_the_audit_service():
    checks = [
        Check.model_validate(
            {
                "id": "CHK-TELNET-OFF",
                "title": "Telnet must be disabled",
                "severity": "high",
                "condition": {"field": "management.telnet", "op": "eq", "value": "DISABLED"},
                "mappings": {"nist": ["AC-17"]},
            }
        ),
        Check.model_validate(
            {
                "id": "CHK-HTTP-OFF",
                "title": "HTTP management must be disabled",
                "severity": "high",
                "condition": {"field": "management.http", "op": "eq", "value": "DISABLED"},
            }
        ),
        Check.model_validate(
            {
                "id": "CHK-SSH-ON",
                "title": "SSH must be enabled",
                "severity": "high",
                "condition": {"field": "management.ssh", "op": "eq", "value": "ENABLED"},
            }
        ),
        Check.model_validate(
            {
                "id": "CHK-PWD-ENC",
                "title": "Password encryption enabled",
                "severity": "medium",
                "condition": {"field": "facts.password_encryption.value", "op": "eq", "value": True},
            }
        ),
        Check.model_validate(
            {
                "id": "CHK-SYSLOG",
                "title": "Remote syslog configured",
                "severity": "medium",
                "condition": {"field": "logging.destinations", "op": "non_empty"},
            }
        ),
    ]
    catalog = Catalog.model_validate(
        {"framework": "nist", "name": "NIST subset", "controls": [{"id": "AC-17", "title": "Remote Access"}]}
    )
    rules = RuleSet(checks=tuple(checks), catalogs={"nist": catalog}, templates={}, warnings=())
    outcome = run_device_audit(to_schema_baseline(make_parsed()), rules)
    status = {r.check_id: r.status for r in outcome.results}
    assert status == {
        "CHK-TELNET-OFF": Status.PASS,
        "CHK-HTTP-OFF": Status.FAIL,
        "CHK-SSH-ON": Status.UNKNOWN,
        "CHK-PWD-ENC": Status.PASS,
        "CHK-SYSLOG": Status.PASS,
    }
