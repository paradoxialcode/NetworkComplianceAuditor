import pytest

from auditor.compliance.engine import run_audit
from auditor.compliance.models import Check, Status
from auditor.compliance.validation import validate_check_fields
from auditor.schema.baseline import (
    AuthenticationSettings,
    DeviceMetadata,
    LoggingSettings,
    ManagementAccess,
    SecurityBaseline,
    SecurityFact,
    SecurityState,
    TimeSync,
    Vendor,
)


def make_baseline(vendor=Vendor.Cisco):
    return SecurityBaseline(
        device=DeviceMetadata(hostname="sw1", vendor=vendor, platform="ios-xe"),
        management=ManagementAccess(
            ssh=SecurityState.ENABLED,
            telnet=SecurityState.DISABLED,
            http=SecurityState.UNKNOWN,
            https=SecurityState.ENABLED,
        ),
        auth=AuthenticationSettings(),
        logging=LoggingSettings(enabled=SecurityState.ENABLED, destinations=["10.0.0.5"]),
        time_sync=TimeSync(enabled=SecurityState.ENABLED, servers=[]),
        facts=[
            SecurityFact(key="ssh_version", value=2, state=SecurityState.ENABLED),
            SecurityFact(key="snmp_community", value="s3cr3t-value"),
        ],
    )


def chk(check_id, condition, **extra):
    return Check.model_validate(
        {"id": check_id, "title": "Contract check", "severity": "high", "condition": condition, **extra}
    )


CHECKS = [
    chk("CHK-TELNET-OFF", {"field": "management.telnet", "op": "eq", "value": "DISABLED"}),
    chk("CHK-HTTP-OFF", {"field": "management.http", "op": "eq", "value": "DISABLED"}),
    chk("CHK-SSH-V2", {"field": "facts.ssh_version.value", "op": "eq", "value": 2}),
    chk("CHK-NTP-SERVER", {"field": "time_sync.servers", "op": "non_empty"}),
    chk("CHK-LOG-HOST", {"field": "logging.destinations", "op": "non_empty"}),
    chk("CHK-SNMP-NOT-PUBLIC", {"field": "facts.snmp_community.value", "op": "ne", "value": "public"}),
    chk("CHK-FACT-MISSING", {"field": "facts.no_such_fact.value", "op": "eq", "value": 1}),
    chk("CHK-CISCO-ONLY", {"field": "management.ssh", "op": "eq", "value": "ENABLED"}, vendors=["cisco"]),
    chk("CHK-JUNIPER-ONLY", {"field": "management.ssh", "op": "eq", "value": "ENABLED"}, vendors=["juniper"]),
]


def test_audit_against_real_baseline():
    results = {r.check_id: r for r in run_audit(CHECKS, make_baseline())}
    assert results["CHK-TELNET-OFF"].status is Status.PASS
    assert results["CHK-HTTP-OFF"].status is Status.UNKNOWN
    assert results["CHK-SSH-V2"].status is Status.PASS
    assert results["CHK-NTP-SERVER"].status is Status.FAIL
    assert results["CHK-LOG-HOST"].status is Status.PASS
    assert results["CHK-SNMP-NOT-PUBLIC"].status is Status.PASS
    assert results["CHK-SNMP-NOT-PUBLIC"].evidence["facts.snmp_community.value"] == "[REDACTED]"
    assert results["CHK-FACT-MISSING"].status is Status.FAIL
    assert results["CHK-CISCO-ONLY"].status is Status.PASS
    assert results["CHK-JUNIPER-ONLY"].status is Status.NOT_APPLICABLE


def test_vendor_derived_from_baseline():
    results = {r.check_id: r for r in run_audit(CHECKS, make_baseline(Vendor.Juniper))}
    assert results["CHK-CISCO-ONLY"].status is Status.NOT_APPLICABLE
    assert results["CHK-JUNIPER-ONLY"].status is Status.PASS


def test_explicit_vendor_overrides_baseline():
    results = {r.check_id: r for r in run_audit(CHECKS, make_baseline(Vendor.Cisco), vendor="juniper")}
    assert results["CHK-JUNIPER-ONLY"].status is Status.PASS


def test_shipped_style_checks_validate_against_schema():
    assert validate_check_fields(CHECKS, SecurityBaseline) == []


@pytest.mark.parametrize(
    ("condition", "fragment"),
    [
        ({"field": "management.telnet.enabled", "op": "eq", "value": False}, "leaf"),
        ({"field": "management.gopher", "op": "eq", "value": "ENABLED"}, "unknown field"),
        ({"field": "management.telnet", "op": "eq", "value": "disabled"}, "not in"),
        ({"field": "management.telnet", "op": "in", "value": ["ENABLED", "off"]}, "off"),
        ({"field": "time_sync.servers", "op": "gte", "value": 1}, "non-numeric"),
        ({"field": "management.telnet", "op": "gte", "value": 1}, "enum"),
        ({"field": "logging.destinations.name", "op": "present"}, "not an index"),
        ({"field": "facts.x.nonexistent", "op": "present"}, "unknown field"),
    ],
)
def test_validator_flags_schema_mismatches(condition, fragment):
    errors = validate_check_fields([chk("CHK-BAD-01", condition)], SecurityBaseline)
    assert len(errors) == 1
    assert fragment in errors[0]


def test_validator_walks_compound_conditions():
    cond = {
        "all_of": [
            {"field": "management.telnet", "op": "eq", "value": "DISABLED"},
            {"any_of": [{"field": "nope.field", "op": "present"}]},
        ]
    }
    errors = validate_check_fields([chk("CHK-BAD-02", cond)], SecurityBaseline)
    assert len(errors) == 1
    assert "nope" in errors[0]


def test_validator_allows_dynamic_fact_values_and_indexes():
    cond = {"all_of": [
        {"field": "facts.anything_here.value", "op": "present"},
        {"field": "facts.0.key", "op": "present"},
        {"field": "interfaces.0.admin_state", "op": "eq", "value": "ENABLED"},
    ]}
    assert validate_check_fields([chk("CHK-OK-01", cond)], SecurityBaseline) == []
