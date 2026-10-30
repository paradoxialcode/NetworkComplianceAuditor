import pytest

from auditor.audit.service import AuditError, load_rule_set, run_device_audit
from auditor.audit.store import init_db, load_audit
from auditor.compliance.models import Status
from auditor.db.session import session
from auditor.remediation.renderer import RemediationKind
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

CHECKS = """
checks:
  - id: CHK-TELNET-OFF
    title: Telnet management must be disabled
    severity: high
    condition: {field: management.telnet, op: eq, value: DISABLED}
    mappings: {nist: [AC-17]}
    remediation_key: disable_telnet
  - id: CHK-NTP
    title: At least one NTP server must be configured
    severity: medium
    condition: {field: time_sync.servers, op: non_empty}
    mappings: {nist: [AU-8]}
    remediation_key: set_ntp
  - id: CHK-SSH-V2
    title: SSH must use version 2
    severity: high
    vendors: [juniper]
    condition: {field: facts.ssh_version.value, op: eq, value: 2}
    mappings: {nist: [SC-8]}
"""
CATALOG = """
framework: nist
name: NIST subset
controls:
  - {id: AC-17, title: Remote Access}
  - {id: AU-8, title: Time Stamps}
  - {id: SC-8, title: Transmission Confidentiality}
  - {id: PE-3, title: Physical Access Control}
"""
TEMPLATES = """
vendor: cisco
steps:
  disable_telnet:
    title: Disable Telnet
    risk: Confirm SSH works first.
    commands: ["line vty 0 15", " transport input ssh"]
"""


@pytest.fixture
def data_dir(tmp_path):
    for name, text in (("checks", CHECKS), ("frameworks", CATALOG), ("remediation", TEMPLATES)):
        folder = tmp_path / name
        folder.mkdir()
        (folder / f"{name}.yaml").write_text(text, encoding="utf-8")
    return tmp_path


def make_baseline(telnet=SecurityState.ENABLED, vendor=Vendor.Cisco):
    return SecurityBaseline(
        device=DeviceMetadata(hostname="sw1", vendor=vendor, platform="ios-xe"),
        management=ManagementAccess(
            ssh=SecurityState.ENABLED, telnet=telnet, http=SecurityState.DISABLED, https=SecurityState.ENABLED
        ),
        auth=AuthenticationSettings(),
        logging=LoggingSettings(enabled=SecurityState.ENABLED),
        time_sync=TimeSync(enabled=SecurityState.DISABLED),
        facts=[SecurityFact(key="ssh_version", value=2)],
    )


def test_load_rule_set(data_dir):
    rules = load_rule_set(data_dir)
    assert [c.id for c in rules.checks] == ["CHK-TELNET-OFF", "CHK-NTP", "CHK-SSH-V2"]
    assert list(rules.catalogs) == ["nist"]
    assert "CHK-NTP: cisco has no step 'set_ntp'" in rules.warnings
    assert not any("CHK-SSH-V2" in w for w in rules.warnings)


@pytest.mark.parametrize("missing", ["checks", "frameworks", "remediation"])
def test_missing_directory_is_an_error(data_dir, missing):
    import shutil

    shutil.rmtree(data_dir / missing)
    with pytest.raises(AuditError, match="not found"):
        load_rule_set(data_dir)


def test_empty_checks_directory_is_an_error(data_dir):
    (data_dir / "checks" / "checks.yaml").unlink()
    with pytest.raises(AuditError, match="no checks"):
        load_rule_set(data_dir)


def test_bad_field_path_is_an_error(data_dir):
    path = data_dir / "checks" / "checks.yaml"
    path.write_text(CHECKS.replace("management.telnet", "management.telnett"), encoding="utf-8")
    with pytest.raises(AuditError, match="management.telnett"):
        load_rule_set(data_dir)


def test_enum_case_typo_is_an_error(data_dir):
    path = data_dir / "checks" / "checks.yaml"
    path.write_text(CHECKS.replace("value: DISABLED", "value: disabled"), encoding="utf-8")
    with pytest.raises(AuditError, match="not in"):
        load_rule_set(data_dir)


def test_unknown_control_mapping_is_an_error(data_dir):
    path = data_dir / "checks" / "checks.yaml"
    path.write_text(CHECKS.replace("[AC-17]", "[AC-99]"), encoding="utf-8")
    with pytest.raises(AuditError, match="AC-99"):
        load_rule_set(data_dir)


def test_malformed_yaml_is_wrapped(data_dir):
    (data_dir / "checks" / "checks.yaml").write_text("checks: [", encoding="utf-8")
    with pytest.raises(AuditError):
        load_rule_set(data_dir)


def test_end_to_end_audit(data_dir):
    rules = load_rule_set(data_dir)
    outcome = run_device_audit(make_baseline(), rules)
    by_id = {r.check_id: r for r in outcome.results}
    assert by_id["CHK-TELNET-OFF"].status is Status.FAIL
    assert by_id["CHK-NTP"].status is Status.FAIL
    assert by_id["CHK-SSH-V2"].status is Status.NOT_APPLICABLE
    assert outcome.audit_id is None
    assert outcome.frameworks == ("nist",)
    score = outcome.scores["nist"]
    assert (score.non_compliant, score.not_applicable, score.not_assessable) == (2, 1, 1)
    kinds = {r.check_id: r.kind for r in outcome.remediations}
    assert kinds == {"CHK-TELNET-OFF": RemediationKind.COMMANDS, "CHK-NTP": RemediationKind.MANUAL}
    telnet = outcome.remediations[0]
    assert telnet.commands == ("line vty 0 15", " transport input ssh")


def test_vendor_specific_check_applies_for_matching_vendor(data_dir):
    rules = load_rule_set(data_dir)
    outcome = run_device_audit(make_baseline(vendor=Vendor.Juniper), rules)
    by_id = {r.check_id: r for r in outcome.results}
    assert by_id["CHK-SSH-V2"].status is Status.PASS


def test_compliant_device_has_no_remediations(data_dir):
    rules = load_rule_set(data_dir)
    baseline = make_baseline(telnet=SecurityState.DISABLED)
    baseline.time_sync.servers.append("10.0.0.1")
    outcome = run_device_audit(baseline, rules)
    assert outcome.remediations == []
    assert outcome.scores["nist"].compliant == 2


def test_framework_selection(data_dir):
    rules = load_rule_set(data_dir)
    assert run_device_audit(make_baseline(), rules, ["NIST"]).frameworks == ("nist",)
    with pytest.raises(AuditError, match="unknown framework"):
        run_device_audit(make_baseline(), rules, ["cis"])


def test_audit_is_persisted_and_reloadable(data_dir, tmp_path):
    rules = load_rule_set(data_dir)
    db = tmp_path / "audits.db"
    init_db(db)
    outcome = run_device_audit(make_baseline(), rules, database=db)
    assert isinstance(outcome.audit_id, int)
    with session(db) as conn:
        stored = load_audit(conn, outcome.audit_id)
    assert stored.results == outcome.results
    assert stored.scores == outcome.scores
