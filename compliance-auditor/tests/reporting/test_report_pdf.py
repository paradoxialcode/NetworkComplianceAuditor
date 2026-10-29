import io
from datetime import UTC, datetime

import pytest
from pypdf import PdfReader

from auditor.audit.service import RuleSet, run_device_audit
from auditor.compliance.catalog import Catalog
from auditor.compliance.models import Check
from auditor.remediation.templates import VendorTemplates
from auditor.reporting.pdf_builder import MAX_APPENDIX_ROWS, build_report_bytes, write_report
from auditor.schema.baseline import (
    AuthenticationSettings,
    DeviceMetadata,
    LoggingSettings,
    ManagementAccess,
    SecurityBaseline,
    SecurityFact,
    SecurityState,
    TimeSync,
    UnrecognizedConfig,
    Vendor,
)

SECRET = "hunter2-super-secret"
FIXED_TIME = datetime(2026, 10, 22, 9, 30, tzinfo=UTC)


def make_baseline(hostname="core-sw-1", telnet=SecurityState.ENABLED, facts=None, unrecognized=None, filename=None):
    return SecurityBaseline(
        device=DeviceMetadata(
            hostname=hostname, vendor=Vendor.Cisco, platform="Catalyst 9300", version="17.9.4", filename=filename
        ),
        management=ManagementAccess(
            ssh=SecurityState.ENABLED, telnet=telnet, http=SecurityState.UNKNOWN, https=SecurityState.ENABLED
        ),
        auth=AuthenticationSettings(),
        logging=LoggingSettings(enabled=SecurityState.ENABLED),
        time_sync=TimeSync(enabled=SecurityState.DISABLED),
        facts=facts if facts is not None else [SecurityFact(key="snmp_community", value=SECRET)],
        unrecognized=unrecognized or [],
    )


def check(check_id, title, field, op, value=None, severity="high", mappings=None, key=None):
    condition = {"field": field, "op": op}
    if value is not None:
        condition["value"] = value
    data = {"id": check_id, "title": title, "severity": severity, "condition": condition}
    if mappings:
        data["mappings"] = mappings
    if key:
        data["remediation_key"] = key
    return Check.model_validate(data)


CHECKS = [
    check("CHK-TELNET-OFF", "Telnet management must be disabled", "management.telnet", "eq", "DISABLED",
          mappings={"nist": ["AC-17"]}, key="disable_telnet"),
    check("CHK-TELNET-OFF-2", "Telnet also disabled on console", "management.telnet", "eq", "DISABLED",
          severity="medium", mappings={"nist": ["AC-17"]}, key="disable_telnet"),
    check("CHK-HTTP-OFF", "HTTP server disabled", "management.http", "eq", "DISABLED", severity="medium"),
    check("CHK-NTP", "NTP server configured", "time_sync.servers", "non_empty", severity="low",
          mappings={"nist": ["AU-8"]}, key="set_ntp"),
    check("CHK-SNMP-COMMUNITY", "SNMP community is not the default", "facts.snmp_community.value", "ne", "public",
          severity="critical", mappings={"nist": ["SC-8"]}),
    check("CHK-HTTPS-ON", "HTTPS enabled", "management.https", "eq", "ENABLED"),
]
CATALOG = Catalog.model_validate(
    {
        "framework": "nist",
        "name": "NIST SP 800-53 Rev. 5 (subset)",
        "controls": [
            {"id": "AC-17", "title": "Remote Access"},
            {"id": "AU-8", "title": "Time Stamps"},
            {"id": "SC-8", "title": "Transmission Confidentiality"},
            {"id": "PE-3", "title": "Physical Access Control"},
        ],
    }
)
TEMPLATES = {
    "cisco": VendorTemplates.model_validate(
        {
            "vendor": "cisco",
            "steps": {
                "disable_telnet": {
                    "title": "Disable Telnet on VTY lines",
                    "risk": "Confirm SSH works before applying.",
                    "order": 20,
                    "commands": ["line vty 0 15", " transport input ssh", "do show run | include & <x>"],
                }
            },
        }
    )
}


def outcome_for(baseline=None, checks=CHECKS, catalog=CATALOG, templates=TEMPLATES, audit_id=None):
    rules = RuleSet(
        checks=tuple(checks), catalogs={catalog.framework: catalog}, templates=dict(templates), warnings=()
    )
    outcome = run_device_audit(baseline or make_baseline(), rules)
    return outcome.model_copy(update={"audit_id": audit_id}) if audit_id is not None else outcome


def text_of(pdf_bytes):
    reader = PdfReader(io.BytesIO(pdf_bytes))
    return "\n".join(page.extract_text() for page in reader.pages), reader


@pytest.fixture(scope="module")
def report():
    pdf = build_report_bytes(outcome_for(audit_id=42), FIXED_TIME)
    text, reader = text_of(pdf)
    return pdf, text, reader


def test_is_a_valid_pdf(report):
    pdf, _text, reader = report
    assert pdf.startswith(b"%PDF-")
    assert pdf.rstrip().endswith(b"%%EOF")
    assert len(reader.pages) >= 1


def test_metadata(report):
    _pdf, _text, reader = report
    assert reader.metadata.title == "Compliance report - core-sw-1"
    assert reader.metadata.author == "Network Compliance Auditor"


def test_page_numbers(report):
    _pdf, text, reader = report
    assert f"Page 1 of {len(reader.pages)}" in text


def test_device_identification(report):
    _pdf, text, _reader = report
    for expected in ("core-sw-1", "Cisco", "Catalyst 9300", "17.9.4", "Audit ID", "42", "2026-10-22 09:30:00"):
        assert expected in text
    assert "Not available in configuration" in text


def test_serial_and_model_taken_from_facts():
    facts = [SecurityFact(key="serial_number", value="FDO1234ABCD"), SecurityFact(key="hardware_model", value="C9300-48P")]
    text, _ = text_of(build_report_bytes(outcome_for(make_baseline(facts=facts)), FIXED_TIME))
    assert "FDO1234ABCD" in text
    assert "C9300-48P" in text


def test_summary_and_framework_tables(report):
    _pdf, text, _reader = report
    assert "Executive summary" in text
    assert "applicable checks are non-compliant" in text
    assert "NIST SP 800-53" in text
    assert "not a certification" in text.replace("\n", " ")
    assert "Coverage" in text


def test_findings_listed_with_status(report):
    _pdf, text, _reader = report
    for expected in ("CHK-TELNET-OFF", "CHK-NTP", "CHK-HTTP-OFF", "CHK-HTTPS-ON", "FAIL", "PASS", "UNKNOWN"):
        assert expected in text


def test_remediation_grouped_and_ordered(report):
    _pdf, text, _reader = report
    assert text.count("Disable Telnet on VTY lines") == 1
    assert "CHK-TELNET-OFF, CHK-TELNET-OFF-2" in text.replace("\n", " ")
    assert "Caution: Confirm SSH works before applying." in text.replace("\n", " ")
    assert "line vty 0 15" in text
    assert "transport input ssh" in text
    assert "Manual action required" in text
    assert "Manual verification required" in text


def test_special_characters_in_commands_render_literally(report):
    _pdf, text, _reader = report
    assert "& <x>" in text


def test_secrets_are_not_printed(report):
    pdf, text, _reader = report
    assert SECRET not in text
    assert SECRET.encode() not in pdf
    assert "[REDACTED]" in text


def test_unrecognized_lines_not_reproduced():
    baseline = make_baseline(
        unrecognized=[UnrecognizedConfig(text=f"username admin password {SECRET}", reason="no mapping")]
    )
    text, _ = text_of(build_report_bytes(outcome_for(baseline), FIXED_TIME))
    assert SECRET not in text
    assert "1 configuration block(s) were not recognized" in text.replace("\n", " ")


def test_markup_in_config_derived_text_is_escaped():
    baseline = make_baseline(hostname="<b>evil</b> & <para>x", filename="<i>f</i>.cfg")
    text, _ = text_of(build_report_bytes(outcome_for(baseline), FIXED_TIME))
    assert "<b>evil</b> & <para>x" in text


def test_unrenderable_characters_do_not_crash():
    baseline = make_baseline(hostname="sw-\u30b5\u30fc\u30d0\u30fc-\U0001f642")
    text, _ = text_of(build_report_bytes(outcome_for(baseline), FIXED_TIME))
    assert "sw-" in text


def test_long_unbroken_strings_do_not_break_layout():
    facts = [SecurityFact(key="banner_text", value="A" * 2000)]
    checks = [*CHECKS, check("CHK-BANNER", "Banner present", "facts.banner_text.value", "ne", "x" * 600)]
    pdf = build_report_bytes(outcome_for(make_baseline(facts=facts), checks=checks), FIXED_TIME)
    assert pdf.startswith(b"%PDF-")


def test_compliant_device_has_no_remediation_needed():
    only_good = [CHECKS[5]]
    text, _ = text_of(build_report_bytes(outcome_for(checks=only_good), FIXED_TIME))
    assert "No remediation required." in text
    assert "No non-compliant findings." in text


def test_large_catalog_is_truncated_in_appendix():
    controls = [{"id": f"CTL-{i}", "title": f"Control {i}"} for i in range(MAX_APPENDIX_ROWS + 50)]
    catalog = Catalog.model_validate({"framework": "nist", "name": "Big", "controls": controls})
    mapped = [
        check(f"CHK-BULK-{i:03d}", f"Bulk check {i}", "management.ssh", "eq", "ENABLED", mappings={"nist": [f"CTL-{i}"]})
        for i in range(MAX_APPENDIX_ROWS + 50)
    ]
    text, reader = text_of(build_report_bytes(outcome_for(catalog=catalog, checks=mapped), FIXED_TIME))
    assert f"Showing {MAX_APPENDIX_ROWS} of {MAX_APPENDIX_ROWS + 50} assessed controls" in text.replace("\n", " ")
    assert len(reader.pages) > 3


def test_not_assessable_controls_listed(report):
    _pdf, text, _reader = report
    assert "Not assessable from device configuration (1): PE-3" in text.replace("\n", " ")


def test_write_report_uses_safe_name_and_atomic_write(tmp_path):
    target = write_report(outcome_for(make_baseline(hostname="../../evil"), audit_id=7), tmp_path / "out", FIXED_TIME)
    assert target == tmp_path / "out" / "audit-7.pdf"
    assert target.read_bytes().startswith(b"%PDF-")
    assert [p.name for p in (tmp_path / "out").iterdir()] == ["audit-7.pdf"]


def test_write_report_without_audit_id_uses_hash_name(tmp_path):
    target = write_report(outcome_for(), tmp_path, FIXED_TIME)
    assert target.name.startswith("report-")
    assert target.suffix == ".pdf"
