from pathlib import Path

import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from auditor.audit.service import load_rule_set, run_device_audit
from auditor.audit.store import init_db, persist_report
from auditor.reporting.pdf_builder import build_report_bytes
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

APP_DIR = Path(__file__).resolve().parents[2] / "app"
MARKDOWN_HOSTNAME = "[click here](http://evil.example) **bold**"

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
"""
CATALOG = """
framework: nist
name: NIST subset
controls:
  - {id: AC-17, title: Remote Access}
  - {id: AU-8, title: Time Stamps}
  - {id: PE-3, title: Physical Access Control}
"""
TEMPLATES = """
vendor: cisco
steps:
  disable_telnet:
    title: Disable Telnet
    commands: ["line vty 0 15", " transport input ssh"]
"""


def write_rules(data_dir: Path, checks: str = CHECKS) -> None:
    for name, text in (("checks", checks), ("frameworks", CATALOG), ("remediation", TEMPLATES)):
        folder = data_dir / name
        folder.mkdir(parents=True, exist_ok=True)
        (folder / f"{name}.yaml").write_text(text, encoding="utf-8")


def make_baseline(hostname: str) -> SecurityBaseline:
    return SecurityBaseline(
        device=DeviceMetadata(hostname=hostname, vendor=Vendor.Cisco, platform="Cisco IOS"),
        management=ManagementAccess(
            ssh=SecurityState.UNKNOWN,
            telnet=SecurityState.ENABLED,
            http=SecurityState.DISABLED,
            https=SecurityState.UNKNOWN,
        ),
        auth=AuthenticationSettings(),
        logging=LoggingSettings(enabled=SecurityState.UNKNOWN),
        time_sync=TimeSync(enabled=SecurityState.UNKNOWN),
        facts=[SecurityFact(key="note", value="x")],
    )


@pytest.fixture
def env(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    database = tmp_path / "instance" / "audits.db"
    write_rules(data_dir)
    monkeypatch.setenv("AUDITOR_DATA_DIR", str(data_dir))
    monkeypatch.setenv("AUDITOR_DB_PATH", str(database))
    st.cache_resource.clear()
    init_db(database)
    yield data_dir, database
    st.cache_resource.clear()


def seed_audit(data_dir: Path, database: Path, hostname: str = "edge-rtr-1", with_report: bool = True) -> int:
    rules = load_rule_set(data_dir)
    outcome = run_device_audit(make_baseline(hostname), rules, database=database)
    if with_report:
        persist_report(database, outcome.audit_id, build_report_bytes(outcome))
    return outcome.audit_id


def run_page(relative: str) -> AppTest:
    at = AppTest.from_file(str(APP_DIR / relative), default_timeout=30)
    at.run()
    return at


def all_text(at: AppTest) -> str:
    parts = [e.value for e in at.text] + [e.value for e in at.markdown] + [e.value for e in at.caption]
    parts += [e.value for e in at.info] + [e.value for e in at.warning] + [e.value for e in at.error]
    return "\n".join(str(p) for p in parts)


def test_main_page_shows_rule_counts(env):
    at = run_page("main.py")
    assert not at.exception
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Checks"] == "2"
    assert metrics["Frameworks"] == "1"
    assert metrics["Remediation vendors"] == "1"


def test_main_page_reports_a_bad_rule_set_without_crashing(env):
    data_dir, _ = env
    write_rules(data_dir, CHECKS.replace("management.telnet", "management.telnett"))
    at = run_page("main.py")
    assert not at.exception
    assert any("rule set could not be loaded" in e.value for e in at.error)
    assert any("management.telnett" in c.value for c in at.code)


def test_findings_empty_state(env):
    at = run_page("pages/3_Findings.py")
    assert not at.exception
    assert any("No audits yet" in i.value for i in at.info)


def test_findings_shows_selected_audit(env):
    data_dir, database = env
    audit_id = seed_audit(data_dir, database)
    at = run_page("pages/3_Findings.py")
    assert not at.exception
    assert at.selectbox[0].value == audit_id
    assert any("edge-rtr-1" in t.value for t in at.text)
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Checks"] == "2"
    assert metrics["Non-compliant"] == "2"
    assert len(at.dataframe) >= 2
    assert len(at.expander) >= 2


def test_findings_filter_by_status(env):
    data_dir, database = env
    seed_audit(data_dir, database)
    at = run_page("pages/3_Findings.py")
    at.text_input[0].set_value("ntp").run()
    assert not at.exception
    frame = at.dataframe[-1].value
    assert list(frame["Check ID"]) == ["CHK-NTP"]


def test_hostname_markdown_is_not_rendered(env):
    data_dir, database = env
    seed_audit(data_dir, database, hostname=MARKDOWN_HOSTNAME)
    at = run_page("pages/3_Findings.py")
    assert not at.exception
    assert any(MARKDOWN_HOSTNAME in t.value for t in at.text)
    assert not any("evil.example" in m.value for m in at.markdown)


def test_findings_delete_requires_confirmation(env):
    data_dir, database = env
    seed_audit(data_dir, database)
    at = run_page("pages/3_Findings.py")
    delete = [b for b in at.button if b.label == "Delete audit"][0]
    assert delete.disabled is True
    at.checkbox[0].check().run()
    [b for b in at.button if b.label == "Delete audit"][0].click().run()
    assert any("No audits yet" in i.value for i in at.info)


def test_reports_empty_state(env):
    at = run_page("pages/4_Reports.py")
    assert not at.exception
    assert any("No reports yet" in i.value for i in at.info)


def test_reports_page_offers_download(env):
    data_dir, database = env
    seed_audit(data_dir, database)
    at = run_page("pages/4_Reports.py")
    assert not at.exception
    assert not at.warning
    buttons = at.get("download_button")
    assert len(buttons) == 1
    assert buttons[0].proto.label == "Download PDF report"


def test_reports_page_warns_when_pdf_missing(env):
    data_dir, database = env
    seed_audit(data_dir, database, with_report=False)
    at = run_page("pages/4_Reports.py")
    assert not at.exception
    assert any("No stored PDF" in w.value for w in at.warning)
    assert at.get("download_button") == []


def test_rules_page(env):
    at = run_page("pages/5_Rules_and_Frameworks.py")
    assert not at.exception
    assert len(at.tabs) == 4
    checks_frame = at.dataframe[0].value
    assert set(checks_frame["ID"]) == {"CHK-TELNET-OFF", "CHK-NTP"}
    frameworks_frame = at.dataframe[1].value
    assert list(frameworks_frame["Controls"]) == [3]
    assert list(frameworks_frame["Controls with a mapped check"]) == [2]
    warnings = [c.value for c in at.code]
    assert any("CHK-NTP" in w for w in warnings)


def test_upload_page_renders_with_disabled_run_button(env):
    at = run_page("pages/1_Upload_and_Audit.py")
    assert not at.exception
    run = [b for b in at.button if b.label == "Run audit"][0]
    assert run.disabled is True
    assert at.selectbox[0].options == [
        "Auto-detect",
        "Cisco IOS",
        "FortiOS",
        "Juniper Junos (trained rules)",
        "Other vendor (generic parser)",
    ]
    assert at.multiselect[0].value == ["nist"]


def test_upload_page_stops_on_bad_rules(env):
    data_dir, _ = env
    write_rules(data_dir, CHECKS.replace("DISABLED", "disabled"))
    at = run_page("pages/1_Upload_and_Audit.py")
    assert not at.exception
    assert any("rule set could not be loaded" in e.value for e in at.error)
    assert not at.button or all(b.label != "Run audit" for b in at.button)


def make_batch(database):
    from auditor.audit.batch import audit_batch
    from auditor.audit.pipeline import Backends
    from auditor.parsers import normalizer as parsed

    def normalize(tokens, vendor):
        evidence = parsed.Evidence("x", 1, 1, "no ip telnet")
        return parsed.SecurityBaseline(
            vendor=vendor,
            hostname=parsed.Fact(MARKDOWN_HOSTNAME, evidence),
            telnet_enabled=parsed.Fact(True, evidence),
            warnings=(parsed.NormalizationWarning("odd block", 4),),
        )

    def detect(text):
        return parsed.Vendor.CISCO_IOS if "hostname" in text or "version" in text else None

    backends = Backends(
        tokenizers={parsed.Vendor.CISCO_IOS: lambda text, name: ["t"]}, normalize=normalize, detect=detect
    )
    rules = load_rule_set(Path(database).parent.parent / "data")
    cisco = b"version 17.9\nhostname r1\nservice password-encryption\nline vty 0 4\nend\n"
    junos = b"set system host-name j1\nset system services ssh\n"
    return audit_batch([("r1.cfg", cisco), ("j1.set", junos), ("empty.cfg", b"")], rules, database=database, backends=backends)


def test_upload_page_renders_batch_results(env):
    _, database = env
    batch = make_batch(database)
    at = AppTest.from_file(str(APP_DIR / "pages/1_Upload_and_Audit.py"), default_timeout=30)
    at.session_state["batch"] = batch
    at.run()
    assert not at.exception
    assert len(at.expander) == 3
    assert len(at.get("download_button")) == 2
    metrics = [{m.label: m.value for m in at.metric[i : i + 4]} for i in range(0, len(at.metric), 4)]
    assert len(metrics) == 2
    assert metrics[0]["Checks"] == "2"
    assert metrics[0]["Non-compliant"] == "2"
    assert metrics[1]["Checks"] == "2"
    assert any("Training page" in i.value for i in at.info)
    assert any("generic" in c.value for c in at.caption)
    assert any("empty" in e.value for e in at.error)
    assert any("1 configuration block(s) were not recognized" in w.value for w in at.warning)
    assert any(MARKDOWN_HOSTNAME in t.value for t in at.text)
    assert not any("evil.example" in m.value for m in at.markdown)


JUNOS_CONFIG = "set system host-name junos-fw-1\nset system services ssh\nset system ntp server 10.0.0.1\n"


def junos_rules():
    from auditor.parsers.normalizer import Vendor as ParsedVendor
    from auditor.training.patterns import MatchMethod, PatternRule

    return [
        PatternRule(
            rule_id="junos-telnet",
            vendor=ParsedVendor.JUNOS,
            method=MatchMethod.PREFIX,
            expression="set system services telnet",
            target_field="telnet_enabled",
            suggested_value=True,
            confidence=0.9,
            explanation="Telnet enabled",
            absent_value=False,
        ),
        PatternRule(
            rule_id="junos-ntp",
            vendor=ParsedVendor.JUNOS,
            method=MatchMethod.REGEX,
            expression=r"set system ntp server (\S+)",
            target_field="ntp_servers",
            suggested_value=None,
            confidence=0.9,
            explanation="NTP server",
            capture_group=1,
        ),
    ]


def test_upload_page_renders_trained_results(env):
    from auditor.audit.batch import audit_batch

    data_dir, database = env
    rules = load_rule_set(data_dir)
    batch = audit_batch(
        [("j.set", JUNOS_CONFIG.encode())],
        rules,
        database=database,
        vendor=__import__("auditor.parsers.normalizer", fromlist=["Vendor"]).Vendor.JUNOS,
        trained_rules=junos_rules(),
    )
    assert batch[0].error is None
    at = AppTest.from_file(str(APP_DIR / "pages/1_Upload_and_Audit.py"), default_timeout=30)
    at.session_state["batch"] = batch
    at.run()
    assert not at.exception
    assert any("Parser: trained rules" in c.value for c in at.caption)
    assert any("1 of 2 trained rules matched" in i.value for i in at.info)


def test_training_page_creates_and_saves_a_capture_rule(env):
    data_dir, _ = env
    at = run_page("pages/2_Training.py")
    assert not at.exception
    select = {w.label: w for w in at.selectbox}
    select["Vendor"].select("junos")
    select["Matching method"].select("regex")
    at.run()
    {w.label: w for w in at.selectbox}["Target field"].select("ntp_servers")
    at.run()
    assert {w.label: w for w in at.selectbox}["Target field"].value == "ntp_servers"
    form = {w.label: w for w in at.text_input}
    form["Rule ID"].set_value("junos-ntp")
    form["Configuration expression"].set_value(r"set system ntp server (\S+)")
    at.number_input[0].set_value(1)
    at.text_area[0].set_value("NTP server")
    [b for b in at.button if b.label == "Validate and add rule"][0].click().run()
    assert not at.exception, at.exception
    assert not at.error
    [b for b in at.button if b.label == "Save rules to JSON"][0].click().run()
    saved = (data_dir / "training_rules.json").read_text(encoding="utf-8")
    assert '"capture_group": 1' in saved
    assert '"vendor": "junos"' in saved
    assert '"target_field": "ntp_servers"' in saved


def test_training_page_offers_capture_only_for_regex_rules_on_text_fields(env):
    at = run_page("pages/2_Training.py")
    select = {w.label: w for w in at.selectbox}
    assert len(at.number_input) == 0
    select["Vendor"].select("junos")
    select["Matching method"].select("regex")
    at.run()
    {w.label: w for w in at.selectbox}["Target field"].select("ntp_servers")
    at.run()
    assert len(at.number_input) == 1
    assert not any(w.label.startswith("Value when no line matches") for w in at.selectbox)
    {w.label: w for w in at.selectbox}["Target field"].select("telnet_enabled")
    at.run()
    assert len(at.number_input) == 0
    assert any(w.label.startswith("Value when no line matches") for w in at.selectbox)


def test_training_page_saves_an_absence_rule(env):
    data_dir, _ = env
    at = run_page("pages/2_Training.py")
    select = {w.label: w for w in at.selectbox}
    select["Vendor"].select("junos")
    select["Matching method"].select("prefix")
    at.run()
    {w.label: w for w in at.selectbox}["Target field"].select("telnet_enabled")
    at.run()
    form = {w.label: w for w in at.text_input}
    form["Rule ID"].set_value("junos-telnet")
    form["Configuration expression"].set_value("set system services telnet")
    {w.label: w for w in at.selectbox}["Value when no line matches (optional)"].select("False / Disabled")
    at.text_area[0].set_value("Telnet service enabled")
    [b for b in at.button if b.label == "Validate and add rule"][0].click().run()
    assert not at.error
    [b for b in at.button if b.label == "Save rules to JSON"][0].click().run()
    saved = (data_dir / "training_rules.json").read_text(encoding="utf-8")
    assert '"absent_value": false' in saved
    assert '"target_field": "telnet_enabled"' in saved
