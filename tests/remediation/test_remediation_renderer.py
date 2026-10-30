from auditor.compliance.models import CheckResult, Severity, Status
from auditor.remediation.renderer import RemediationKind, render_all, render_remediation
from auditor.remediation.templates import VendorTemplates


def templates(**steps):
    return {
        "cisco": VendorTemplates.model_validate({"vendor": "cisco", "steps": steps}),
    }


TELNET = {
    "title": "Disable Telnet on VTY lines",
    "risk": "Confirm SSH works first.",
    "order": 20,
    "params": {"vty_range": {"pattern": "[0-9]{1,3} [0-9]{1,3}", "default": "0 15"}},
    "commands": ["line vty {{ vty_range }}", " transport input ssh"],
}
SSH = {"title": "Require SSH version 2", "order": 10, "commands": ["ip ssh version 2"]}
TPL = templates(disable_telnet=TELNET, set_ssh_v2=SSH)


def result(check_id="CHK-A-01", status=Status.FAIL, key="disable_telnet", severity=Severity.HIGH):
    return CheckResult(
        check_id=check_id,
        title="Check title",
        severity=severity,
        status=status,
        evidence={},
        mappings={},
        remediation_key=key,
    )


def test_renders_commands_with_default_param():
    rem = render_remediation(result(), "Cisco", TPL)
    assert rem.kind is RemediationKind.COMMANDS
    assert rem.commands == ("line vty 0 15", " transport input ssh")
    assert rem.warning == "Confirm SSH works first."
    assert rem.step_title == "Disable Telnet on VTY lines"


def test_context_overrides_default():
    rem = render_remediation(result(), "cisco", TPL, {"vty_range": "0 4"})
    assert rem.commands[0] == "line vty 0 4"


def test_unknown_context_keys_are_ignored():
    rem = render_remediation(result(), "cisco", TPL, {"evil": "x", "vty_range": "0 4"})
    assert rem.commands[0] == "line vty 0 4"


def test_injection_attempt_falls_back_to_manual_without_echoing_value():
    payload = "0 4\nno logging on"
    rem = render_remediation(result(), "cisco", TPL, {"vty_range": payload})
    assert rem.kind is RemediationKind.MANUAL
    assert rem.commands == ()
    assert "no logging" not in (rem.note or "")
    assert "vty_range" in (rem.note or "")


def test_required_param_without_default():
    tpl = templates(
        x_step={
            "title": "Needs a value",
            "params": {"iface": {"pattern": "[A-Za-z0-9/]+"}},
            "commands": ["interface {{ iface }}"],
        }
    )
    assert render_remediation(result(key="x_step"), "cisco", tpl).kind is RemediationKind.MANUAL
    ok = render_remediation(result(key="x_step"), "cisco", tpl, {"iface": "Gi0/1"})
    assert ok.commands == ("interface Gi0/1",)


def test_sandbox_blocks_template_introspection():
    tpl = templates(evil_step={"title": "Evil template", "commands": ["{{ ''.__class__.__mro__ }}"]})
    rem = render_remediation(result(key="evil_step"), "cisco", tpl)
    assert rem.kind is RemediationKind.MANUAL
    assert rem.commands == ()


def test_manual_fallbacks():
    assert render_remediation(result(key=None), "cisco", TPL).kind is RemediationKind.MANUAL
    assert render_remediation(result(), "juniper", TPL).kind is RemediationKind.MANUAL
    assert render_remediation(result(), None, TPL).kind is RemediationKind.MANUAL
    assert render_remediation(result(key="no_such_key"), "cisco", TPL).kind is RemediationKind.MANUAL


def test_not_configured_gets_commands():
    rem = render_remediation(result(status=Status.NOT_CONFIGURED, key="set_ssh_v2"), "cisco", TPL)
    assert rem.kind is RemediationKind.COMMANDS


def test_unknown_and_error_need_verification():
    for status in (Status.UNKNOWN, Status.ERROR):
        rem = render_remediation(result(status=status), "cisco", TPL)
        assert rem.kind is RemediationKind.VERIFY
        assert rem.commands == ()


def test_render_all_filters_and_orders():
    results = [
        result("CHK-PASS-01", Status.PASS),
        result("CHK-NA-01", Status.NOT_APPLICABLE),
        result("CHK-UNK-01", Status.UNKNOWN),
        result("CHK-MAN-01", Status.FAIL, key=None),
        result("CHK-TEL-01", Status.FAIL, key="disable_telnet", severity=Severity.CRITICAL),
        result("CHK-SSH-01", Status.FAIL, key="set_ssh_v2", severity=Severity.LOW),
    ]
    rendered = render_all(results, "cisco", TPL)
    assert [r.check_id for r in rendered] == ["CHK-SSH-01", "CHK-TEL-01", "CHK-MAN-01", "CHK-UNK-01"]


def test_render_all_uses_per_check_context():
    rendered = render_all([result("CHK-TEL-01")], "cisco", TPL, {"CHK-TEL-01": {"vty_range": "0 4"}})
    assert rendered[0].commands[0] == "line vty 0 4"


def test_same_severity_ties_sorted_by_check_id():
    results = [result("CHK-B-01", key="set_ssh_v2"), result("CHK-A-01", key="set_ssh_v2")]
    assert [r.check_id for r in render_all(results, "cisco", TPL)] == ["CHK-A-01", "CHK-B-01"]
