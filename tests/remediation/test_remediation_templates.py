import pytest

from auditor.compliance.models import Check
from auditor.remediation.templates import (
    ParamSpec,
    RemediationStep,
    TemplateLoadError,
    load_templates,
    missing_templates,
)

CISCO = """
vendor: Cisco
steps:
  disable_telnet:
    title: Disable Telnet on VTY lines
    risk: Confirm SSH works before applying or you may lose remote access.
    order: 20
    params:
      vty_range: {pattern: '[0-9]{1,3} [0-9]{1,3}', default: '0 15'}
    commands:
      - "line vty {{ vty_range }}"
      - " transport input ssh"
  set_ssh_v2:
    title: Require SSH version 2
    order: 10
    commands: ["ip ssh version 2"]
"""


def write(tmp_path, name, text):
    (tmp_path / name).write_text(text, encoding="utf-8")


def step(**overrides):
    data = {"title": "Example step", "commands": ["show version"], **overrides}
    return RemediationStep.model_validate(data)


def test_loads_and_normalizes_vendor(tmp_path):
    write(tmp_path, "cisco.yaml", CISCO)
    templates = load_templates(tmp_path)
    assert list(templates) == ["cisco"]
    assert templates["cisco"].steps["disable_telnet"].commands[1] == " transport input ssh"


def test_empty_directory(tmp_path):
    assert load_templates(tmp_path) == {}


def test_duplicate_vendor_rejected(tmp_path):
    write(tmp_path, "a.yaml", CISCO)
    write(tmp_path, "b.yml", CISCO)
    with pytest.raises(TemplateLoadError, match="duplicate"):
        load_templates(tmp_path)


@pytest.mark.parametrize(
    "text",
    [
        "vendor: cisco\nsteps: {}",
        "vendor: 'Bad Vendor!'\nsteps: {abc_def: {title: Valid title, commands: [x]}}",
        "vendor: cisco\nsteps: {Bad-Key: {title: Valid title, commands: [x]}}",
        "vendor: cisco\nsteps: {abc_def: {title: Valid title, commands: []}}",
        "vendor: cisco\nsteps: {abc_def: {title: Valid title, commands: ['  ']}}",
        "vendor: cisco\nsteps: {abc_def: {title: Valid title, commands: [x], bogus: 1}}",
        "vendor: [",
        "- list",
    ],
)
def test_invalid_template_files_rejected(tmp_path, text):
    write(tmp_path, "bad.yaml", text)
    with pytest.raises(TemplateLoadError):
        load_templates(tmp_path)


def test_python_yaml_tags_not_executed(tmp_path):
    write(tmp_path, "evil.yaml", "vendor: !!python/object/apply:os.system ['echo pwned']\nsteps: {}")
    with pytest.raises(TemplateLoadError):
        load_templates(tmp_path)


@pytest.mark.parametrize(
    "overrides",
    [
        {"commands": ["line {{ undeclared }}"]},
        {"commands": ["{% if %}"]},
        {"commands": ["a\nb"]},
        {"commands": ["a\x00b"]},
        {"commands": ["x" * 600]},
        {"params": {"Bad-Name": {"pattern": "[a-z]+"}}, "commands": ["x"]},
        {"params": {"ok": {"pattern": "(unclosed"}}, "commands": ["x"]},
        {"params": {"ok": {"pattern": "[0-9]+", "default": "abc"}}, "commands": ["x"]},
        {"order": 99},
    ],
)
def test_invalid_steps_rejected(overrides):
    with pytest.raises(ValueError):
        step(**overrides)


def test_param_spec_accepts():
    spec = ParamSpec(pattern=r"[A-Za-z0-9/._-]+")
    assert spec.accepts("GigabitEthernet0/1")
    assert not spec.accepts("Gi0/1\nno logging")
    assert not spec.accepts("Gi0/1; reload")
    assert not spec.accepts("")
    assert not spec.accepts("x" * 200)
    assert not spec.accepts(5)


def test_missing_templates_report(tmp_path):
    write(tmp_path, "cisco.yaml", CISCO)
    templates = load_templates(tmp_path)

    def chk(check_id, key, vendors=None):
        data = {
            "id": check_id,
            "title": "Some check",
            "severity": "low",
            "condition": {"field": "a.b", "op": "present"},
            "remediation_key": key,
        }
        if vendors:
            data["vendors"] = vendors
        return Check.model_validate(data)

    problems = missing_templates(
        [
            chk("CHK-OK-01", "set_ssh_v2"),
            chk("CHK-MISSING-KEY", "no_such_key"),
            chk("CHK-NO-VENDOR", "set_ssh_v2", ["juniper"]),
            chk("CHK-NO-KEY-FIELD", None),
        ],
        templates,
    )
    assert problems == [
        "CHK-MISSING-KEY: cisco has no step 'no_such_key'",
        "CHK-NO-VENDOR: no templates loaded for vendor 'juniper'",
    ]
