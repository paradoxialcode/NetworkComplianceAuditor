import pytest

from auditor.compliance.loader import MAX_FILE_BYTES, CheckLoadError, load_checks

VALID = """
checks:
  - id: CHK-MGMT-TELNET
    title: Telnet management must be disabled
    severity: high
    condition: {field: mgmt.telnet.enabled, op: eq, value: false, on_missing: pass}
    mappings:
      nist: [AC-17]
      iso27001: [A.8.20]
      soc2: [CC6.6]
    remediation_key: disable_telnet
  - id: CHK-MGMT-SSH2
    title: SSH must use version 2
    severity: high
    vendors: [cisco, junos]
    condition: {field: mgmt.ssh.version, op: eq, value: 2}
"""


def write(tmp_path, name, text):
    (tmp_path / name).write_text(text, encoding="utf-8")


def test_loads_valid_files(tmp_path):
    write(tmp_path, "management.yaml", VALID)
    checks = load_checks(tmp_path)
    assert [c.id for c in checks] == ["CHK-MGMT-TELNET", "CHK-MGMT-SSH2"]
    assert checks[0].mappings["nist"] == ("AC-17",)


def test_empty_directory(tmp_path):
    assert load_checks(tmp_path) == []


def test_ignores_other_extensions(tmp_path):
    write(tmp_path, "notes.txt", "garbage: [")
    assert load_checks(tmp_path) == []


def test_duplicate_ids_across_files(tmp_path):
    write(tmp_path, "a.yaml", VALID)
    write(tmp_path, "b.yml", VALID)
    with pytest.raises(CheckLoadError, match="duplicate"):
        load_checks(tmp_path)


@pytest.mark.parametrize(
    "text",
    [
        "checks: [",
        "- just\n- a list",
        "checks: not-a-list",
        "checks:\n  - id: lower-case-id\n    title: Bad id\n    severity: high\n    condition: {field: a.b, op: present}",
        "checks:\n  - id: CHK-X-01\n    title: Bad framework\n    severity: high\n    condition: {field: a.b, op: present}\n    mappings: {pci: [1]}",
        "checks:\n  - id: CHK-X-02\n    title: Bad severity\n    severity: urgent\n    condition: {field: a.b, op: present}",
    ],
)
def test_invalid_files_rejected(tmp_path, text):
    write(tmp_path, "bad.yaml", text)
    with pytest.raises(CheckLoadError):
        load_checks(tmp_path)


def test_python_tags_not_executed(tmp_path):
    write(tmp_path, "evil.yaml", "checks: !!python/object/apply:os.system ['echo pwned']")
    with pytest.raises(CheckLoadError):
        load_checks(tmp_path)


def test_oversized_file_rejected(tmp_path):
    write(tmp_path, "big.yaml", "checks: []\n" + "#" * MAX_FILE_BYTES)
    with pytest.raises(CheckLoadError, match="exceeds"):
        load_checks(tmp_path)
