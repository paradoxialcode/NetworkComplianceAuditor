import pytest

from auditor.audit.restore import MAX_RESTORE_IDS, fetch_audits, format_audit_ids, parse_audit_ids
from auditor.audit.settings import load_settings
from auditor.audit.store import init_db


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("1", (1,)),
        ("3,1,3,2", (3, 1, 2)),
        ("0", ()),
        ("", ()),
        ("1,", ()),
        (",1", ()),
        ("-1", ()),
        ("1 2", ()),
        ("1;DROP TABLE audits", ()),
        ("\u0661", ()),
        ("9999999999", ()),
        (None, ()),
        (["1"], ()),
        (",".join(["1"] * (MAX_RESTORE_IDS + 1)), ()),
    ],
)
def test_parse_audit_ids(raw, expected):
    assert parse_audit_ids(raw) == expected


def test_format_audit_ids_filters_invalid():
    assert format_audit_ids([1, None, True, 0, 7]) == "1,7"
    assert parse_audit_ids(format_audit_ids([4, 5])) == (4, 5)


def test_fetch_missing_ids_returns_empty(tmp_path):
    db = tmp_path / "a.db"
    init_db(db)
    assert fetch_audits(db, (1, 2, 3)) == []


def test_training_rules_default_and_override(tmp_path):
    default = load_settings({"AUDITOR_DATA_DIR": str(tmp_path)})
    assert default.training_rules_file == tmp_path.resolve() / "training_rules.json"
    custom = tmp_path / "rules" / "t.json"
    override = load_settings({"AUDITOR_DATA_DIR": str(tmp_path), "AUDITOR_TRAINING_RULES": str(custom)})
    assert override.training_rules_file == custom.resolve()


def test_null_byte_in_path_rejected():
    with pytest.raises(ValueError, match="AUDITOR_DB_PATH"):
        load_settings({"AUDITOR_DB_PATH": "a\x00b"})
