from pathlib import Path

import pytest

from auditor.audit.settings import PROJECT_ROOT, load_settings


def test_defaults():
    settings = load_settings({})
    assert settings.data_dir == (PROJECT_ROOT / "data").resolve()
    assert settings.database == (PROJECT_ROOT / "instance" / "audits.db").resolve()
    assert settings.max_upload_bytes == 5 * 1024 * 1024


def test_environment_overrides(tmp_path):
    settings = load_settings(
        {
            "AUDITOR_DATA_DIR": str(tmp_path / "rules"),
            "AUDITOR_DB_PATH": str(tmp_path / "x.db"),
            "AUDITOR_MAX_UPLOAD_MB": "12",
        }
    )
    assert settings.data_dir == (tmp_path / "rules").resolve()
    assert settings.database == Path(tmp_path / "x.db").resolve()
    assert settings.max_upload_bytes == 12 * 1024 * 1024


def test_empty_values_fall_back_to_defaults():
    assert load_settings({"AUDITOR_DATA_DIR": "", "AUDITOR_MAX_UPLOAD_MB": ""}) == load_settings({})


@pytest.mark.parametrize("value", ["abc", "0", "-3", "51", "1.5"])
def test_invalid_upload_limit_rejected(value):
    with pytest.raises(ValueError):
        load_settings({"AUDITOR_MAX_UPLOAD_MB": value})
