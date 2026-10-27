"""Tests for auditor.config."""

from __future__ import annotations

import dataclasses
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import auditor.config as config
from auditor.config import (
    DEFAULT_MAX_UPLOAD_BYTES,
    ENV_DATA_DIR,
    ENV_DATABASE_PATH,
    ENV_ENABLE_PDF_REPORTS,
    ENV_ENABLE_SUGGESTIONS,
    ENV_HOME,
    ENV_MAX_UPLOAD_BYTES,
    ENV_REPORTS_DIR,
    ENV_VARS,
    MAX_UPLOAD_LIMIT,
    PROJECT_ROOT,
    Settings,
    ensure_directories,
    get_settings,
    load_settings,
)

SECRET = "hunter2"


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def load(root: Path, env: dict[str, str] | None = None) -> Settings:
    return load_settings(env or {}, root=root)


def make_settings(base: Path, **overrides: Any) -> Settings:
    kwargs: dict[str, Any] = {
        "root": base,
        "data_dir": base / "data",
        "database_path": base / "app.db",
        "reports_dir": base / "reports_out",
    }
    kwargs.update(overrides)
    return Settings(**kwargs)


# --------------------------------------------------------------------------
# Defaults
# --------------------------------------------------------------------------


class TestDefaults:
    def test_paths(self, tmp_path: Path) -> None:
        settings = load(tmp_path)
        assert settings.root == tmp_path
        assert settings.data_dir == tmp_path / "data"
        assert settings.database_path == tmp_path / "app.db"
        assert settings.reports_dir == tmp_path / "reports_out"

    def test_limits_and_flags(self, tmp_path: Path) -> None:
        settings = load(tmp_path)
        assert settings.max_upload_bytes == DEFAULT_MAX_UPLOAD_BYTES == 10 * 1024 * 1024
        assert settings.suggestions_enabled is True
        assert settings.pdf_reports_enabled is True

    def test_derived_directories(self, tmp_path: Path) -> None:
        settings = load(tmp_path)
        data = tmp_path / "data"
        assert settings.mappings_dir == data / "mappings"
        assert settings.checks_dir == data / "checks"
        assert settings.frameworks_dir == data / "frameworks"
        assert settings.remediation_dir == data / "remediation"
        assert settings.samples_dir == data / "samples"
        assert settings.blind_test_dir == data / "blind_test"

    def test_derived_directories_follow_data_dir(self, tmp_path: Path) -> None:
        elsewhere = tmp_path / "elsewhere"
        settings = load(tmp_path, {ENV_DATA_DIR: str(elsewhere)})
        assert settings.mappings_dir == elsewhere / "mappings"
        assert settings.blind_test_dir == elsewhere / "blind_test"

    def test_database_url(self, tmp_path: Path) -> None:
        url = load(tmp_path).database_url
        assert url.startswith("sqlite:///")
        assert url.endswith("/app.db")
        assert "\\" not in url

    def test_project_root_is_this_project(self) -> None:
        assert PROJECT_ROOT.is_absolute()
        assert (PROJECT_ROOT / "auditor" / "config.py").is_file()

    def test_default_root_is_the_project_root(self) -> None:
        assert load_settings({}).root == PROJECT_ROOT

    def test_load_has_no_side_effects(self, tmp_path: Path) -> None:
        load(tmp_path)
        assert list(tmp_path.iterdir()) == []


# --------------------------------------------------------------------------
# Root
# --------------------------------------------------------------------------


class TestRoot:
    def test_home_variable(self, tmp_path: Path) -> None:
        settings = load_settings({ENV_HOME: str(tmp_path)})
        assert settings.root == tmp_path
        assert settings.data_dir == tmp_path / "data"

    def test_home_must_be_absolute(self) -> None:
        with pytest.raises(ValueError, match=f"{ENV_HOME} must be an absolute path"):
            load_settings({ENV_HOME: "relative/dir"})

    def test_home_rejects_null_character(self) -> None:
        with pytest.raises(ValueError, match="null character"):
            load_settings({ENV_HOME: "a\x00b"})

    def test_blank_home_is_ignored(self) -> None:
        assert load_settings({ENV_HOME: "   "}).root == PROJECT_ROOT

    def test_explicit_root_wins_over_home(self, tmp_path: Path) -> None:
        other = tmp_path / "other"
        settings = load_settings({ENV_HOME: str(other)}, root=tmp_path)
        assert settings.root == tmp_path

    def test_explicit_root_must_be_absolute(self) -> None:
        with pytest.raises(ValueError, match="root must be an absolute path"):
            load_settings({}, root=Path("relative"))

    @pytest.mark.parametrize("bad", ["root", 5, None.__class__])
    def test_explicit_root_must_be_path(self, bad: object) -> None:
        with pytest.raises(TypeError, match="root must be pathlib.Path"):
            load_settings({}, root=bad)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Path variables
# --------------------------------------------------------------------------


PATH_VARIABLES = [
    pytest.param(ENV_DATA_DIR, "data_dir", id="data-dir"),
    pytest.param(ENV_DATABASE_PATH, "database_path", id="database-path"),
    pytest.param(ENV_REPORTS_DIR, "reports_dir", id="reports-dir"),
]


class TestPathVariables:
    @pytest.mark.parametrize(("name", "attribute"), PATH_VARIABLES)
    def test_relative_path_is_joined_to_root(
        self, tmp_path: Path, name: str, attribute: str
    ) -> None:
        settings = load(tmp_path, {name: "custom/place"})
        assert getattr(settings, attribute) == tmp_path / "custom" / "place"

    @pytest.mark.parametrize(("name", "attribute"), PATH_VARIABLES)
    def test_absolute_path_is_kept(
        self, tmp_path: Path, name: str, attribute: str
    ) -> None:
        target = tmp_path / "elsewhere" / "thing"
        settings = load(tmp_path / "root", {name: str(target)})
        assert getattr(settings, attribute) == target

    @pytest.mark.parametrize(("name", "attribute"), PATH_VARIABLES)
    def test_whitespace_is_stripped(
        self, tmp_path: Path, name: str, attribute: str
    ) -> None:
        target = tmp_path / "elsewhere"
        settings = load(tmp_path, {name: f"  {target}  "})
        assert getattr(settings, attribute) == target

    @pytest.mark.parametrize(("name", "attribute"), PATH_VARIABLES)
    def test_blank_uses_default(
        self, tmp_path: Path, name: str, attribute: str
    ) -> None:
        assert getattr(load(tmp_path, {name: "  "}), attribute) == getattr(
            load(tmp_path), attribute
        )

    @pytest.mark.parametrize(("name", "attribute"), PATH_VARIABLES)
    def test_null_character_is_rejected(
        self, tmp_path: Path, name: str, attribute: str
    ) -> None:
        with pytest.raises(ValueError, match=f"{name} must not contain a null"):
            load(tmp_path, {name: "a\x00b"})

    def test_variables_are_independent(self, tmp_path: Path) -> None:
        settings = load(tmp_path, {ENV_DATABASE_PATH: "db/x.sqlite"})
        assert settings.database_path == tmp_path / "db" / "x.sqlite"
        assert settings.data_dir == tmp_path / "data"
        assert settings.reports_dir == tmp_path / "reports_out"


# --------------------------------------------------------------------------
# Upload limit
# --------------------------------------------------------------------------


class TestMaxUploadBytes:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            pytest.param("1", 1, id="one"),
            pytest.param("2048", 2048, id="plain"),
            pytest.param("  2048  ", 2048, id="spaces"),
            pytest.param(str(MAX_UPLOAD_LIMIT), MAX_UPLOAD_LIMIT, id="maximum"),
        ],
    )
    def test_valid(self, tmp_path: Path, text: str, expected: int) -> None:
        assert load(tmp_path, {ENV_MAX_UPLOAD_BYTES: text}).max_upload_bytes == expected

    def test_blank_uses_default(self, tmp_path: Path) -> None:
        settings = load(tmp_path, {ENV_MAX_UPLOAD_BYTES: " "})
        assert settings.max_upload_bytes == DEFAULT_MAX_UPLOAD_BYTES

    @pytest.mark.parametrize(
        "text",
        [
            pytest.param("abc", id="letters"),
            pytest.param("-5", id="negative"),
            pytest.param("+5", id="plus-sign"),
            pytest.param("1.5", id="decimal"),
            pytest.param("1e3", id="exponent"),
            pytest.param("5 5", id="inner-space"),
            pytest.param("\u0663", id="non-ascii-digit"),
        ],
    )
    def test_not_a_whole_number(self, tmp_path: Path, text: str) -> None:
        with pytest.raises(ValueError, match="must be a whole number"):
            load(tmp_path, {ENV_MAX_UPLOAD_BYTES: text})

    @pytest.mark.parametrize(
        "text",
        [
            pytest.param("0", id="zero"),
            pytest.param(str(MAX_UPLOAD_LIMIT + 1), id="above-maximum"),
            pytest.param("9" * 5000, id="huge"),
        ],
    )
    def test_out_of_range(self, tmp_path: Path, text: str) -> None:
        with pytest.raises(ValueError, match="must be between 1 and"):
            load(tmp_path, {ENV_MAX_UPLOAD_BYTES: text})


# --------------------------------------------------------------------------
# Feature flags
# --------------------------------------------------------------------------

FLAGS = [
    pytest.param(ENV_ENABLE_SUGGESTIONS, "suggestions_enabled", id="suggestions"),
    pytest.param(ENV_ENABLE_PDF_REPORTS, "pdf_reports_enabled", id="pdf-reports"),
]


class TestFeatureFlags:
    @pytest.mark.parametrize(("name", "attribute"), FLAGS)
    @pytest.mark.parametrize(
        "text", ["1", "true", "TRUE", "True", "yes", "on", " Yes "]
    )
    def test_true_words(
        self, tmp_path: Path, name: str, attribute: str, text: str
    ) -> None:
        assert getattr(load(tmp_path, {name: text}), attribute) is True

    @pytest.mark.parametrize(("name", "attribute"), FLAGS)
    @pytest.mark.parametrize("text", ["0", "false", "False", "no", "off", "OFF"])
    def test_false_words(
        self, tmp_path: Path, name: str, attribute: str, text: str
    ) -> None:
        assert getattr(load(tmp_path, {name: text}), attribute) is False

    @pytest.mark.parametrize(("name", "attribute"), FLAGS)
    @pytest.mark.parametrize("text", ["maybe", "2", "tru", "y", "enabled"])
    def test_invalid_words(
        self, tmp_path: Path, name: str, attribute: str, text: str
    ) -> None:
        with pytest.raises(ValueError, match=f"{name} must be a boolean"):
            load(tmp_path, {name: text})

    @pytest.mark.parametrize(("name", "attribute"), FLAGS)
    def test_blank_uses_default(
        self, tmp_path: Path, name: str, attribute: str
    ) -> None:
        assert getattr(load(tmp_path, {name: ""}), attribute) is True

    def test_flags_are_independent(self, tmp_path: Path) -> None:
        settings = load(tmp_path, {ENV_ENABLE_SUGGESTIONS: "off"})
        assert settings.suggestions_enabled is False
        assert settings.pdf_reports_enabled is True


# --------------------------------------------------------------------------
# Environment handling
# --------------------------------------------------------------------------


class TestEnvironment:
    def test_unknown_variables_are_ignored(self, tmp_path: Path) -> None:
        env = {"AUDITOR_TYPO": "x", "PATH": "/bin", "HOME": "/home/me"}
        assert load(tmp_path, env) == load(tmp_path)

    def test_default_source_is_os_environ(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(ENV_MAX_UPLOAD_BYTES, "123")
        assert load_settings(root=tmp_path).max_upload_bytes == 123

    def test_explicit_mapping_ignores_os_environ(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(ENV_MAX_UPLOAD_BYTES, "123")
        settings = load_settings({}, root=tmp_path)
        assert settings.max_upload_bytes == DEFAULT_MAX_UPLOAD_BYTES

    @pytest.mark.parametrize("bad", ["env", 5, ["a"], None.__class__])
    def test_environ_must_be_a_mapping(self, bad: object) -> None:
        with pytest.raises(TypeError, match="environ must be a mapping"):
            load_settings(bad)  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "name",
        [ENV_ENABLE_SUGGESTIONS, ENV_MAX_UPLOAD_BYTES, ENV_DATA_DIR, ENV_HOME],
    )
    def test_values_must_be_strings(self, tmp_path: Path, name: str) -> None:
        with pytest.raises(TypeError, match=f"{name} must be a str"):
            load_settings({name: 1}, root=tmp_path)  # type: ignore[dict-item]

    def test_does_not_modify_the_mapping(self, tmp_path: Path) -> None:
        env = {ENV_MAX_UPLOAD_BYTES: "5"}
        load(tmp_path, env)
        assert env == {ENV_MAX_UPLOAD_BYTES: "5"}


# --------------------------------------------------------------------------
# Error messages never echo values
# --------------------------------------------------------------------------


class TestNoValueEcho:
    @pytest.mark.parametrize(
        ("name", "value"),
        [
            pytest.param(ENV_MAX_UPLOAD_BYTES, SECRET, id="upload"),
            pytest.param(ENV_ENABLE_SUGGESTIONS, SECRET, id="suggestions"),
            pytest.param(ENV_ENABLE_PDF_REPORTS, SECRET, id="pdf"),
            pytest.param(ENV_DATA_DIR, f"a\x00{SECRET}", id="data-null"),
            pytest.param(ENV_DATABASE_PATH, f"a\x00{SECRET}", id="db-null"),
            pytest.param(ENV_REPORTS_DIR, f"a\x00{SECRET}", id="reports-null"),
            pytest.param(ENV_HOME, f"a\x00{SECRET}", id="home-null"),
            pytest.param(ENV_HOME, SECRET, id="home-relative"),
        ],
    )
    def test_message_names_variable_not_value(self, name: str, value: str) -> None:
        with pytest.raises(ValueError) as info:
            load_settings({name: value})
        assert name in str(info.value)
        assert SECRET not in str(info.value)

    def test_wrong_type_errors_do_not_echo(self) -> None:
        with pytest.raises(TypeError) as info:
            load_settings(SECRET)  # type: ignore[arg-type]
        assert SECRET not in str(info.value)


# --------------------------------------------------------------------------
# Settings dataclass
# --------------------------------------------------------------------------


class TestSettings:
    def test_is_frozen(self, tmp_path: Path) -> None:
        settings = make_settings(tmp_path)
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(settings, "max_upload_bytes", 1)

    def test_uses_slots(self, tmp_path: Path) -> None:
        assert not hasattr(make_settings(tmp_path), "__dict__")

    def test_equality_and_hash(self, tmp_path: Path) -> None:
        first, second = load(tmp_path), load(tmp_path)
        assert first == second
        assert hash(first) == hash(second)
        assert first != load(tmp_path, {ENV_ENABLE_SUGGESTIONS: "off"})

    @pytest.mark.parametrize(
        "name", ["root", "data_dir", "database_path", "reports_dir"]
    )
    def test_paths_must_be_absolute(self, tmp_path: Path, name: str) -> None:
        with pytest.raises(ValueError, match=f"{name} must be an absolute path"):
            make_settings(tmp_path, **{name: Path("relative")})

    @pytest.mark.parametrize(
        "name", ["root", "data_dir", "database_path", "reports_dir"]
    )
    def test_paths_must_be_path_objects(self, tmp_path: Path, name: str) -> None:
        with pytest.raises(TypeError, match=f"{name} must be pathlib.Path"):
            make_settings(tmp_path, **{name: str(tmp_path)})

    @pytest.mark.parametrize(
        "value",
        [pytest.param(True, id="bool"), pytest.param("5", id="str"), pytest.param(1.0, id="float")],
    )
    def test_upload_limit_type(self, tmp_path: Path, value: object) -> None:
        with pytest.raises(TypeError, match="max_upload_bytes must be int"):
            make_settings(tmp_path, max_upload_bytes=value)

    @pytest.mark.parametrize("value", [0, -1, MAX_UPLOAD_LIMIT + 1])
    def test_upload_limit_range(self, tmp_path: Path, value: int) -> None:
        with pytest.raises(ValueError, match="max_upload_bytes must be between"):
            make_settings(tmp_path, max_upload_bytes=value)

    @pytest.mark.parametrize("name", ["suggestions_enabled", "pdf_reports_enabled"])
    @pytest.mark.parametrize("value", [1, 0, "true", None])
    def test_flags_must_be_bool(
        self, tmp_path: Path, name: str, value: object
    ) -> None:
        with pytest.raises(TypeError, match=f"{name} must be bool"):
            make_settings(tmp_path, **{name: value})


# --------------------------------------------------------------------------
# get_settings
# --------------------------------------------------------------------------


class TestGetSettings:
    def test_returns_the_same_instance(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(ENV_HOME, str(tmp_path))
        first = get_settings()
        assert get_settings() is first
        assert first.root == tmp_path

    def test_environment_changes_need_a_cache_clear(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(ENV_HOME, str(tmp_path))
        monkeypatch.setenv(ENV_ENABLE_SUGGESTIONS, "on")
        first = get_settings()
        monkeypatch.setenv(ENV_ENABLE_SUGGESTIONS, "off")
        assert get_settings() is first
        assert first.suggestions_enabled is True

        get_settings.cache_clear()
        second = get_settings()
        assert second is not first
        assert second.suggestions_enabled is False

    def test_invalid_environment_raises_and_is_not_cached(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(ENV_HOME, str(tmp_path))
        monkeypatch.setenv(ENV_MAX_UPLOAD_BYTES, "oops")
        with pytest.raises(ValueError, match=ENV_MAX_UPLOAD_BYTES):
            get_settings()
        monkeypatch.setenv(ENV_MAX_UPLOAD_BYTES, "9")
        assert get_settings().max_upload_bytes == 9


# --------------------------------------------------------------------------
# ensure_directories
# --------------------------------------------------------------------------


class TestEnsureDirectories:
    def test_creates_reports_and_database_parent(self, tmp_path: Path) -> None:
        settings = load(
            tmp_path,
            {ENV_REPORTS_DIR: "out/reports", ENV_DATABASE_PATH: "var/db/app.db"},
        )
        assert ensure_directories(settings) is None
        assert (tmp_path / "out" / "reports").is_dir()
        assert (tmp_path / "var" / "db").is_dir()

    def test_does_not_create_database_or_data_dir(self, tmp_path: Path) -> None:
        settings = load(tmp_path, {ENV_DATABASE_PATH: "var/app.db"})
        ensure_directories(settings)
        assert not (tmp_path / "var" / "app.db").exists()
        assert not settings.data_dir.exists()

    def test_is_idempotent(self, tmp_path: Path) -> None:
        settings = load(tmp_path)
        ensure_directories(settings)
        ensure_directories(settings)
        assert settings.reports_dir.is_dir()

    def test_existing_file_in_the_way_raises(self, tmp_path: Path) -> None:
        settings = load(tmp_path)
        settings.reports_dir.write_text("not a directory", encoding="utf-8")
        with pytest.raises(OSError):
            ensure_directories(settings)

    @pytest.mark.parametrize("bad", ["settings", None, 5])
    def test_requires_settings(self, bad: object) -> None:
        with pytest.raises(TypeError, match="settings must be Settings"):
            ensure_directories(bad)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Module surface
# --------------------------------------------------------------------------


def test_public_api() -> None:
    assert set(config.__all__) == {
        "DEFAULT_MAX_UPLOAD_BYTES",
        "ENV_DATABASE_PATH",
        "ENV_DATA_DIR",
        "ENV_ENABLE_PDF_REPORTS",
        "ENV_ENABLE_SUGGESTIONS",
        "ENV_HOME",
        "ENV_MAX_UPLOAD_BYTES",
        "ENV_REPORTS_DIR",
        "ENV_VARS",
        "MAX_UPLOAD_LIMIT",
        "PROJECT_ROOT",
        "Settings",
        "ensure_directories",
        "get_settings",
        "load_settings",
    }
    for name in config.__all__:
        assert hasattr(config, name)


def test_environment_variable_names() -> None:
    assert ENV_VARS == (
        "AUDITOR_HOME",
        "AUDITOR_DATA_DIR",
        "AUDITOR_DATABASE_PATH",
        "AUDITOR_REPORTS_DIR",
        "AUDITOR_MAX_UPLOAD_BYTES",
        "AUDITOR_ENABLE_SUGGESTIONS",
        "AUDITOR_ENABLE_PDF_REPORTS",
    )
    assert all(name.startswith("AUDITOR_") for name in ENV_VARS)


def test_limits() -> None:
    assert DEFAULT_MAX_UPLOAD_BYTES == 10_485_760
    assert MAX_UPLOAD_LIMIT == 1_073_741_824