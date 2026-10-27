"""Application settings: paths, database location and feature flags.

Everything is read from environment variables (all prefixed ``AUDITOR_``) with
sensible defaults, so the app runs with no setup at all. There are no third
party dependencies and this module never reads ``.env`` files; set variables in
the shell, or let Docker load ``.env`` through ``env_file``.

Variables (all optional; blank values count as unset):

    AUDITOR_HOME                Project root (absolute path).
    AUDITOR_DATA_DIR            Data directory (default ``<root>/data``).
    AUDITOR_DATABASE_PATH       SQLite file (default ``<root>/app.db``).
    AUDITOR_REPORTS_DIR         Generated PDFs (default ``<root>/reports_out``).
    AUDITOR_MAX_UPLOAD_BYTES    Largest accepted config upload (default 10 MiB).
    AUDITOR_ENABLE_SUGGESTIONS  Training suggestions on/off (default on).
    AUDITOR_ENABLE_PDF_REPORTS  PDF report generation on/off (default on).

Relative paths in variables are resolved against the project root. Booleans
accept ``1/0``, ``true/false``, ``yes/no`` and ``on/off`` in any case.

Responsibilities:
    - Parse and validate settings (:func:`load_settings`).
    - Provide one cached instance for the app (:func:`get_settings`).
    - Create output directories on request (:func:`ensure_directories`).

Non-responsibilities:
    - Reading files, opening the database, or any business logic.

Safety:
    - :func:`load_settings` has no side effects; it never touches the disk.
    - Error messages name the variable but never echo its value.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

__all__ = [
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
]

PROJECT_ROOT = Path(__file__).resolve().parents[1]

ENV_HOME = "AUDITOR_HOME"
ENV_DATA_DIR = "AUDITOR_DATA_DIR"
ENV_DATABASE_PATH = "AUDITOR_DATABASE_PATH"
ENV_REPORTS_DIR = "AUDITOR_REPORTS_DIR"
ENV_MAX_UPLOAD_BYTES = "AUDITOR_MAX_UPLOAD_BYTES"
ENV_ENABLE_SUGGESTIONS = "AUDITOR_ENABLE_SUGGESTIONS"
ENV_ENABLE_PDF_REPORTS = "AUDITOR_ENABLE_PDF_REPORTS"
ENV_VARS = (
    ENV_HOME,
    ENV_DATA_DIR,
    ENV_DATABASE_PATH,
    ENV_REPORTS_DIR,
    ENV_MAX_UPLOAD_BYTES,
    ENV_ENABLE_SUGGESTIONS,
    ENV_ENABLE_PDF_REPORTS,
)

DEFAULT_MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_UPLOAD_LIMIT = 1024 * 1024 * 1024

_TRUE_WORDS = frozenset({"1", "true", "yes", "on"})
_FALSE_WORDS = frozenset({"0", "false", "no", "off"})
_MAX_DIGITS = 18


# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Settings:
    """Validated application settings (immutable).

    Raises:
        TypeError: a field has the wrong type.
        ValueError: a path is not absolute, or ``max_upload_bytes`` is outside
            1 to ``MAX_UPLOAD_LIMIT``.
    """

    root: Path
    data_dir: Path
    database_path: Path
    reports_dir: Path
    max_upload_bytes: int = DEFAULT_MAX_UPLOAD_BYTES
    suggestions_enabled: bool = True
    pdf_reports_enabled: bool = True

    def __post_init__(self) -> None:
        for name in ("root", "data_dir", "database_path", "reports_dir"):
            value = getattr(self, name)
            if not isinstance(value, Path):
                raise TypeError(
                    f"{name} must be pathlib.Path, got {type(value).__name__}"
                )
            if not value.is_absolute():
                raise ValueError(f"{name} must be an absolute path")

        size = self.max_upload_bytes
        if isinstance(size, bool) or not isinstance(size, int):
            raise TypeError(
                f"max_upload_bytes must be int, got {type(size).__name__}"
            )
        if not 1 <= size <= MAX_UPLOAD_LIMIT:
            raise ValueError(
                f"max_upload_bytes must be between 1 and {MAX_UPLOAD_LIMIT}"
            )

        for name in ("suggestions_enabled", "pdf_reports_enabled"):
            flag = getattr(self, name)
            if not isinstance(flag, bool):
                raise TypeError(f"{name} must be bool, got {type(flag).__name__}")

    @property
    def mappings_dir(self) -> Path:
        """Pre-trained rule files (``*.json``)."""
        return self.data_dir / "mappings"

    @property
    def checks_dir(self) -> Path:
        return self.data_dir / "checks"

    @property
    def frameworks_dir(self) -> Path:
        return self.data_dir / "frameworks"

    @property
    def remediation_dir(self) -> Path:
        return self.data_dir / "remediation"

    @property
    def samples_dir(self) -> Path:
        return self.data_dir / "samples"

    @property
    def blind_test_dir(self) -> Path:
        return self.data_dir / "blind_test"

    @property
    def database_url(self) -> str:
        """``sqlite:///`` URL for the database file (forward slashes only)."""
        return "sqlite:///" + self.database_path.as_posix()


# --------------------------------------------------------------------------
# Parsing helpers
# --------------------------------------------------------------------------


def _get(env: Mapping[str, str], name: str) -> str | None:
    """Return the stripped value of ``name``, or None if unset or blank."""
    raw = env.get(name)
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise TypeError(f"{name} must be a str")
    text = raw.strip()
    return text or None


def _parse_bool(name: str, text: str) -> bool:
    """Parse a boolean word.

    >>> _parse_bool("X", "Yes")
    True
    >>> _parse_bool("X", "off")
    False
    >>> _parse_bool("X", "maybe")
    Traceback (most recent call last):
        ...
    ValueError: X must be a boolean (true/false, yes/no, on/off, 1/0)
    """
    lowered = text.lower()
    if lowered in _TRUE_WORDS:
        return True
    if lowered in _FALSE_WORDS:
        return False
    raise ValueError(f"{name} must be a boolean (true/false, yes/no, on/off, 1/0)")


def _parse_int(name: str, text: str, *, minimum: int, maximum: int) -> int:
    """Parse a plain ASCII whole number within ``minimum``..``maximum``.

    >>> _parse_int("X", "42", minimum=1, maximum=100)
    42
    >>> _parse_int("X", "-1", minimum=1, maximum=100)
    Traceback (most recent call last):
        ...
    ValueError: X must be a whole number
    >>> _parse_int("X", "101", minimum=1, maximum=100)
    Traceback (most recent call last):
        ...
    ValueError: X must be between 1 and 100
    """
    if not (text.isascii() and text.isdigit()):
        raise ValueError(f"{name} must be a whole number")
    if len(text) > _MAX_DIGITS or not minimum <= int(text) <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return int(text)


def _path_setting(
    env: Mapping[str, str], name: str, root: Path, default: Path
) -> Path:
    text = _get(env, name)
    if text is None:
        return default
    if "\x00" in text:
        raise ValueError(f"{name} must not contain a null character")
    path = Path(text)
    return path if path.is_absolute() else root / path


def _resolve_root(env: Mapping[str, str], root: Path | None) -> Path:
    if root is not None:
        if not isinstance(root, Path):
         raise TypeError("root must be pathlib.Path")
        
        if not root.is_absolute():
            raise ValueError("root must be an absolute path")
        return root
    text = _get(env, ENV_HOME)
    if text is None:
        return PROJECT_ROOT
    if "\x00" in text:
        raise ValueError(f"{ENV_HOME} must not contain a null character")
    path = Path(text)
    if not path.is_absolute():
        raise ValueError(f"{ENV_HOME} must be an absolute path")
    return path


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def load_settings(
    environ: Mapping[str, str] | None = None,
    *,
    root: Path | None = None,
) -> Settings:
        env = os.environ if environ is None else environ

        if not isinstance(env, Mapping):
         raise TypeError(
            f"environ must be a mapping, got {type(env).__name__}"
        )

        for name in ENV_VARS:
         if name in env and not isinstance(env[name], str):
            raise TypeError(f"{name} must be a str")
        """Build :class:`Settings` from environment variables.
    
    Args:
        environ: Variables to read (default: ``os.environ``).
        root: Project root; overrides ``AUDITOR_HOME`` when given.

    Raises:
        TypeError: ``environ`` is not a mapping, ``root`` is not a ``Path``,
            or an environment value is not a string.
        ValueError: a variable is malformed or out of range. The message
            names the variable but not its value.

    >>> settings = load_settings({}, root=PROJECT_ROOT)
    >>> settings.suggestions_enabled
    True
    >>> settings.max_upload_bytes == DEFAULT_MAX_UPLOAD_BYTES
    True
    >>> load_settings({"AUDITOR_ENABLE_PDF_REPORTS": "no"}, root=PROJECT_ROOT).pdf_reports_enabled
    False
    >>> load_settings({"AUDITOR_MAX_UPLOAD_BYTES": "x"}, root=PROJECT_ROOT)
    Traceback (most recent call last):
        ...
    ValueError: AUDITOR_MAX_UPLOAD_BYTES must be a whole number
    """
        for name in ENV_VARS:
         if name in env and not isinstance(env[name], str):
          raise TypeError(f"{name} must be a str")
        for name in ENV_VARS:
         if name in env and not isinstance(env[name], str):
          raise TypeError(f"{name} must be a str")

        base = _resolve_root(env, root)
        data_dir = _path_setting(env, ENV_DATA_DIR, base, base / "data")
        database_path = _path_setting(env, ENV_DATABASE_PATH, base, base / "app.db")
        reports_dir = _path_setting(env, ENV_REPORTS_DIR, base, base / "reports_out")

        upload_text = _get(env, ENV_MAX_UPLOAD_BYTES)
        max_upload = (
        DEFAULT_MAX_UPLOAD_BYTES
        if upload_text is None
        else _parse_int(
            ENV_MAX_UPLOAD_BYTES, upload_text, minimum=1, maximum=MAX_UPLOAD_LIMIT
        )
    )

        suggestions_text = _get(env, ENV_ENABLE_SUGGESTIONS)
        pdf_text = _get(env, ENV_ENABLE_PDF_REPORTS)
        return Settings(
        root=base,
        data_dir=data_dir,
        database_path=database_path,
        reports_dir=reports_dir,
        max_upload_bytes=max_upload,
        suggestions_enabled=(
            True
            if suggestions_text is None
            else _parse_bool(ENV_ENABLE_SUGGESTIONS, suggestions_text)
        ),
        pdf_reports_enabled=(
            True
            if pdf_text is None
            else _parse_bool(ENV_ENABLE_PDF_REPORTS, pdf_text)
        ),
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings, loaded once from ``os.environ``.

    Call ``get_settings.cache_clear()`` after changing the environment.
    """
    return load_settings()


def ensure_directories(settings: Settings) -> None:
    """Create the reports directory and the database file's parent directory.

    Does not create the database file or the data directory.

    Raises:
        TypeError: ``settings`` is not a :class:`Settings`.
        OSError: a directory cannot be created.
    """
    if not isinstance(settings, Settings):
        raise TypeError(f"settings must be Settings, got {type(settings).__name__}")
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    settings.database_path.parent.mkdir(parents=True, exist_ok=True)


if __name__ == "__main__":
    import doctest

    doctest.testmod()