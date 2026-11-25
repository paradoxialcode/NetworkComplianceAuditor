from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

PROJECT_ROOT: Final = Path(__file__).resolve().parents[2]
MIN_UPLOAD_MB: Final = 1
MAX_UPLOAD_MB: Final = 50
DEFAULT_UPLOAD_MB: Final = 5
TRAINING_RULES_FILE: Final = "training_rules.json"


@dataclass(frozen=True)
class AppSettings:
    data_dir: Path
    database: Path
    max_upload_bytes: int
    training_rules: Path | None = None

    @property
    def training_rules_file(self) -> Path:
        return self.training_rules or self.data_dir / TRAINING_RULES_FILE


def _path(source: Mapping[str, str], name: str, default: Path) -> Path:
    raw = source.get(name)
    if raw is not None and "\x00" in raw:
        raise ValueError(f"{name} must not contain a null character")
    return Path(raw or default).expanduser().resolve()


def load_settings(env: Mapping[str, str] | None = None) -> AppSettings:
    source = os.environ if env is None else env
    data_dir = _path(source, "AUDITOR_DATA_DIR", PROJECT_ROOT / "data")
    database = _path(source, "AUDITOR_DB_PATH", PROJECT_ROOT / "instance" / "audits.db")
    training = source.get("AUDITOR_TRAINING_RULES")
    training_rules = _path(source, "AUDITOR_TRAINING_RULES", data_dir) if training else None
    raw = source.get("AUDITOR_MAX_UPLOAD_MB") or str(DEFAULT_UPLOAD_MB)
    try:
        megabytes = int(raw)
    except ValueError as exc:
        raise ValueError("AUDITOR_MAX_UPLOAD_MB must be an integer") from exc
    if not MIN_UPLOAD_MB <= megabytes <= MAX_UPLOAD_MB:
        raise ValueError(f"AUDITOR_MAX_UPLOAD_MB must be between {MIN_UPLOAD_MB} and {MAX_UPLOAD_MB}")
    return AppSettings(
        data_dir=data_dir,
        database=database,
        max_upload_bytes=megabytes * 1024 * 1024,
        training_rules=training_rules,
    )
