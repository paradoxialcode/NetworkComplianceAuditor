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


@dataclass(frozen=True)
class AppSettings:
    data_dir: Path
    database: Path
    max_upload_bytes: int


def load_settings(env: Mapping[str, str] | None = None) -> AppSettings:
    source = os.environ if env is None else env
    data_dir = Path(source.get("AUDITOR_DATA_DIR") or PROJECT_ROOT / "data").expanduser().resolve()
    database = Path(source.get("AUDITOR_DB_PATH") or PROJECT_ROOT / "instance" / "audits.db").expanduser().resolve()
    raw = source.get("AUDITOR_MAX_UPLOAD_MB") or str(DEFAULT_UPLOAD_MB)
    try:
        megabytes = int(raw)
    except ValueError as exc:
        raise ValueError("AUDITOR_MAX_UPLOAD_MB must be an integer") from exc
    if not MIN_UPLOAD_MB <= megabytes <= MAX_UPLOAD_MB:
        raise ValueError(f"AUDITOR_MAX_UPLOAD_MB must be between {MIN_UPLOAD_MB} and {MAX_UPLOAD_MB}")
    return AppSettings(data_dir=data_dir, database=database, max_upload_bytes=megabytes * 1024 * 1024)
