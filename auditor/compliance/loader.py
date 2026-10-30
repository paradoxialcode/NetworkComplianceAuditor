from itertools import chain
from pathlib import Path
from typing import Final

import yaml
from pydantic import ValidationError

from .models import Check

MAX_FILE_BYTES: Final = 1_000_000


class CheckLoadError(Exception):
    pass


def load_checks(directory: Path) -> list[Check]:
    files = sorted(
        p for p in chain(directory.glob("*.yaml"), directory.glob("*.yml")) if p.is_file()
    )
    checks: list[Check] = []
    seen: dict[str, str] = {}
    for path in files:
        if path.stat().st_size > MAX_FILE_BYTES:
            raise CheckLoadError(f"{path.name}: file exceeds {MAX_FILE_BYTES} bytes")
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError) as exc:
            raise CheckLoadError(f"{path.name}: unreadable YAML: {exc}") from exc
        if not isinstance(doc, dict) or not isinstance(doc.get("checks"), list):
            raise CheckLoadError(f"{path.name}: top level must be a mapping with a 'checks' list")
        for index, raw in enumerate(doc["checks"]):
            try:
                check = Check.model_validate(raw)
            except ValidationError as exc:
                raise CheckLoadError(f"{path.name}[{index}]: {exc}") from exc
            if check.id in seen:
                raise CheckLoadError(f"{path.name}: duplicate check id {check.id} (also in {seen[check.id]})")
            seen[check.id] = path.name
            checks.append(check)
    return checks
