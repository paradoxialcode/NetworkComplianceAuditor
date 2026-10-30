from __future__ import annotations

from functools import lru_cache
from typing import Final

import regex

REGEX_TIMEOUT_SECONDS: Final = 0.05
_PROBES: Final = (
    "a" * 64 + "!",
    "0" * 64 + "!",
    " " * 64 + "!",
    "ab" * 32 + "!",
    "a" * 20 + "b" * 20 + "!",
)


class UnsafePatternError(ValueError):
    pass


@lru_cache(maxsize=512)
def compile_pattern(pattern: str) -> regex.Pattern[str]:
    try:
        compiled = regex.compile(pattern)
    except regex.error as exc:
        raise ValueError(f"invalid regex: {exc}") from exc
    for probe in _PROBES:
        try:
            compiled.search(probe, timeout=REGEX_TIMEOUT_SECONDS)
        except TimeoutError as exc:
            raise UnsafePatternError(
                "regex is too slow on adversarial input (possible catastrophic backtracking)"
            ) from exc
    return compiled


def search(pattern: str, text: str) -> bool:
    return compile_pattern(pattern).search(text, timeout=REGEX_TIMEOUT_SECONDS) is not None


def fullmatch(pattern: str, text: str) -> bool:
    return compile_pattern(pattern).fullmatch(text, timeout=REGEX_TIMEOUT_SECONDS) is not None
