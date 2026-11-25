from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from auditor.ingestion.detector import MIN_RATIO, MIN_SCORE, detect_vendor
from auditor.parsers.normalizer import Vendor

__all__ = ["JunosDetection", "JunosSignal", "detect_junos", "detect_vendor_with_junos"]

_JUNOS_VERSION: Final = re.compile(r"\d+\.\d+[A-Z]\d")
_SET_TOP: Final = frozenset(
    {
        "system",
        "interfaces",
        "routing-options",
        "protocols",
        "policy-options",
        "chassis",
        "routing-instances",
        "snmp",
        "vlans",
        "forwarding-options",
        "class-of-service",
        "event-options",
    }
)
_SECURITY_SECOND: Final = frozenset(
    {"zones", "policies", "nat", "screen", "ike", "ipsec", "flow", "log", "address-book", "utm", "alg", "idp"}
)
_BRACE_TOP: Final = _SET_TOP | frozenset({"security", "firewall", "services", "applications", "groups", "access"})

_RULES: Final[dict[str, tuple[int, int]]] = {
    "junos-commit-header": (5, 1),
    "junos-version": (6, 1),
    "junos-host-name": (4, 1),
    "junos-set-hierarchy": (2, 4),
    "junos-brace-block": (3, 3),
}


@dataclass(frozen=True, slots=True)
class JunosSignal:
    name: str
    line_number: int
    hits: int
    points: int


@dataclass(frozen=True, slots=True)
class JunosDetection:
    score: int
    signals: tuple[JunosSignal, ...]


def _line_signals(raw: str, stripped: str) -> list[str]:
    words = stripped.split()
    head, count = words[0], len(words)
    top_level = not raw[0].isspace()
    names: list[str] = []
    if top_level and stripped.startswith(("## Last commit:", "## Last changed:")):
        names.append("junos-commit-header")
    if head == "set" and count >= 3:
        second = words[1]
        if second == "version":
            if count == 3 and _JUNOS_VERSION.match(words[2]):
                names.append("junos-version")
        elif second in _SET_TOP or (second == "security" and words[2] in _SECURITY_SECOND):
            names.append("junos-set-hierarchy")
            if second == "system" and words[2] == "host-name" and count == 4:
                names.append("junos-host-name")
    elif top_level and head == "version" and count == 2 and words[1].endswith(";") and _JUNOS_VERSION.match(words[1]):
        names.append("junos-version")
    elif top_level and count == 2 and words[1] == "{" and head in _BRACE_TOP:
        names.append("junos-brace-block")
    elif head == "host-name" and count == 2 and words[1].endswith(";"):
        names.append("junos-host-name")
    return names


def detect_junos(content: str) -> JunosDetection:
    if not isinstance(content, str):
        raise TypeError(f"content must be a str, got {type(content).__name__}")
    if content.startswith("\ufeff"):
        content = content[1:]
    hits: dict[str, int] = {}
    first: dict[str, int] = {}
    for number, raw in enumerate(content.replace("\r\n", "\n").replace("\r", "\n").split("\n"), start=1):
        stripped = raw.strip()
        if not stripped:
            continue
        for name in _line_signals(raw, stripped):
            if name not in hits:
                hits[name] = 0
                first[name] = number
            hits[name] += 1
    signals = tuple(
        sorted(
            (
                JunosSignal(name, first[name], count, _RULES[name][0] * min(count, _RULES[name][1]))
                for name, count in hits.items()
            ),
            key=lambda signal: (signal.line_number, signal.name),
        )
    )
    return JunosDetection(score=sum(signal.points for signal in signals), signals=signals)


def detect_vendor_with_junos(content: str) -> Vendor | None:
    base = detect_vendor(content)
    junos = detect_junos(content)
    best_builtin = max((score for _, score in base.scores), default=0)
    if junos.score >= MIN_SCORE and junos.score >= MIN_RATIO * best_builtin:
        return Vendor.JUNOS
    return base.vendor
