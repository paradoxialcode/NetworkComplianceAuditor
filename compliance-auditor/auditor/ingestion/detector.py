"""
Vendor detection for raw configuration text.

Given the text of a device configuration, :func:`detect_vendor` decides which
supported dialect it is written in (``Vendor.CISCO_IOS`` or
``Vendor.FORTIOS``) so the ingestion pipeline can pick the matching
tokenizer, or reports that it cannot tell. It only DETECTS; tokenizing,
normalizing and everything after belong elsewhere.

How it decides:
    Each line is checked, in one pass, for a small set of named signals
    (for example ``cisco-hostname`` or ``forti-config-block``). A signal has
    a vendor, a weight and a hit cap, so a huge file cannot drown out
    stronger evidence. A vendor's score is the sum of ``weight * min(hits,
    cap)`` over its signals. The top vendor wins only if its score is at
    least ``MIN_SCORE`` AND at least ``MIN_RATIO`` times the runner-up's;
    otherwise the result is "unknown" (``vendor is None``). Confidence is the
    score's strength (saturating at ``STRONG_SCORE``) times how far it leads
    the runner-up.

Properties:
    - Deterministic and O(n) in the number of lines. Line order does not
      change any score (only which line is reported as a signal's first hit).
    - Line endings, a leading BOM and blank lines do not matter. Lines are
      split on ``\\n`` only, like the tokenizers, so line numbers agree.
    - The result never contains configuration text, only signal names, line
      numbers and counts, so detection cannot leak a secret.
    - Cisco signals count only at column 0 (IOS puts global commands there);
      FortiOS signals ignore indentation because exports are sometimes
      flattened.

Known limitations:
    - It is a heuristic: a very short snippet (for example just
      ``hostname R1``) is "unknown", and a file that mixes both dialects
      with similar weight is "unknown".
    - Only Cisco IOS-style and FortiOS dialects are recognized. Other
      vendors that resemble IOS (some Arista or Huawei configs) can be
      detected as Cisco IOS.
    - The whole text is scanned; callers with untrusted input should bound
      its size first.

Example:
    >>> detection = detect_vendor("hostname R1\\n!\\ninterface Gi0/0\\n shutdown\\n")
    >>> detection.vendor
    <Vendor.CISCO_IOS: 'cisco_ios'>
    >>> [signal.name for signal in detection.signals]
    ['cisco-hostname', 'cisco-bang', 'cisco-interface']
    >>> detect_vendor("hostname R1\\n").vendor is None
    True
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from auditor.parsers.normalizer import Vendor

__all__ = [
    "MIN_SCORE",
    "MIN_RATIO",
    "STRONG_SCORE",
    "Signal",
    "Detection",
    "detect_vendor",
]

MIN_SCORE = 6
MIN_RATIO = 2
STRONG_SCORE = 12


@dataclass(frozen=True, slots=True)
class _SignalRule:
    vendor: Vendor
    weight: int
    max_hits: int


_RULES: dict[str, _SignalRule] = {
    # FortiOS (indentation-agnostic, except the header)
    "forti-config-version-header": _SignalRule(Vendor.FORTIOS, 10, 1),
    "forti-system-global": _SignalRule(Vendor.FORTIOS, 6, 1),
    "forti-config-block": _SignalRule(Vendor.FORTIOS, 2, 3),
    "forti-edit": _SignalRule(Vendor.FORTIOS, 2, 2),
    "forti-next": _SignalRule(Vendor.FORTIOS, 2, 2),
    "forti-set": _SignalRule(Vendor.FORTIOS, 1, 3),
    # Cisco IOS (column 0 only)
    "cisco-building-configuration": _SignalRule(Vendor.CISCO_IOS, 8, 1),
    "cisco-current-configuration": _SignalRule(Vendor.CISCO_IOS, 8, 1),
    "cisco-version": _SignalRule(Vendor.CISCO_IOS, 4, 1),
    "cisco-hostname": _SignalRule(Vendor.CISCO_IOS, 3, 1),
    "cisco-interface": _SignalRule(Vendor.CISCO_IOS, 2, 3),
    "cisco-line": _SignalRule(Vendor.CISCO_IOS, 4, 1),
    "cisco-service": _SignalRule(Vendor.CISCO_IOS, 3, 1),
    "cisco-router": _SignalRule(Vendor.CISCO_IOS, 2, 2),
    "cisco-enable": _SignalRule(Vendor.CISCO_IOS, 3, 1),
    "cisco-ip-command": _SignalRule(Vendor.CISCO_IOS, 2, 2),
    "cisco-global-command": _SignalRule(Vendor.CISCO_IOS, 1, 3),
    "cisco-bang": _SignalRule(Vendor.CISCO_IOS, 1, 3),
}

_VERSION = re.compile(r"\d+(?:\.\d+)+")
_CISCO_LINES = frozenset({"vty", "con", "aux"})
_CISCO_SERVICES = frozenset(
    {"timestamps", "password-encryption", "call-home", "sequence-numbers",
     "tcp-keepalives-in", "tcp-keepalives-out"}
)
_CISCO_ROUTERS = frozenset({"ospf", "bgp", "eigrp", "rip", "isis"})
_CISCO_ENABLE = frozenset({"secret", "password"})
_CISCO_IP = frozenset({"route", "routing", "domain-name", "name-server", "http", "ssh", "access-list"})
_CISCO_GLOBAL = frozenset({"ntp", "logging", "snmp-server", "aaa", "username", "banner", "clock", "archive"})


def _signals_for(raw: str, stripped: str) -> list[str]:
    """Names of the signals one non-blank line produces."""

    names: list[str] = []
    top_level = not raw[0].isspace()

    if top_level:
        if stripped.startswith("#config-version="):
            names.append("forti-config-version-header")
        elif stripped[0] == "!":
            names.append("cisco-bang")

    words = stripped.split()
    head = words[0]
    count = len(words)

    # FortiOS structure, regardless of indentation.
    if head == "config" and count >= 2:
        names.append("forti-config-block")
        if count == 3 and words[1] == "system" and words[2] == "global":
            names.append("forti-system-global")
    elif head == "edit" and count == 2:
        names.append("forti-edit")
    elif head == "next" and count == 1:
        names.append("forti-next")
    elif head == "set" and count >= 3:
        names.append("forti-set")

    if not top_level:
        return names

    # Cisco IOS global commands live at column 0.
    lowered = stripped.lower()
    if lowered.startswith("building configuration"):
        names.append("cisco-building-configuration")
    elif lowered.startswith("current configuration"):
        names.append("cisco-current-configuration")
    elif head == "version" and count == 2 and _VERSION.match(words[1]):
        names.append("cisco-version")
    elif head == "hostname" and count == 2:
        names.append("cisco-hostname")
    elif head == "interface" and count >= 2:
        names.append("cisco-interface")
    elif head == "line" and count >= 2 and words[1] in _CISCO_LINES:
        names.append("cisco-line")
    elif head == "service" and count >= 2 and words[1] in _CISCO_SERVICES:
        names.append("cisco-service")
    elif head == "router" and count >= 2 and words[1] in _CISCO_ROUTERS:
        names.append("cisco-router")
    elif head == "enable" and count >= 2 and words[1] in _CISCO_ENABLE:
        names.append("cisco-enable")
    elif head == "ip" and count >= 2 and words[1] in _CISCO_IP:
        names.append("cisco-ip-command")
    elif head in _CISCO_GLOBAL:
        names.append("cisco-global-command")

    return names


@dataclass(frozen=True, slots=True)
class Signal:
    """One piece of evidence for a vendor.

    Attributes:
        vendor: Vendor the signal supports.
        name: Signal name (never configuration text).
        line_number: First line (1-based) where the signal was seen.
        hits: How many lines produced the signal.
        points: Score contributed, ``weight * min(hits, cap)``.
    """

    vendor: Vendor
    name: str
    line_number: int
    hits: int
    points: int


@dataclass(frozen=True, slots=True)
class Detection:
    """Result of :func:`detect_vendor`.

    Attributes:
        vendor: The detected vendor, or None when unknown or ambiguous.
        confidence: 0.0-1.0; exactly 0.0 when ``vendor`` is None.
        scores: ``(vendor, score)`` for every supported vendor, in
            ``Vendor`` order.
        signals: Evidence found, ordered by first line then name.

    The invariants (one score per vendor, scores equal the sum of signal
    points, the decision thresholds, confidence 0.0 for unknown) are checked
    on construction.
    """

    vendor: Vendor | None
    confidence: float
    scores: tuple[tuple[Vendor, int], ...]
    signals: tuple[Signal, ...]

    def __post_init__(self) -> None:
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
            raise TypeError("confidence must be a number")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        if self.vendor is not None and not isinstance(self.vendor, Vendor):
            raise TypeError("vendor must be a Vendor or None")
        if tuple(vendor for vendor, _ in self.scores) != tuple(Vendor):
            raise ValueError("scores must contain exactly one entry per Vendor, in Vendor order")
        if any(isinstance(score, bool) or not isinstance(score, int) or score < 0 for _, score in self.scores):
            raise ValueError("scores must be non-negative integers")
        if not all(isinstance(signal, Signal) for signal in self.signals):
            raise TypeError("signals must contain only Signal")

        totals = {vendor: 0 for vendor in Vendor}
        for signal in self.signals:
            totals[signal.vendor] += signal.points
        if any(totals[vendor] != score for vendor, score in self.scores):
            raise ValueError("scores must equal the sum of signal points per vendor")

        if self.vendor is None:
            if self.confidence != 0.0:
                raise ValueError("confidence must be 0.0 when vendor is None")
        else:
            top = self.score_of(self.vendor)
            others = max((s for v, s in self.scores if v is not self.vendor), default=0)
            if top < MIN_SCORE or top < MIN_RATIO * others:
                raise ValueError("vendor does not satisfy the detection thresholds")

    def score_of(self, vendor: Vendor) -> int:
        """Score of ``vendor``."""

        for candidate, score in self.scores:
            if candidate is vendor:
                return score
        raise ValueError("unsupported vendor")


def _split_lines(content: str) -> list[str]:
    """Strip a BOM, normalize line endings, split on "\\n" only."""

    if content.startswith("\ufeff"):
        content = content[1:]
    return content.replace("\r\n", "\n").replace("\r", "\n").split("\n")


def detect_vendor(content: str) -> Detection:
    """Detect which supported dialect ``content`` is written in.

    Args:
        content: Full configuration text.

    Returns:
        A Detection. ``vendor`` is None when the evidence is too weak or the
        two dialects are too close to call.

    Raises:
        TypeError: If ``content`` is not a str.
    """

    if not isinstance(content, str):
        raise TypeError(f"content must be a str, got {type(content).__name__}")

    hits: dict[str, int] = {}
    first_line: dict[str, int] = {}
    for line_number, raw in enumerate(_split_lines(content), start=1):
        stripped = raw.strip()
        if not stripped:
            continue
        for name in _signals_for(raw, stripped):
            if name not in hits:
                first_line[name] = line_number
                hits[name] = 1
            else:
                hits[name] += 1

    signals = sorted(
        (
            Signal(
                vendor=_RULES[name].vendor,
                name=name,
                line_number=first_line[name],
                hits=count,
                points=_RULES[name].weight * min(count, _RULES[name].max_hits),
            )
            for name, count in hits.items()
        ),
        key=lambda signal: (signal.line_number, signal.name),
    )

    totals = {vendor: 0 for vendor in Vendor}
    for signal in signals:
        totals[signal.vendor] += signal.points
    scores = tuple((vendor, totals[vendor]) for vendor in Vendor)

    top_vendor = max(Vendor, key=lambda vendor: totals[vendor])
    top = totals[top_vendor]
    runner_up = max((score for vendor, score in totals.items() if vendor is not top_vendor), default=0)

    if top >= MIN_SCORE and top >= MIN_RATIO * runner_up:
        confidence = round(min(1.0, top / STRONG_SCORE) * (top - runner_up) / top, 4)
        return Detection(top_vendor, confidence, scores, tuple(signals))
    return Detection(None, 0.0, scores, tuple(signals))


if __name__ == "__main__":
    import doctest

    doctest.testmod()