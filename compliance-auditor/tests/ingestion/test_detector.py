"""Tests for auditor.ingestion.detector."""

from __future__ import annotations

import dataclasses
import random
import time
from typing import Any

import pytest

from auditor.ingestion import detector as det
from auditor.ingestion.detector import (
    MIN_RATIO,
    MIN_SCORE,
    STRONG_SCORE,
    Detection,
    Signal,
    detect_vendor,
)
from auditor.parsers.normalizer import Vendor, normalize
from auditor.parsers.tokenizers.fortinet import tokenize_fortinet
from auditor.parsers.tokenizers.indented import tokenize_indented

CISCO, FORTI = Vendor.CISCO_IOS, Vendor.FORTIOS

CISCO_CFG = """\
hostname EDGE-R1
!
service password-encryption
!
username admin privilege 15 secret 9 $9$abcdef
username ops password 7 0822455D0A16
!
ntp server 10.0.0.1 prefer
ntp server vrf MGMT 10.0.0.2
!
logging host 10.0.1.1
logging 10.0.1.2
logging buffered 8192
!
no ip http server
!
interface GigabitEthernet0/0
 description uplink to core
 ip address 10.0.0.2 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/1
 shutdown
!
line vty 0 4
 transport input ssh
line vty 5 15
 transport input telnet ssh
"""

FORTI_CFG = r'''#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0:user=admin
config system global
    set hostname "FW-HQ-01"
end
config system ntp
    config ntpserver
        edit 1
            set server "pool.ntp.org"
        next
        edit 2
            set server "10.0.0.5"
        next
    end
end
config log syslogd setting
    set status enable
    set server "10.0.1.9"
end
config log syslogd2 setting
    set server "10.0.1.10"
end
config system admin
    edit "admin"
        set password ENC SH2abc==
    next
    edit "auditor"
    next
end
config system interface
    edit "port1"
        set description "wan uplink"
        set status up
        set allowaccess ping https ssh
    next
    edit "port2"
        set status down
        set allowaccess ping http telnet
        append allowaccess snmp
    next
end
'''

KITCHEN_SINK = """\
#config-version=FGT60F-7.2.5-FW
Building configuration...
Current configuration : 100 bytes
version 15.2
hostname R1
!
service timestamps log datetime
enable secret 5 x
ip route 0.0.0.0 0.0.0.0 10.0.0.1
router ospf 1
interface Gi0/0
line vty 0 4
ntp server 1.1.1.1
config system global
edit 1
set a b c
next
"""


def names(raw: str) -> list[str]:
    return det._signals_for(raw, raw.strip())


def signal_view(d: Detection) -> list[tuple[str, int, int, int]]:
    return [(s.name, s.line_number, s.hits, s.points) for s in d.signals]


# ================================================================ fixtures ====
def test_cisco_fixture() -> None:
    d = detect_vendor(CISCO_CFG)
    assert d.vendor is CISCO
    assert d.confidence == 1.0
    assert d.scores == ((CISCO, 20), (FORTI, 0))
    assert signal_view(d) == [
        ("cisco-hostname", 1, 1, 3),
        ("cisco-bang", 2, 8, 3),
        ("cisco-service", 3, 1, 3),
        ("cisco-global-command", 5, 7, 3),
        ("cisco-interface", 17, 2, 4),
        ("cisco-line", 25, 2, 4),
    ]


def test_forti_fixture() -> None:
    d = detect_vendor(FORTI_CFG)
    assert d.vendor is FORTI
    assert d.confidence == 1.0
    assert d.scores == ((CISCO, 0), (FORTI, 33))
    assert signal_view(d) == [
        ("forti-config-version-header", 1, 1, 10),
        ("forti-config-block", 2, 7, 6),
        ("forti-system-global", 2, 1, 6),
        ("forti-set", 3, 12, 3),
        ("forti-edit", 7, 6, 4),
        ("forti-next", 9, 6, 4),
    ]
    assert d.score_of(FORTI) == 33 and d.score_of(CISCO) == 0


def test_detection_then_tokenize_and_normalize_end_to_end() -> None:
    cisco = detect_vendor(CISCO_CFG).vendor
    forti = detect_vendor(FORTI_CFG).vendor
    assert cisco is CISCO and forti is FORTI
    assert normalize(tokenize_indented(CISCO_CFG), cisco).hostname is not None
    assert normalize(tokenize_fortinet(FORTI_CFG), forti).hostname is not None


# ======================================================= decisions and scores ====
@pytest.mark.parametrize(
    ("config", "vendor", "score", "confidence"),
    [
        ("#config-version=FGT60F-7.2.5-FW-build1517:opmode=0\n", FORTI, 10, 0.8333),
        ("Building configuration...\n\nCurrent configuration : 1234 bytes\n", CISCO, 16, 1.0),
        ("building configuration...\n", CISCO, 8, 0.6667),
        ("hostname R1\n!\ninterface Gi0/0\n shutdown\n", CISCO, 6, 0.5),
        ('config system global\n    set hostname "FW"\nend\n', FORTI, 9, 0.75),
    ],
)
def test_minimal_evidence_cases(config: str, vendor: Vendor, score: int, confidence: float) -> None:
    d = detect_vendor(config)
    assert d.vendor is vendor
    assert d.score_of(vendor) == score
    assert d.confidence == confidence


@pytest.mark.parametrize(
    "config",
    ["", "   \n\n\t\n", "hostname R1\n", "! just a comment\n", "hello world\n", "# a comment\n", "version 15.2\n"],
)
def test_unknown_when_evidence_is_weak(config: str) -> None:
    d = detect_vendor(config)
    assert d.vendor is None
    assert d.confidence == 0.0
    assert max(score for _, score in d.scores) < MIN_SCORE


def test_mixed_dialects_are_unknown() -> None:
    d = detect_vendor(CISCO_CFG + FORTI_CFG)
    assert d.scores == ((CISCO, 20), (FORTI, 33))
    assert d.vendor is None and d.confidence == 0.0
    assert 33 < MIN_RATIO * 20


def test_dominant_dialect_wins_over_a_little_noise() -> None:
    d = detect_vendor(CISCO_CFG + 'config system global\nset hostname x\nend\n')
    assert d.vendor is CISCO
    assert d.score_of(FORTI) == 9
    assert d.confidence == round(1.0 * (20 - 9) / 20, 4)


def test_threshold_boundaries() -> None:
    assert MIN_SCORE == 6 and MIN_RATIO == 2 and STRONG_SCORE == 12
    exactly_min = detect_vendor("hostname R1\n!\ninterface Gi0/0\n")
    assert exactly_min.score_of(CISCO) == MIN_SCORE and exactly_min.vendor is CISCO
    below = detect_vendor("hostname R1\ninterface Gi0/0\n")
    assert below.score_of(CISCO) == 5 and below.vendor is None


def test_ratio_boundary_is_inclusive() -> None:
    # 12 vs 6 is exactly MIN_RATIO times the runner-up, which is still decisive.
    signals = (
        Signal(CISCO, "cisco-building-configuration", 1, 1, 8),
        Signal(CISCO, "cisco-hostname", 2, 1, 3),
        Signal(CISCO, "cisco-bang", 3, 1, 1),
        Signal(FORTI, "forti-system-global", 4, 1, 6),
    )
    tied = Detection(CISCO, 0.5, ((CISCO, 12), (FORTI, 6)), signals)
    assert tied.vendor is CISCO
    just_below = (signals[0], signals[1], signals[3])  # cisco 11 vs forti 6
    with pytest.raises(ValueError, match="detection thresholds"):
        Detection(CISCO, 0.5, ((CISCO, 11), (FORTI, 6)), just_below)


def test_just_below_the_ratio_is_unknown() -> None:
    # cisco 12 (building 8 + hostname 3 + bang 1) vs forti 8 (config block 2 + global 6)
    d = detect_vendor("Building configuration...\nhostname R1\n!\nconfig system global\n")
    assert d.scores == ((CISCO, 12), (FORTI, 8))
    assert d.vendor is None


# ================================================================ line rules ====
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("hostname R1", ["cisco-hostname"]),
        (" hostname R1", []),
        ("hostname", []),
        ("hostname a b", []),
        ("version 15.2(4)M", ["cisco-version"]),
        ("version 7", []),
        ("version abc", []),
        ("interface Gi0/0", ["cisco-interface"]),
        (" interface Gi0/0", []),
        ("interface", []),
        ("line vty 0 4", ["cisco-line"]),
        ("line con 0", ["cisco-line"]),
        ("line x 0", []),
        ("line", []),
        ("service timestamps log datetime", ["cisco-service"]),
        ("service foo", []),
        ("router bgp 65000", ["cisco-router"]),
        ("router foo", []),
        ("enable secret 9 x", ["cisco-enable"]),
        ("enable foo", []),
        ("ip route 0.0.0.0 0.0.0.0 1.1.1.1", ["cisco-ip-command"]),
        ("ip foo", []),
        ("ntp server 1.1.1.1", ["cisco-global-command"]),
        ("username a secret 5 x", ["cisco-global-command"]),
        (" ntp server 1.1.1.1", []),
        ("!", ["cisco-bang"]),
        ("! comment", ["cisco-bang"]),
        (" !", []),
        ("Building configuration...", ["cisco-building-configuration"]),
        ("BUILDING CONFIGURATION", ["cisco-building-configuration"]),
        ("Current configuration : 5 bytes", ["cisco-current-configuration"]),
        (" Current configuration", []),
        ("#config-version=FGT", ["forti-config-version-header"]),
        (" #config-version=x", []),
        ("# config-version=x", []),
        ("config system global", ["forti-config-block", "forti-system-global"]),
        ("config firewall policy", ["forti-config-block"]),
        ("  config system interface", ["forti-config-block"]),
        ("config system global extra", ["forti-config-block"]),
        ("config", []),
        ("edit 1", ["forti-edit"]),
        ('  edit "port1"', ["forti-edit"]),
        ("edit", []),
        ("edit 1 2", []),
        ("next", ["forti-next"]),
        ("   next", ["forti-next"]),
        ("next x", []),
        ("set status up", ["forti-set"]),
        ("    set status up", ["forti-set"]),
        ("set status", []),
        ("set", []),
        ("end", []),
        ("random words here", []),
    ],
)
def test_signals_for_a_single_line(raw: str, expected: list[str]) -> None:
    assert names(raw) == expected


def test_every_rule_is_reachable_and_every_signal_is_known() -> None:
    produced = {name for line in KITCHEN_SINK.split("\n") if line.strip() for name in names(line)}
    assert produced == set(det._RULES)
    assert all(rule.weight > 0 and rule.max_hits > 0 for rule in det._RULES.values())
    assert {rule.vendor for rule in det._RULES.values()} == set(Vendor)
    for name, rule in det._RULES.items():
        assert name.startswith("cisco-" if rule.vendor is CISCO else "forti-")


# ============================================================ input handling ====
def test_line_endings_bom_and_blank_lines() -> None:
    base = detect_vendor(CISCO_CFG)
    assert detect_vendor(CISCO_CFG.replace("\n", "\r\n")) == base
    assert detect_vendor(CISCO_CFG.replace("\n", "\r")) == base
    assert detect_vendor("\ufeff" + CISCO_CFG) == base
    spaced = detect_vendor("\n\n   \n".join(CISCO_CFG.split("\n")))
    assert [(v, s) for v, s in spaced.scores] == list(base.scores)
    assert spaced.vendor is base.vendor


@pytest.mark.parametrize("char", ["\x0b", "\x0c", "\x1c", "\x85", "\u2028", "\u2029"])
def test_unusual_separators_do_not_split_lines_or_shift_line_numbers(char: str) -> None:
    # The odd character sits BEFORE the checked lines; splitlines() would add
    # a line and push "interface" to line 4.
    d = detect_vendor(f"hostname R1{char}\n!\ninterface Gi0/0\n shutdown\n")
    assert d.vendor is CISCO
    first_lines = {s.name: s.line_number for s in d.signals}
    assert first_lines == {"cisco-hostname": 1, "cisco-bang": 2, "cisco-interface": 3}


@pytest.mark.parametrize("style", ["none", "tabs", "mixed"])
def test_forti_ignores_indentation_but_cisco_needs_column_zero(style: str) -> None:
    rng = random.Random(5)

    def reindent(line: str) -> str:
        body = line.lstrip()
        if style == "none":
            return body
        if style == "tabs":
            return "\t" * rng.randint(0, 3) + body
        return "".join(rng.choice(" \t") for _ in range(rng.randint(0, 6))) + body

    forti = detect_vendor("\n".join(reindent(line) for line in FORTI_CFG.split("\n")))
    assert forti.vendor is FORTI
    # Only the column-0 header can be lost to indentation (10 points).
    assert forti.score_of(FORTI) in (33, 23)
    assert forti.score_of(CISCO) == 0

    indented_cisco = detect_vendor("\n".join(" " + line for line in CISCO_CFG.split("\n")))
    assert indented_cisco.vendor is None
    assert indented_cisco.score_of(CISCO) == 0


def test_hit_caps_stop_large_files_from_swamping_evidence() -> None:
    many_sets = detect_vendor("set a b c\n" * 1000)
    assert many_sets.score_of(FORTI) == 3 and many_sets.vendor is None
    assert signal_view(many_sets) == [("forti-set", 1, 1000, 3)]
    many_interfaces = detect_vendor("interface Gi0/0\n" * 1000)
    assert many_interfaces.score_of(CISCO) == 6 and many_interfaces.vendor is CISCO


def test_non_str_input() -> None:
    for bad in (None, b"hostname R1", 5, ["hostname R1"]):
        with pytest.raises(TypeError, match="content must be a str"):
            detect_vendor(bad)  # type: ignore[arg-type]


def test_detection_never_contains_configuration_text() -> None:
    d = detect_vendor(CISCO_CFG + "username x secret hunter2\n")
    assert "hunter2" not in repr(d) and "abcdef" not in repr(d)
    assert all(isinstance(s.name, str) and s.name.startswith(("cisco-", "forti-")) for s in d.signals)


# ============================================================ model validation ====
def good() -> Detection:
    return detect_vendor(CISCO_CFG)


@pytest.mark.parametrize(
    ("overrides", "exc", "message"),
    [
        ({"confidence": 1.5}, ValueError, "confidence must be between"),
        ({"confidence": -0.1}, ValueError, "confidence must be between"),
        ({"confidence": True}, TypeError, "confidence must be a number"),
        ({"confidence": "1"}, TypeError, "confidence must be a number"),
        ({"vendor": "cisco_ios"}, TypeError, "vendor must be a Vendor or None"),
        ({"vendor": None}, ValueError, "confidence must be 0.0 when vendor is None"),
        ({"scores": ((FORTI, 0), (CISCO, 20))}, ValueError, "one entry per Vendor, in Vendor order"),
        ({"scores": ((CISCO, 20),)}, ValueError, "one entry per Vendor"),
        ({"scores": ((CISCO, -1), (FORTI, 0))}, ValueError, "non-negative integers"),
        ({"scores": ((CISCO, 20.0), (FORTI, 0))}, ValueError, "non-negative integers"),
        ({"scores": ((CISCO, 21), (FORTI, 0))}, ValueError, "sum of signal points"),
        ({"signals": ("cisco-hostname",)}, TypeError, "signals must contain only Signal"),
        ({"vendor": FORTI}, ValueError, "does not satisfy the detection thresholds"),
    ],
)
def test_detection_validates_its_invariants(overrides: dict[str, Any], exc: type[Exception], message: str) -> None:
    with pytest.raises(exc, match=message):
        dataclasses.replace(good(), **overrides)


def test_detection_threshold_invariants() -> None:
    weak = Signal(CISCO, "cisco-hostname", 1, 1, 3)
    with pytest.raises(ValueError, match="detection thresholds"):
        Detection(CISCO, 0.5, ((CISCO, 3), (FORTI, 0)), (weak,))
    contested = (
        Signal(CISCO, "cisco-building-configuration", 1, 1, 8),
        Signal(FORTI, "forti-system-global", 2, 1, 6),
    )
    with pytest.raises(ValueError, match="detection thresholds"):
        Detection(CISCO, 0.5, ((CISCO, 8), (FORTI, 6)), contested)
    assert Detection(None, 0.0, ((CISCO, 8), (FORTI, 6)), contested).vendor is None


def test_score_of_rejects_unsupported_vendors() -> None:
    with pytest.raises(ValueError, match="unsupported vendor"):
        good().score_of("junos")  # type: ignore[arg-type]


def test_models_are_frozen_slotted_and_hashable() -> None:
    d = good()
    with pytest.raises(dataclasses.FrozenInstanceError):
        d.vendor = None  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        d.signals[0].points = 1  # type: ignore[misc]
    assert not hasattr(d, "__dict__") and not hasattr(d.signals[0], "__dict__")
    assert {d, good()} == {d}
    assert d == good() and d != detect_vendor(FORTI_CFG)


def test_module_scope() -> None:
    assert set(det.__all__) == {"MIN_SCORE", "MIN_RATIO", "STRONG_SCORE", "Signal", "Detection", "detect_vendor"}


# =============================================================== properties ====
POOL = [
    "hostname R1", "!", "! note", "interface Gi0/0", " shutdown", "line vty 0 4", "service timestamps log datetime",
    "ntp server 1.1.1.1", "ip route 0.0.0.0 0.0.0.0 1.1.1.1", "router ospf 1", "enable secret 5 x", "version 15.2",
    "Building configuration...", "#config-version=FGT60F-7.2.5", "config system global", "config firewall policy",
    "    edit 1", "edit \"p\"", "next", "    next", "    set a b c", "set status up", "end", "", "   ", "# note",
    "random words", "username a secret 5 x", " hostname R2",
]


def test_fuzz_invariants_and_order_independence() -> None:
    rng = random.Random(7531)
    decided = {CISCO: 0, FORTI: 0, None: 0}
    for _ in range(1500):
        lines = [rng.choice(POOL) for _ in range(rng.randint(0, 40))]
        d = detect_vendor("\n".join(lines))
        decided[d.vendor] += 1
        assert 0.0 <= d.confidence <= 1.0
        assert (d.vendor is None) == (d.confidence == 0.0)
        shuffled = lines[:]
        rng.shuffle(shuffled)
        e = detect_vendor("\n".join(shuffled))
        assert (e.vendor, e.confidence, e.scores) == (d.vendor, d.confidence, d.scores)
        assert sorted((s.name, s.hits, s.points) for s in e.signals) == sorted((s.name, s.hits, s.points) for s in d.signals)
        padded = detect_vendor("\n".join(lines) + "\n\n# note\n   \n")
        assert (padded.vendor, padded.scores) == (d.vendor, d.scores)
    assert all(count > 20 for count in decided.values())  # every outcome was exercised


# ============================================================ performance ====
# Regression guard against accidental O(n^2) behaviour, NOT a benchmark.
def test_large_input_is_fast() -> None:
    content = (CISCO_CFG + FORTI_CFG) * 6000  # ~300k lines
    start = time.perf_counter()
    d = detect_vendor(content)
    assert time.perf_counter() - start < 10
    assert d.vendor is None  # both dialects present with similar weight
    assert detect_vendor(CISCO_CFG * 10000).vendor is CISCO