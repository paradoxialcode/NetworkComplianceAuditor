"""Tests for auditor.parsers.normalizer."""

from __future__ import annotations

import dataclasses
import random
import re
import time
from typing import Any, TypeVar

import pytest

from auditor.parsers import normalizer as norm
from auditor.parsers.normalizer import (
    BUILTIN_VENDORS,
    REDACTED,
    Evidence,
    Fact,
    InterfaceBaseline,
    NormalizationWarning,
    SecurityBaseline,
    Vendor,
    normalize,
)
from auditor.parsers.tokenizers.fortinet import tokenize_fortinet
from auditor.parsers.tokenizers.indented import tokenize_indented

T = TypeVar("T")


# ---------------------------------------------------------------- helpers ----
def cis(text: str, source_file: str | None = None) -> SecurityBaseline:
    return normalize(tokenize_indented(text, source_file=source_file), Vendor.CISCO_IOS)


def fgt(text: str, source_file: str | None = None) -> SecurityBaseline:
    return normalize(tokenize_fortinet(text, source_file=source_file), Vendor.FORTIOS)


def pair(fact: Fact[T] | None) -> tuple[T, int] | None:
    return None if fact is None else (fact.value, fact.evidence.line_number)


def pairs(facts: tuple[Fact[T], ...]) -> list[tuple[T, int]]:
    return [(f.value, f.evidence.line_number) for f in facts]


def ifaces(
    b: SecurityBaseline,
) -> list[tuple[str, int, tuple[str, int] | None, tuple[bool, int] | None]]:
    return [
        (i.name.value, i.name.evidence.line_number, pair(i.description), pair(i.admin_down))
        for i in b.interfaces
    ]


def messages(b: SecurityBaseline) -> list[tuple[str, int]]:
    return [(w.message, w.line_number) for w in b.warnings]


def all_facts(b: SecurityBaseline) -> list[Fact[Any]]:
    facts: list[Fact[Any]] = [*b.ntp_servers, *b.syslog_servers, *b.local_users]
    for single in (b.hostname, b.telnet_enabled, b.http_management_enabled, b.password_encryption):
        if single is not None:
            facts.append(single)
    for interface in b.interfaces:
        facts.append(interface.name)
        for optional in (interface.description, interface.admin_down):
            if optional is not None:
                facts.append(optional)
    return facts


def assert_baseline_invariants(b: SecurityBaseline, total_lines: int) -> None:
    for fact in all_facts(b):
        evidence = fact.evidence
        assert 1 <= evidence.line_number <= evidence.end_line_number <= total_lines
    for unique in (b.ntp_servers, b.syslog_servers, b.local_users):
        values = [f.value for f in unique]
        assert len(values) == len(set(values))
    names = [i.name.value for i in b.interfaces]
    assert len(names) == len(set(names))
    for warning in b.warnings:
        assert 1 <= warning.line_number <= total_lines


# --------------------------------------------------------------- fixtures ----
CISCO = """\
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

FORTI = r'''#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0:user=admin
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


# ================================================================== CISCO ====
def test_cisco_fixture() -> None:
    b = cis(CISCO, source_file="r1.cfg")
    assert b.vendor is Vendor.CISCO_IOS
    assert b.source_file == "r1.cfg"
    assert b.hostname == Fact("EDGE-R1", Evidence("r1.cfg", 1, 1, "hostname EDGE-R1"))
    assert pairs(b.ntp_servers) == [("10.0.0.1", 8), ("10.0.0.2", 9)]
    assert pairs(b.syslog_servers) == [("10.0.1.1", 11), ("10.0.1.2", 12)]
    assert pairs(b.local_users) == [("admin", 5), ("ops", 6)]
    assert pair(b.password_encryption) == (True, 3)
    assert pair(b.http_management_enabled) == (False, 15)
    assert pair(b.telnet_enabled) == (True, 28)
    assert ifaces(b) == [
        ("GigabitEthernet0/0", 17, ("uplink to core", 18), (False, 20)),
        ("GigabitEthernet0/1", 22, None, (True, 23)),
    ]
    assert b.warnings == ()
    assert_baseline_invariants(b, total_lines=28)


def test_cisco_evidence_details() -> None:
    b = cis(CISCO, source_file="r1.cfg")
    assert b.telnet_enabled is not None
    assert b.telnet_enabled.evidence == Evidence("r1.cfg", 28, 28, " transport input telnet ssh")
    admin, ops = b.local_users
    assert admin.evidence == Evidence(
        "r1.cfg", 5, 5, "username admin privilege 15 secret <redacted>", True
    )
    assert ops.evidence.raw == "username ops password <redacted>"
    assert ops.evidence.redacted is True
    assert "abcdef" not in repr(b)
    assert "0822455D0A16" not in repr(b)


def test_cisco_line_endings_do_not_change_the_baseline() -> None:
    assert cis(CISCO.replace("\n", "\r\n")) == cis(CISCO)
    assert cis(CISCO.replace("\n", "\r")) == cis(CISCO)


def test_cisco_ignores_indented_and_comment_lines() -> None:
    b = cis("interface Gi0/0\n hostname X\n ntp server 1.1.1.1\n! hostname Y\n")
    assert b.hostname is None
    assert b.ntp_servers == ()
    assert [i.name.value for i in b.interfaces] == ["Gi0/0"]


def test_cisco_hostname_redefinition() -> None:
    b = cis("hostname A\n!\nhostname B\n")
    assert pair(b.hostname) == ("B", 3)
    assert messages(b) == [
        ("hostname redefined at line 3; previous definition at line 1; last definition wins", 3)
    ]


def test_cisco_same_hostname_twice_is_not_a_warning() -> None:
    b = cis("hostname A\n!\nhostname A\n")
    assert pair(b.hostname) == ("A", 3)
    assert b.warnings == ()


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        ("ntp server 10.0.0.1", [("10.0.0.1", 1)]),
        ("ntp server 10.0.0.1 prefer key 5", [("10.0.0.1", 1)]),
        ("ntp server vrf MGMT 10.0.0.2", [("10.0.0.2", 1)]),
        ("ntp server", []),
        ("ntp server vrf MGMT", []),
        ("ntp peer 10.0.0.3", []),
        ("ntp authenticate", []),
        ("ntp server 10.0.0.1\nntp server 10.0.0.1", [("10.0.0.1", 1)]),
    ],
)
def test_cisco_ntp(config: str, expected: list[tuple[str, int]]) -> None:
    assert pairs(cis(config).ntp_servers) == expected


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        ("logging host 10.0.1.1", [("10.0.1.1", 1)]),
        ("logging host syslog.example.com", [("syslog.example.com", 1)]),
        ("logging host 10.0.1.1 transport udp port 514", [("10.0.1.1", 1)]),
        ("logging 10.0.1.2", [("10.0.1.2", 1)]),
        ("logging 2001:db8::1", [("2001:db8::1", 1)]),
        ("logging buffered 8192", []),
        ("logging console", []),
        ("logging host", []),
        ("logging", []),
    ],
)
def test_cisco_syslog(config: str, expected: list[tuple[str, int]]) -> None:
    assert pairs(cis(config).syslog_servers) == expected


def test_cisco_users() -> None:
    b = cis("username a secret 5 x\nusername b\nusername\nusername a password 0 y\n")
    assert pairs(b.local_users) == [("a", 1), ("b", 2)]


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        ("service password-encryption", (True, 1)),
        ("no service password-encryption", (False, 1)),
        ("service password-encryption\nno service password-encryption", (False, 2)),
        ("no service password-encryption\nservice password-encryption", (True, 2)),
        ("service timestamps log datetime", None),
        ("", None),
    ],
)
def test_cisco_password_encryption(config: str, expected: tuple[bool, int] | None) -> None:
    assert pair(cis(config).password_encryption) == expected


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        ("ip http server", (True, 1)),
        ("no ip http server", (False, 1)),
        ("ip http server\nno ip http server", (False, 2)),
        ("no ip http server\nip http server", (True, 2)),
        ("ip http secure-server", None),
        ("", None),
    ],
)
def test_cisco_http(config: str, expected: tuple[bool, int] | None) -> None:
    assert pair(cis(config).http_management_enabled) == expected


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        ("line vty 0 4\n transport input ssh", (False, 2)),
        ("line vty 0 4\n transport input telnet", (True, 2)),
        ("line vty 0 4\n transport input all", (True, 2)),
        ("line vty 0 4\n transport input none", (False, 2)),
        ("line vty 0 4\n transport input ssh telnet", (True, 2)),
        ("line vty 0 4\n login local", None),
        ("line vty 0 4\n transport input", None),
        ("line con 0\n transport input telnet", None),
        ("transport input telnet", None),
        ("", None),
        ("line vty 0 4\n transport input ssh\nline vty 5 15\n transport input telnet", (True, 4)),
        ("line vty 0 4\n transport input ssh\nline vty 5 15\n transport input none", (False, 2)),
    ],
)
def test_cisco_telnet(config: str, expected: tuple[bool, int] | None) -> None:
    assert pair(cis(config).telnet_enabled) == expected


def test_cisco_interface_repeated_blocks_merge() -> None:
    b = cis("interface Gi0/0\n description a\n!\ninterface Gi0/0\n shutdown\n")
    assert ifaces(b) == [("Gi0/0", 1, ("a", 2), (True, 5))]


def test_cisco_interface_last_statement_wins() -> None:
    b = cis("interface Gi0/0\n shutdown\n no shutdown\n description a\n description b\n")
    assert ifaces(b) == [("Gi0/0", 1, ("b", 5), (False, 3))]


def test_cisco_interface_edge_cases() -> None:
    assert ifaces(cis("interface Gi0/0\n description\n")) == [("Gi0/0", 1, ("", 2), None)]
    assert ifaces(cis("interface range Gi0/1 - 24\n")) == [("range Gi0/1 - 24", 1, None, None)]
    assert ifaces(cis("interface\n")) == []
    # a grandchild is not a direct child of the interface
    deep = cis("interface Gi0/0\n service-policy\n  description deep\n")
    assert ifaces(deep) == [("Gi0/0", 1, None, None)]


def test_cisco_description_with_secret_is_redacted() -> None:
    b = cis("interface Gi0/0\n description password is hunter2\n")
    description = b.interfaces[0].description
    assert description is not None
    assert description.evidence.redacted is True
    assert description.value == "password <redacted>"
    assert "hunter2" not in repr(b)


# ================================================================ FORTIOS ====
def test_forti_fixture() -> None:
    b = fgt(FORTI, source_file="fw.conf")
    assert b.vendor is Vendor.FORTIOS
    assert b.source_file == "fw.conf"
    assert b.hostname is not None
    assert b.hostname.value == "FW-HQ-01"
    assert b.hostname.evidence == Evidence("fw.conf", 3, 3, '    set hostname "FW-HQ-01"')
    assert pairs(b.ntp_servers) == [("pool.ntp.org", 8), ("10.0.0.5", 11)]
    assert pairs(b.syslog_servers) == [("10.0.1.9", 17)]
    assert pairs(b.local_users) == [("admin", 23), ("auditor", 26)]
    assert pair(b.telnet_enabled) == (True, 37)
    assert pair(b.http_management_enabled) == (True, 37)
    assert pair(b.password_encryption) == (True, 24)
    assert ifaces(b) == [
        ("port1", 30, ("wan uplink", 31), (False, 32)),
        ("port2", 35, None, (True, 36)),
    ]
    assert b.warnings == ()
    assert_baseline_invariants(b, total_lines=40)


def test_forti_line_endings_do_not_change_the_baseline() -> None:
    assert fgt(FORTI.replace("\n", "\r\n")) == fgt(FORTI)


def test_forti_global_and_vdom_scopes_are_ignored() -> None:
    in_global = fgt('config global\nconfig system global\nset hostname "G"\nend\nend\n')
    assert pair(in_global.hostname) == ("G", 3)

    in_vdom = fgt('config vdom\nedit root\nconfig system global\nset hostname "V"\nend\nnext\nend\n')
    assert pair(in_vdom.hostname) == ("V", 4)

    interfaces = fgt(
        "config global\nconfig system interface\nedit \"port1\"\n"
        "set allowaccess ping telnet\nnext\nend\nend\n"
    )
    assert [i.name.value for i in interfaces.interfaces] == ["port1"]
    assert pair(interfaces.telnet_enabled) == (True, 4)


def test_forti_hostname_in_wrong_block_is_ignored() -> None:
    assert fgt('config system snmp sysinfo\nset hostname "x"\nend\n').hostname is None


def test_forti_hostname_redefinition() -> None:
    b = fgt(
        'config system global\nset hostname "A"\nend\n'
        'config system global\nset hostname "B"\nend\n'
    )
    assert pair(b.hostname) == ("B", 5)
    assert messages(b) == [
        ("hostname redefined at line 5; previous definition at line 2; last definition wins", 5)
    ]


def test_forti_ntp_rules() -> None:
    config = (
        "config system ntp\n"
        "set server \"direct\"\n"  # wrong depth, ignored
        "config ntpserver\n"
        "edit 1\n"
        "set ntpv3 enable\n"  # no server key
        "next\n"
        "edit 2\n"
        "set server \"a.example\"\n"
        "next\n"
        "edit 3\n"
        "set server \"a.example\"\n"  # duplicate
        "next\n"
        "end\n"
        "end\n"
    )
    assert pairs(fgt(config).ntp_servers) == [("a.example", 8)]


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        ('config log syslogd setting\nset status enable\nset server "1.1.1.1"\nend', [("1.1.1.1", 3)]),
        ('config log syslogd setting\nset server "1.1.1.1"\nset status enable\nend', [("1.1.1.1", 2)]),
        ('config log syslogd setting\nset server "1.1.1.1"\nend', []),
        ('config log syslogd setting\nset status disable\nset server "1.1.1.1"\nend', []),
        (
            'config log syslogd setting\nset status enable\nset server "1.1.1.1"\nset status disable\nend',
            [],
        ),
        ('config log syslogd setting\nset status enable\nend', []),
        ('config log syslogd4 setting\nset status enable\nset server "4.4.4.4"\nend', [("4.4.4.4", 3)]),
        ('config log syslogd5 setting\nset status enable\nset server "5.5.5.5"\nend', []),
        (
            'config log syslogd setting\nset status enable\nset server "1.1.1.1"\nend\n'
            'config log syslogd2 setting\nset status enable\nset server "1.1.1.1"\nend',
            [("1.1.1.1", 3)],
        ),
    ],
)
def test_forti_syslog(config: str, expected: list[tuple[str, int]]) -> None:
    assert pairs(fgt(config).syslog_servers) == expected


@pytest.mark.parametrize(
    ("body", "telnet", "http"),
    [
        ("set allowaccess ping https ssh", (False, 3), (False, 3)),
        ("set allowaccess telnet", (True, 3), (False, 3)),
        ("set allowaccess http", (False, 3), (True, 3)),
        ("set allowaccess telnet\nset allowaccess ssh", (False, 4), (False, 4)),
        ("set allowaccess ssh\nappend allowaccess telnet", (True, 4), (False, 3)),
        ("set allowaccess telnet\nappend allowaccess http", (True, 3), (True, 4)),
        ("append allowaccess ssh", None, None),
        ("set status up", None, None),
    ],
)
def test_forti_allowaccess(
    body: str, telnet: tuple[bool, int] | None, http: tuple[bool, int] | None
) -> None:
    b = fgt(f'config system interface\nedit "p"\n{body}\nnext\nend\n')
    assert pair(b.telnet_enabled) == telnet
    assert pair(b.http_management_enabled) == http


def test_forti_allowaccess_any_interface_enabling_wins() -> None:
    config = (
        'config system interface\nedit "a"\nset allowaccess ssh\nnext\n'
        'edit "b"\nset allowaccess telnet\nnext\nend\n'
    )
    assert pair(fgt(config).telnet_enabled) == (True, 6)


def test_forti_unset_allowaccess_warns() -> None:
    b = fgt('config system interface\nedit "p"\nunset allowaccess\nnext\nend\n')
    assert b.telnet_enabled is None
    assert messages(b) == [
        (
            "'unset allowaccess' at line 3 is not interpreted; its effect on "
            "management access is unknown",
            3,
        )
    ]


def test_forti_interface_status_and_description() -> None:
    b = fgt(
        'config system interface\nedit "p"\nset status maybe\nset description ""\n'
        "set alias x\nnext\nedit \"q\"\nset status up\nset status down\nnext\nend\n"
    )
    assert ifaces(b) == [
        ("p", 2, ("", 4), None),
        ("q", 7, None, (True, 9)),
    ]


def test_forti_nested_config_inside_interface_is_not_an_interface_attribute() -> None:
    b = fgt(
        'config system interface\nedit "p"\nconfig ipv6\nset description "v6"\n'
        "set status down\nend\nnext\nend\n"
    )
    assert ifaces(b) == [("p", 2, None, None)]


def test_forti_users_only_from_system_admin() -> None:
    b = fgt(
        'config system admin\nedit "a"\nnext\nend\n'
        'config system interface\nedit "port1"\nnext\nend\n'
        'config user local\nedit "notadmin"\nnext\nend\n'
    )
    assert pairs(b.local_users) == [("a", 2)]


def test_forti_ignores_comments_and_unknown_keywords() -> None:
    b = fgt('# hostname "x"\nconfig system global\npurge\nset hostname "ok"\nend\n')
    assert pair(b.hostname) == ("ok", 4)
    assert b.warnings == ()


def test_forti_sensitive_evidence_is_redacted() -> None:
    tokens = tokenize_fortinet(
        'config system admin\nedit "a"\nset password ENC TOPSECRET\nnext\nend\n'
    )
    evidence = norm._forti_evidence(tokens[2])
    assert evidence.redacted is True
    assert evidence.raw == "set password <redacted>"
    assert "TOPSECRET" not in evidence.raw
    plain = norm._forti_evidence(tokens[1])
    assert plain.redacted is False
    assert plain.raw == 'edit "a"'


# ======================================================== redaction helpers ====
def test_redaction_helpers() -> None:
    words = ["username", "a", "secret", "9", "$x"]
    assert norm._has_secret(words, norm._CISCO_SENSITIVE_WORDS) is True
    assert norm._redacted_text(words, norm._CISCO_SENSITIVE_WORDS) == (
        "username a secret <redacted>"
    )
    assert norm._has_secret(["secret"], norm._CISCO_SENSITIVE_WORDS) is False
    assert norm._redacted_text(["set", "x", "y"], frozenset()) == "set <redacted>"
    assert norm._redacted_text([], frozenset()) == REDACTED
    assert REDACTED == "<redacted>"


# ============================================================ property tests ====
CISCO_FUZZ_LINES = [
    "hostname R{n}",
    "ntp server 10.0.0.{n}",
    "ntp server vrf MGMT 10.0.9.{n}",
    "logging host 10.0.1.{n}",
    "logging 10.0.2.{n}",
    "username u{n} secret 9 TOPSECRET{n}",
    "username v{n} password 7 TOPSECRET{n}",
    "service password-encryption",
    "no service password-encryption",
    "ip http server",
    "no ip http server",
    "interface Gi0/{n}",
    " description password TOPSECRET{n}",
    " description d{n}",
    " shutdown",
    " no shutdown",
    "line vty 0 4",
    " transport input ssh",
    " transport input telnet",
    " transport input",
    "!",
    "! comment {n}",
    "",
    "  deep {n}",
]


def test_cisco_fuzz_invariants_and_no_secret_leaks() -> None:
    rng = random.Random(2468)
    for _ in range(600):
        lines = [
            rng.choice(CISCO_FUZZ_LINES).format(n=rng.randint(0, 4))
            for _ in range(rng.randint(0, 40))
        ]
        content = "\n".join(lines) + "\n"
        baseline = cis(content)
        assert baseline == cis(content)
        assert_baseline_invariants(baseline, max(len(lines), 1))
        assert "TOPSECRET" not in repr(baseline)


FORTI_FUZZ_BLOCKS = [
    'config system global\nset hostname "H{n}"\nend',
    'config system ntp\nconfig ntpserver\nedit {n}\nset server "10.0.0.{n}"\nnext\nend\nend',
    'config log syslogd setting\nset status {s}\nset server "10.1.0.{n}"\nend',
    'config system admin\nedit "a{n}"\nset password ENC TOPSECRET{n}\nnext\nend',
    'config system interface\nedit "p{n}"\nset status {u}\nset allowaccess {a}\n'
    'set description "d{n}"\nnext\nend',
    'config system interface\nedit "p{n}"\nunset allowaccess\nnext\nend',
    'config vpn ipsec phase1-interface\nedit "t{n}"\nset psksecret ENC TOPSECRET{n}\nnext\nend',
    "# comment {n}",
    "",
    "purge",
]


def test_forti_fuzz_invariants_and_no_secret_leaks() -> None:
    rng = random.Random(1357)
    for _ in range(400):
        blocks = [
            rng.choice(FORTI_FUZZ_BLOCKS).format(
                n=rng.randint(0, 4),
                s=rng.choice(["enable", "disable"]),
                u=rng.choice(["up", "down"]),
                a=rng.choice(["ping ssh", "telnet", "http https", "ssh"]),
            )
            for _ in range(rng.randint(0, 8))
        ]
        inner = "\n".join(blocks)
        wrapper = rng.choice(["plain", "global", "vdom"])
        if wrapper == "global" and inner:
            content = f"config global\n{inner}\nend\n"
        elif wrapper == "vdom" and inner:
            content = f"config vdom\nedit root\n{inner}\nnext\nend\n"
        else:
            content = inner + "\n"
        baseline = fgt(content)
        assert baseline == fgt(content)
        assert_baseline_invariants(baseline, len(content.split("\n")))
        assert "TOPSECRET" not in repr(baseline)


# ============================================================== validation ====
def test_empty_tokens_give_empty_baselines() -> None:
    for vendor in BUILTIN_VENDORS:
        assert normalize([], vendor) == SecurityBaseline(vendor=vendor)
        assert normalize((), vendor) == SecurityBaseline(vendor=vendor)


def test_tuple_of_tokens_is_accepted() -> None:
    tokens = tuple(tokenize_indented("hostname A\n"))
    assert pair(normalize(tokens, Vendor.CISCO_IOS).hostname) == ("A", 1)


@pytest.mark.parametrize("bad", ["cisco_ios", "junos", None, 1, object()])
def test_bad_vendor(bad: object) -> None:
    with pytest.raises(TypeError, match="vendor must be a Vendor"):
        normalize([], bad)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", [None, 123, "hostname A", b"x", iter([]), {1, 2}])
def test_bad_tokens_container(bad: object) -> None:
    with pytest.raises(TypeError, match="tokens must be a sequence of tokens"):
        normalize(bad, Vendor.CISCO_IOS)  # type: ignore[arg-type]


def test_wrong_token_type_for_vendor() -> None:
    forti_tokens = tokenize_fortinet("config a\nend\n")
    with pytest.raises(TypeError, match=re.escape(
        "tokens[0] must be ConfigToken for vendor cisco_ios, got FortiToken"
    )):
        normalize(forti_tokens, Vendor.CISCO_IOS)

    cisco_tokens = tokenize_indented("hostname A\n")
    with pytest.raises(TypeError, match=re.escape(
        "tokens[0] must be FortiToken for vendor fortios, got ConfigToken"
    )):
        normalize(cisco_tokens, Vendor.FORTIOS)


def test_mixed_token_types_report_the_index() -> None:
    mixed: list[Any] = [*tokenize_indented("hostname A\n")]
    mixed.append(tokenize_fortinet("config a\nend\n")[0])
    with pytest.raises(TypeError, match=r"tokens\[1\] must be ConfigToken"):
        normalize(mixed, Vendor.CISCO_IOS)


def test_tokens_must_be_in_source_order() -> None:
    tokens = tokenize_indented("hostname A\nntp server 1.1.1.1\n")
    with pytest.raises(ValueError, match="out of source order"):
        normalize(list(reversed(tokens)), Vendor.CISCO_IOS)
    with pytest.raises(ValueError, match="out of source order"):
        normalize([tokens[0], tokens[0]], Vendor.CISCO_IOS)


def test_forti_multiline_token_order_uses_end_line() -> None:
    tokens = tokenize_fortinet('config a\nset v "x\ny"\nend\n')
    assert normalize(tokens, Vendor.FORTIOS).warnings == ()
    overlapping = dataclasses.replace(tokens[2], line_number=3, end_line_number=3)
    with pytest.raises(ValueError, match="out of source order"):
        normalize([tokens[0], tokens[1], overlapping], Vendor.FORTIOS)


def test_mixed_source_files_are_rejected() -> None:
    first = tokenize_indented("hostname A\n", source_file="a.cfg")[0]
    second = dataclasses.replace(
        tokenize_indented("hostname B\n", source_file="b.cfg")[0], line_number=2
    )
    with pytest.raises(ValueError, match=re.escape("more than one source_file: 'a.cfg', 'b.cfg'")):
        normalize([first, second], Vendor.CISCO_IOS)


def test_source_file_none_is_consistent() -> None:
    assert cis("hostname A\n").source_file is None


# ============================================================ data models ====
def test_evidence_validation() -> None:
    assert Evidence(None, 1, 1, "x").redacted is False
    with pytest.raises(ValueError, match="line_number must be >= 1"):
        Evidence(None, 0, 1, "x")
    with pytest.raises(ValueError, match="end_line_number must be >= line_number"):
        Evidence(None, 3, 2, "x")


def test_warning_and_baseline_validation() -> None:
    with pytest.raises(ValueError, match="line_number must be >= 1"):
        NormalizationWarning("m", 0)
    with pytest.raises(TypeError, match="vendor must be a Vendor"):
        SecurityBaseline(vendor="cisco_ios")  # type: ignore[arg-type]


def test_models_are_frozen_and_hashable() -> None:
    b = cis(CISCO)
    with pytest.raises(dataclasses.FrozenInstanceError):
        b.hostname = None  # type: ignore[misc]
    assert isinstance(hash(b), int)
    fact = Fact(1, Evidence(None, 1, 1, "x"))
    with pytest.raises(dataclasses.FrozenInstanceError):
        fact.value = 2  # type: ignore[misc]
    assert isinstance(InterfaceBaseline(Fact("a", Evidence(None, 1, 1, "x"))).name, Fact)


def test_normalization_is_deterministic() -> None:
    assert cis(CISCO) == cis(CISCO)
    assert fgt(FORTI) == fgt(FORTI)


def test_only_cisco_and_fortios_have_builtin_normalizers() -> None:
    assert [str(v) for v in Vendor] == ["cisco_ios", "fortios", "junos"]
    assert BUILTIN_VENDORS == (Vendor.CISCO_IOS, Vendor.FORTIOS)
    with pytest.raises(ValueError):
        Vendor("palo")
    with pytest.raises(ValueError, match="no built-in normalizer"):
        normalize([], Vendor.JUNOS)


# ============================================================ performance ====
# Regression guards against accidental O(n^2) behaviour, NOT benchmarks.
def test_cisco_many_interfaces_is_fast() -> None:
    content = "".join(
        f"interface Gi0/{i}\n description link {i}\n no shutdown\n!\n" for i in range(50_000)
    )
    tokens = tokenize_indented(content)
    start = time.perf_counter()
    baseline = normalize(tokens, Vendor.CISCO_IOS)
    assert time.perf_counter() - start < 10
    assert len(baseline.interfaces) == 50_000


def test_cisco_many_global_commands_is_fast() -> None:
    content = "".join(
        f"ntp server 10.{i // 65536}.{(i // 256) % 256}.{i % 256}\nusername u{i} secret 9 x\n"
        for i in range(60_000)
    )
    tokens = tokenize_indented(content)
    start = time.perf_counter()
    baseline = normalize(tokens, Vendor.CISCO_IOS)
    assert time.perf_counter() - start < 10
    assert len(baseline.ntp_servers) == 60_000
    assert len(baseline.local_users) == 60_000


def test_forti_many_interfaces_is_fast() -> None:
    body = "".join(
        f'edit "p{i}"\nset allowaccess ping ssh\nset status up\nnext\n' for i in range(30_000)
    )
    tokens = tokenize_fortinet("config system interface\n" + body + "end\n")
    start = time.perf_counter()
    baseline = normalize(tokens, Vendor.FORTIOS)
    assert time.perf_counter() - start < 10
    assert len(baseline.interfaces) == 30_000