"""
Vendor-neutral normalizer for the Multi-Vendor Network Security Compliance
Auditor.

The tokenizers in ``auditor/parsers/tokenizers`` turn raw configuration text
into tokens. This module interprets those tokens and builds a
:class:`SecurityBaseline`: the small set of security-relevant facts the rule
engine audits, identical in shape for every vendor.

Vendor mapping:
    ``Vendor.CISCO_IOS``  <- ``ConfigToken``  (``tokenize_indented``)
    ``Vendor.FORTIOS``    <- ``FortiToken``   (``tokenize_fortinet``)
    ``Vendor.JUNOS``      <- no built-in normalizer; its baseline is built
                            from trained rules (``auditor/audit/trained.py``)

Design rules:
    - ``None`` (or an empty tuple) means "not stated in the configuration".
      The normalizer never infers vendor defaults; that is the rule engine's
      job. A ``Fact`` whose value is ``False`` means the configuration
      explicitly turns the feature off or restricts it.
    - Every fact carries :class:`Evidence` (file, line numbers, original
      text) so a finding can cite exactly where it came from.
    - Secrets never enter the baseline. When an evidence line contains a
      secret (a password, key or similar), its text is replaced by a
      redacted rendering and ``Evidence.redacted`` is set. The original text
      is not stored.
    - Nothing is dropped silently when it could change the meaning of the
      configuration: such cases are reported in ``SecurityBaseline.warnings``.
    - Invalid input raises (``TypeError`` or ``ValueError``); it is never
      guessed at.

Three-state facts (``telnet_enabled``, ``http_management_enabled``):
    Any statement that enables the feature wins (``True``, evidence is the
    first such statement); otherwise any statement that explicitly restricts
    it gives ``False``; otherwise ``None``.

Known limitations:
    - Only the facts in ``SecurityBaseline`` are extracted; every other
      command is ignored.
    - Cisco: global facts come from top-level commands only, telnet from
      ``transport input`` under ``line vty``, banners are not handled.
    - FortiOS: a leading ``config global`` or ``config vdom`` / ``edit NAME``
      scope is ignored when matching. A syslog server counts only when its
      block sets ``status enable``. ``unset allowaccess`` is reported as a
      warning and not interpreted.
    - Redaction is word-list based and therefore a heuristic.

Example:
    >>> from auditor.parsers.tokenizers.indented import tokenize_indented
    >>> tokens = tokenize_indented("hostname R1\\n!\\ninterface Gi0/0\\n shutdown\\n")
    >>> baseline = normalize(tokens, Vendor.CISCO_IOS)
    >>> baseline.hostname.value
    'R1'
    >>> baseline.hostname.evidence.line_number
    1
    >>> [(i.name.value, i.admin_down.value) for i in baseline.interfaces]
    [('Gi0/0', True)]
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Generic, TypeVar

from auditor.parsers.tokenizers.fortinet import (
    SENSITIVE_KEYS as FORTI_SENSITIVE_KEYS,
)
from auditor.parsers.tokenizers.fortinet import FortiKind, FortiToken
from auditor.parsers.tokenizers.indented import ConfigToken, TokenKind

__all__ = [
    "REDACTED",
    "Vendor",
    "BUILTIN_VENDORS",
    "Evidence",
    "Fact",
    "NamedFact",
    "InterfaceBaseline",
    "NormalizationWarning",
    "SecurityBaseline",
    "normalize",
]

REDACTED = "<redacted>"

T = TypeVar("T")
Tok = TypeVar("Tok", ConfigToken, FortiToken)


class Vendor(StrEnum):
    """Supported configuration dialects."""

    CISCO_IOS = "cisco_ios"
    FORTIOS = "fortios"
    JUNOS = "junos"


BUILTIN_VENDORS: tuple[Vendor, ...] = (Vendor.CISCO_IOS, Vendor.FORTIOS)


@dataclass(frozen=True, slots=True)
class Evidence:
    """Where a fact came from.

    Attributes:
        source_file: Source filename, if known.
        line_number: First physical line (1-based).
        end_line_number: Last physical line (greater than ``line_number``
            only for multi-line values).
        raw: Original text of the evidence line(s), or a redacted rendering
            when ``redacted`` is True.
        redacted: True if ``raw`` had a secret replaced.
    """

    source_file: str | None
    line_number: int
    end_line_number: int
    raw: str
    redacted: bool = False

    def __post_init__(self) -> None:
        if self.line_number < 1:
            raise ValueError("line_number must be >= 1")
        if self.end_line_number < self.line_number:
            raise ValueError("end_line_number must be >= line_number")


@dataclass(frozen=True, slots=True)
class Fact(Generic[T]):
    """A normalized value together with its evidence."""

    value: T
    evidence: Evidence


_FACT_KEY = re.compile(r"[a-z][a-z0-9_]{0,63}")


@dataclass(frozen=True, slots=True)
class NamedFact:
    """A named security fact beyond the fixed ``SecurityBaseline`` fields.

    Attributes:
        key: Lower snake_case name, for example ``ssh_version``.
        value: A bool, an int or a short printable string. Secrets are never
            stored here; derived values (counts, booleans) are used instead.
        evidence: The line the value comes from, or ``None`` for a value
            derived from the whole configuration (for example a count).
    """

    key: str
    value: bool | int | str
    evidence: Evidence | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.key, str) or _FACT_KEY.fullmatch(self.key) is None:
            raise ValueError("key must be lower snake_case (letters, digits, underscore)")
        value = self.value
        if isinstance(value, str):
            if not value or len(value) > 255 or not value.isprintable():
                raise ValueError("string values must be 1-255 printable characters")
        elif not isinstance(value, (bool, int)):
            raise TypeError("value must be a bool, int or str")
        if self.evidence is not None and not isinstance(self.evidence, Evidence):
            raise TypeError("evidence must be an Evidence or None")


@dataclass(frozen=True, slots=True)
class InterfaceBaseline:
    """Security-relevant state of one interface.

    Attributes:
        name: Interface name; evidence is the line that introduced it.
        description: Configured description, if any.
        admin_down: True if administratively shut down, False if explicitly
            enabled, None if not stated.
    """

    name: Fact[str]
    description: Fact[str] | None = None
    admin_down: Fact[bool] | None = None


@dataclass(frozen=True, slots=True)
class NormalizationWarning:
    """Something the normalizer could not interpret or had to resolve.

    Attributes:
        message: Human-readable description.
        line_number: Source line the warning refers to (1-based).
    """

    message: str
    line_number: int

    def __post_init__(self) -> None:
        if self.line_number < 1:
            raise ValueError("line_number must be >= 1")


@dataclass(frozen=True, slots=True)
class SecurityBaseline:
    """Vendor-neutral security facts extracted from one configuration.

    Attributes:
        vendor: Dialect the configuration was interpreted as.
        source_file: Source filename shared by all tokens, if any.
        hostname: Device hostname (last definition wins).
        ntp_servers: NTP servers in order of appearance, without duplicates.
        syslog_servers: Remote syslog servers, without duplicates.
        local_users: Local account names, without duplicates.
        interfaces: Interfaces in order of first appearance.
        telnet_enabled: Whether telnet management is enabled.
        http_management_enabled: Whether clear-text HTTP management is
            enabled.
        password_encryption: Whether stored passwords are obfuscated
            (Cisco ``service password-encryption``); None elsewhere.
        facts: Further named facts (management, authentication, logging and
            filtering state) with unique keys, in the order they were added.
        warnings: Interpretation problems, in the order they occurred.
    """

    vendor: Vendor
    source_file: str | None = None
    hostname: Fact[str] | None = None
    ntp_servers: tuple[Fact[str], ...] = ()
    syslog_servers: tuple[Fact[str], ...] = ()
    local_users: tuple[Fact[str], ...] = ()
    interfaces: tuple[InterfaceBaseline, ...] = ()
    telnet_enabled: Fact[bool] | None = None
    http_management_enabled: Fact[bool] | None = None
    password_encryption: Fact[bool] | None = None
    facts: tuple[NamedFact, ...] = ()
    warnings: tuple[NormalizationWarning, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.vendor, Vendor):
            raise TypeError("vendor must be a Vendor")
        keys = [fact.key for fact in self.facts]
        if len(set(keys)) != len(keys):
            raise ValueError("facts must have unique keys")


# --------------------------------------------------------------------------
# Redaction and evidence
# --------------------------------------------------------------------------

_CISCO_SENSITIVE_WORDS: frozenset[str] = frozenset(
    {
        "password",
        "secret",
        "key-string",
        "authentication-key",
        "pre-shared-key",
        "community",
    }
)


def _has_secret(words: Sequence[str], sensitive_words: frozenset[str]) -> bool:
    """True if a sensitive word is followed by at least one more word."""

    return any(word in sensitive_words for word in words[:-1])


def _redacted_text(words: Sequence[str], sensitive_words: frozenset[str]) -> str:
    """Render a line with everything after the first sensitive word hidden.

    If no sensitive word matches, everything after the first word is hidden
    so the fallback is always safe.
    """

    for index in range(len(words) - 1):
        if words[index] in sensitive_words:
            return " ".join((*words[: index + 1], REDACTED))
    return f"{words[0]} {REDACTED}" if words else REDACTED


def _cisco_evidence(token: ConfigToken) -> Evidence:
    words = token.text.split()
    if _has_secret(words, _CISCO_SENSITIVE_WORDS):
        return Evidence(
            token.source_file,
            token.line_number,
            token.line_number,
            _redacted_text(words, _CISCO_SENSITIVE_WORDS),
            True,
        )
    return Evidence(token.source_file, token.line_number, token.line_number, token.raw)


def _forti_evidence(token: FortiToken) -> Evidence:
    if token.sensitive:
        words = (token.keyword, *token.args)
        return Evidence(
            token.source_file,
            token.line_number,
            token.end_line_number,
            _redacted_text(words, FORTI_SENSITIVE_KEYS),
            True,
        )
    return Evidence(
        token.source_file, token.line_number, token.end_line_number, token.raw
    )


def _tri_state(on: Sequence[Evidence], off: Sequence[Evidence]) -> Fact[bool] | None:
    """Any enabling evidence wins, then any restricting evidence, else None."""

    if on:
        return Fact(True, on[0])
    if off:
        return Fact(False, off[0])
    return None


# --------------------------------------------------------------------------
# Builder
# --------------------------------------------------------------------------


@dataclass(slots=True)
class _InterfaceState:
    name: Fact[str]
    description: Fact[str] | None = None
    admin_down: Fact[bool] | None = None


class _Builder:
    """Mutable accumulator turned into an immutable SecurityBaseline."""

    def __init__(self, vendor: Vendor, source_file: str | None) -> None:
        self.vendor = vendor
        self.source_file = source_file
        self.hostname: Fact[str] | None = None
        self.ntp: dict[str, Fact[str]] = {}
        self.syslog: dict[str, Fact[str]] = {}
        self.users: dict[str, Fact[str]] = {}
        self.interfaces: dict[str, _InterfaceState] = {}
        self.telnet: Fact[bool] | None = None
        self.http: Fact[bool] | None = None
        self.password_encryption: Fact[bool] | None = None
        self.facts: dict[str, NamedFact] = {}
        self.warnings: list[NormalizationWarning] = []

    def warn(self, message: str, line_number: int) -> None:
        self.warnings.append(NormalizationWarning(message, line_number))

    def set_hostname(self, value: str, evidence: Evidence) -> None:
        previous = self.hostname
        if previous is not None and previous.value != value:
            self.warn(
                f"hostname redefined at line {evidence.line_number}; previous "
                f"definition at line {previous.evidence.line_number}; "
                "last definition wins",
                evidence.line_number,
            )
        self.hostname = Fact(value, evidence)

    def add_ntp(self, value: str, evidence: Evidence) -> None:
        self.ntp.setdefault(value, Fact(value, evidence))

    def add_syslog(self, value: str, evidence: Evidence) -> None:
        self.syslog.setdefault(value, Fact(value, evidence))

    def add_user(self, value: str, evidence: Evidence) -> None:
        self.users.setdefault(value, Fact(value, evidence))

    def set_fact(self, key: str, value: bool | int | str, evidence: Evidence | None) -> None:
        self.facts[key] = NamedFact(key, value, evidence)

    def set_tri(self, key: str, fact: Fact[bool] | None) -> None:
        if fact is not None:
            self.set_fact(key, fact.value, fact.evidence)

    def set_count(self, key: str, evidence: Sequence[Evidence]) -> None:
        self.set_fact(key, len(evidence), evidence[0] if evidence else None)

    def interface(self, name: str, evidence: Evidence) -> _InterfaceState:
        state = self.interfaces.get(name)
        if state is None:
            state = _InterfaceState(Fact(name, evidence))
            self.interfaces[name] = state
        return state

    def build(self) -> SecurityBaseline:
        return SecurityBaseline(
            vendor=self.vendor,
            source_file=self.source_file,
            hostname=self.hostname,
            ntp_servers=tuple(self.ntp.values()),
            syslog_servers=tuple(self.syslog.values()),
            local_users=tuple(self.users.values()),
            interfaces=tuple(
                InterfaceBaseline(s.name, s.description, s.admin_down)
                for s in self.interfaces.values()
            ),
            telnet_enabled=self.telnet,
            http_management_enabled=self.http,
            password_encryption=self.password_encryption,
            facts=tuple(self.facts.values()),
            warnings=tuple(self.warnings),
        )


# --------------------------------------------------------------------------
# Cisco IOS (ConfigToken)
# --------------------------------------------------------------------------


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _cisco_ntp_address(words: list[str]) -> str | None:
    index = 2
    if len(words) > index and words[index] == "vrf":
        index += 2
    return words[index] if index < len(words) else None


def _cisco_syslog_address(words: list[str]) -> str | None:
    if len(words) >= 3 and words[1] == "host":
        return words[2]
    if len(words) == 2 and _is_ip(words[1]):
        return words[1]
    return None


def _cisco_interface_child(child: ConfigToken, state: _InterfaceState) -> None:
    words = child.text.split()
    evidence = _cisco_evidence(child)

    if words[0] == "description":
        source = evidence.raw.strip() if evidence.redacted else child.text
        parts = source.split(None, 1)
        state.description = Fact(parts[1] if len(parts) > 1 else "", evidence)
    elif words == ["shutdown"]:
        state.admin_down = Fact(True, evidence)
    elif words == ["no", "shutdown"]:
        state.admin_down = Fact(False, evidence)


# --------------------------------------------------------------------------
# Cisco IOS: named facts
# --------------------------------------------------------------------------

_TRAP_LEVELS: dict[str, int] = {
    "emergencies": 0,
    "alerts": 1,
    "critical": 2,
    "errors": 3,
    "warnings": 4,
    "notifications": 5,
    "informational": 6,
    "debugging": 7,
}
_DEFAULT_SNMP_COMMUNITIES: frozenset[str] = frozenset({"public", "private"})
_NO_TIMEOUT_MINUTES = 99999
_MAX_DIGITS = 9


def _digits(text: str) -> int | None:
    if text.isascii() and text.isdecimal() and len(text) <= _MAX_DIGITS:
        return int(text)
    return None


def _hidden(token: ConfigToken, keep: int) -> Evidence:
    """Evidence that keeps only the first ``keep`` words of a line."""

    words = token.text.split()
    text = " ".join((*words[:keep], REDACTED))
    return Evidence(token.source_file, token.line_number, token.line_number, text, True)


def _cisco_server_evidence(token: ConfigToken) -> Evidence:
    words = token.text.split()
    sensitive = _CISCO_SENSITIVE_WORDS | {"key"}
    if _has_secret(words, sensitive):
        return Evidence(
            token.source_file,
            token.line_number,
            token.line_number,
            _redacted_text(words, sensitive),
            True,
        )
    return Evidence(token.source_file, token.line_number, token.line_number, token.raw)


def _is_plaintext_password(rest: list[str]) -> bool:
    """True if the words after a ``password`` keyword are a clear-text value."""

    if rest[:1] == ["level"]:
        rest = rest[2:]
    if not rest or rest[0] in {"5", "7", "8", "9"}:
        return False
    if rest[0] == "0":
        return len(rest) > 1
    return True


def _is_permit_any(words: list[str]) -> bool:
    if words and words[0].isdecimal():
        words = words[1:]
    if not words or words[0] != "permit":
        return False
    rest = words[1:]
    if rest[:3] == ["ip", "any", "any"]:
        return True
    return rest[:1] == ["any"] and (len(rest) == 1 or rest[1] == "log")


def _cisco_facts(
    commands: list[ConfigToken], children: dict[int, list[ConfigToken]], b: _Builder
) -> None:
    if not commands:
        return

    ssh_on: list[Evidence] = []
    ssh_off: list[Evidence] = []
    servers: dict[tuple[str, str], Evidence] = {}
    plaintext: list[Evidence] = []
    attempts: list[tuple[int, Evidence]] = []
    stamps_on: list[Evidence] = []
    stamps_off: list[Evidence] = []
    communities: list[Evidence] = []
    default_communities: list[Evidence] = []
    permit_any: list[Evidence] = []
    source_route_on: list[Evidence] = []
    source_route_off: list[Evidence] = []
    broadcast_on: list[Evidence] = []
    broadcast_off: list[Evidence] = []
    redirects_on: list[Evidence] = []
    redirects_off: list[Evidence] = []
    urpf: list[Evidence] = []
    vty_timeouts: list[tuple[int, Evidence]] = []
    vty_restricted: list[Evidence] = []
    vty_open: list[Evidence] = []

    for token in commands:
        if token.parent_line is not None:
            continue
        words = token.text.split()
        head = words[0]
        evidence = _cisco_evidence(token)

        if words[:3] == ["ip", "ssh", "version"] and len(words) == 4:
            version = _digits(words[3])
            if version in (1, 2):
                b.set_fact("ssh_version", version, evidence)
        if words == ["ip", "http", "secure-server"]:
            b.set_fact("https_enabled", True, evidence)
        elif words == ["no", "ip", "http", "secure-server"]:
            b.set_fact("https_enabled", False, evidence)
        elif words == ["aaa", "new-model"]:
            b.set_fact("aaa_enabled", True, evidence)
        elif words == ["no", "aaa", "new-model"]:
            b.set_fact("aaa_enabled", False, evidence)
        elif head in ("radius", "tacacs") and len(words) == 3 and words[1] == "server":
            servers.setdefault((head, words[2]), _cisco_server_evidence(token))
        elif head in ("radius-server", "tacacs-server") and len(words) >= 3 and words[1] == "host":
            servers.setdefault((head.split("-")[0], words[2]), _cisco_server_evidence(token))
        elif head == "username" and "password" in words[:-1]:
            if _is_plaintext_password(words[words.index("password") + 1 :]):
                plaintext.append(evidence)
        elif words[:2] == ["enable", "password"]:
            if _is_plaintext_password(words[2:]):
                plaintext.append(evidence)
            if "privileged_secret_set" not in b.facts:
                b.set_fact("privileged_secret_set", False, evidence)
        elif words[:2] == ["enable", "secret"] and len(words) > 2:
            b.set_fact("privileged_secret_set", True, evidence)
        elif words[:2] == ["login", "block-for"] and "attempts" in words[:-1]:
            count = _digits(words[words.index("attempts") + 1])
            if count is not None:
                attempts.append((count, evidence))
        elif words[:5] == ["aaa", "local", "authentication", "attempts", "max-fail"] and len(words) == 6:
            count = _digits(words[5])
            if count is not None:
                attempts.append((count, evidence))
        elif words == ["logging", "on"]:
            b.set_fact("logging_enabled", True, evidence)
        elif words == ["no", "logging", "on"]:
            b.set_fact("logging_enabled", False, evidence)
        elif words[:3] == ["service", "timestamps", "log"] and words[3:4] in (["datetime"], ["uptime"]):
            stamps_on.append(evidence)
        elif words[:4] == ["no", "service", "timestamps", "log"] or words == ["no", "service", "timestamps"]:
            stamps_off.append(evidence)
        elif words[:2] == ["logging", "trap"] and len(words) >= 3:
            level = _TRAP_LEVELS.get(words[2]) if not words[2].isdecimal() else _digits(words[2])
            if level is not None and 0 <= level <= 7:
                b.set_fact("trap_level_numeric", level, evidence)
        elif words == ["ip", "source-route"]:
            source_route_on.append(evidence)
        elif words == ["no", "ip", "source-route"]:
            source_route_off.append(evidence)
        elif words[:2] == ["snmp-server", "community"] and len(words) >= 3:
            communities.append(_hidden(token, 2))
            if words[2].lower() in _DEFAULT_SNMP_COMMUNITIES:
                default_communities.append(_hidden(token, 2))
        elif words[:2] in (["snmp-server", "group"], ["snmp-server", "user"]):
            b.set_fact("snmp_v3_configured", True, _hidden(token, 2))
        elif head == "banner" and words[1:2] in (["login"], ["motd"], ["exec"], ["incoming"]):
            if "login_banner_present" not in b.facts:
                b.set_fact("login_banner_present", True, _hidden(token, 2))
        elif words[:3] == ["license", "udi", "pid"] and len(words) >= 6 and words[4] == "sn":
            b.set_fact("hardware_model", words[3][:64], evidence)
            b.set_fact("serial_number", words[5][:64], evidence)
        elif head == "version" and len(words) == 2 and words[1].isprintable():
            b.set_fact("os_version", words[1][:64], evidence)
        elif head == "access-list" and len(words) >= 4 and _is_permit_any(words[2:]):
            permit_any.append(evidence)
        elif words[:1] in (["ip"], ["ipv6"]) and words[1:2] == ["access-list"]:
            for child in children.get(token.line_number, []):
                if _is_permit_any(child.text.split()):
                    permit_any.append(_cisco_evidence(child))
        elif head == "interface" and len(words) >= 2:
            for child in children.get(token.line_number, []):
                child_words = child.text.split()
                child_evidence = _cisco_evidence(child)
                if child_words == ["ip", "directed-broadcast"] or (
                    child_words[:2] == ["ip", "directed-broadcast"] and len(child_words) == 3
                ):
                    broadcast_on.append(child_evidence)
                elif child_words == ["no", "ip", "directed-broadcast"]:
                    broadcast_off.append(child_evidence)
                elif child_words == ["ip", "redirects"]:
                    redirects_on.append(child_evidence)
                elif child_words == ["no", "ip", "redirects"]:
                    redirects_off.append(child_evidence)
                elif child_words[:3] == ["ip", "verify", "unicast"] and len(child_words) > 3:
                    urpf.append(child_evidence)
        elif words[:2] == ["line", "vty"]:
            restricted: Evidence | None = None
            for child in children.get(token.line_number, []):
                child_words = child.text.split()
                child_evidence = _cisco_evidence(child)
                if child_words[:2] == ["transport", "input"] and len(child_words) > 2:
                    target = ssh_on if {"ssh", "all"} & set(child_words[2:]) else ssh_off
                    target.append(child_evidence)
                elif child_words[:1] == ["password"] and _is_plaintext_password(child_words[1:]):
                    plaintext.append(child_evidence)
                elif child_words[:1] == ["exec-timeout"] and 2 <= len(child_words) <= 3:
                    minutes = _digits(child_words[1])
                    seconds = _digits(child_words[2]) if len(child_words) == 3 else 0
                    if minutes is not None and seconds is not None:
                        total = _NO_TIMEOUT_MINUTES if minutes == 0 and seconds == 0 else minutes + (1 if seconds else 0)
                        vty_timeouts.append((total, child_evidence))
                elif child_words[:1] == ["access-class"] and "in" in child_words[2:]:
                    restricted = child_evidence
            if restricted is not None:
                vty_restricted.append(restricted)
            else:
                vty_open.append(evidence)
        elif words[:1] == ["line"] and words[1:2] in (["con"], ["aux"]):
            for child in children.get(token.line_number, []):
                child_words = child.text.split()
                if child_words[:1] == ["password"] and _is_plaintext_password(child_words[1:]):
                    plaintext.append(_cisco_evidence(child))

    b.set_tri("ssh_enabled", _tri_state(ssh_on, ssh_off))
    b.set_count("remote_auth_server_count", list(servers.values()))
    b.set_count("plaintext_password_count", plaintext)
    if attempts:
        count, evidence = min(attempts, key=lambda item: item[0])
        b.set_fact("max_login_attempts", count, evidence)
    b.set_tri("timestamps_enabled", _tri_state(stamps_on, stamps_off))
    b.set_tri("ip_source_route_enabled", _tri_state(source_route_on, source_route_off))
    b.set_tri("directed_broadcast_enabled", _tri_state(broadcast_on, broadcast_off))
    b.set_tri("icmp_redirects_enabled", _tri_state(redirects_on, redirects_off))
    if communities:
        b.set_fact("snmp_community_configured", True, communities[0])
        b.set_tri("snmp_default_community", _tri_state(default_communities, communities))
    if urpf:
        b.set_fact("antispoofing_enabled", True, urpf[0])
    if vty_timeouts:
        total, evidence = max(vty_timeouts, key=lambda item: item[0])
        b.set_fact("exec_timeout_minutes", total, evidence)
    if vty_open:
        b.set_fact("mgmt_access_restricted", False, vty_open[0])
    elif vty_restricted:
        b.set_fact("mgmt_access_restricted", True, vty_restricted[0])
    b.set_count("permit_any_any_count", permit_any)


def _normalize_cisco(tokens: list[ConfigToken], b: _Builder) -> None:
    commands = [t for t in tokens if t.kind is TokenKind.COMMAND]
    children: dict[int, list[ConfigToken]] = {}
    for token in commands:
        if token.parent_line is not None:
            children.setdefault(token.parent_line, []).append(token)

    telnet_on: list[Evidence] = []
    telnet_off: list[Evidence] = []

    for token in commands:
        if token.parent_line is not None:
            continue

        words = token.text.split()
        head = words[0]
        evidence = _cisco_evidence(token)

        if head == "hostname" and len(words) >= 2:
            b.set_hostname(words[1], evidence)
        elif head == "ntp" and len(words) >= 2 and words[1] == "server":
            address = _cisco_ntp_address(words)
            if address is not None:
                b.add_ntp(address, evidence)
        elif head == "logging":
            address = _cisco_syslog_address(words)
            if address is not None:
                b.add_syslog(address, evidence)
        elif head == "username" and len(words) >= 2:
            b.add_user(words[1], evidence)
        elif words == ["service", "password-encryption"]:
            b.password_encryption = Fact(True, evidence)
        elif words == ["no", "service", "password-encryption"]:
            b.password_encryption = Fact(False, evidence)
        elif words == ["ip", "http", "server"]:
            b.http = Fact(True, evidence)
        elif words == ["no", "ip", "http", "server"]:
            b.http = Fact(False, evidence)
        elif head == "interface" and len(words) >= 2:
            state = b.interface(" ".join(words[1:]), evidence)
            for child in children.get(token.line_number, []):
                _cisco_interface_child(child, state)
        elif words[:2] == ["line", "vty"]:
            for child in children.get(token.line_number, []):
                child_words = child.text.split()
                if child_words[:2] == ["transport", "input"] and len(child_words) > 2:
                    target = (
                        telnet_on
                        if {"telnet", "all"} & set(child_words[2:])
                        else telnet_off
                    )
                    target.append(_cisco_evidence(child))

    b.telnet = _tri_state(telnet_on, telnet_off)
    _cisco_facts(commands, children, b)


# --------------------------------------------------------------------------
# FortiOS (FortiToken)
# --------------------------------------------------------------------------

_FORTI_SYSLOG_BLOCKS: frozenset[str] = frozenset(
    {
        "log syslogd setting",
        "log syslogd2 setting",
        "log syslogd3 setting",
        "log syslogd4 setting",
    }
)


def _forti_scope(path: tuple[str, ...]) -> tuple[str, ...]:
    """Drop a leading ``config global`` or ``config vdom`` / ``edit NAME``."""

    if path[:1] == ("global",):
        return path[1:]
    if len(path) >= 2 and path[0] == "vdom":
        return path[2:]
    return path


class _AllowAccess:
    """Effective ``allowaccess`` list of one interface, in token order."""

    def __init__(self) -> None:
        self.values: set[str] = set()
        self.evidence_by_value: dict[str, Evidence] = {}
        self.last_set: Evidence | None = None

    def apply_set(self, values: tuple[str, ...], evidence: Evidence) -> None:
        self.values = set(values)
        self.evidence_by_value = {value: evidence for value in values}
        self.last_set = evidence

    def apply_append(self, values: tuple[str, ...], evidence: Evidence) -> None:
        for value in values:
            if value not in self.values:
                self.values.add(value)
                self.evidence_by_value[value] = evidence

    def contribution(self, value: str) -> tuple[Evidence | None, Evidence | None]:
        """Return (enabling evidence, restricting evidence) for ``value``."""

        if value in self.values:
            return self.evidence_by_value[value], None
        return None, self.last_set


class _FortiInterfaces:
    """Tracks ``config system interface`` entries while tokens stream by."""

    def __init__(self, builder: _Builder) -> None:
        self._builder = builder
        self._states: dict[int, _InterfaceState] = {}
        self._allow: dict[int, _AllowAccess] = {}
        self._flags: dict[str, tuple[list[Evidence], list[Evidence]]] = {}

    def open(self, edit_token: FortiToken) -> None:
        """Register the interface introduced by an ``edit`` token."""

        self._states[edit_token.line_number] = self._builder.interface(
            edit_token.args[0], _forti_evidence(edit_token)
        )

    def handle(self, token: FortiToken) -> bool:
        """Apply a set/append/unset token that sits directly in an interface.

        Returns:
            True if the token belonged to an interface and was consumed.
        """

        parent = token.parent_line
        state = self._states.get(parent) if parent is not None else None
        if parent is None or state is None:
            return False

        key = token.args[0]
        values = token.args[1:]
        evidence = _forti_evidence(token)

        if key == "allowaccess":
            if token.kind is FortiKind.UNSET:
                self._builder.warn(
                    f"'unset allowaccess' at line {token.line_number} is not "
                    "interpreted; its effect on management access is unknown",
                    token.line_number,
                )
                return True
            allow = self._allow.setdefault(parent, _AllowAccess())
            if token.kind is FortiKind.SET:
                allow.apply_set(values, evidence)
            else:
                allow.apply_append(values, evidence)
        elif token.kind is FortiKind.SET:
            if key == "description" and values:
                state.description = Fact(values[0], evidence)
            elif key == "status" and values and values[0] in ("up", "down"):
                state.admin_down = Fact(values[0] == "down", evidence)
            elif key == "icmp-redirect" and values and values[0] in ("enable", "disable"):
                on, off = self._flags.setdefault(key, ([], []))
                (on if values[0] == "enable" else off).append(evidence)
        return True

    def access(self, value: str) -> Fact[bool] | None:
        """Return whether ``value`` is allowed on any interface."""

        on: list[Evidence] = []
        off: list[Evidence] = []
        for allow in self._allow.values():
            enabling, restricting = allow.contribution(value)
            if enabling is not None:
                on.append(enabling)
            if restricting is not None:
                off.append(restricting)
        return _tri_state(on, off)

    def flag(self, key: str) -> Fact[bool] | None:
        """Return the enable/disable state of a per-interface ``key``."""

        on, off = self._flags.get(key, ([], []))
        return _tri_state(on, off)

    def management_access(self) -> tuple[Fact[bool] | None, Fact[bool] | None]:
        """Return (telnet, http) derived from all interfaces' allowaccess."""

        return self.access("telnet"), self.access("http")


_FORTI_HEADER = re.compile(r"#config-version=([A-Za-z0-9]{1,32})-(\d{1,3}\.\d{1,3}\.\d{1,3})(?=-|:|$)")
_FORTI_SEVERITY: dict[str, int] = {
    "emergency": 0,
    "alert": 1,
    "critical": 2,
    "error": 3,
    "warning": 4,
    "notification": 5,
    "information": 6,
    "debug": 7,
}
_FORTI_REMOTE_AUTH: frozenset[str] = frozenset({"user radius", "user tacacs+", "user ldap"})
_FORTI_OPEN_HOSTS: frozenset[tuple[str, ...]] = frozenset(
    {("0.0.0.0", "0.0.0.0"), ("0.0.0.0", "0.0.0.0/0"), ("0.0.0.0/0",)}  # nosec B104
)


def _forti_hidden(token: FortiToken, text: str) -> Evidence:
    return Evidence(token.source_file, token.line_number, token.end_line_number, text, True)


def _forti_facts(tokens: list[FortiToken], interfaces: _FortiInterfaces, b: _Builder) -> None:
    if not tokens:
        return
    servers: dict[int, list[FortiToken | None]] = {}
    admins: dict[int, tuple[FortiToken, list[FortiToken]]] = {}
    communities: dict[int, tuple[FortiToken, dict[str, str]]] = {}
    snmp_users: list[FortiToken] = []
    policies: dict[int, tuple[FortiToken, dict[str, tuple[str, ...]]]] = {}
    policies_seen = False
    syslog_status: dict[int, FortiToken] = {}
    syslog_severity: dict[int, FortiToken] = {}
    banner_on: list[Evidence] = []
    banner_off: list[Evidence] = []
    encrypted: list[Evidence] = []
    plaintext: list[Evidence] = []

    for token in tokens:
        kind = token.kind
        if kind is FortiKind.COMMENT:
            match = _FORTI_HEADER.match(token.text)
            if match and "os_version" not in b.facts:
                header = _forti_hidden(token, match.group(0))
                b.set_fact("hardware_model", match.group(1), header)
                b.set_fact("os_version", match.group(2), header)
            continue

        scope = _forti_scope(token.path)
        if kind is FortiKind.CONFIG:
            if _forti_scope(token.args) == ("firewall", "policy"):
                policies_seen = True
            continue

        if kind is FortiKind.EDIT and scope:
            name = scope[0]
            if name in _FORTI_REMOTE_AUTH:
                servers[token.line_number] = [None]
            elif name == "system admin":
                admins[token.line_number] = (token, [])
            elif name == "system snmp community":
                communities[token.line_number] = (token, {})
            elif name == "system snmp user":
                snmp_users.append(token)
            elif name == "firewall policy":
                policies[token.line_number] = (token, {})
            continue

        if kind is not FortiKind.SET or token.parent_line is None or not token.args:
            continue

        parent = token.parent_line
        key = token.args[0]
        values = token.args[1:]

        if parent in servers and key == "server" and values:
            servers[parent][0] = token
        elif parent in admins:
            if key == "password" and values:
                (encrypted if values[0] == "ENC" else plaintext).append(_forti_evidence(token))
            elif key.startswith("trusthost") or key.startswith("ip6-trusthost"):
                admins[parent][1].append(token)
        elif parent in communities and values:
            communities[parent][1][key] = values[0]
        elif parent in policies:
            policies[parent][1][key] = values
        elif scope == ("system global",):
            if key == "admintimeout" and values and (minutes := _digits(values[0])) is not None:
                b.set_fact("exec_timeout_minutes", minutes, _forti_evidence(token))
            elif key == "admin-lockout-threshold" and values and (count := _digits(values[0])) is not None:
                b.set_fact("max_login_attempts", count, _forti_evidence(token))
            elif key in ("pre-login-banner", "post-login-banner") and values:
                target = banner_on if values[0] == "enable" else banner_off
                target.append(_forti_evidence(token))
        elif scope == ("system settings",) and key == "strict-src-check" and values == ("enable",):
            b.set_fact("antispoofing_enabled", True, _forti_evidence(token))
        elif scope and scope[0].startswith("system replacemsg admin") and "disclaimer" in scope[0]:
            if key == "buffer" and values and values[0]:
                banner_on.append(_forti_hidden(token, "set buffer " + REDACTED))
        elif len(scope) == 1 and scope[0] in _FORTI_SYSLOG_BLOCKS:
            if key == "status":
                syslog_status[parent] = token
            elif key == "severity":
                syslog_severity[parent] = token

    b.set_tri("ssh_enabled", interfaces.access("ssh"))
    b.set_tri("https_enabled", interfaces.access("https"))
    b.set_tri("icmp_redirects_enabled", interfaces.flag("icmp-redirect"))
    if b.facts.get("ssh_enabled") is not None and b.facts["ssh_enabled"].value is True:
        # FortiOS only implements SSH protocol version 2.
        b.set_fact("ssh_version", 2, b.facts["ssh_enabled"].evidence)

    remote = [tokens_[0] for tokens_ in servers.values() if tokens_[0] is not None]
    b.set_count("remote_auth_server_count", [_forti_evidence(t) for t in remote])
    if remote:
        b.set_fact("aaa_enabled", True, _forti_evidence(remote[0]))

    b.set_count("plaintext_password_count", plaintext)
    if plaintext:
        b.password_encryption = Fact(False, plaintext[0])
    elif encrypted:
        b.password_encryption = Fact(True, encrypted[0])

    live = [
        (edit, keys)
        for edit, keys in communities.values()
        if keys.get("status", "enable") == "enable" and "name" in keys
    ]
    if live:
        first = _forti_hidden(live[0][0], "set name " + REDACTED)
        b.set_fact("snmp_community_configured", True, first)
        default = [
            _forti_hidden(edit, "set name " + REDACTED)
            for edit, keys in live
            if keys["name"].lower() in _DEFAULT_SNMP_COMMUNITIES
        ]
        b.set_fact("snmp_default_community", bool(default), default[0] if default else first)
    if snmp_users:
        b.set_fact("snmp_v3_configured", True, _forti_evidence(snmp_users[0]))

    if banner_on:
        b.set_fact("login_banner_present", True, banner_on[0])
    elif banner_off:
        b.set_fact("login_banner_present", False, banner_off[0])

    for parent, status in syslog_status.items():
        if status.args[1:2] != ("enable",):
            continue
        severity = syslog_severity.get(parent)
        if severity is not None and severity.args[1:2]:
            level = _FORTI_SEVERITY.get(severity.args[1])
            if level is not None:
                b.set_fact("trap_level_numeric", level, _forti_evidence(severity))
        elif "trap_level_numeric" not in b.facts:
            # FortiOS default severity is "information".
            b.set_fact("trap_level_numeric", _FORTI_SEVERITY["information"], _forti_evidence(status))

    if admins:
        open_admin: FortiToken | None = None
        restricted: FortiToken | None = None
        for edit, hosts in admins.values():
            usable = [h for h in hosts if h.args[1:] and tuple(h.args[1:]) not in _FORTI_OPEN_HOSTS]
            if usable:
                restricted = restricted or usable[0]
            elif open_admin is None:
                open_admin = edit
        if open_admin is not None:
            b.set_fact("mgmt_access_restricted", False, _forti_evidence(open_admin))
        elif restricted is not None:
            b.set_fact("mgmt_access_restricted", True, _forti_evidence(restricted))

    if policies_seen:
        permissive = [
            _forti_evidence(edit)
            for edit, keys in policies.values()
            if keys.get("action") == ("accept",)
            and keys.get("status", ("enable",)) != ("disable",)
            and keys.get("srcaddr") == ("all",)
            and keys.get("dstaddr") == ("all",)
            and keys.get("service") == ("ALL",)
        ]
        b.set_count("permit_any_any_count", permissive)


def _normalize_forti(tokens: list[FortiToken], b: _Builder) -> None:
    interfaces = _FortiInterfaces(b)
    syslog_blocks: dict[int, dict[str, FortiToken]] = {}

    for token in tokens:
        scope = _forti_scope(token.path)
        kind = token.kind

        if kind is FortiKind.EDIT:
            if scope == ("system admin",):
                b.add_user(token.args[0], _forti_evidence(token))
            elif scope == ("system interface",):
                interfaces.open(token)
            continue

        if kind not in (FortiKind.SET, FortiKind.APPEND, FortiKind.UNSET):
            continue

        if interfaces.handle(token):
            continue

        parent = token.parent_line
        if kind is not FortiKind.SET or parent is None:
            continue

        key = token.args[0]
        values = token.args[1:]

        if scope == ("system global",) and key == "hostname" and values:
            b.set_hostname(values[0], _forti_evidence(token))
        elif (
            len(scope) == 3
            and scope[:2] == ("system ntp", "ntpserver")
            and key == "server"
            and values
        ):
            b.add_ntp(values[0], _forti_evidence(token))
        elif len(scope) == 1 and scope[0] in _FORTI_SYSLOG_BLOCKS:
            syslog_blocks.setdefault(parent, {})[key] = token

    for block in syslog_blocks.values():
        status = block.get("status")
        server = block.get("server")
        if (
            status is not None
            and server is not None
            and status.args[1:2] == ("enable",)
            and len(server.args) >= 2
        ):
            b.add_syslog(server.args[1], _forti_evidence(server))

    b.telnet, b.http = interfaces.management_access()
    _forti_facts(tokens, interfaces, b)


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def _require(
    tokens: object, cls: type[Tok], vendor: Vendor
) -> tuple[list[Tok], str | None]:
    """Validate the token sequence and return it with its source file."""

    if isinstance(tokens, (str, bytes)) or not isinstance(tokens, Sequence):
        raise TypeError(
            f"tokens must be a sequence of tokens, got {type(tokens).__name__}"
        )

    checked: list[Tok] = []
    sources: set[str | None] = set()
    previous_end = 0

    for index, token in enumerate(tokens):
        if not isinstance(token, cls):
            raise TypeError(
                f"tokens[{index}] must be {cls.__name__} for vendor "
                f"{vendor.value}, got {type(token).__name__}"
            )
        if token.line_number <= previous_end:
            raise ValueError(
                f"tokens[{index}] is out of source order (line "
                f"{token.line_number} follows line {previous_end})"
            )
        previous_end = (
            token.end_line_number if isinstance(token, FortiToken) else token.line_number
        )
        sources.add(token.source_file)
        checked.append(token)

    if len(sources) > 1:
        names = ", ".join(sorted(repr(name) for name in sources))
        raise ValueError(f"tokens come from more than one source_file: {names}")

    return checked, next(iter(sources)) if sources else None


def normalize(
    tokens: Sequence[ConfigToken] | Sequence[FortiToken],
    vendor: Vendor,
) -> SecurityBaseline:
    """Build a SecurityBaseline from tokenizer output.

    Args:
        tokens: Tokens from the tokenizer that matches ``vendor``, in source
            order, all from one source file.
        vendor: Dialect to interpret the tokens as.

    Returns:
        The normalized baseline. An empty token sequence gives an empty
        baseline.

    Raises:
        TypeError: If ``vendor`` is not a Vendor, ``tokens`` is not a
            sequence, or a token has the wrong type for ``vendor``.
        ValueError: If ``vendor`` is not in ``BUILTIN_VENDORS``, or the tokens
            are out of source order or come from more than one source file.
    """

    if not isinstance(vendor, Vendor):
        raise TypeError(f"vendor must be a Vendor, got {type(vendor).__name__}")

    if vendor not in BUILTIN_VENDORS:
        raise ValueError(
            f"vendor {vendor.value} has no built-in normalizer; build its baseline from trained rules"
        )

    if vendor is Vendor.CISCO_IOS:
        cisco, source_file = _require(tokens, ConfigToken, vendor)
        builder = _Builder(vendor, source_file)
        _normalize_cisco(cisco, builder)
    else:
        forti, source_file = _require(tokens, FortiToken, vendor)
        builder = _Builder(vendor, source_file)
        _normalize_forti(forti, builder)

    return builder.build()


if __name__ == "__main__":
    import doctest

    doctest.testmod()