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
    "Evidence",
    "Fact",
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
    warnings: tuple[NormalizationWarning, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.vendor, Vendor):
            raise TypeError("vendor must be a Vendor")


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
        return True

    def management_access(self) -> tuple[Fact[bool] | None, Fact[bool] | None]:
        """Return (telnet, http) derived from all interfaces' allowaccess."""

        telnet_on: list[Evidence] = []
        telnet_off: list[Evidence] = []
        http_on: list[Evidence] = []
        http_off: list[Evidence] = []

        for allow in self._allow.values():
            for value, on, off in (
                ("telnet", telnet_on, telnet_off),
                ("http", http_on, http_off),
            ):
                enabling, restricting = allow.contribution(value)
                if enabling is not None:
                    on.append(enabling)
                if restricting is not None:
                    off.append(restricting)

        return _tri_state(telnet_on, telnet_off), _tri_state(http_on, http_off)


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
        ValueError: If the tokens are out of source order or come from more
            than one source file.
    """

    if not isinstance(vendor, Vendor):
        raise TypeError(f"vendor must be a Vendor, got {type(vendor).__name__}")

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