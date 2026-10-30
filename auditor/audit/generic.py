from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Final

from auditor.schema import baseline as schema

MIN_CONFIDENCE: Final = 0.7
MAX_UNRECOGNIZED: Final = 200
MAX_LIST_ITEMS: Final = 20
MAX_BLOCK_DEPTH: Final = 50
MAX_VALUE_LEN: Final = 255
BASICS: Final = (
    "hostname",
    "os_version",
    "serial_number",
    "hardware_model",
    "ssh",
    "telnet",
    "http",
    "https",
    "syslog",
    "ntp",
)
_FALLBACK_HOSTNAME: Final = "unknown-device"
_COMMENT_PREFIXES: Final = ("#", "!", "//", "/*")
_STRUCTURAL: Final = frozenset({"end", "next", "exit"})
_SENSITIVE_MARKERS: Final = ("passw", "secret", "key", "communit", "token", "credential", "psk", "hash", "encrypt", "auth")
_WORD: Final = re.compile(r'"[^"]*"|\S+')
_VERSION: Final = re.compile(r"\d+(?:\.\d+)*[A-Za-z0-9._-]*")
_HOST: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,252}")
_FORTI_HEADER: Final = re.compile(r"#config-version=([A-Za-z0-9]{2,20})-(\d+\.\d+\.\d+)")
_JUNOS_VERSION: Final = re.compile(r"\d+\.\d+R\d.*")
_NOT_VALUES: Final = frozenset({"serial", "number", "no", "id", "is", "model", "name", "type"})


@dataclass(frozen=True, slots=True)
class _Line:
    number: int
    words: tuple[str, ...]

    @property
    def lower(self) -> tuple[str, ...]:
        return tuple(w.lower() for w in self.words)

    @property
    def text(self) -> str:
        return " ".join(self.words)


@dataclass(frozen=True, slots=True)
class _Proposal:
    value: bool | str
    confidence: float
    line: int
    rule: str
    text: str


@dataclass(frozen=True)
class GenericResult:
    baseline: schema.SecurityBaseline
    mapped: tuple[str, ...]
    total_basics: int
    unmatched_count: int
    conflicts: tuple[str, ...]


def _clip(text: str, limit: int = 200) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _is_sensitive(words: Sequence[str]) -> bool:
    joined = " ".join(words).lower()
    return any(marker in joined for marker in _SENSITIVE_MARKERS)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _words(text: str) -> tuple[str, ...]:
    return tuple(w.strip('"') for w in _WORD.findall(text))


def _flatten(text: str) -> tuple[list[_Line], list[tuple[int, str]]]:
    lines: list[_Line] = []
    headers: list[tuple[int, str]] = []
    stack: list[tuple[str, ...]] = []
    for number, raw in enumerate(text.split("\n"), start=1):
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith("#config-version="):
            headers.append((number, stripped))
        if stripped.startswith(_COMMENT_PREFIXES):
            continue
        if stripped.startswith("}"):
            if stack:
                stack.pop()
            continue
        body = stripped.rstrip(";").strip()
        if body.endswith("{"):
            if len(stack) < MAX_BLOCK_DEPTH:
                words = _words(body[:-1])
                stack.append(("__inactive__",) if words[:1] == ("inactive:",) else words)
            continue
        words = _words(body)
        if not words or words[0] == "inactive:":
            continue
        if words[0] == "set":
            words = words[1:]
            prefix: tuple[str, ...] = ()
        else:
            prefix = tuple(w for block in stack for w in block)
        if "__inactive__" in prefix or not (prefix + words):
            continue
        lines.append(_Line(number, prefix + words))
    return lines, headers


Predicate = Callable[[tuple[str, ...]], bool]

_BOOL_RULES: Final[tuple[tuple[str, str, Predicate, bool, float], ...]] = (
    ("junos-telnet", "telnet", lambda w: w[:3] == ("system", "services", "telnet"), True, 0.9),
    ("forti-telnet-on", "telnet", lambda w: w[:2] == ("admin-telnet", "enable"), True, 0.9),
    ("forti-telnet-off", "telnet", lambda w: w[:2] == ("admin-telnet", "disable"), False, 0.9),
    ("transport-telnet", "telnet", lambda w: w[:2] == ("transport", "input") and "telnet" in w[2:], True, 0.85),
    ("transport-all", "telnet", lambda w: w == ("transport", "input", "all"), True, 0.8),
    ("transport-ssh-only", "telnet", lambda w: w == ("transport", "input", "ssh"), False, 0.75),
    ("telnet-server-on", "telnet", lambda w: w in {("telnet", "server", "enable"), ("telnet", "enable")}, True, 0.85),
    (
        "telnet-server-off",
        "telnet",
        lambda w: len(w) == 4 and w[0] in {"no", "undo"} and w[1:] == ("telnet", "server", "enable"),
        False,
        0.85,
    ),
    ("junos-http", "http", lambda w: w[:4] == ("system", "services", "web-management", "http"), True, 0.9),
    ("ip-http-server", "http", lambda w: w == ("ip", "http", "server"), True, 0.9),
    ("http-server-on", "http", lambda w: w == ("http", "server", "enable"), True, 0.85),
    ("no-ip-http-server", "http", lambda w: w == ("no", "ip", "http", "server"), False, 0.9),
    (
        "http-server-off",
        "http",
        lambda w: len(w) == 4 and w[0] in {"no", "undo"} and w[1:] == ("http", "server", "enable"),
        False,
        0.85,
    ),
    ("junos-https", "https", lambda w: w[:4] == ("system", "services", "web-management", "https"), True, 0.9),
    ("ip-http-secure", "https", lambda w: w == ("ip", "http", "secure-server"), True, 0.9),
    ("https-server-on", "https", lambda w: w == ("https", "server", "enable"), True, 0.85),
    ("no-ip-http-secure", "https", lambda w: w == ("no", "ip", "http", "secure-server"), False, 0.9),
    ("junos-ssh", "ssh", lambda w: w[:3] == ("system", "services", "ssh"), True, 0.9),
    ("ssh-server-on", "ssh", lambda w: w in {("ssh", "server", "enable"), ("ssh", "enable")}, True, 0.85),
    ("ip-ssh", "ssh", lambda w: w[:2] == ("ip", "ssh"), True, 0.7),
    ("transport-ssh", "ssh", lambda w: w[:2] == ("transport", "input") and "ssh" in w[2:], True, 0.7),
    (
        "ssh-server-off",
        "ssh",
        lambda w: len(w) == 4 and w[0] in {"no", "undo"} and w[1:] == ("ssh", "server", "enable"),
        False,
        0.8,
    ),
)
_JUNOS_SERVICE_FIELDS: Final = ("ssh", "telnet", "http", "https")


def _hostname(line: _Line) -> str | None:
    w, orig = line.lower, line.words
    if len(w) == 2 and w[0] in {"hostname", "host-name", "sysname"}:
        return orig[1]
    if len(w) == 3 and w[:2] == ("system", "host-name"):
        return orig[2]
    return None


def _version(line: _Line) -> str | None:
    w, orig = line.lower, line.words
    if len(w) == 2 and w[0] == "version" and _VERSION.fullmatch(orig[1]):
        return orig[1]
    return None


def _serial(line: _Line) -> str | None:
    w, orig = line.lower, line.words
    if w[:3] == ("processor", "board", "id") and len(w) == 4:
        return orig[3]
    if len(w) >= 2 and ("serial" in w[:3] or "serial-number" in w[:3]):
        value = orig[-1].strip(":=")
        if value and value.lower() not in _NOT_VALUES and _HOST.fullmatch(value):
            return value
    return None


def _model(line: _Line) -> str | None:
    w, orig = line.lower, line.words
    if len(w) >= 2 and ("model" in w[:3] or "hardware-model" in w[:3]):
        value = orig[-1].strip(":=")
        if value and value.lower() not in _NOT_VALUES and _HOST.fullmatch(value):
            return value
    return None


def _host_after(words: tuple[str, ...], index: int) -> str | None:
    rest = list(words[index:])
    if rest[:1] and rest[0].lower() == "vrf":
        rest = rest[2:]
    if rest and _HOST.fullmatch(rest[0]) and rest[0].lower() != "vrf":
        return rest[0]
    return None


def _ntp(line: _Line) -> str | None:
    w = line.lower
    if w[:3] == ("system", "ntp", "server"):
        return _host_after(line.words, 3)
    if w[:2] in {("ntp", "server"), ("ntp", "peer"), ("sntp", "server")}:
        return _host_after(line.words, 2)
    return None


def _syslog(line: _Line) -> str | None:
    w, orig = line.lower, line.words
    if w[:3] == ("system", "syslog", "host"):
        return _host_after(orig, 3)
    if w[:2] in {("logging", "host"), ("logging", "server"), ("syslog", "server"), ("syslog", "host")}:
        return _host_after(orig, 2)
    if w[0] == "logging" and len(w) >= 2 and _is_ip(orig[1]):
        return orig[1]
    if w[0] == "loghost" and len(w) >= 2:
        return _host_after(orig, 1)
    return None


_VALUE_RULES: Final[tuple[tuple[str, str, Callable[[_Line], str | None], float], ...]] = (
    ("hostname", "hostname", _hostname, 0.9),
    ("version", "os_version", _version, 0.8),
    ("serial", "serial_number", _serial, 0.8),
    ("model", "hardware_model", _model, 0.7),
    ("ntp-server", "ntp", _ntp, 0.85),
    ("syslog-host", "syslog", _syslog, 0.85),
)


def _junos_signals(line: _Line) -> set[str]:
    w = line.lower
    found: set[str] = set()
    if w[:2] == ("system", "host-name"):
        found.add("host-name")
    if w[:2] == ("system", "services"):
        found.add("services")
    if w[0] == "routing-options":
        found.add("routing-options")
    if w[:2] == ("security", "zones"):
        found.add("zones")
    if w[0] == "interfaces" and len(w) > 1 and w[1][:3] in {"ge-", "xe-", "et-"}:
        found.add("interfaces")
    if w[0] == "version" and len(w) == 2 and _JUNOS_VERSION.fullmatch(line.words[1]):
        found.add("version")
    return found


def _best(proposals: list[_Proposal]) -> _Proposal | None:
    good = [p for p in proposals if p.confidence >= MIN_CONFIDENCE]
    if not good:
        return None
    enabled = [p for p in good if p.value is True]
    pool = enabled or good
    return max(pool, key=lambda p: (p.confidence, -p.line))


def _state(proposal: _Proposal | None) -> schema.SecurityState:
    if proposal is None:
        return schema.SecurityState.UNKNOWN
    return schema.SecurityState.ENABLED if proposal.value is True else schema.SecurityState.DISABLED


def _evidence(proposal: _Proposal) -> schema.Evidence:
    return schema.Evidence(
        text=_clip(proposal.text),
        line=proposal.line,
        mapping_id=f"generic:{proposal.rule}",
        confidence=proposal.confidence,
    )


def build_generic_baseline(text: str, *, filename: str | None = None, sha256: str | None = None) -> GenericResult:
    if not isinstance(text, str):
        raise TypeError(f"text must be a str, got {type(text).__name__}")
    lines, headers = _flatten(text)
    bools: dict[str, list[_Proposal]] = {field: [] for field in ("ssh", "telnet", "http", "https")}
    values: dict[str, list[_Proposal]] = {field: [] for _, field, _, _ in _VALUE_RULES}
    junos: set[str] = set()
    services_line: _Line | None = None
    unmatched: list[_Line] = []
    unmatched_count = 0

    for number, header in headers:
        match = _FORTI_HEADER.match(header)
        if match:
            values["hardware_model"].append(_Proposal(match.group(1), 0.8, number, "forti-header", match.group(1)))
            values["os_version"].append(_Proposal(match.group(2), 0.8, number, "forti-header", match.group(2)))

    for line in lines:
        w = line.lower
        junos |= _junos_signals(line)
        if w[:2] == ("system", "services") and services_line is None:
            services_line = line
        matched = False
        for rule, field, predicate, value, confidence in _BOOL_RULES:
            if predicate(w):
                bools[field].append(_Proposal(value, confidence, line.number, rule, line.text))
                matched = True
        for rule, field, extract, confidence in _VALUE_RULES:
            extracted = extract(line)
            if extracted is not None:
                values[field].append(_Proposal(extracted[:MAX_VALUE_LEN], confidence, line.number, rule, extracted))
                matched = True
        if not matched and w[0] not in _STRUCTURAL and not (w[0] == "config" and len(w) <= 3):
            unmatched_count += 1
            if len(unmatched) < MAX_UNRECOGNIZED:
                unmatched.append(line)

    is_junos = len(junos) >= 2
    if services_line is not None:
        for field in _JUNOS_SERVICE_FIELDS:
            if not any(p.confidence >= MIN_CONFIDENCE for p in bools[field]):
                bools[field].append(
                    _Proposal(False, 0.75, services_line.number, "junos-services-absence", "not listed under system services")
                )

    resolved = {field: _best(props) for field, props in bools.items()}
    conflicts = tuple(
        f"conflicting evidence for {field}; enabled takes precedence"
        for field, props in bools.items()
        if any(p.value is True and p.confidence >= MIN_CONFIDENCE for p in props)
        and any(p.value is False and p.confidence >= MIN_CONFIDENCE for p in props)
    )
    single = {field: _best(values[field]) for field in ("hostname", "os_version", "serial_number", "hardware_model")}

    def unique(field: str) -> list[_Proposal]:
        seen: dict[str, _Proposal] = {}
        for p in values[field]:
            if p.confidence >= MIN_CONFIDENCE and isinstance(p.value, str):
                seen.setdefault(p.value, p)
        return list(seen.values())[:MAX_LIST_ITEMS]

    syslog, ntp = unique("syslog"), unique("ntp")
    vendor = schema.Vendor.Juniper if is_junos else schema.Vendor.Unknown
    hostname = single["hostname"]
    version, serial, model = single["os_version"], single["serial_number"], single["hardware_model"]

    facts: list[schema.SecurityFact] = []
    for key, proposal in (
        ("serial_number", serial),
        ("hardware_model", model),
        ("os_version", version),
        ("ssh_enabled", resolved["ssh"]),
        ("telnet_enabled", resolved["telnet"]),
        ("http_management_enabled", resolved["http"]),
        ("https_enabled", resolved["https"]),
    ):
        if proposal is not None:
            facts.append(
                schema.SecurityFact(
                    key=key,
                    value=proposal.value,
                    state=_state(proposal) if isinstance(proposal.value, bool) else None,
                    evidence=_evidence(proposal),
                )
            )

    unrecognized = [
        schema.UnrecognizedConfig(
            text="<redacted>" if _is_sensitive(line.words) else _clip(line.text),
            vendor=vendor,
            location=f"line {line.number}",
            reason="no matching rule",
        )
        for line in unmatched
    ] + [
        schema.UnrecognizedConfig(text=note, vendor=vendor, location=None, reason="conflict") for note in conflicts
    ]

    baseline = schema.SecurityBaseline(
        device=schema.DeviceMetadata(
            hostname=str(hostname.value) if hostname else _FALLBACK_HOSTNAME,
            vendor=vendor,
            platform="Junos (generic parser)" if is_junos else "Unknown (generic parser)",
            version=str(version.value) if version else None,
            sha256=sha256,
            filename=filename,
        ),
        management=schema.ManagementAccess(
            ssh=_state(resolved["ssh"]),
            telnet=_state(resolved["telnet"]),
            http=_state(resolved["http"]),
            https=_state(resolved["https"]),
        ),
        auth=schema.AuthenticationSettings(),
        logging=schema.LoggingSettings(
            enabled=schema.SecurityState.ENABLED if syslog else schema.SecurityState.UNKNOWN,
            destinations=[str(p.value) for p in syslog],
        ),
        time_sync=schema.TimeSync(
            enabled=schema.SecurityState.ENABLED if ntp else schema.SecurityState.UNKNOWN,
            servers=[str(p.value) for p in ntp],
        ),
        facts=facts,
        unrecognized=unrecognized,
    )
    mapped = tuple(
        name
        for name, present in (
            ("hostname", hostname is not None),
            ("os_version", version is not None),
            ("serial_number", serial is not None),
            ("hardware_model", model is not None),
            ("ssh", resolved["ssh"] is not None),
            ("telnet", resolved["telnet"] is not None),
            ("http", resolved["http"] is not None),
            ("https", resolved["https"] is not None),
            ("syslog", bool(syslog)),
            ("ntp", bool(ntp)),
        )
        if present
    )
    return GenericResult(
        baseline=baseline,
        mapped=mapped,
        total_basics=len(BASICS),
        unmatched_count=unmatched_count,
        conflicts=conflicts,
    )


def flatten_lines(text: str) -> list[tuple[int, tuple[str, ...], bool]]:
    if not isinstance(text, str):
        raise TypeError(f"text must be a str, got {type(text).__name__}")
    lines, _ = _flatten(text)
    return [(line.number, line.words, _is_sensitive(line.words)) for line in lines]
