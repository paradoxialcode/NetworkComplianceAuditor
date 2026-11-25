from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

from auditor.parsers.normalizer import Vendor
from auditor.schema import baseline as schema
from auditor.training import matcher
from auditor.training.patterns import PatternRule

from . import generic

logger = logging.getLogger(__name__)

MIN_CONFIDENCE: Final = generic.MIN_CONFIDENCE
MAX_LIST_ITEMS: Final = generic.MAX_LIST_ITEMS
MAX_RULE_ERRORS: Final = 3
REDACTED_TEXT: Final = "<redacted>"
ABSENT_TEXT: Final = "not present in the configuration"
MAPPING_PREFIX: Final = "trained:"

_SET_PREFIXED: Final = frozenset({Vendor.JUNOS})
_IDENTITY: Final = {Vendor.JUNOS: (schema.Vendor.Juniper, "Junos (trained rules)")}
_BOOL_FIELDS: Final = (
    "telnet_enabled",
    "http_management_enabled",
    "ssh_enabled",
    "https_enabled",
    "password_encryption",
)
_LIST_FIELDS: Final = ("ntp_servers", "syslog_servers", "local_users")
_FALLBACK_HOSTNAME: Final = "unknown-device"
_LINE_REF: Final = re.compile(r"line (\d+)")
_State = schema.SecurityState


@dataclass(frozen=True, slots=True)
class _Hit:
    value: bool | str
    confidence: float
    line: int | None
    rule_id: str
    text: str


@dataclass(frozen=True)
class TrainedResult:
    baseline: schema.SecurityBaseline
    mapped: tuple[str, ...]
    total_basics: int
    rules_total: int
    rules_matched: int
    lines_matched: int
    rule_errors: int


def _clip(text: str, limit: int = 200) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _evidence(hit: _Hit) -> schema.Evidence:
    return schema.Evidence(
        text=hit.text,
        line=hit.line,
        mapping_id=f"{MAPPING_PREFIX}{hit.rule_id}",
        confidence=hit.confidence,
    )


def _good(hits: list[_Hit]) -> list[_Hit]:
    return [hit for hit in hits if hit.confidence >= MIN_CONFIDENCE]


def _best(hits: list[_Hit]) -> _Hit:
    return max(hits, key=lambda hit: (hit.confidence, -(hit.line or 0)))


def _pick_bool(hits: list[_Hit]) -> tuple[_Hit | None, bool]:
    good = _good(hits)
    if not good:
        return None, False
    if {hit.value for hit in good} == {True, False}:
        return None, True
    return _best(good), False


def _pick_single(hits: list[_Hit]) -> tuple[_Hit | None, bool]:
    good = _good(hits)
    if not good:
        return None, False
    top = _best(good)
    rivals = {hit.value for hit in good if hit.confidence == top.confidence and hit.value != top.value}
    if rivals:
        return None, True
    return top, False


def _pick_many(hits: list[_Hit]) -> list[_Hit]:
    seen: dict[str, _Hit] = {}
    for hit in sorted(_good(hits), key=lambda item: item.line or 0):
        if isinstance(hit.value, str):
            seen.setdefault(hit.value, hit)
    return list(seen.values())[:MAX_LIST_ITEMS]


def _state(value: bool) -> schema.SecurityState:
    return _State.ENABLED if value else _State.DISABLED


def _basics(baseline: schema.SecurityBaseline) -> tuple[str, ...]:
    keys = {fact.key for fact in baseline.facts}
    management = baseline.management
    present = (
        ("hostname", baseline.device.hostname != _FALLBACK_HOSTNAME),
        ("os_version", baseline.device.version is not None),
        ("serial_number", "serial_number" in keys),
        ("hardware_model", "hardware_model" in keys),
        ("ssh", management.ssh is not _State.UNKNOWN),
        ("telnet", management.telnet is not _State.UNKNOWN),
        ("http", management.http is not _State.UNKNOWN),
        ("https", management.https is not _State.UNKNOWN),
        ("syslog", bool(baseline.logging.destinations)),
        ("ntp", bool(baseline.time_sync.servers)),
    )
    return tuple(name for name, ok in present if ok)


def build_trained_baseline(
    text: str,
    rules: Iterable[PatternRule],
    vendor: Vendor,
    *,
    filename: str | None = None,
    sha256: str | None = None,
) -> TrainedResult:
    if not isinstance(text, str):
        raise TypeError(f"text must be a str, got {type(text).__name__}")
    if not isinstance(vendor, Vendor):
        raise TypeError(f"vendor must be a Vendor, got {type(vendor).__name__}")
    collected = tuple(rules)
    for rule in collected:
        if not isinstance(rule, PatternRule):
            raise TypeError(f"rules must contain PatternRule objects, got {type(rule).__name__}")
    active = tuple(rule for rule in collected if rule.vendor is vendor)
    if not active:
        raise ValueError("no trained rules for this vendor")

    base = generic.build_generic_baseline(text, filename=filename, sha256=sha256).baseline
    prefix = "set " if vendor in _SET_PREFIXED else ""
    hits: dict[str, list[_Hit]] = {field: [] for field in ("hostname", *_BOOL_FIELDS, *_LIST_FIELDS)}
    matched_rules: set[str] = set()
    matched_lines: set[int] = set()
    error_counts: dict[str, int] = {}
    disabled: set[str] = set()

    for number, words, sensitive in generic.flatten_lines(text):
        line_text = prefix + " ".join(words)
        for rule in active:
            if rule.rule_id in disabled:
                continue
            try:
                resolution = matcher.resolve(rule, line_text)
            except ValueError:
                count = error_counts.get(rule.rule_id, 0) + 1
                error_counts[rule.rule_id] = count
                if count >= MAX_RULE_ERRORS:
                    disabled.add(rule.rule_id)
                    logger.warning("trained rule disabled after repeated errors: %s", rule.rule_id)
                continue
            if not resolution.matched:
                continue
            matched_rules.add(rule.rule_id)
            matched_lines.add(number)
            if resolution.value is None or (sensitive and rule.capture_group is not None):
                continue
            hits[rule.target_field].append(
                _Hit(
                    value=resolution.value,
                    confidence=rule.confidence,
                    line=number,
                    rule_id=rule.rule_id,
                    text=REDACTED_TEXT if sensitive else _clip(line_text),
                )
            )

    if matched_rules:
        for rule in active:
            if rule.absent_value is not None and rule.rule_id not in matched_rules and rule.rule_id not in disabled:
                hits[rule.target_field].append(
                    _Hit(rule.absent_value, rule.confidence, None, rule.rule_id, ABSENT_TEXT)
                )

    vendor_value, platform = _IDENTITY.get(vendor, (schema.Vendor.Unknown, "Unknown (trained rules)"))
    facts = list(base.facts)
    notes: list[schema.UnrecognizedConfig] = []

    def conflict(field: str) -> None:
        notes.append(
            schema.UnrecognizedConfig(
                text=f"conflicting trained rules for {field}; value left undetermined",
                vendor=vendor_value,
                location=None,
                reason="conflict",
            )
        )

    def put_fact(key: str, value: object, state: schema.SecurityState | None, hit: _Hit) -> None:
        facts[:] = [fact for fact in facts if fact.key != key]
        facts.append(schema.SecurityFact(key=key, value=value, state=state, evidence=_evidence(hit)))

    def drop_fact(key: str) -> None:
        facts[:] = [fact for fact in facts if fact.key != key]

    management = base.management
    states: dict[str, schema.SecurityState] = {}
    for field in _BOOL_FIELDS:
        picked, conflicted = _pick_bool(hits[field])
        if conflicted:
            conflict(field)
            drop_fact(field)
            states[field] = _State.UNKNOWN
        elif picked is not None:
            put_fact(field, picked.value, _state(bool(picked.value)), picked)
            states[field] = _state(bool(picked.value))
    updates = {}
    if "telnet_enabled" in states:
        updates["telnet"] = states["telnet_enabled"]
    if "http_management_enabled" in states:
        updates["http"] = states["http_management_enabled"]
    if "ssh_enabled" in states:
        updates["ssh"] = states["ssh_enabled"]
    if "https_enabled" in states:
        updates["https"] = states["https_enabled"]
    if updates:
        management = management.model_copy(update=updates)

    device = base.device.model_copy(update={"vendor": vendor_value, "platform": platform})
    host, host_conflict = _pick_single(hits["hostname"])
    if host_conflict:
        conflict("hostname")
    elif host is not None:
        device = device.model_copy(update={"hostname": str(host.value)})

    logging_settings, time_sync, auth = base.logging, base.time_sync, base.auth
    syslog = _pick_many(hits["syslog_servers"])
    if syslog:
        logging_settings = logging_settings.model_copy(
            update={"enabled": _State.ENABLED, "destinations": [str(hit.value) for hit in syslog]}
        )
    ntp = _pick_many(hits["ntp_servers"])
    if ntp:
        time_sync = time_sync.model_copy(
            update={"enabled": _State.ENABLED, "servers": [str(hit.value) for hit in ntp]}
        )
    users = _pick_many(hits["local_users"])
    if users:
        auth = auth.model_copy(update={"local": _State.ENABLED})
        put_fact("local_users", [str(hit.value) for hit in users], _State.ENABLED, users[0])

    for rule_id in sorted(disabled):
        notes.append(
            schema.UnrecognizedConfig(
                text=f"trained rule {rule_id} was skipped after repeated evaluation errors",
                vendor=vendor_value,
                location=None,
                reason="rule error",
            )
        )

    def still_unmatched(item: schema.UnrecognizedConfig) -> bool:
        found = _LINE_REF.fullmatch(item.location or "")
        return not (found and int(found.group(1)) in matched_lines)

    baseline = base.model_copy(
        update={
            "device": device,
            "management": management,
            "auth": auth,
            "logging": logging_settings,
            "time_sync": time_sync,
            "facts": facts,
            "unrecognized": [item for item in base.unrecognized if still_unmatched(item)] + notes,
        }
    )
    return TrainedResult(
        baseline=baseline,
        mapped=_basics(baseline),
        total_basics=len(generic.BASICS),
        rules_total=len(active),
        rules_matched=len(matched_rules),
        lines_matched=len(matched_lines),
        rule_errors=sum(error_counts.values()),
    )
