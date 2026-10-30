"""
Immutable, validated pattern-rule models for the Multi-Vendor Network
Security Compliance Auditor.

A :class:`PatternRule` is a reusable training rule: "for this vendor, a
configuration line that matches this expression suggests this value for this
``SecurityBaseline`` field". This module only MODELS and VALIDATES such rules.
Matching, persistence, training and compliance evaluation live elsewhere.

Guarantees:
    - Everything is immutable (frozen dataclasses with slots) and hashable.
    - All text is Unicode-NFC normalized and stripped, free of control and
      invisible formatting characters, and length-limited. Prose fields
      (explanation, source metadata) also have their whitespace collapsed.
    - ``vendor`` and ``method`` accept the enum member or its string value
      (case-insensitive) so rules can be built from JSON/YAML; anything else
      is rejected.
    - ``target_field`` must be a real, suggestable ``SecurityBaseline`` field
      available for the rule's vendor, and ``suggested_value`` must have that
      field's type (strict: ``"true"`` or ``1`` is not a bool).
    - ``confidence`` is a finite number in 0.0-1.0 and is stored as a float.
    - A ``REGEX`` expression must compile, must not match the empty string,
      must not use character-class syntax that Python warns will change
      meaning (nested ``[``, ``--``, ``&&``, ``~~``, ``||``), and must survive
      the adversarial probes of :mod:`auditor.regex_safety` (a pattern prone
      to catastrophic backtracking such as ``(a+)+$`` is rejected).
    - ``capture_group`` (REGEX rules on text fields) makes the rule take its
      value from that group of the matching line instead of a constant, and
      then ``suggested_value`` must be ``None``.
    - ``absent_value`` (boolean fields) is the value the field takes when no
      line matches the rule; see :mod:`auditor.audit.trained` for when it
      applies.
    - Secrets are rejected, never stored: private keys, password hashes, URL
      credentials, long high-entropy tokens, and (in configuration-like text)
      a secret keyword followed by a literal value. Error messages name the
      field and the kind of problem but never echo the offending text.

Uniqueness:
    A single frozen model cannot know its siblings, so ``rule_id`` format is
    validated per rule and uniqueness across a rule set is checked with
    :func:`ensure_unique_rule_ids`.

Known limitations:
    - The secret scan is a heuristic: it cannot recognize a short secret that
      stands alone (for example a bare 12-character hash). To describe a
      credential line, end the expression at the keyword
      (``username admin secret``) or use a regex placeholder
      (``^username \\S+ secret \\S+$``).
    - Regular expressions are checked for syntax, for ambiguous
      character-class syntax, for matching the empty string and against a
      fixed set of adversarial probes. The probes cannot prove a pattern safe,
      so the matcher also enforces a per-match timeout.
    - Expressions are stored trimmed, because configuration tokens are
      trimmed; leading or trailing spaces in an expression are not preserved.

Example:
    >>> rule = PatternRule(
    ...     rule_id="Cisco-HTTP-Server",
    ...     vendor="cisco_ios",
    ...     method="exact",
    ...     expression="ip http server",
    ...     target_field="http_management_enabled",
    ...     suggested_value=True,
    ...     confidence=0.9,
    ...     explanation="Clear-text HTTP management is enabled.",
    ... )
    >>> rule.rule_id
    'cisco-http-server'
    >>> rule.vendor
    <Vendor.CISCO_IOS: 'cisco_ios'>
    >>> rule.confidence
    0.9
"""

from __future__ import annotations

import dataclasses
import math
import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TypeVar

from auditor import regex_safety
from auditor.parsers.normalizer import SecurityBaseline, Vendor
from auditor.parsers.tokenizers.fortinet import SENSITIVE_KEYS as _FORTI_SENSITIVE_KEYS

__all__ = [
    "MatchMethod",
    "RuleSource",
    "PatternRule",
    "TARGET_FIELD_TYPES",
    "clean_captured_value",
    "ensure_unique_rule_ids",
]

MAX_EXPRESSION_LENGTH = 256
MAX_SUGGESTED_LENGTH = 255
MAX_EXPLANATION_LENGTH = 500
MAX_SOURCE_NAME_LENGTH = 100
MAX_SOURCE_REFERENCE_LENGTH = 300
MAX_SOURCE_VERSION_LENGTH = 50
MAX_TARGET_LENGTH = 64

_RULE_ID = re.compile(r"[a-z0-9][a-z0-9._:-]{0,63}")

E = TypeVar("E", bound=StrEnum)


class MatchMethod(StrEnum):
    """How a rule's expression is compared with a configuration line."""

    EXACT = "exact"
    PREFIX = "prefix"
    REGEX = "regex"


# SecurityBaseline fields a rule may suggest a value for, with the type the
# suggested value must have. For the collection fields the value is one entry
# (one NTP server, one username, ...).
TARGET_FIELD_TYPES: Mapping[str, type] = MappingProxyType(
    {
        "hostname": str,
        "ntp_servers": str,
        "syslog_servers": str,
        "local_users": str,
        "telnet_enabled": bool,
        "http_management_enabled": bool,
        "password_encryption": bool,
    }
)

# Fields that exist for only some vendors; unlisted fields apply to all.
_FIELD_VENDORS: Mapping[str, frozenset[Vendor]] = MappingProxyType(
    {"password_encryption": frozenset({Vendor.CISCO_IOS})}
)


def _verify_targets(baseline_fields: Iterable[str]) -> None:
    """Fail loudly if a target field no longer exists on SecurityBaseline."""

    known = set(baseline_fields)
    missing = sorted(set(TARGET_FIELD_TYPES) - known)
    if missing:
        raise RuntimeError(
            "TARGET_FIELD_TYPES refers to fields missing from SecurityBaseline: "
            + ", ".join(missing)
        )


_verify_targets(field.name for field in dataclasses.fields(SecurityBaseline))


# --------------------------------------------------------------------------
# Secret detection
# --------------------------------------------------------------------------

_SECRET_KEYWORDS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "passphrase",
        "secret",
        "psksecret",
        "key-string",
        "authentication-key",
        "authentication-password",
        "privacy-password",
        "pre-shared-key",
        "private-key",
        "encrypted-password",
        "community",
        "md5-key",
    }
) | _FORTI_SENSITIVE_KEYS

_REGEX_META = frozenset("\\^$.*+?()[]{}|")
_WORD_RUNS = re.compile(r"[A-Za-z0-9_-]+")
_PEM = re.compile(r"-----(?:BEGIN|END)\b", re.IGNORECASE)
_CRYPT_HASH = re.compile(r"\$[0-9a-z]{1,3}\$[^\s$]{3,}", re.IGNORECASE)
_URL_CREDENTIALS = re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@", re.IGNORECASE)
_URL_SECRET_PARAM = re.compile(
    r"[?&](?:token|access_token|api[_-]?key|key|secret|password|passwd|pwd|"
    r"sig|signature|auth)=[^&\s]+",
    re.IGNORECASE,
)
_LONG_TOKEN = re.compile(r"[A-Za-z0-9+/=]{32,}")


def _starts_literal(word: str) -> bool:
    """True if ``word`` could be a literal value rather than a regex placeholder.

    Judged by the first character only: ``hunter2$`` and ``hunter2|x)`` start
    like a literal value, while ``\\S+``, ``(5|9)`` and ``.*`` do not.
    """

    return bool(word) and word[0] not in _REGEX_META


def _find_secret(text: str, *, config_like: bool) -> str | None:
    """Return the KIND of secret found in ``text``, never the secret itself.

    Args:
        text: Text to scan.
        config_like: True for configuration-style text, where a secret
            keyword followed by a literal word counts as a credential. Prose
            is exempt from that check ("password policy" is not a secret).
    """

    for candidate in (text, text.replace("\\", "")):
        if _PEM.search(candidate):
            return "PEM block"
        if _CRYPT_HASH.search(candidate):
            return "password hash"
        if _URL_CREDENTIALS.search(candidate):
            return "URL credentials"
        if _URL_SECRET_PARAM.search(candidate):
            return "URL secret parameter"
        for run in _LONG_TOKEN.findall(candidate):
            if any(ch.isdigit() for ch in run) and any(ch.isalpha() for ch in run):
                return "high-entropy token"

    if config_like:
        words = text.split()
        for index in range(len(words) - 1):
            if not _starts_literal(words[index + 1]):
                continue
            # Runs, not whole words, so "^password", "(?:secret)" and
            # "(password|secret)" are still recognized as keywords.
            if any(run.lower() in _SECRET_KEYWORDS for run in _WORD_RUNS.findall(words[index])):
                return "credential value"

    return None


def _reject_secret(text: str, field: str, *, config_like: bool) -> None:
    kind = _find_secret(text, config_like=config_like)
    if kind is not None:
        raise ValueError(f"{field} must not contain a secret ({kind})")


# --------------------------------------------------------------------------
# Field cleaning
# --------------------------------------------------------------------------


def _clean_text(value: object, field: str, *, max_length: int, collapse: bool) -> str:
    """NFC-normalize, strip and validate one text field."""

    if not isinstance(value, str):
        raise TypeError(f"{field} must be a str, got {type(value).__name__}")

    text = unicodedata.normalize("NFC", value).strip()
    if collapse:
        text = " ".join(text.split())

    if not text:
        raise ValueError(f"{field} must not be empty")
    if len(text) > max_length:
        raise ValueError(f"{field} must be at most {max_length} characters")

    for ch in text:
        if unicodedata.category(ch).startswith("C"):
            raise ValueError(f"{field} must not contain control or invisible characters")
        if ch.isspace() and ch != " ":
            raise ValueError(f"{field} must not contain non-space whitespace")

    return text


def _clean_prose(value: object, field: str, max_length: int) -> str:
    text = _clean_text(value, field, max_length=max_length, collapse=True)
    _reject_secret(text, field, config_like=False)
    return text


def _clean_rule_id(value: object) -> str:
    text = _clean_text(value, "rule_id", max_length=64, collapse=False).lower()
    if _RULE_ID.fullmatch(text) is None:
        raise ValueError(
            "rule_id must start with a letter or digit and contain only "
            "letters, digits, '.', '_', ':' or '-' (max 64 characters)"
        )
    return text


def _coerce_enum(value: object, enum_cls: type[E], field: str) -> E:
    if isinstance(value, enum_cls):
        return value
    if not isinstance(value, str):
        raise TypeError(
            f"{field} must be a {enum_cls.__name__} or str, got {type(value).__name__}"
        )
    try:
        return enum_cls(value.strip().lower())
    except ValueError:
        allowed = ", ".join(member.value for member in enum_cls)
        raise ValueError(f"unsupported {field}; expected one of: {allowed}") from None


def _has_ambiguous_set_syntax(expression: str) -> bool:
    """True for character-class syntax whose meaning changes across Pythons.

    Python warns (FutureWarning) about a ``[`` inside a class and about
    ``--``, ``&&``, ``~~`` and ``||`` inside one, because a future version
    will treat them as set operations. Such a rule would silently change
    meaning, so it is rejected. This scan is deliberately a superset of what
    CPython warns about, and does not depend on process-wide warning filters.
    """

    in_class = False
    index = 0
    length = len(expression)
    while index < length:
        ch = expression[index]
        if ch == "\\":
            index += 2
            continue
        if not in_class:
            if ch == "[":
                in_class = True
                index += 1
                if index < length and expression[index] == "^":
                    index += 1
                if index < length and expression[index] == "]":
                    index += 1  # a leading "]" is a literal member
                continue
        elif ch == "[":
            return True
        elif ch == "]":
            in_class = False
        elif expression[index : index + 2] in ("--", "&&", "~~", "||"):
            return True
        index += 1
    return False


def _validate_regex(expression: str) -> None:
    if _has_ambiguous_set_syntax(expression):
        raise ValueError(
            "expression uses character-class syntax whose meaning is ambiguous "
            "across Python versions (nested '[', '--', '&&', '~~' or '||')"
        )
    try:
        compiled = re.compile(expression)
    except re.error as exc:
        where = f" at position {exc.pos}" if exc.pos is not None else ""
        raise ValueError(
            f"expression is not a valid regular expression: {exc.msg}{where}"
        ) from None
    except (OverflowError, RecursionError):
        raise ValueError(
            "expression is not a valid regular expression: pattern too complex "
            "or repeat count too large"
        ) from None

    if compiled.search("") is not None:
        raise ValueError("regular expression must not match the empty string")

    try:
        regex_safety.compile_pattern(expression)
    except regex_safety.UnsafePatternError:
        raise ValueError(
            "regular expression is too slow on adversarial input "
            "(possible catastrophic backtracking)"
        ) from None
    except ValueError:
        raise ValueError(
            "expression is not supported by the matching engine"
        ) from None


def _clean_expression(value: object, method: MatchMethod) -> str:
    text = _clean_text(value, "expression", max_length=MAX_EXPRESSION_LENGTH, collapse=False)
    # Scan BEFORE compiling: compile errors can quote parts of the pattern.
    _reject_secret(text, "expression", config_like=True)
    if method is MatchMethod.REGEX:
        _validate_regex(text)
    return text


def _clean_target(value: object, vendor: Vendor) -> str:
    text = _clean_text(value, "target_field", max_length=MAX_TARGET_LENGTH, collapse=False)
    if text not in TARGET_FIELD_TYPES:
        allowed = ", ".join(sorted(TARGET_FIELD_TYPES))
        raise ValueError(f"unsupported target_field; expected one of: {allowed}")
    vendors = _FIELD_VENDORS.get(text)
    if vendors is not None and vendor not in vendors:
        raise ValueError(f"target_field '{text}' is not available for vendor {vendor.value}")
    return text


def _clean_capture_group(
    value: object, method: MatchMethod, expression: str, target: str
) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"capture_group must be an int or None, got {type(value).__name__}")
    if method is not MatchMethod.REGEX:
        raise ValueError("capture_group requires method 'regex'")
    if TARGET_FIELD_TYPES[target] is not str:
        raise ValueError("capture_group requires a text target_field")
    groups = re.compile(expression).groups
    if not 1 <= value <= groups:
        raise ValueError(f"capture_group must be between 1 and {groups} for this expression")
    return value


def _clean_absent(value: object, target: str) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise TypeError(f"absent_value must be a bool or None, got {type(value).__name__}")
    if TARGET_FIELD_TYPES[target] is not bool:
        raise ValueError("absent_value requires a boolean target_field")
    return value


def clean_captured_value(value: object) -> str | None:
    """Return ``value`` as a safe text value, or ``None`` if it is not one.

    Used for text captured from a configuration line: it must be non-empty,
    single-spaced, free of control characters, at most 255 characters and free
    of secrets. The reason for a rejection is deliberately not reported, since
    it could echo configuration content.
    """

    try:
        text = _clean_text(
            value, "captured value", max_length=MAX_SUGGESTED_LENGTH, collapse=True
        )
        _reject_secret(text, "captured value", config_like=True)
    except (TypeError, ValueError):
        return None
    return text


def _clean_suggested(value: object, target: str, *, captured: bool = False) -> str | bool | None:
    if captured:
        if value is not None:
            raise ValueError("suggested_value must be None when capture_group is set")
        return None

    if TARGET_FIELD_TYPES[target] is bool:
        if not isinstance(value, bool):
            raise TypeError(
                f"suggested_value for '{target}' must be a bool, got {type(value).__name__}"
            )
        return value

    text = _clean_text(
        value, "suggested_value", max_length=MAX_SUGGESTED_LENGTH, collapse=True
    )
    _reject_secret(text, "suggested_value", config_like=True)
    return text


def _clean_confidence(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"confidence must be a number, got {type(value).__name__}")
    if isinstance(value, int) and not 0 <= value <= 1:
        raise ValueError("confidence must be between 0.0 and 1.0")
    number = float(value)
    if math.isnan(number) or not 0.0 <= number <= 1.0:
        raise ValueError("confidence must be between 0.0 and 1.0")
    return number + 0.0  # normalizes -0.0 to 0.0


# --------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RuleSource:
    """Where a rule came from (all text is validated and secret-free).

    Attributes:
        name: Source name, for example a benchmark or runbook.
        reference: Optional section, document or URL.
        version: Optional source version.
    """

    name: str
    reference: str | None = None
    version: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "name", _clean_prose(self.name, "source name", MAX_SOURCE_NAME_LENGTH)
        )
        if self.reference is not None:
            object.__setattr__(
                self,
                "reference",
                _clean_prose(self.reference, "source reference", MAX_SOURCE_REFERENCE_LENGTH),
            )
        if self.version is not None:
            object.__setattr__(
                self,
                "version",
                _clean_prose(self.version, "source version", MAX_SOURCE_VERSION_LENGTH),
            )


@dataclass(frozen=True, slots=True)
class PatternRule:
    """A reusable training rule.

    Attributes:
        rule_id: Rule identifier, lower-cased; unique within a rule set
            (see :func:`ensure_unique_rule_ids`).
        vendor: Vendor the rule applies to. A ``Vendor`` or its string value.
        method: How ``expression`` is compared. A ``MatchMethod`` or its
            string value.
        expression: The match expression (a valid, non-empty-matching regex
            for ``REGEX``).
        target_field: ``SecurityBaseline`` field the rule suggests a value
            for; one of ``TARGET_FIELD_TYPES``.
        suggested_value: Suggested value; a bool for boolean fields, one
            text entry for the others, ``None`` only when ``capture_group``
            is set.
        confidence: Confidence in 0.0-1.0, stored as a float.
        explanation: Human-readable reason for the rule.
        source: Optional description of where the rule came from.
        capture_group: Optional 1-based regex group whose text becomes the
            value (``REGEX`` rules on text fields only).
        absent_value: Optional bool the field takes when no line matches this
            rule (boolean fields only).

    Raises:
        TypeError: If a field has the wrong type.
        ValueError: If a field is invalid, unsupported, malformed or would
            contain a secret.
    """

    rule_id: str
    vendor: Vendor
    method: MatchMethod
    expression: str
    target_field: str
    suggested_value: str | bool | None
    confidence: float
    explanation: str
    source: RuleSource | None = None
    capture_group: int | None = None
    absent_value: bool | None = None

    def __post_init__(self) -> None:
        rule_id = _clean_rule_id(self.rule_id)
        vendor = _coerce_enum(self.vendor, Vendor, "vendor")
        method = _coerce_enum(self.method, MatchMethod, "method")
        expression = _clean_expression(self.expression, method)
        target = _clean_target(self.target_field, vendor)
        capture = _clean_capture_group(self.capture_group, method, expression, target)
        absent = _clean_absent(self.absent_value, target)
        suggested = _clean_suggested(self.suggested_value, target, captured=capture is not None)
        confidence = _clean_confidence(self.confidence)
        explanation = _clean_prose(self.explanation, "explanation", MAX_EXPLANATION_LENGTH)

        source = self.source
        if source is not None and not isinstance(source, RuleSource):
            raise TypeError("source must be a RuleSource or None")

        object.__setattr__(self, "rule_id", rule_id)
        object.__setattr__(self, "vendor", vendor)
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "expression", expression)
        object.__setattr__(self, "target_field", target)
        object.__setattr__(self, "suggested_value", suggested)
        object.__setattr__(self, "confidence", confidence)
        object.__setattr__(self, "explanation", explanation)
        object.__setattr__(self, "capture_group", capture)
        object.__setattr__(self, "absent_value", absent)


def ensure_unique_rule_ids(rules: Iterable[PatternRule]) -> None:
    """Raise if two rules share a ``rule_id``.

    Args:
        rules: Rules to check.

    Raises:
        TypeError: If an item is not a PatternRule.
        ValueError: Listing every duplicated ``rule_id``.
    """

    seen: set[str] = set()
    duplicates: list[str] = []
    for rule in rules:
        if not isinstance(rule, PatternRule):
            raise TypeError(f"rules must contain only PatternRule, got {type(rule).__name__}")
        if rule.rule_id in seen and rule.rule_id not in duplicates:
            duplicates.append(rule.rule_id)
        seen.add(rule.rule_id)

    if duplicates:
        raise ValueError("duplicate rule_id values: " + ", ".join(duplicates))


if __name__ == "__main__":
    import doctest

    doctest.testmod()