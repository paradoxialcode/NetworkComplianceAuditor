"""
Immutable, validated container for a trained set of pattern rules.

A :class:`PatternModel` is what a trainer produces and what a matcher or the
compliance engine consumes: a versioned, timestamped, canonically ordered
collection of :class:`~auditor.parsers.patterns.PatternRule` objects with
fast, read-only lookups. This module only MODELS and VALIDATES; matching,
persistence, training and compliance evaluation live elsewhere.

Guarantees:
    - Frozen, slotted and hashable. Lookup indexes are built once and exposed
      read-only; they are excluded from equality, hashing and ``repr``.
    - ``model_id`` is a lower-cased slug (same format as a rule id).
    - ``version`` is a positive integer; ``created_at`` must be
      timezone-aware and is normalized to UTC.
    - ``rules`` accepts any iterable of ``PatternRule`` (list, tuple, set,
      generator). It is validated (every item a PatternRule, unique rule ids
      after normalization) and stored as a tuple in canonical order
      (vendor, target field, rule id). Two models built from the same rules
      in any order are therefore equal and hash alike.
    - Rules are already validated and secret-free, and the only other text is
      the optional ``source`` (a validated ``RuleSource``), so a model never
      holds or exposes secrets. Error messages never echo field values.

Notes:
    - ``len(model)`` is the rule count, so an empty model is falsy; test
      ``model is None`` rather than ``if model``.
    - A rule's position carries no priority; ordering is only for
      determinism.
    - Rule count is not capped; callers loading untrusted rule files should
      bound the size before constructing a model.

Example:
    >>> from datetime import datetime, timezone
    >>> rule = PatternRule(
    ...     rule_id="cisco-http",
    ...     vendor="cisco_ios",
    ...     method="exact",
    ...     expression="ip http server",
    ...     target_field="http_management_enabled",
    ...     suggested_value=True,
    ...     confidence=0.9,
    ...     explanation="Clear-text HTTP management is enabled.",
    ... )
    >>> model = PatternModel(
    ...     model_id="Baseline-V1",
    ...     version=1,
    ...     created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    ...     rules=(rule,),
    ... )
    >>> model.model_id
    'baseline-v1'
    >>> len(model)
    1
    >>> model.for_target(Vendor.CISCO_IOS, "http_management_enabled") == (rule,)
    True
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType

from auditor.parsers.normalizer import Vendor
from auditor.training.patterns import (
    TARGET_FIELD_TYPES,
    PatternRule,
    RuleSource,
    ensure_unique_rule_ids,
)

__all__ = ["PatternModel"]

_MODEL_ID = re.compile(r"[a-z0-9][a-z0-9._:-]{0,63}")


def _clean_model_id(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"model_id must be a str, got {type(value).__name__}")
    text = value.strip().lower()
    if _MODEL_ID.fullmatch(text) is None:
        raise ValueError(
            "model_id must start with a letter or digit and contain only "
            "letters, digits, '.', '_', ':' or '-' (max 64 characters)"
        )
    return text


def _clean_version(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"version must be an int, got {type(value).__name__}")
    if value < 1:
        raise ValueError("version must be >= 1")
    return value


def _clean_created_at(value: object) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"created_at must be a datetime, got {type(value).__name__}")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("created_at must be timezone-aware")
    return value.astimezone(timezone.utc)


def _canonical_key(rule: PatternRule) -> tuple[str, str, str]:
    return (rule.vendor.value, rule.target_field, rule.rule_id)


def _clean_rules(value: object) -> tuple[PatternRule, ...]:
    if isinstance(value, (str, bytes, Mapping)) or not isinstance(value, Iterable):
        raise TypeError(
            f"rules must be an iterable of PatternRule, got {type(value).__name__}"
        )
    items = list(value)
    ensure_unique_rule_ids(items)  # TypeError for non-rules, ValueError for duplicates
    return tuple(sorted(items, key=_canonical_key))


def _require_vendor(value: object) -> Vendor:
    if not isinstance(value, Vendor):
        raise TypeError(f"vendor must be a Vendor, got {type(value).__name__}")
    return value


@dataclass(frozen=True, slots=True)
class PatternModel:
    """A versioned, immutable set of pattern rules.

    Attributes:
        model_id: Lower-cased slug identifying the model.
        version: Positive integer revision of the model.
        created_at: Creation time, timezone-aware, stored in UTC.
        rules: Rules in canonical order (see the module docstring). Any
            iterable of ``PatternRule`` is accepted at construction.
        source: Optional description of what the model was trained from.

    Raises:
        TypeError: If a field has the wrong type.
        ValueError: If a field is invalid or rule ids are not unique.
    """

    model_id: str
    version: int
    created_at: datetime
    rules: tuple[PatternRule, ...] = ()
    source: RuleSource | None = None
    _by_id: Mapping[str, PatternRule] = field(init=False, repr=False, compare=False)
    _by_key: Mapping[tuple[Vendor, str], tuple[PatternRule, ...]] = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        model_id = _clean_model_id(self.model_id)
        version = _clean_version(self.version)
        created_at = _clean_created_at(self.created_at)
        rules = _clean_rules(self.rules)

        source = self.source
        if source is not None and not isinstance(source, RuleSource):
            raise TypeError("source must be a RuleSource or None")

        buckets: dict[tuple[Vendor, str], list[PatternRule]] = {}
        for rule in rules:
            buckets.setdefault((rule.vendor, rule.target_field), []).append(rule)

        object.__setattr__(self, "model_id", model_id)
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(self, "rules", rules)
        object.__setattr__(
            self, "_by_id", MappingProxyType({rule.rule_id: rule for rule in rules})
        )
        object.__setattr__(
            self,
            "_by_key",
            MappingProxyType({key: tuple(group) for key, group in buckets.items()}),
        )

    # ---- read-only access -------------------------------------------------
    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self) -> Iterator[PatternRule]:
        return iter(self.rules)

    def __contains__(self, item: object) -> bool:
        """True for a rule id (any case) or for exactly this rule."""

        if isinstance(item, PatternRule):
            return self._by_id.get(item.rule_id) == item
        if isinstance(item, str):
            return item.strip().lower() in self._by_id
        return False

    def get(self, rule_id: str) -> PatternRule | None:
        """Return the rule with this id (case-insensitive), or None."""

        if not isinstance(rule_id, str):
            raise TypeError(f"rule_id must be a str, got {type(rule_id).__name__}")
        return self._by_id.get(rule_id.strip().lower())

    @property
    def vendors(self) -> tuple[Vendor, ...]:
        """Vendors that have at least one rule, in ``Vendor`` order."""

        present = {vendor for vendor, _ in self._by_key}
        return tuple(vendor for vendor in Vendor if vendor in present)

    def for_vendor(self, vendor: Vendor) -> tuple[PatternRule, ...]:
        """All rules for ``vendor`` in canonical order."""

        wanted = _require_vendor(vendor)
        return tuple(rule for rule in self.rules if rule.vendor is wanted)

    def for_target(self, vendor: Vendor, target_field: str) -> tuple[PatternRule, ...]:
        """Rules for ``vendor`` that suggest a value for ``target_field``.

        Raises:
            TypeError: If ``vendor`` is not a Vendor or ``target_field`` is
                not a str.
            ValueError: If ``target_field`` is not a suggestable field, which
                catches typos instead of returning an empty result.
        """

        wanted = _require_vendor(vendor)
        if not isinstance(target_field, str):
            raise TypeError(
                f"target_field must be a str, got {type(target_field).__name__}"
            )
        if target_field not in TARGET_FIELD_TYPES:
            allowed = ", ".join(sorted(TARGET_FIELD_TYPES))
            raise ValueError(f"unsupported target_field; expected one of: {allowed}")
        return self._by_key.get((wanted, target_field), ())