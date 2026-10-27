"""Tests for PatternModel (auditor model.py)."""

from __future__ import annotations

import dataclasses
import importlib
from collections.abc import Iterator
from datetime import date, datetime, timedelta, timezone, tzinfo
from types import MappingProxyType, ModuleType
from typing import Any

import pytest

# --------------------------------------------------------------------------
# Locate model.py. PatternRule, Vendor and RuleSource are taken from the model
# module itself, so the tests always use the exact classes it validates with.
# --------------------------------------------------------------------------

_MODEL_MODULES = ("auditor.db.models",)


def _load_model_module() -> ModuleType:
    for name in _MODEL_MODULES:
        try:
            return importlib.import_module(name)
        except ModuleNotFoundError as exc:
            if exc.name != name:
                raise  # a dependency INSIDE model.py is missing (wrong import)
    raise ImportError("model.py not found; checked: " + ", ".join(_MODEL_MODULES))


_module = _load_model_module()
PatternModel: Any = _module.PatternModel
PatternRule: Any = _module.PatternRule
RuleSource: Any = _module.RuleSource
Vendor: Any = _module.Vendor

CISCO = Vendor.CISCO_IOS
FORTI = Vendor.FORTIOS
CREATED = datetime(2026, 1, 1, tzinfo=timezone.utc)
SECRET = "hunter2"


class _NoOffset(tzinfo):
    """A tzinfo whose utcoffset() is None (so the datetime is not aware)."""

    def utcoffset(self, dt: datetime | None) -> timedelta | None:
        return None

    def dst(self, dt: datetime | None) -> timedelta | None:
        return None

    def tzname(self, dt: datetime | None) -> str | None:
        return None


# --------------------------------------------------------------------------
# Rule and model factories
# --------------------------------------------------------------------------

_SUGGESTED_CANDIDATES: tuple[object, ...] = (True, "example.com", "example", False)

RULE_SPECS: tuple[tuple[str, Any, str, str, str], ...] = (
    ("cisco-http", CISCO, "exact", "ip http server", "http_management_enabled"),
    ("cisco-telnet", CISCO, "prefix", "transport input telnet", "telnet_enabled"),
    ("cisco-host", CISCO, "prefix", "hostname", "hostname"),
    ("cisco-ntp-b", CISCO, "prefix", "ntp server", "ntp_servers"),
    ("cisco-ntp-a", CISCO, "prefix", "ntp server pool", "ntp_servers"),
    ("forti-telnet", FORTI, "exact", "set admin-telnet enable", "telnet_enabled"),
    ("forti-host", FORTI, "prefix", "set hostname", "hostname"),
)

# vendor value, then target field, then rule id
EXPECTED_ORDER = [
    "cisco-host",
    "cisco-http",
    "cisco-ntp-a",
    "cisco-ntp-b",
    "cisco-telnet",
    "forti-host",
    "forti-telnet",
]


def make_rule(
    rule_id: str,
    vendor: Any,
    method: str,
    expression: str,
    target_field: str,
) -> Any:
    last: Exception | None = None
    for candidate in _SUGGESTED_CANDIDATES:
        try:
            return PatternRule(
                rule_id=rule_id,
                vendor=vendor.value,
                method=method,
                expression=expression,
                target_field=target_field,
                suggested_value=candidate,
                confidence=0.9,
                explanation="Example explanation for tests.",
            )
        except (TypeError, ValueError) as exc:
            last = exc
    raise RuntimeError(
        "could not build a PatternRule for the tests; see __cause__"
    ) from last


@pytest.fixture
def rules() -> dict[str, Any]:
    return {spec[0]: make_rule(*spec) for spec in RULE_SPECS}


def build(rules: object = (), **overrides: object) -> Any:
    kwargs: dict[str, object] = {
        "model_id": "baseline-v1",
        "version": 1,
        "created_at": CREATED,
        "rules": rules,
    }
    kwargs.update(overrides)
    return PatternModel(**kwargs)


def ids(items: object) -> list[str]:
    return [rule.rule_id for rule in items]  # type: ignore[attr-defined]


# --------------------------------------------------------------------------
# Construction
# --------------------------------------------------------------------------


class TestConstruction:
    def test_minimal_model(self) -> None:
        model = PatternModel(
            model_id="m",
            version=1,
            created_at=CREATED,
        )
        assert model.model_id == "m"
        assert model.version == 1
        assert model.created_at == CREATED
        assert model.rules == ()
        assert model.source is None

    def test_full_model(self, rules: dict[str, Any]) -> None:
        source = RuleSource(
            name="Test benchmark",
            reference="section-1",
            version="1.0",
        )
        model = build(tuple(rules.values()), source=source)

        assert len(model.rules) == len(RULE_SPECS)
        assert model.source is source

class TestModelId:
    def test_is_stripped_and_lowercased(self) -> None:
        assert build(model_id="  Baseline-V1 ").model_id == "baseline-v1"

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param("a", id="one-char"),
            pytest.param("0abc", id="starts-with-digit"),
            pytest.param("v1.0", id="dot"),
            pytest.param("a_b", id="underscore"),
            pytest.param("a:b", id="colon"),
            pytest.param("a-b-c", id="hyphen"),
            pytest.param("a" * 64, id="max-length"),
        ],
    )
    def test_valid(self, value: str) -> None:
        assert build(model_id=value).model_id == value

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param("", id="empty"),
            pytest.param("   ", id="blank"),
            pytest.param("-a", id="leading-hyphen"),
            pytest.param(".a", id="leading-dot"),
            pytest.param("_a", id="leading-underscore"),
            pytest.param("a b", id="space"),
            pytest.param("a/b", id="slash"),
            pytest.param("a" * 65, id="too-long"),
            pytest.param("caf\u00e9", id="non-ascii"),
        ],
    )
    def test_invalid(self, value: str) -> None:
        with pytest.raises(ValueError, match="model_id must start"):
            build(model_id=value)

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param(5, id="int"),
            pytest.param(None, id="none"),
            pytest.param(b"abc", id="bytes"),
            pytest.param(["a"], id="list"),
        ],
    )
    def test_must_be_str(self, value: object) -> None:
        with pytest.raises(TypeError, match="model_id must be a str"):
            build(model_id=value)


class TestVersion:
    @pytest.mark.parametrize("value", [1, 2, 10**9])
    def test_valid(self, value: int) -> None:
        assert build(version=value).version == value

    @pytest.mark.parametrize("value", [0, -1])
    def test_must_be_positive(self, value: int) -> None:
        with pytest.raises(ValueError, match="version must be >= 1"):
            build(version=value)

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param(True, id="bool"),
            pytest.param(1.0, id="float"),
            pytest.param("1", id="str"),
            pytest.param(None, id="none"),
        ],
    )
    def test_must_be_int(self, value: object) -> None:
        with pytest.raises(TypeError, match="version must be an int"):
            build(version=value)


class TestCreatedAt:
    def test_utc_is_kept(self) -> None:
        assert build().created_at == CREATED

    def test_other_zone_is_normalized_to_utc(self) -> None:
        zone = timezone(timedelta(hours=5, minutes=30))
        model = build(created_at=datetime(2026, 1, 1, 5, 30, tzinfo=zone))
        assert model.created_at == CREATED
        assert model.created_at.tzinfo is timezone.utc
        assert model.created_at.utcoffset() == timedelta(0)
        assert (model.created_at.hour, model.created_at.minute) == (0, 0)

    def test_naive_datetime_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            build(created_at=datetime(2026, 1, 1))

    def test_tzinfo_without_offset_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            build(created_at=datetime(2026, 1, 1, tzinfo=_NoOffset()))

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param("2026-01-01", id="str"),
            pytest.param(None, id="none"),
            pytest.param(5, id="int"),
            pytest.param(date(2026, 1, 1), id="date"),
        ],
    )
    def test_must_be_datetime(self, value: object) -> None:
        with pytest.raises(TypeError, match="created_at must be a datetime"):
            build(created_at=value)


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------


class TestRules:
    def test_stored_as_tuple(self, rules: dict[str, Any]) -> None:
        model = build(list(rules.values()))
        assert isinstance(model.rules, tuple)

    @pytest.mark.parametrize("kind", ["tuple", "list", "set", "generator"])
    def test_accepts_any_iterable(self, rules: dict[str, Any], kind: str) -> None:
        values = list(rules.values())
        source: object
        if kind == "tuple":
            source = tuple(values)
        elif kind == "list":
            source = values
        elif kind == "set":
            source = set(values)
        else:
            source = (rule for rule in values)
        assert ids(build(source).rules) == EXPECTED_ORDER

    def test_canonical_order(self, rules: dict[str, Any]) -> None:
        assert ids(build(tuple(rules.values())).rules) == EXPECTED_ORDER

    def test_order_does_not_depend_on_input_order(
        self, rules: dict[str, Any]
    ) -> None:
        values = tuple(rules.values())
        orders = (values, tuple(reversed(values)), values[3:] + values[:3])
        models = [build(order) for order in orders]
        for model in models:
            assert ids(model.rules) == EXPECTED_ORDER
            assert model == models[0]
            assert hash(model) == hash(models[0])

    def test_input_list_is_not_kept(self, rules: dict[str, Any]) -> None:
        values = list(rules.values())
        model = build(values)
        values.clear()
        assert len(model.rules) == len(RULE_SPECS)

    def test_input_is_not_mutated(self, rules: dict[str, Any]) -> None:
        values = list(rules.values())
        snapshot = list(values)
        build(values)
        assert len(values) == len(snapshot)
        assert all(a is b for a, b in zip(values, snapshot))

    def test_duplicate_ids_are_rejected(self, rules: dict[str, Any]) -> None:
        with pytest.raises(ValueError):
            build([rules["cisco-http"], rules["cisco-http"]])

    def test_same_id_with_different_content_is_rejected(
        self, rules: dict[str, Any]
    ) -> None:
        other = make_rule(
            "cisco-http", CISCO, "prefix", "ip http", "http_management_enabled"
        )
        with pytest.raises(ValueError):
            build([rules["cisco-http"], other])

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param("text", id="str"),
            pytest.param(b"bytes", id="bytes"),
            pytest.param({"a": 1}, id="mapping"),
            pytest.param(5, id="int"),
            pytest.param(None, id="none"),
        ],
    )
    def test_rules_must_be_iterable_of_rules(self, value: object) -> None:
        with pytest.raises(TypeError, match="rules must be an iterable"):
            build(value)

    @pytest.mark.parametrize(
        "bad",
        [
            pytest.param("bad", id="str"),
            pytest.param(5, id="int"),
            pytest.param(None, id="none"),
            pytest.param({"rule_id": "x"}, id="dict"),
        ],
    )
    def test_non_rule_element_is_rejected(
        self, rules: dict[str, Any], bad: object
    ) -> None:
        with pytest.raises(TypeError):
            build([rules["cisco-http"], bad])


class TestSource:
    def test_default_is_none(self) -> None:
        assert build().source is None

    def test_accepts_rule_source(self) -> None:
        source = RuleSource(name="Test benchmark")
        assert build(source=source).source is source

    @pytest.mark.parametrize(
        "bad",
        [
            pytest.param("not-a-source", id="str"),
            pytest.param(5, id="int"),
            pytest.param(object(), id="object"),
        ],
    )
    def test_wrong_type_is_rejected(self, bad: object) -> None:
        with pytest.raises(
            TypeError, match="source must be a RuleSource or None"
        ):
            build(source=bad)


# --------------------------------------------------------------------------
# Equality, hashing, immutability
# --------------------------------------------------------------------------


class TestEqualityAndHash:
    def test_equal_models(self, rules: dict[str, Any]) -> None:
        first = build(tuple(rules.values()))
        second = build(tuple(rules.values()))
        assert first == second
        assert hash(first) == hash(second)

    def test_usable_in_sets_and_dicts(self, rules: dict[str, Any]) -> None:
        first = build(tuple(rules.values()))
        second = build(tuple(reversed(rules.values())))
        assert len({first, second}) == 1
        assert {first: 1}[second] == 1

    def test_same_instant_in_other_zone_is_equal(self) -> None:
        zone = timezone(timedelta(hours=5, minutes=30))
        other = build(created_at=datetime(2026, 1, 1, 5, 30, tzinfo=zone))
        assert other == build()
        assert hash(other) == hash(build())

    @pytest.mark.parametrize(
        "override",
        [
            pytest.param({"model_id": "other"}, id="model-id"),
            pytest.param({"version": 2}, id="version"),
            pytest.param(
                {"created_at": datetime(2026, 1, 2, tzinfo=timezone.utc)},
                id="created-at",
            ),
        ],
    )
    def test_different_fields_are_not_equal(self, override: dict[str, object]) -> None:
        assert build(**override) != build()

    def test_different_rules_are_not_equal(self, rules: dict[str, Any]) -> None:
        assert build([rules["cisco-http"]]) != build([rules["cisco-host"]])
        assert build([rules["cisco-http"]]) != build()

    def test_different_sources_are_not_equal(self) -> None:
        first = RuleSource(name="Benchmark A")
        second = RuleSource(name="Benchmark B")

        assert build(source=first) != build(source=second)
        assert build(source=first) != build()

    def test_not_equal_to_other_types(self) -> None:
        assert build() != "baseline-v1"
        assert build() != ()


class TestImmutability:
    @pytest.mark.parametrize(
        "name",
        ["model_id", "version", "created_at", "rules", "source", "_by_id"],
    )
    def test_attributes_cannot_be_set(self, name: str) -> None:
        model = build()
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(model, name, None)

    def test_no_new_attributes(self) -> None:
        with pytest.raises((AttributeError, TypeError)):
            setattr(build(), "extra", 1)

    def test_uses_slots(self) -> None:
        assert not hasattr(build(), "__dict__")

    def test_indexes_are_read_only(self, rules: dict[str, Any]) -> None:
        model = build(tuple(rules.values()))
        assert isinstance(model._by_id, MappingProxyType)
        assert isinstance(model._by_key, MappingProxyType)
        with pytest.raises(TypeError):
            model._by_id["x"] = rules["cisco-http"]
        with pytest.raises(TypeError):
            model._by_key[(CISCO, "hostname")] = ()

    def test_repr_hides_indexes(self, rules: dict[str, Any]) -> None:
        text = repr(build(tuple(rules.values())))
        assert "_by_id" not in text
        assert "_by_key" not in text
        assert "baseline-v1" in text

    def test_replace_revalidates(self, rules: dict[str, Any]) -> None:
        model = build(tuple(rules.values()))
        newer = dataclasses.replace(model, version=2)
        assert newer.version == 2
        assert newer.rules == model.rules
        assert newer.model_id == model.model_id
        with pytest.raises(ValueError):
            dataclasses.replace(model, version=0)


# --------------------------------------------------------------------------
# Container behaviour
# --------------------------------------------------------------------------


class TestContainer:
    def test_len(self, rules: dict[str, Any]) -> None:
        assert len(build()) == 0
        assert len(build(tuple(rules.values()))) == len(RULE_SPECS)

    def test_empty_model_is_falsy(self, rules: dict[str, Any]) -> None:
        assert bool(build()) is False
        assert bool(build([rules["cisco-http"]])) is True

    def test_iteration_follows_canonical_order(self, rules: dict[str, Any]) -> None:
        model = build(tuple(rules.values()))
        assert ids(list(model)) == EXPECTED_ORDER
        assert ids(iter(model)) == EXPECTED_ORDER
        assert isinstance(iter(model), Iterator)

    def test_contains_rule(self, rules: dict[str, Any]) -> None:
        model = build(tuple(rules.values()))
        assert rules["cisco-http"] in model

    def test_contains_requires_equal_rule(self, rules: dict[str, Any]) -> None:
        model = build(tuple(rules.values()))
        other = make_rule(
            "cisco-http", CISCO, "prefix", "ip http", "http_management_enabled"
        )
        assert other not in model

    def test_contains_rule_not_in_model(self, rules: dict[str, Any]) -> None:
        model = build([rules["cisco-http"]])
        assert rules["cisco-host"] not in model

    @pytest.mark.parametrize(
        "rule_id",
        ["cisco-http", "CISCO-HTTP", "  Cisco-Http  "],
    )
    def test_contains_id_is_case_insensitive(
        self, rules: dict[str, Any], rule_id: str
    ) -> None:
        assert rule_id in build(tuple(rules.values()))

    def test_contains_unknown_id(self, rules: dict[str, Any]) -> None:
        model = build(tuple(rules.values()))
        assert "no-such-rule" not in model
        assert "" not in model

    @pytest.mark.parametrize(
        "item",
        [
            pytest.param(5, id="int"),
            pytest.param(None, id="none"),
            pytest.param(b"cisco-http", id="bytes"),
            pytest.param([], id="list"),
        ],
    )
    def test_contains_other_types_is_false(
        self, rules: dict[str, Any], item: object
    ) -> None:
        assert item not in build(tuple(rules.values()))

    def test_get_returns_the_same_object(self, rules: dict[str, Any]) -> None:
        model = build(tuple(rules.values()))
        assert model.get("cisco-http") is rules["cisco-http"]
        assert model.get("  CISCO-HTTP ") is rules["cisco-http"]

    def test_get_unknown_returns_none(self, rules: dict[str, Any]) -> None:
        model = build(tuple(rules.values()))
        assert model.get("no-such-rule") is None
        assert build().get("cisco-http") is None

    @pytest.mark.parametrize(
        "bad",
        [
            pytest.param(None, id="none"),
            pytest.param(5, id="int"),
            pytest.param(b"cisco-http", id="bytes"),
        ],
    )
    def test_get_requires_str(self, bad: object) -> None:
        with pytest.raises(TypeError, match="rule_id must be a str"):
            build().get(bad)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Lookups by vendor and target
# --------------------------------------------------------------------------


class TestVendors:
    def test_empty_model(self) -> None:
        assert build().vendors == ()

    def test_single_vendor(self, rules: dict[str, Any]) -> None:
        model = build([rules["forti-host"]])
        assert model.vendors == (FORTI,)

    def test_follows_vendor_enum_order(self, rules: dict[str, Any]) -> None:
        model = build(tuple(rules.values()))
        expected = tuple(vendor for vendor in Vendor if vendor in (CISCO, FORTI))
        assert model.vendors == expected
        assert isinstance(model.vendors, tuple)


class TestForVendor:
    def test_returns_vendor_rules_in_canonical_order(
        self, rules: dict[str, Any]
    ) -> None:
        model = build(tuple(rules.values()))
        assert ids(model.for_vendor(CISCO)) == EXPECTED_ORDER[:5]
        assert ids(model.for_vendor(FORTI)) == EXPECTED_ORDER[5:]

    def test_vendor_without_rules(self, rules: dict[str, Any]) -> None:
        model = build([rules["forti-host"]])
        assert model.for_vendor(CISCO) == ()
        assert isinstance(model.for_vendor(CISCO), tuple)

    def test_empty_model(self) -> None:
        assert build().for_vendor(CISCO) == ()

    @pytest.mark.parametrize(
        "bad",
        [
            pytest.param("cisco_ios", id="str"),
            pytest.param(None, id="none"),
            pytest.param(5, id="int"),
        ],
    )
    def test_requires_vendor(self, bad: object) -> None:
        with pytest.raises(TypeError, match="vendor must be a Vendor"):
            build().for_vendor(bad)  # type: ignore[arg-type]


class TestForTarget:
    def test_returns_matching_rules_in_canonical_order(
        self, rules: dict[str, Any]
    ) -> None:
        model = build(tuple(rules.values()))
        assert ids(model.for_target(CISCO, "ntp_servers")) == [
            "cisco-ntp-a",
            "cisco-ntp-b",
        ]

    def test_single_rule(self, rules: dict[str, Any]) -> None:
        model = build(tuple(rules.values()))
        result = model.for_target(CISCO, "http_management_enabled")
        assert len(result) == 1
        assert result[0] is rules["cisco-http"]

    def test_vendors_are_separated(self, rules: dict[str, Any]) -> None:
        model = build(tuple(rules.values()))
        assert ids(model.for_target(CISCO, "telnet_enabled")) == ["cisco-telnet"]
        assert ids(model.for_target(FORTI, "telnet_enabled")) == ["forti-telnet"]

    def test_valid_target_without_rules(self, rules: dict[str, Any]) -> None:
        model = build(tuple(rules.values()))
        result = model.for_target(FORTI, "ntp_servers")
        assert result == ()
        assert isinstance(result, tuple)

    @pytest.mark.parametrize("target", sorted(_module.TARGET_FIELD_TYPES))
    def test_every_supported_target_is_accepted(self, target: str) -> None:
        assert build().for_target(CISCO, target) == ()

    @pytest.mark.parametrize(
        "target",
        [
            pytest.param("bogus", id="unknown"),
            pytest.param("", id="empty"),
            pytest.param("Hostname", id="wrong-case"),
            pytest.param(" hostname", id="whitespace"),
        ],
    )
    def test_unknown_target_raises(self, target: str) -> None:
        with pytest.raises(ValueError, match="unsupported target_field"):
            build().for_target(CISCO, target)

    @pytest.mark.parametrize(
        "bad",
        [
            pytest.param(None, id="none"),
            pytest.param(5, id="int"),
            pytest.param(b"hostname", id="bytes"),
        ],
    )
    def test_target_must_be_str(self, bad: object) -> None:
        with pytest.raises(TypeError, match="target_field must be a str"):
            build().for_target(CISCO, bad)  # type: ignore[arg-type]

    def test_vendor_must_be_vendor(self) -> None:
        with pytest.raises(TypeError, match="vendor must be a Vendor"):
            build().for_target("cisco_ios", "hostname")  # type: ignore[arg-type]

    def test_vendor_is_checked_before_target(self) -> None:
        with pytest.raises(TypeError, match="vendor must be a Vendor"):
            build().for_target("cisco_ios", 5)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Error messages never echo values
# --------------------------------------------------------------------------


class TestNoValueEcho:
    def test_invalid_model_id(self) -> None:
        with pytest.raises(ValueError) as info:
            build(model_id=f"{SECRET} secret")
        assert SECRET not in str(info.value)

    def test_wrong_type_model_id(self) -> None:
        with pytest.raises(TypeError) as info:
            build(model_id=[SECRET])
        assert SECRET not in str(info.value)

    def test_wrong_type_version(self) -> None:
        with pytest.raises(TypeError) as info:
            build(version=SECRET)
        assert SECRET not in str(info.value)

    def test_wrong_type_created_at(self) -> None:
        with pytest.raises(TypeError) as info:
            build(created_at=SECRET)
        assert SECRET not in str(info.value)

    def test_wrong_type_source(self) -> None:
        with pytest.raises(TypeError) as info:
            build(source=SECRET)
        assert SECRET not in str(info.value)

    def test_wrong_type_rules(self) -> None:
        with pytest.raises(TypeError) as info:
            build(SECRET)
        assert SECRET not in str(info.value)

    def test_unknown_target(self) -> None:
        with pytest.raises(ValueError) as info:
            build().for_target(CISCO, SECRET)
        assert SECRET not in str(info.value)

    def test_wrong_type_rule_id(self) -> None:
        with pytest.raises(TypeError) as info:
            build().get(SECRET.encode())  # type: ignore[arg-type]
        assert SECRET not in str(info.value)


# --------------------------------------------------------------------------
# Module surface
# --------------------------------------------------------------------------


def test_public_api() -> None:
    assert list(_module.__all__) == ["PatternModel"]
    assert hasattr(_module, "PatternModel")