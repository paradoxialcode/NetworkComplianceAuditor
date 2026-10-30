"""Tests for auditor.training.matcher."""

from __future__ import annotations

import dataclasses
import enum
import itertools
import types
import typing
from collections.abc import Iterator
from typing import Any

import pytest

from auditor.training import matcher
from auditor.training.matcher import (
    MatchResult,
    evaluate,
    matches,
    matching_rules,
)
from auditor.training.patterns import MatchMethod, PatternRule

# --------------------------------------------------------------------------
# Rule factories
# --------------------------------------------------------------------------


def _any(value: object) -> Any:
    """Hand a deliberately wrong value to a typed API without type noise."""
    return value


def make_rule(method: MatchMethod, expression: str) -> PatternRule:
    """Build a PatternRule WITHOUT running its validation.

    The matcher only reads ``method`` and ``expression``. Skipping
    ``__post_init__`` lets tests use inputs the constructor rejects
    (empty expression, trailing whitespace, invalid regex), which the
    matcher must still handle safely, e.g. for rules loaded from a
    corrupt store.
    """
    rule = object.__new__(PatternRule)
    for f in dataclasses.fields(PatternRule):
        object.__setattr__(rule, f.name, None)
    object.__setattr__(rule, "method", method)
    object.__setattr__(rule, "expression", expression)
    return rule


def exact(expression: str) -> PatternRule:
    return make_rule(MatchMethod.EXACT, expression)


def prefix(expression: str) -> PatternRule:
    return make_rule(MatchMethod.PREFIX, expression)


def regex(expression: str) -> PatternRule:
    return make_rule(MatchMethod.REGEX, expression)


# --- real (validated) rule builder, used by one integration test ----------

_TARGETS = (
    "telnet_enabled",
    "http_management_enabled",
    "password_encryption",
    "hostname",
    "ntp_servers",
    "syslog_servers",
    "local_users",
)
_SUGGESTED_VALUES: tuple[object, ...] = (True, "test", "10.0.0.1")
_rule_ids = itertools.count(1)


def _default_for(hint: object) -> object:
    origin = typing.get_origin(hint)
    if origin is typing.Union or origin is types.UnionType:
        options = [a for a in typing.get_args(hint) if a is not type(None)]
        return _default_for(options[0])
    if isinstance(hint, type) and issubclass(hint, enum.Enum):
        return next(iter(hint))
    if hint is str:
        return "test"
    if hint is bool:
        return True
    if hint is int:
        return 0
    if hint is float:
        return 0.0
    if origin in (tuple, list, set, frozenset, dict):
        return origin()
    raise RuntimeError(f"no default for type {hint!r}")


def _build_real_rule(method: MatchMethod, expression: str) -> PatternRule | None:
    """Try to build a validated PatternRule; return None if impossible."""
    try:
        hints = typing.get_type_hints(PatternRule)
    except (NameError, TypeError):
        return None
    required = [
        f
        for f in dataclasses.fields(PatternRule)
        if f.init
        and f.default is dataclasses.MISSING
        and f.default_factory is dataclasses.MISSING
    ]
    for target in _TARGETS:
        for suggested in _SUGGESTED_VALUES:
            values: dict[str, object] = {"method": method, "expression": expression}
            try:
                for f in required:
                    if f.name in values:
                        continue
                    if f.name == "target_field":
                        values[f.name] = target
                    elif f.name == "suggested_value":
                        values[f.name] = suggested
                    elif f.name in ("rule_id", "id"):
                        values[f.name] = f"rule-{next(_rule_ids)}"
                    else:
                        values[f.name] = _default_for(hints[f.name])
                return PatternRule(**_any(values))
            except (ValueError, TypeError, RuntimeError, KeyError):
                continue
    return None


# --------------------------------------------------------------------------
# EXACT
# --------------------------------------------------------------------------


class TestExact:
    def test_identical_line_matches(self) -> None:
        assert matches(exact("ip http server"), "ip http server") is True

    @pytest.mark.parametrize(
        "text",
        [
            "ip http server ",  # trailing space
            " ip http server",  # leading space
            "IP HTTP SERVER",  # case
            "ip http",  # shorter
            "ip http server x",  # longer
            "",
        ],
    )
    def test_near_misses_do_not_match(self, text: str) -> None:
        assert matches(exact("ip http server"), text) is False

    def test_regex_metacharacters_are_literal(self) -> None:
        assert matches(exact("a.b*c"), "a.b*c") is True
        assert matches(exact("a.b*c"), "aXbbbc") is False

    def test_empty_expression_matches_only_empty_line(self) -> None:
        assert matches(exact(""), "") is True
        assert matches(exact(""), "x") is False


# --------------------------------------------------------------------------
# PREFIX
# --------------------------------------------------------------------------


class TestPrefix:
    def test_prefix_matches(self) -> None:
        assert matches(prefix("ntp server "), "ntp server 10.0.0.1") is True

    def test_whole_line_equal_to_prefix_matches(self) -> None:
        assert matches(prefix("logging host"), "logging host") is True

    @pytest.mark.parametrize(
        "text",
        ["no ntp server 10.0.0.1", " ntp server 1", "NTP server 1", "ntp", ""],
    )
    def test_non_prefix_does_not_match(self, text: str) -> None:
        assert matches(prefix("ntp server "), text) is False

    def test_prefix_is_not_substring(self) -> None:
        assert matches(prefix("server"), "ntp server 1") is False

    def test_empty_expression_raises(self) -> None:
        with pytest.raises(ValueError, match="empty expression"):
            matches(prefix(""), "anything")

    def test_empty_expression_raises_even_for_empty_text(self) -> None:
        with pytest.raises(ValueError, match="empty expression"):
            matches(prefix(""), "")


# --------------------------------------------------------------------------
# REGEX
# --------------------------------------------------------------------------


class TestRegex:
    def test_full_match(self) -> None:
        assert matches(regex(r"ntp server \S+"), "ntp server 10.0.0.1") is True

    def test_partial_match_is_not_a_match(self) -> None:
        assert matches(regex(r"ntp server"), "ntp server 10.0.0.1") is False

    def test_leading_garbage_is_not_a_match(self) -> None:
        assert matches(regex(r"ip http server"), "no ip http server") is False

    def test_negated_line_not_confused_with_positive(self) -> None:
        rule = regex(r"ip http server")
        assert matches(rule, "ip http server") is True
        assert matches(rule, "no ip http server") is False

    def test_explicit_wildcards_allow_partial(self) -> None:
        assert matches(regex(r".*http server.*"), "no ip http server") is True

    def test_alternation_is_fully_anchored(self) -> None:
        rule = regex(r"a|ab")
        assert matches(rule, "ab") is True  # fullmatch backtracks to "ab"
        assert matches(rule, "abc") is False

    def test_empty_pattern_matches_only_empty_line(self) -> None:
        assert matches(regex(""), "") is True
        assert matches(regex(""), "x") is False

    def test_invalid_regex_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="invalid regular expression"):
            matches(regex("("), "line")

    def test_invalid_regex_raises_every_time(self) -> None:
        # lru_cache must not turn an error into a cached success.
        rule = regex("[")
        for _ in range(3):
            with pytest.raises(ValueError):
                matches(rule, "line")

    def test_invalid_regex_error_does_not_echo_text(self) -> None:
        secret = "password SuperSecret123"
        with pytest.raises(ValueError) as info:
            matches(regex("("), secret)
        assert "SuperSecret123" not in str(info.value)
        assert "SuperSecret123" not in repr(info.value.__cause__)

    def test_compile_is_cached(self) -> None:
        matcher._compile.cache_clear()
        rule = regex(r"cached \d+")
        matches(rule, "cached 1")
        matches(rule, "cached 2")
        info = matcher._compile.cache_info()
        assert info.misses == 1
        assert info.hits >= 1


# --------------------------------------------------------------------------
# Input validation
# --------------------------------------------------------------------------


class TestValidation:
    @pytest.mark.parametrize("bad", [None, 5, b"line", ["line"], object()])
    def test_non_str_text_raises_type_error(self, bad: object) -> None:
        with pytest.raises(TypeError, match="text must be str"):
            matches(exact("x"), _any(bad))

    @pytest.mark.parametrize("bad", [None, "rule", 5, ("EXACT", "x")])
    def test_non_rule_raises_type_error(self, bad: object) -> None:
        with pytest.raises(TypeError, match="rule must be PatternRule"):
            matches(_any(bad), "line")

    def test_newline_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="single line"):
            matches(exact("x"), "a\nb")

    def test_trailing_newline_raises(self) -> None:
        with pytest.raises(ValueError, match="single line"):
            matches(exact("x"), "x\n")

    def test_carriage_return_is_not_a_newline(self) -> None:
        # Lines are split on \n only; \r is the caller's concern.
        assert matches(exact("x\r"), "x\r") is True

    def test_newline_error_does_not_echo_text(self) -> None:
        with pytest.raises(ValueError) as info:
            matches(exact("x"), "enable secret 9 TopSecretHash\nnext")
        assert "TopSecretHash" not in str(info.value)

    def test_non_str_type_error_does_not_echo_value(self) -> None:
        with pytest.raises(TypeError) as info:
            matches(exact("x"), _any(12345))
        assert "12345" not in str(info.value)


# --------------------------------------------------------------------------
# evaluate / MatchResult
# --------------------------------------------------------------------------


class TestEvaluate:
    def test_matched_result(self) -> None:
        rule = exact("x")
        result = evaluate(rule, "x")
        assert result == MatchResult(matched=True, rule=rule)
        assert result.rule is rule

    def test_unmatched_result(self) -> None:
        rule = exact("x")
        result = evaluate(rule, "y")
        assert result.matched is False
        assert result.rule is rule

    def test_evaluate_propagates_errors(self) -> None:
        with pytest.raises(TypeError):
            evaluate(_any("nope"), "x")
        with pytest.raises(ValueError):
            evaluate(exact("x"), "a\nb")

    def test_match_result_is_frozen(self) -> None:
        result = evaluate(exact("x"), "x")
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(result, "matched", False)

    def test_match_result_uses_slots(self) -> None:
        assert not hasattr(evaluate(exact("x"), "x"), "__dict__")


# --------------------------------------------------------------------------
# matching_rules
# --------------------------------------------------------------------------


class TestMatchingRules:
    def test_empty_rules_returns_empty_tuple(self) -> None:
        result = matching_rules([], "any line")
        assert result == ()
        assert isinstance(result, tuple)

    def test_no_match_returns_empty_tuple(self) -> None:
        assert matching_rules([exact("a"), prefix("b")], "zzz") == ()

    def test_returns_only_matching_rules_in_original_order(self) -> None:
        r1 = regex(r"ntp .*")
        r2 = exact("other")
        r3 = prefix("ntp ")
        r4 = exact("ntp server 1")
        result = matching_rules([r1, r2, r3, r4], "ntp server 1")
        assert len(result) == 3
        assert result[0] is r1
        assert result[1] is r3
        assert result[2] is r4

    def test_returns_same_objects(self) -> None:
        rule = exact("x")
        assert matching_rules([rule], "x")[0] is rule

    def test_duplicate_rules_are_both_returned(self) -> None:
        rule = exact("x")
        result = matching_rules([rule, rule], "x")
        assert len(result) == 2
        assert result[0] is rule
        assert result[1] is rule

    def test_accepts_generator(self) -> None:
        def gen() -> Iterator[PatternRule]:
            yield exact("x")
            yield exact("y")

        assert len(matching_rules(gen(), "x")) == 1

    def test_accepts_tuple(self) -> None:
        rule = exact("x")
        result = matching_rules((rule,), "x")
        assert len(result) == 1
        assert result[0] is rule

    def test_non_rule_element_raises(self) -> None:
        with pytest.raises(TypeError, match="rules must contain PatternRule"):
            matching_rules(_any([exact("x"), "bad"]), "x")

    def test_non_rule_element_raises_even_if_earlier_rule_matches(self) -> None:
        with pytest.raises(TypeError):
            matching_rules(_any([exact("x"), 5]), "x")

    def test_text_validated_even_with_no_rules(self) -> None:
        with pytest.raises(TypeError):
            matching_rules([], _any(5))
        with pytest.raises(ValueError):
            matching_rules([], "a\nb")

    def test_bad_rule_expression_propagates(self) -> None:
        with pytest.raises(ValueError, match="invalid regular expression"):
            matching_rules([exact("x"), regex("(")], "x")

    def test_does_not_mutate_input_list(self) -> None:
        rules = [exact("x"), exact("y")]
        snapshot = list(rules)
        matching_rules(rules, "x")
        assert len(rules) == 2
        assert rules[0] is snapshot[0]
        assert rules[1] is snapshot[1]


# --------------------------------------------------------------------------
# Integration with real, validated PatternRule objects
# --------------------------------------------------------------------------


class TestWithValidatedRules:
    @pytest.mark.parametrize(
        ("method", "expression", "text", "expected"),
        [
            (MatchMethod.EXACT, "ip http server", "ip http server", True),
            (MatchMethod.EXACT, "ip http server", "no ip http server", False),
            (MatchMethod.PREFIX, "ntp server", "ntp server 10.0.0.1", True),
            (MatchMethod.PREFIX, "ntp server", "no ntp server 1", False),
            (MatchMethod.REGEX, r"ntp server \S+", "ntp server 10.0.0.1", True),
            (MatchMethod.REGEX, r"ntp server", "ntp server 10.0.0.1", False),
        ],
    )
    def test_real_rule_behaves_like_unvalidated_rule(
        self,
        method: MatchMethod,
        expression: str,
        text: str,
        expected: bool,
    ) -> None:
        rule = _build_real_rule(method, expression)
        if rule is None:
            pytest.skip("could not auto-build a validated PatternRule")
        assert matches(rule, text) is expected
        assert evaluate(rule, text).matched is expected


# --------------------------------------------------------------------------
# Module surface
# --------------------------------------------------------------------------


def test_public_api() -> None:
    assert set(matcher.__all__) == {
        "MatchResult",
        "Resolution",
        "evaluate",
        "matches",
        "matching_rules",
        "resolve",
    }
    for name in matcher.__all__:
        assert hasattr(matcher, name)


@pytest.mark.parametrize("method", list(MatchMethod))
def test_every_match_method_is_handled(method: MatchMethod) -> None:
    # Guards the assert_never branch: a new MatchMethod must be handled in
    # matches(), otherwise this fails with AssertionError.
    assert matches(make_rule(method, "x"), "x") is True