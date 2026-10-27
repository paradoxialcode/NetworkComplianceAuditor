"""Tests for auditor.training.suggester."""

from __future__ import annotations

import dataclasses
import enum
import itertools
import math
import types
import typing
from collections.abc import Iterator
from typing import Any

import pytest

from auditor.training import suggester
from auditor.training.patterns import MatchMethod, PatternRule
from auditor.training.suggester import Suggestion, suggest

# --------------------------------------------------------------------------
# Rule factories
# --------------------------------------------------------------------------


def _any(value: object) -> Any:
    """Hand a deliberately wrong value to a typed API without type noise."""
    return value


def make_rule(method: MatchMethod, expression: str) -> PatternRule:
    """Build a PatternRule WITHOUT running its validation.

    The suggester only reads ``method`` and ``expression``.
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


def rules_of(result: tuple[Suggestion, ...]) -> list[PatternRule]:
    return [item.rule for item in result]


def ranking_rules() -> tuple[PatternRule, PatternRule, PatternRule]:
    """Rules whose similarity to "ntp server ..." is ordered A > C > B."""
    return prefix("ntp server"), prefix("ntp"), prefix("ntp server pool")


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
# Tokenization
# --------------------------------------------------------------------------


class TestLineWords:
    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            pytest.param("ntp server 10.0.0.1", ("ntp", "server"), id="drops-ip"),
            pytest.param("NTP SERVER", ("ntp", "server"), id="lowercases"),
            pytest.param(
                "ip http secure-server",
                ("ip", "http", "secure", "server"),
                id="splits-hyphen",
            ),
            pytest.param("logging_host a b", ("logging", "host"), id="underscore"),
            pytest.param(
                "interface GigabitEthernet0/1",
                ("interface", "gigabitethernet"),
                id="digits-split",
            ),
            pytest.param("no ip http server", ("no", "ip", "http", "server"), id="no"),
            pytest.param("", (), id="empty"),
            pytest.param("   ", (), id="blank"),
            pytest.param("10.0.0.1 /24 !", (), id="symbols-only"),
        ],
    )
    def test_words(self, line: str, expected: tuple[str, ...]) -> None:
        assert suggester._line_words(line) == expected


class TestExpressionWords:
    @pytest.mark.parametrize(
        ("expression", "is_regex", "expected"),
        [
            pytest.param(
                "ip http server", False, ("ip", "http", "server"), id="plain"
            ),
            pytest.param(
                r"ntp server \S+", True, ("ntp", "server"), id="regex-escape"
            ),
            pytest.param(
                r"logging host (?P<host>\S+)",
                True,
                ("logging", "host"),
                id="named-group",
            ),
            pytest.param(
                r"snmp-server community [A-Za-z0-9]+ (?:RO|RW)",
                True,
                ("snmp", "server", "community", "ro", "rw"),
                id="char-class",
            ),
            pytest.param(
                r"ntp server\s+(?P=host)",
                True,
                ("ntp", "server"),
                id="backreference",
            ),
            pytest.param(r"abc\defg", True, ("abc", "efg"), id="escape-removed"),
            pytest.param(r"abc\defg", False, ("abc", "defg"), id="escape-kept"),
            pytest.param("", False, (), id="empty"),
        ],
    )
    def test_words(
        self, expression: str, is_regex: bool, expected: tuple[str, ...]
    ) -> None:
        assert suggester._expression_words(expression, regex=is_regex) == expected

    def test_rule_words_uses_method(self) -> None:
        assert suggester._rule_words(regex(r"abc\defg")) == ("abc", "efg")
        assert suggester._rule_words(prefix(r"abc\defg")) == ("abc", "defg")
        assert suggester._rule_words(exact(r"abc\defg")) == ("abc", "defg")


class TestIdf:
    def test_common_word_has_minimum_weight(self) -> None:
        assert suggester._idf(4, 4) == 1.0
        assert suggester._idf(0, 0) == 1.0

    def test_unseen_word(self) -> None:
        assert suggester._idf(3, 0) == pytest.approx(math.log(4) + 1.0)

    def test_rarer_words_weigh_more(self) -> None:
        assert suggester._idf(10, 1) > suggester._idf(10, 5) > suggester._idf(10, 10)


# --------------------------------------------------------------------------
# suggest(): ranking
# --------------------------------------------------------------------------


class TestSuggestRanking:
    def test_returns_only_related_rule(self) -> None:
        rules = [prefix("logging host"), prefix("ntp server"), exact("ip http secure")]
        result = suggest("ntp server 10.0.0.1", rules)
        assert len(result) == 1
        assert result[0].rule is rules[1]
        assert result[0].score == pytest.approx(1.0)

    def test_best_first(self) -> None:
        a, b, c = ranking_rules()
        result = suggest("ntp server 10.0.0.1", [b, c, a])
        assert rules_of(result) == [a, c, b]
        assert result[0].score == pytest.approx(1.0)
        assert result[0].score > result[1].score > result[2].score > 0.0

    def test_result_is_tuple_of_suggestions(self) -> None:
        a, _, _ = ranking_rules()
        result = suggest("ntp server", [a])
        assert isinstance(result, tuple)
        assert all(isinstance(item, Suggestion) for item in result)

    def test_shared_terms_are_sorted_and_specific(self) -> None:
        a, b, c = ranking_rules()
        result = suggest("ntp server 10.0.0.1", [a, b, c])
        by_rule = {id(item.rule): item for item in result}
        assert by_rule[id(a)].shared_terms == ("ntp", "server")
        assert by_rule[id(b)].shared_terms == ("ntp",)
        assert by_rule[id(c)].shared_terms == ("ntp", "server")

    def test_numbers_and_ips_do_not_change_score(self) -> None:
        rules = [prefix("ntp server")]
        first = suggest("ntp server 10.0.0.1", rules)
        second = suggest("ntp server 192.168.77.5", rules)
        assert first[0].score == second[0].score

    def test_case_insensitive(self) -> None:
        rules = [prefix("ntp server")]
        assert (
            suggest("NTP SERVER 1.1.1.1", rules)[0].score
            == suggest("ntp server 1.1.1.1", rules)[0].score
        )

    def test_regex_and_prefix_rules_tie_in_original_order(self) -> None:
        rules = [regex(r"ntp server \S+"), prefix("ntp server")]
        result = suggest("ntp server 1.1.1.1", rules)
        assert len(result) == 2
        assert result[0].rule is rules[0]
        assert result[1].rule is rules[1]
        assert result[0].score == pytest.approx(1.0)
        assert result[1].score == pytest.approx(1.0)

    def test_identical_rules_tie_in_original_order(self) -> None:
        first, second = prefix("ntp server"), prefix("ntp server")
        result = suggest("ntp server 1.1.1.1", [first, second])
        assert len(result) == 2
        assert result[0].rule is first
        assert result[1].rule is second

    def test_negated_line_scores_below_exact_but_above_zero(self) -> None:
        rules = [exact("ip http server")]
        exact_score = suggest("ip http server", rules)[0].score
        negated_score = suggest("no ip http server", rules)[0].score
        assert 0.0 < negated_score < exact_score
        assert exact_score == pytest.approx(1.0)

    def test_unrelated_line_gets_nothing(self) -> None:
        assert suggest("interface Gi0/1", [prefix("ntp server")]) == ()

    def test_is_deterministic(self) -> None:
        a, b, c = ranking_rules()
        first = suggest("ntp server 1.1.1.1", [a, b, c])
        second = suggest("ntp server 1.1.1.1", [a, b, c])
        assert [s.score for s in first] == [s.score for s in second]
        assert rules_of(first) == rules_of(second)


class TestSuggestFiltering:
    def test_limit_truncates(self) -> None:
        a, b, c = ranking_rules()
        assert rules_of(suggest("ntp server 1.1.1.1", [a, b, c], limit=1)) == [a]
        assert rules_of(suggest("ntp server 1.1.1.1", [a, b, c], limit=2)) == [a, c]

    def test_default_limit(self) -> None:
        rules = [prefix("ntp server") for _ in range(8)]
        assert len(suggest("ntp server 1.1.1.1", rules)) == suggester.DEFAULT_LIMIT

    def test_min_score_filters_weak_matches(self) -> None:
        a, b, c = ranking_rules()
        assert rules_of(suggest("ntp server 1.1.1.1", [a, b, c], min_score=0.65)) == [
            a,
            c,
        ]

    def test_min_score_one_keeps_only_perfect_matches(self) -> None:
        a, b, c = ranking_rules()
        assert rules_of(suggest("ntp server 1.1.1.1", [a, b, c], min_score=1)) == [a]

    def test_min_score_zero_still_excludes_zero_similarity(self) -> None:
        assert suggest("ntp server", [prefix("logging host")], min_score=0.0) == ()

    def test_min_score_zero_keeps_all_positive_scores(self) -> None:
        a, b, c = ranking_rules()
        assert len(suggest("ntp server 1.1.1.1", [a, b, c], min_score=0)) == 3

    def test_empty_rules(self) -> None:
        assert suggest("ntp server 1.1.1.1", []) == ()

    @pytest.mark.parametrize("line", ["", "   ", "10.0.0.1 /24"])
    def test_line_without_words(self, line: str) -> None:
        assert suggest(line, [prefix("ntp server")]) == ()


class TestSuggestInputs:
    def test_accepts_generator(self) -> None:
        def gen() -> Iterator[PatternRule]:
            yield prefix("ntp server")
            yield prefix("logging host")

        assert len(suggest("ntp server 1.1.1.1", gen())) == 1

    def test_accepts_tuple(self) -> None:
        rule = prefix("ntp server")
        result = suggest("ntp server 1.1.1.1", (rule,))
        assert result[0].rule is rule

    def test_does_not_mutate_input(self) -> None:
        a, b, c = ranking_rules()
        rules = [c, b, a]
        suggest("ntp server 1.1.1.1", rules)
        assert len(rules) == 3
        assert rules[0] is c
        assert rules[1] is b
        assert rules[2] is a

    def test_line_at_maximum_length_is_accepted(self) -> None:
        line = "ab" * (suggester.MAX_LINE_LENGTH // 2)
        assert len(line) == suggester.MAX_LINE_LENGTH
        assert suggest(line, [prefix("ntp server")]) == ()


class TestSuggestValidation:
    @pytest.mark.parametrize(
        "bad",
        [
            pytest.param(None, id="none"),
            pytest.param(5, id="int"),
            pytest.param(b"line", id="bytes"),
            pytest.param(["line"], id="list"),
        ],
    )
    def test_line_must_be_str(self, bad: object) -> None:
        with pytest.raises(TypeError, match="line must be str"):
            suggest(_any(bad), [])

    def test_line_must_be_single_line(self) -> None:
        with pytest.raises(ValueError, match="single line"):
            suggest("a\nb", [])
        with pytest.raises(ValueError, match="single line"):
            suggest("ntp server\n", [])

    def test_carriage_return_is_not_a_newline(self) -> None:
        assert suggest("ntp server\r", [prefix("ntp server")])[0].score > 0.0

    def test_line_too_long(self) -> None:
        with pytest.raises(ValueError, match="too long"):
            suggest("a" * (suggester.MAX_LINE_LENGTH + 1), [])

    @pytest.mark.parametrize(
        "bad",
        [
            pytest.param(None, id="none"),
            pytest.param("3", id="str"),
            pytest.param(1.5, id="float"),
            pytest.param(True, id="bool"),
        ],
    )
    def test_limit_must_be_int(self, bad: object) -> None:
        with pytest.raises(TypeError, match="limit must be int"):
            suggest("ntp", [], limit=_any(bad))

    @pytest.mark.parametrize("bad", [0, -1])
    def test_limit_must_be_positive(self, bad: int) -> None:
        with pytest.raises(ValueError, match="at least 1"):
            suggest("ntp", [], limit=bad)

    @pytest.mark.parametrize(
        "bad",
        [
            pytest.param(None, id="none"),
            pytest.param("0.5", id="str"),
            pytest.param(True, id="bool"),
        ],
    )
    def test_min_score_must_be_number(self, bad: object) -> None:
        with pytest.raises(TypeError, match="min_score must be a number"):
            suggest("ntp", [], min_score=_any(bad))

    @pytest.mark.parametrize(
        "bad",
        [
            pytest.param(-0.1, id="negative"),
            pytest.param(1.1, id="above-one"),
            pytest.param(float("nan"), id="nan"),
            pytest.param(float("inf"), id="inf"),
        ],
    )
    def test_min_score_must_be_in_range(self, bad: float) -> None:
        with pytest.raises(ValueError, match="between 0 and 1"):
            suggest("ntp", [], min_score=bad)

    @pytest.mark.parametrize(
        "bad",
        [
            pytest.param("text", id="str"),
            pytest.param(b"bytes", id="bytes"),
            pytest.param(5, id="int"),
            pytest.param(None, id="none"),
        ],
    )
    def test_rules_must_be_iterable(self, bad: object) -> None:
        with pytest.raises(TypeError, match="rules must be an iterable"):
            suggest("ntp server", _any(bad))

    def test_rules_must_contain_pattern_rules(self) -> None:
        with pytest.raises(TypeError, match="rules must contain PatternRule"):
            suggest("ntp server", _any([prefix("ntp server"), "bad"]))

    def test_rules_validated_even_when_line_has_no_words(self) -> None:
        with pytest.raises(TypeError, match="rules must be an iterable"):
            suggest("", _any("text"))
        with pytest.raises(TypeError, match="rules must contain PatternRule"):
            suggest("10.0.0.1", _any([5]))


class TestNoSecretEcho:
    def test_newline_error_does_not_echo_line(self) -> None:
        with pytest.raises(ValueError) as info:
            suggest("enable secret 9 TopSecretHash\nnext", [])
        assert "TopSecretHash" not in str(info.value)

    def test_too_long_error_does_not_echo_line(self) -> None:
        with pytest.raises(ValueError) as info:
            suggest("TopSecretHash" + "a" * suggester.MAX_LINE_LENGTH, [])
        assert "TopSecretHash" not in str(info.value)

    def test_type_errors_do_not_echo_values(self) -> None:
        with pytest.raises(TypeError) as line_info:
            suggest(_any(12345), [])
        assert "12345" not in str(line_info.value)
        with pytest.raises(TypeError) as limit_info:
            suggest("ntp", [], limit=_any("7777"))
        assert "7777" not in str(limit_info.value)

    def test_suggestion_does_not_keep_the_line(self) -> None:
        secret = "TopSecretHash"
        result = suggest(f"ntp server {secret}", [prefix("ntp server")])
        fields = [getattr(result[0], f.name) for f in dataclasses.fields(Suggestion)]
        assert all(secret.lower() not in repr(value).lower() for value in fields)


# --------------------------------------------------------------------------
# Suggestion dataclass
# --------------------------------------------------------------------------


class TestSuggestion:
    def test_is_frozen(self) -> None:
        result = suggest("ntp server", [prefix("ntp server")])
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(result[0], "score", 0.0)

    def test_uses_slots(self) -> None:
        result = suggest("ntp server", [prefix("ntp server")])
        assert not hasattr(result[0], "__dict__")


# --------------------------------------------------------------------------
# Integration with real, validated PatternRule objects
# --------------------------------------------------------------------------


class TestWithValidatedRules:
    def test_real_rules_are_ranked(self) -> None:
        ntp = _build_real_rule(MatchMethod.PREFIX, "ntp server")
        logging = _build_real_rule(MatchMethod.PREFIX, "logging host")
        if ntp is None or logging is None:
            pytest.skip("could not auto-build a validated PatternRule")
        result = suggest("ntp server 10.0.0.1", [logging, ntp])
        assert len(result) == 1
        assert result[0].rule is ntp
        assert result[0].score == pytest.approx(1.0)


# --------------------------------------------------------------------------
# Module surface
# --------------------------------------------------------------------------


def test_public_api() -> None:
    assert set(suggester.__all__) == {
        "DEFAULT_LIMIT",
        "DEFAULT_MIN_SCORE",
        "MAX_LINE_LENGTH",
        "Suggestion",
        "suggest",
    }
    for name in suggester.__all__:
        assert hasattr(suggester, name)


def test_constants() -> None:
    assert suggester.DEFAULT_LIMIT == 5
    assert suggester.DEFAULT_MIN_SCORE == 0.25
    assert suggester.MAX_LINE_LENGTH == 4096