"""Pattern matching engine for training rules.

Evaluates :class:`PatternRule` objects against a single configuration line.

Responsibilities:
    - Validate matcher inputs (types, single line, sane expressions).
    - Apply EXACT, PREFIX and REGEX matching.
    - Return matching rules in their original order.
    - Remain side-effect free (no I/O, no persistence, no state).

Non-responsibilities:
    - Persistence, training, suggestions.
    - Rule precedence or conflict resolution.
    - Compliance evaluation or SecurityBaseline modification.

Semantics:
    - EXACT: ``text == expression``.
    - PREFIX: ``text.startswith(expression)``; empty expression is rejected.
    - REGEX: ``re.fullmatch`` against the whole line (no implicit search).
    - ``text`` must be one line: it may not contain ``\\n``. Tokenizers
      split on ``\\n`` only; leading whitespace is the caller's concern.

Error messages never include the text being matched, so secrets in a
configuration line cannot leak through exceptions.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from typing import assert_never

from auditor.training.patterns import MatchMethod, PatternRule

__all__ = [
    "MatchResult",
    "evaluate",
    "matches",
    "matching_rules",
]


@dataclass(frozen=True, slots=True)
class MatchResult:
    """Result of matching one rule against one line."""

    matched: bool
    rule: PatternRule


def _require_rule(rule: object) -> PatternRule:
    """Return ``rule`` if it is a PatternRule, else raise TypeError.

    >>> _require_rule("x")
    Traceback (most recent call last):
        ...
    TypeError: rule must be PatternRule, got str
    """
    if not isinstance(rule, PatternRule):
        raise TypeError(f"rule must be PatternRule, got {type(rule).__name__}")
    return rule


def _require_text(text: object) -> str:
    """Return ``text`` if it is a single-line str, else raise.

    >>> _require_text("ntp server 10.0.0.1")
    'ntp server 10.0.0.1'
    >>> _require_text("")
    ''
    >>> _require_text(5)
    Traceback (most recent call last):
        ...
    TypeError: text must be str, got int
    >>> _require_text("a\\nb")
    Traceback (most recent call last):
        ...
    ValueError: text must be a single line (contains newline)
    """
    if not isinstance(text, str):
        raise TypeError(f"text must be str, got {type(text).__name__}")
    if "\n" in text:
        raise ValueError("text must be a single line (contains newline)")
    return text


@lru_cache(maxsize=1024)
def _compile(expression: str) -> re.Pattern[str]:
    """Compile a regex once; invalid patterns raise ValueError.

    >>> _compile("ab+").fullmatch("abbb") is not None
    True
    >>> _compile("ab+").fullmatch("xabbb") is None
    True
    >>> _compile("(")
    Traceback (most recent call last):
        ...
    ValueError: invalid regular expression in rule
    """
    try:
        return re.compile(expression)
    except re.error as exc:
        raise ValueError("invalid regular expression in rule") from exc


def matches(rule: PatternRule, text: str) -> bool:
    """Return True if ``text`` matches ``rule``.

    Args:
        rule: Pattern rule to evaluate.
        text: One configuration line.

    Raises:
        TypeError: ``rule`` is not a PatternRule or ``text`` is not a str.
        ValueError: ``text`` has a newline, a PREFIX expression is empty,
            or a REGEX expression is invalid.

    >>> matches("not a rule", "line")
    Traceback (most recent call last):
        ...
    TypeError: rule must be PatternRule, got str
    """
    rule = _require_rule(rule)
    text = _require_text(text)
    method = rule.method
    expression = rule.expression

    match method:
        case MatchMethod.EXACT:
            return text == expression
        case MatchMethod.PREFIX:
            if not expression:
                raise ValueError("PREFIX rule has an empty expression")
            return text.startswith(expression)
        case MatchMethod.REGEX:
            return _compile(expression).fullmatch(text) is not None
        case _:
            assert_never(method)


def evaluate(rule: PatternRule, text: str) -> MatchResult:
    """Return a structured :class:`MatchResult` for one rule and one line."""
    return MatchResult(matched=matches(rule, text), rule=rule)


def matching_rules(
    rules: Iterable[PatternRule],
    text: str,
) -> tuple[PatternRule, ...]:
    """Return every rule that matches ``text``, in original order.

    Args:
        rules: Rules to evaluate.
        text: One configuration line.

    Raises:
        TypeError: ``rules`` holds a non-PatternRule, or ``text`` is not a str.
        ValueError: as for :func:`matches`.

    >>> matching_rules([], "any line")
    ()
    >>> matching_rules(["x"], "any line")
    Traceback (most recent call last):
        ...
    TypeError: rules must contain PatternRule objects, got str
    >>> matching_rules([], 5)
    Traceback (most recent call last):
        ...
    TypeError: text must be str, got int
    """
    text = _require_text(text)
    found: list[PatternRule] = []
    for rule in rules:
        if not isinstance(rule, PatternRule):
            raise TypeError(
                f"rules must contain PatternRule objects, got {type(rule).__name__}"
            )
        if matches(rule, text):
            found.append(rule)
    return tuple(found)


if __name__ == "__main__":
    import doctest

    doctest.testmod()