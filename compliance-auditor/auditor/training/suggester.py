r"""Rank existing rules by similarity to an unrecognized configuration line.

The Training page uses this to answer "which known rule does this new line
look most like?". It is a heuristic helper: it only ranks, it never decides.

How it works:
    - The line and every rule expression are reduced to lowercase ASCII words
      of two or more letters. Digits, IP addresses and punctuation are
      ignored, so values never influence the ranking. Hyphens and underscores
      split words (``secure-server`` -> ``secure``, ``server``).
    - REGEX expressions are cleaned first (escapes, character classes and
      named groups removed) so ``\S+`` and ``[A-Za-z0-9]+`` do not create
      fake words.
    - Words are weighted with TF-IDF over the supplied rules and compared
      with cosine similarity (0.0 to 1.0, rounded to 12 places).

Responsibilities:
    - Validate inputs and rank rules, best first.

Non-responsibilities:
    - Persistence, matching, rule creation, compliance evaluation.
    - Deciding whether a suggestion is correct.

Behaviour worth knowing:
    - Only rules with a score above 0 are returned, even if ``min_score`` is 0.
    - Ties keep the original rule order.
    - A negated line (``no ip http server``) can resemble the positive rule
      (``ip http server``). It scores below an exact match but is not
      excluded, so the user must confirm suggestions.
    - With no rules, there is nothing to suggest and the result is ``()``.

Safety:
    - The line is used transiently and never stored.
    - Error messages never include the line or any rule text.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from auditor.training.patterns import MatchMethod, PatternRule

__all__ = [
    "DEFAULT_LIMIT",
    "DEFAULT_MIN_SCORE",
    "MAX_LINE_LENGTH",
    "Suggestion",
    "suggest",
]

DEFAULT_LIMIT = 5
DEFAULT_MIN_SCORE = 0.25
MAX_LINE_LENGTH = 4096

_WORD = re.compile(r"[a-z]{2,}")
_REGEX_NAMED_GROUP = re.compile(r"\(\?P<[^>]*>")
_REGEX_NAMED_BACKREF = re.compile(r"\(\?P=[^)]*\)")
_REGEX_ESCAPE = re.compile(r"\\.")
_REGEX_CLASS = re.compile(r"\[[^\]]*\]")


@dataclass(frozen=True, slots=True)
class Suggestion:
    """One ranked suggestion.

    Attributes:
        rule: The existing rule that resembles the line.
        score: Cosine similarity, greater than 0.0 and at most 1.0.
        shared_terms: Words found in both the line and the rule, sorted.
    """

    rule: PatternRule
    score: float
    shared_terms: tuple[str, ...]


# --------------------------------------------------------------------------
# Input validation
# --------------------------------------------------------------------------


def _require_line(line: object) -> str:
    if not isinstance(line, str):
        raise TypeError(f"line must be str, got {type(line).__name__}")
    if "\n" in line:
        raise ValueError("line must be a single line (contains newline)")
    if len(line) > MAX_LINE_LENGTH:
        raise ValueError("line is too long")
    return line


def _require_limit(limit: object) -> int:
    """Return ``limit`` if it is an int of at least 1.

    >>> _require_limit(3)
    3
    >>> _require_limit(0)
    Traceback (most recent call last):
        ...
    ValueError: limit must be at least 1
    >>> _require_limit(True)
    Traceback (most recent call last):
        ...
    TypeError: limit must be int, got bool
    """
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise TypeError(f"limit must be int, got {type(limit).__name__}")
    if limit < 1:
        raise ValueError("limit must be at least 1")
    return limit


def _require_min_score(value: object) -> float:
    """Return ``value`` as a float in [0, 1].

    >>> _require_min_score(1)
    1.0
    >>> _require_min_score(1.5)
    Traceback (most recent call last):
        ...
    ValueError: min_score must be between 0 and 1
    >>> _require_min_score("0.5")
    Traceback (most recent call last):
        ...
    TypeError: min_score must be a number, got str
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"min_score must be a number, got {type(value).__name__}")
    score = float(value)
    if not math.isfinite(score) or not 0.0 <= score <= 1.0:
        raise ValueError("min_score must be between 0 and 1")
    return score


def _require_rules(rules: object) -> tuple[PatternRule, ...]:
    if isinstance(rules, (str, bytes)) or not isinstance(rules, Iterable):
        raise TypeError(
            f"rules must be an iterable of PatternRule, got {type(rules).__name__}"
        )
    collected: list[PatternRule] = []
    for item in rules:
        if not isinstance(item, PatternRule):
            raise TypeError(
                f"rules must contain PatternRule objects, got {type(item).__name__}"
            )
        collected.append(item)
    return tuple(collected)


# --------------------------------------------------------------------------
# Tokenization
# --------------------------------------------------------------------------


def _line_words(line: str) -> tuple[str, ...]:
    """Reduce a line to lowercase words; digits and punctuation are dropped.

    >>> _line_words("ntp server 10.0.0.1")
    ('ntp', 'server')
    >>> _line_words("NTP-SERVER x")
    ('ntp', 'server')
    >>> _line_words("10.0.0.1 /24 !")
    ()
    """
    return tuple(_WORD.findall(line.lower()))


def _expression_words(expression: str, *, regex: bool) -> tuple[str, ...]:
    r"""Reduce a rule expression to lowercase words.

    For REGEX expressions, escapes, character classes and named groups are
    removed first so they do not produce fake words.

    >>> _expression_words(r"abc\defg", regex=True)
    ('abc', 'efg')
    >>> _expression_words(r"abc\defg", regex=False)
    ('abc', 'defg')
    >>> _expression_words("ip http server", regex=False)
    ('ip', 'http', 'server')
    """
    text = expression
    if regex:
        text = _REGEX_NAMED_GROUP.sub(" ", text)
        text = _REGEX_NAMED_BACKREF.sub(" ", text)
        text = _REGEX_ESCAPE.sub(" ", text)
        text = _REGEX_CLASS.sub(" ", text)
    return tuple(_WORD.findall(text.lower()))


def _rule_words(rule: PatternRule) -> tuple[str, ...]:
    return _expression_words(rule.expression, regex=rule.method is MatchMethod.REGEX)


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------


def _idf(n_docs: int, doc_freq: int) -> float:
    """Smoothed inverse document frequency; always at least 1.0.

    >>> _idf(4, 4)
    1.0
    >>> _idf(0, 0)
    1.0
    """
    return math.log((1 + n_docs) / (1 + doc_freq)) + 1.0


def _weights(
    counts: Mapping[str, int],
    doc_freq: Mapping[str, int],
    n_docs: int,
) -> dict[str, float]:
    return {
        word: count * _idf(n_docs, doc_freq.get(word, 0))
        for word, count in counts.items()
    }


def _norm(weights: Mapping[str, float]) -> float:
    return math.sqrt(sum(weight * weight for weight in weights.values()))


def _cosine(
    left: Mapping[str, float],
    left_norm: float,
    right: Mapping[str, float],
    right_norm: float,
) -> float:
    if left_norm == 0.0 or right_norm == 0.0:
        return 0.0
    small, large = (left, right) if len(left) <= len(right) else (right, left)
    dot = sum(weight * large[word] for word, weight in small.items() if word in large)
    raw = dot / (left_norm * right_norm)
    return round(min(1.0, max(0.0, raw)), 12)


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def suggest(
    line: str,
    rules: Iterable[PatternRule],
    *,
    limit: int = DEFAULT_LIMIT,
    min_score: float = DEFAULT_MIN_SCORE,
) -> tuple[Suggestion, ...]:
    r"""Return the rules most similar to ``line``, best first.

    Args:
        line: One unrecognized configuration line.
        rules: Existing rules to rank.
        limit: Maximum number of suggestions (at least 1).
        min_score: Minimum similarity, from 0.0 to 1.0.

    Returns:
        Suggestions sorted by score (highest first); ties keep rule order.
        Rules with a score of 0 are never returned.

    Raises:
        TypeError: an argument has the wrong type.
        ValueError: ``line`` has a newline or is too long, ``limit`` is below
            1, or ``min_score`` is outside 0 to 1.

    >>> suggest("ntp server 10.0.0.1", [])
    ()
    >>> suggest("a\nb", [])
    Traceback (most recent call last):
        ...
    ValueError: line must be a single line (contains newline)
    >>> suggest(5, [])
    Traceback (most recent call last):
        ...
    TypeError: line must be str, got int
    """
    text = _require_line(line)
    max_results = _require_limit(limit)
    threshold = _require_min_score(min_score)
    rule_list = _require_rules(rules)

    query = Counter(_line_words(text))
    if not query or not rule_list:
        return ()

    docs = [Counter(_rule_words(rule)) for rule in rule_list]
    doc_freq: Counter[str] = Counter()
    for doc in docs:
        doc_freq.update(doc.keys())
    n_docs = len(docs)

    query_weights = _weights(query, doc_freq, n_docs)
    query_norm = _norm(query_weights)

    ranked: list[tuple[float, int]] = []
    for index, doc in enumerate(docs):
        doc_weights = _weights(doc, doc_freq, n_docs)
        score = _cosine(query_weights, query_norm, doc_weights, _norm(doc_weights))
        if score > 0.0 and score >= threshold:
            ranked.append((score, index))
    ranked.sort(key=lambda item: (-item[0], item[1]))

    return tuple(
        Suggestion(
            rule=rule_list[index],
            score=score,
            shared_terms=tuple(sorted(set(query) & set(docs[index]))),
        )
        for score, index in ranked[:max_results]
    )


if __name__ == "__main__":
    import doctest

    doctest.testmod()