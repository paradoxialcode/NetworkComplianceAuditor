"""Persistence for confirmed PatternRule objects.

A rule file is a small UTF-8 JSON document::

    {"rules": [{...}, ...], "version": 1}

Responsibilities:
    - Save rules atomically (temp file in the same directory, fsync, replace),
      so a crash can never leave a half-written rule file.
    - Load rules, rebuilding each one through ``PatternRule(...)`` so every
      loaded rule passes the same validation as a freshly created one.
    - Reject duplicate rule ids (via ``ensure_unique_rule_ids``).

Non-responsibilities:
    - Matching, suggestions, compliance evaluation.
    - Deciding what a good rule is. Rules hold patterns, not sample lines.

Safety:
    - Malformed input raises ``ValueError``; nothing is silently skipped.
    - Error messages never include file contents, so a secret that ended up
      in a bad file cannot leak through an exception.
    - Files larger than ``MAX_STORE_BYTES`` are refused.
    - Fields are discovered from the ``PatternRule`` dataclass itself, so a
      new field needs no change here as long as its type is an enum, str,
      bool, int, float, None, a union of those, or ``tuple[X, ...]`` of those.
"""

from __future__ import annotations

import dataclasses
import enum
import json
import os
import tempfile
import types
import typing
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path
from typing import Any

from auditor.training.patterns import PatternRule, ensure_unique_rule_ids

__all__ = [
    "MAX_STORE_BYTES",
    "STORE_VERSION",
    "add_rule",
    "load_rules",
    "save_rules",
]

STORE_VERSION = 1
MAX_STORE_BYTES = 5 * 1024 * 1024

_WRONG_TYPE = "value has the wrong type"


# --------------------------------------------------------------------------
# Input validation
# --------------------------------------------------------------------------


def _require_path(path: object) -> Path:
    if not isinstance(path, Path):
        raise TypeError(f"path must be pathlib.Path, got {type(path).__name__}")
    return path


def _require_rule(rule: object) -> PatternRule:
    if not isinstance(rule, PatternRule):
        raise TypeError(f"rule must be PatternRule, got {type(rule).__name__}")
    return rule


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
# Field encoding / decoding
# --------------------------------------------------------------------------


@lru_cache(maxsize=1)
def _init_fields() -> tuple[dataclasses.Field[Any], ...]:
    return tuple(f for f in dataclasses.fields(PatternRule) if f.init)


@lru_cache(maxsize=1)
def _hints() -> dict[str, Any]:
    return typing.get_type_hints(PatternRule)


def _has_default(field: dataclasses.Field[Any]) -> bool:
    return (
        field.default is not dataclasses.MISSING
        or field.default_factory is not dataclasses.MISSING
    )


def _encode(value: object) -> object:
    """Convert a field value to plain JSON data.

    >>> _encode((1, "a", None))
    [1, 'a', None]
    >>> _encode(object())
    Traceback (most recent call last):
        ...
    TypeError: cannot store value of type object
    """
    if isinstance(value, enum.Enum):
        return _encode(value.value)
    if value is None or type(value) in (bool, int, float, str):
        return value
    if isinstance(value, (tuple, list)):
        return [_encode(item) for item in value]
    raise TypeError(f"cannot store value of type {type(value).__name__}")


def _decode(hint: object, value: object) -> object:
    """Convert plain JSON data back to a value of type ``hint``.

    >>> _decode(bool, True)
    True
    >>> _decode(bool, "yes")
    Traceback (most recent call last):
        ...
    ValueError: value has the wrong type
    >>> _decode(int, True)
    Traceback (most recent call last):
        ...
    ValueError: value has the wrong type
    """
    origin = typing.get_origin(hint)

    if origin is typing.Union or origin is types.UnionType:
        for option in typing.get_args(hint):
            if option is type(None):
                if value is None:
                    return None
                continue
            try:
                return _decode(option, value)
            except (TypeError, ValueError):
                continue
        raise ValueError(_WRONG_TYPE)

    if hint is type(None):
        if value is None:
            return None
        raise ValueError(_WRONG_TYPE)

    if isinstance(hint, type) and issubclass(hint, enum.Enum):
        try:
            return hint(value)
        except (TypeError, ValueError):
            raise ValueError(_WRONG_TYPE) from None

    if origin is tuple:
        args = typing.get_args(hint)
        if not isinstance(value, list):
            raise ValueError(_WRONG_TYPE)
        if len(args) == 2 and args[1] is Ellipsis:
            return tuple(_decode(args[0], item) for item in value)
        raise TypeError(f"unsupported field type {hint!r}")

    if hint is bool:
        if type(value) is bool:
            return value
        raise ValueError(_WRONG_TYPE)
    if hint is int:
        if type(value) is int:
            return value
        raise ValueError(_WRONG_TYPE)
    if hint is float:
        if type(value) in (int, float):
            return float(typing.cast(float, value))
        raise ValueError(_WRONG_TYPE)
    if hint is str:
        if isinstance(value, str):
            return value
        raise ValueError(_WRONG_TYPE)

    raise TypeError(f"unsupported field type {hint!r}")


def _rule_to_dict(rule: PatternRule) -> dict[str, object]:
    return {f.name: _encode(getattr(rule, f.name)) for f in _init_fields()}


def _dict_to_rule(data: object, index: int) -> PatternRule:
    if not isinstance(data, dict):
        raise ValueError(f"rule {index} must be a JSON object")

    fields = _init_fields()
    known = {f.name for f in fields}
    if any(key not in known for key in data):
        raise ValueError(f"rule {index} has unknown fields")

    kwargs: dict[str, Any] = {}
    hints = _hints()
    for field in fields:
        if field.name not in data:
            if _has_default(field):
                continue
            raise ValueError(f"rule {index} is missing required field: {field.name}")
        try:
            kwargs[field.name] = _decode(hints[field.name], data[field.name])
        except (TypeError, ValueError):
            raise ValueError(
                f"rule {index}: invalid value for field {field.name}"
            ) from None

    try:
        return PatternRule(**kwargs)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"rule {index} is invalid: {exc}") from None


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def _reject_constant(_name: str) -> object:
    raise ValueError("non-finite numbers are not allowed")


def load_rules(path: Path, *, missing_ok: bool = False) -> tuple[PatternRule, ...]:
    """Load and validate all rules from ``path``.

    Args:
        path: Rule file written by :func:`save_rules`.
        missing_ok: Return ``()`` instead of raising when the file is absent.

    Raises:
        TypeError: ``path`` is not a ``Path``.
        FileNotFoundError: the file does not exist and ``missing_ok`` is False.
        ValueError: the file is too large, not UTF-8, not valid JSON, has the
            wrong structure or version, holds an invalid rule, or holds
            duplicate rule ids.
    """
    path = _require_path(path)

    try:
        size = path.stat().st_size
    except FileNotFoundError:
        if missing_ok:
            return ()
        raise
    if size > MAX_STORE_BYTES:
        raise ValueError("rule store is too large")

    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("rule store is not valid UTF-8") from None
    try:
        document = json.loads(text, parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        raise ValueError("rule store is not valid JSON") from None

    if not isinstance(document, dict):
        raise ValueError("rule store must be a JSON object")
    if set(document) != {"version", "rules"}:
        raise ValueError("rule store has unexpected top-level keys")
    if type(document["version"]) is not int or document["version"] != STORE_VERSION:
        raise ValueError("unsupported rule store version")
    items = document["rules"]
    if not isinstance(items, list):
        raise ValueError("rule store 'rules' must be a list")

    rules = tuple(_dict_to_rule(item, index) for index, item in enumerate(items))
    ensure_unique_rule_ids(rules)
    return rules


def save_rules(path: Path, rules: Iterable[PatternRule]) -> None:
    """Atomically write ``rules`` to ``path`` (replacing any existing file).

    Nothing is written if validation fails, so an existing file stays intact.

    Raises:
        TypeError: bad argument types.
        ValueError: duplicate rule ids, or the result exceeds the size limit.
        OSError: the file system refused the write.
    """
    path = _require_path(path)
    checked = _require_rules(rules)
    ensure_unique_rule_ids(checked)

    document = {
        "version": STORE_VERSION,
        "rules": [_rule_to_dict(rule) for rule in checked],
    }
    text = json.dumps(
        document, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False
    )
    encoded = (text + "\n").encode("utf-8")
    if len(encoded) > MAX_STORE_BYTES:
        raise ValueError("rule store would be too large")

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def add_rule(path: Path, rule: PatternRule) -> None:
    """Append one rule to the file at ``path`` (created if missing).

    Raises:
        ValueError: the rule's id already exists, or the existing file is bad.
    """
    path = _require_path(path)
    rule = _require_rule(rule)
    existing = load_rules(path, missing_ok=True)
    save_rules(path, (*existing, rule))


if __name__ == "__main__":
    import doctest

    doctest.testmod()