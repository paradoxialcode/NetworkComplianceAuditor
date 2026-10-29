from collections.abc import Callable
from enum import Enum
from numbers import Real
from typing import Any, Final

from auditor import regex_safety

MAX_REGEX_LEN: Final = 256
MAX_MATCH_INPUT: Final = 4096


class _Missing(Enum):
    MISSING = "MISSING"


MISSING: Final = _Missing.MISSING


def _is_num(x: Any) -> bool:
    return isinstance(x, Real) and not isinstance(x, bool)


def _require_nums(a: Any, b: Any) -> None:
    if not (_is_num(a) and _is_num(b)):
        raise TypeError("numeric comparison requires numbers")


def _eq(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    return bool(a == b)


def _ne(a: Any, b: Any) -> bool:
    return not _eq(a, b)


def _gt(a: Any, b: Any) -> bool:
    _require_nums(a, b)
    return bool(a > b)


def _gte(a: Any, b: Any) -> bool:
    _require_nums(a, b)
    return bool(a >= b)


def _lt(a: Any, b: Any) -> bool:
    _require_nums(a, b)
    return bool(a < b)


def _lte(a: Any, b: Any) -> bool:
    _require_nums(a, b)
    return bool(a <= b)


def _in(a: Any, b: Any) -> bool:
    return any(_eq(a, x) for x in b)


def _not_in(a: Any, b: Any) -> bool:
    return not _in(a, b)


def _contains(a: Any, b: Any) -> bool:
    if isinstance(a, str):
        if not isinstance(b, str):
            raise TypeError("substring test requires a string operand")
        return b in a
    if isinstance(a, (list, tuple, set, frozenset)):
        return any(_eq(x, b) for x in a)
    raise TypeError("contains requires a string or a collection")


def _regex(a: Any, b: Any) -> bool:
    if not isinstance(a, str):
        raise TypeError("regex requires a string")
    return regex_safety.search(b, a[:MAX_MATCH_INPUT])


def _non_empty(a: Any, _b: Any) -> bool:
    if isinstance(a, (str, list, tuple, set, frozenset, dict)):
        return len(a) > 0
    raise TypeError("non_empty requires a string or a collection")


def _present(a: Any, _b: Any) -> bool:
    return a is not MISSING and a is not None


def _absent(a: Any, _b: Any) -> bool:
    return a is MISSING or a is None


OPERATORS: Final[dict[str, Callable[[Any, Any], bool]]] = {
    "eq": _eq,
    "ne": _ne,
    "gt": _gt,
    "gte": _gte,
    "lt": _lt,
    "lte": _lte,
    "in": _in,
    "not_in": _not_in,
    "contains": _contains,
    "regex": _regex,
    "non_empty": _non_empty,
    "present": _present,
    "absent": _absent,
}

EXISTENCE_OPS: Final = frozenset({"present", "absent"})
NO_VALUE_OPS: Final = frozenset({"present", "absent", "non_empty"})
_NUMERIC_OPS: Final = frozenset({"gt", "gte", "lt", "lte"})
_SET_OPS: Final = frozenset({"in", "not_in"})


def validate_operand(op: str, value: Any) -> None:
    if op not in OPERATORS:
        raise ValueError(f"unknown operator: {op!r}")
    if op in NO_VALUE_OPS:
        if value is not None:
            raise ValueError(f"operator {op!r} takes no value")
        return
    if value is None:
        raise ValueError(f"operator {op!r} requires a value")
    if op in _NUMERIC_OPS and not _is_num(value):
        raise ValueError(f"operator {op!r} requires a numeric value")
    if op in _SET_OPS and (not isinstance(value, (list, tuple)) or not value):
        raise ValueError(f"operator {op!r} requires a non-empty list")
    if op == "regex":
        if not isinstance(value, str) or len(value) > MAX_REGEX_LEN:
            raise ValueError(f"regex must be a string of at most {MAX_REGEX_LEN} chars")
        regex_safety.compile_pattern(value)
