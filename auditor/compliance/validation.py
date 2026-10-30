import types
from collections.abc import Iterable, Iterator
from enum import Enum
from typing import Any, Union, get_args, get_origin

from pydantic import BaseModel

from .models import Check, Condition

_ENUM_OPS = frozenset({"eq", "ne", "in", "not_in"})
_NUMERIC_OPS = frozenset({"gt", "gte", "lt", "lte"})


def _unwrap(tp: Any) -> Any:
    while get_origin(tp) in (Union, types.UnionType):
        args = [a for a in get_args(tp) if a is not type(None)]
        if len(args) != 1:
            return Any
        tp = args[0]
    return tp


def _is_model(tp: Any) -> bool:
    return isinstance(tp, type) and issubclass(tp, BaseModel)


def _resolve_type(model: type[BaseModel], path: str) -> tuple[Any, str | None]:
    current: Any = model
    for segment in path.split("."):
        current = _unwrap(current)
        if current is Any:
            return Any, None
        if _is_model(current):
            info = current.model_fields.get(segment)
            if info is None:
                return None, f"unknown field {segment!r} on {current.__name__}"
            current = info.annotation
        elif get_origin(current) is list:
            args = get_args(current)
            item = _unwrap(args[0]) if args else Any
            if segment.isdigit() or item is Any:
                current = item
            elif _is_model(item) and "key" in item.model_fields:
                current = item
            else:
                return None, f"{segment!r} is not an index or key lookup into {current}"
        else:
            return None, f"cannot descend into {segment!r}: {current} is a leaf"
    return _unwrap(current), None


def _leaves(cond: Condition) -> Iterator[Condition]:
    if cond.field is not None:
        yield cond
        return
    children = cond.all_of if cond.all_of is not None else cond.any_of
    for child in children or []:
        yield from _leaves(child)


def _leaf_errors(cond: Condition, model: type[BaseModel]) -> Iterator[str]:
    if cond.field is None or cond.op is None:
        return
    leaf_type, error = _resolve_type(model, cond.field)
    if error:
        yield f"{cond.field}: {error}"
        return
    if isinstance(leaf_type, type) and issubclass(leaf_type, Enum):
        if cond.op in _ENUM_OPS:
            allowed = {m.value for m in leaf_type}
            values = cond.value if cond.op in ("in", "not_in") else [cond.value]
            bad = [v for v in values if v not in allowed]
            if bad:
                yield f"{cond.field}: {bad} not in {sorted(allowed)}"
        elif cond.op in _NUMERIC_OPS:
            yield f"{cond.field}: numeric operator {cond.op!r} on enum field"
    elif cond.op in _NUMERIC_OPS and leaf_type not in (int, float, Any):
        yield f"{cond.field}: numeric operator {cond.op!r} on non-numeric field ({leaf_type})"


def validate_check_fields(checks: Iterable[Check], model: type[BaseModel]) -> list[str]:
    errors: list[str] = []
    for check in checks:
        for leaf in _leaves(check.condition):
            errors.extend(f"{check.id}: {msg}" for msg in _leaf_errors(leaf, model))
    return errors
