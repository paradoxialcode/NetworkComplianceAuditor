import types
from collections.abc import Iterable, Iterator
from enum import Enum
from typing import Any, Union, get_args, get_origin

from pydantic import BaseModel, create_model

from .models import Check, Condition

_ENUM_OPS = frozenset({"eq", "ne", "in", "not_in"})
_NUMERIC_OPS = frozenset({"gt", "gte", "lt", "lte"})
_SCALAR_ITEM_FIELD = "value"


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


def _match_errors(cond: Condition, model: type[BaseModel]) -> Iterator[str]:
    if cond.field is None:
        return
    list_type, error = _resolve_type(model, cond.field)
    if error:
        yield f"{cond.field}: {error}"
        return
    if list_type is Any:
        return
    if get_origin(list_type) is not list:
        yield f"{cond.field}: any_match/none_match requires a list field ({list_type})"
        return
    args = get_args(list_type)
    item = _unwrap(args[0]) if args else Any
    if item is Any:
        return
    item_model = item if _is_model(item) else create_model("_ScalarItem", **{_SCALAR_ITEM_FIELD: (item, ...)})
    sub = cond.any_match if cond.any_match is not None else cond.none_match
    if sub is None:
        return
    for leaf in _leaves(sub):
        for message in _leaf_errors(leaf, item_model):
            yield f"{cond.field}[]: {message}"


def _leaf_errors(cond: Condition, model: type[BaseModel]) -> Iterator[str]:
    if cond.field is None:
        return
    if cond.any_match is not None or cond.none_match is not None:
        yield from _match_errors(cond, model)
        return
    if cond.op is None:
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
