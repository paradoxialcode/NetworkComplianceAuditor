"""Tests for auditor.training.store."""

from __future__ import annotations

import dataclasses
import enum
import itertools
import json
import types
import typing
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from auditor.training import store
from auditor.training.patterns import MatchMethod, PatternRule
from auditor.training.store import add_rule, load_rules, save_rules

# --------------------------------------------------------------------------
# Building real, validated rules
# --------------------------------------------------------------------------

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


def _any(value: object) -> Any:
    """Hand a deliberately wrong value to a typed API without type noise."""
    return value


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


def _make(method: MatchMethod, expression: str) -> PatternRule:
    rule = _build_real_rule(method, expression)
    if rule is None:
        pytest.skip(
            "could not auto-build a validated PatternRule; "
            "paste the PatternRule class so the builder can be adjusted"
        )
    return rule


RuleFactory = Callable[[int], PatternRule]


@pytest.fixture
def rule_factory() -> RuleFactory:
    def factory(n: int) -> PatternRule:
        return _make(MatchMethod.EXACT, f"ntp server host{n}")

    return factory


@pytest.fixture
def path(tmp_path: Path) -> Path:
    return tmp_path / "rules.json"


def _document(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _first_rule(document: dict[str, Any]) -> dict[str, Any]:
    rules = document["rules"]
    assert isinstance(rules, list)
    first = rules[0]
    assert isinstance(first, dict)
    return first


def _write_document(path: Path, document: object) -> None:
    path.write_text(json.dumps(document), encoding="utf-8")


def _saved_document(path: Path, rule: PatternRule) -> dict[str, Any]:
    save_rules(path, [rule])
    return _document(path)


# --------------------------------------------------------------------------
# Round trips
# --------------------------------------------------------------------------


class TestRoundTrip:
    def test_single_rule(self, path: Path, rule_factory: RuleFactory) -> None:
        rule = rule_factory(1)
        save_rules(path, [rule])
        assert load_rules(path) == (rule,)

    def test_many_rules_keep_order_and_methods(self, path: Path) -> None:
        rules = (
            _make(MatchMethod.EXACT, "ip http server"),
            _make(MatchMethod.PREFIX, "ntp server"),
            _make(MatchMethod.REGEX, r"logging host \S+"),
        )
        save_rules(path, rules)
        assert load_rules(path) == rules

    def test_empty_rule_set(self, path: Path) -> None:
        save_rules(path, [])
        assert load_rules(path) == ()

    def test_accepts_generator(self, path: Path, rule_factory: RuleFactory) -> None:
        def gen() -> Iterator[PatternRule]:
            yield rule_factory(1)
            yield rule_factory(2)

        save_rules(path, gen())
        assert len(load_rules(path)) == 2

    def test_returns_tuple(self, path: Path, rule_factory: RuleFactory) -> None:
        save_rules(path, [rule_factory(1)])
        assert isinstance(load_rules(path), tuple)

    def test_overwrite_replaces_content(
        self, path: Path, rule_factory: RuleFactory
    ) -> None:
        save_rules(path, [rule_factory(1), rule_factory(2)])
        replacement = rule_factory(3)
        save_rules(path, [replacement])
        assert load_rules(path) == (replacement,)


# --------------------------------------------------------------------------
# File format and write behaviour
# --------------------------------------------------------------------------


class TestFileFormat:
    def test_document_shape(self, path: Path, rule_factory: RuleFactory) -> None:
        save_rules(path, [rule_factory(1), rule_factory(2)])
        raw = path.read_bytes()
        document = json.loads(raw.decode("utf-8"))
        assert document["version"] == 1
        assert isinstance(document["rules"], list)
        assert len(document["rules"]) == 2
        assert raw.endswith(b"\n")
        assert b"\r" not in raw

    def test_output_is_deterministic(
        self, path: Path, rule_factory: RuleFactory
    ) -> None:
        rules = [rule_factory(1), rule_factory(2)]
        save_rules(path, rules)
        first = path.read_bytes()
        save_rules(path, rules)
        assert path.read_bytes() == first

    def test_creates_parent_directories(
        self, tmp_path: Path, rule_factory: RuleFactory
    ) -> None:
        target = tmp_path / "a" / "b" / "rules.json"
        save_rules(target, [rule_factory(1)])
        assert target.is_file()

    def test_no_temp_files_left_behind(
        self, tmp_path: Path, path: Path, rule_factory: RuleFactory
    ) -> None:
        save_rules(path, [rule_factory(1)])
        save_rules(path, [rule_factory(2)])
        assert sorted(p.name for p in tmp_path.iterdir()) == ["rules.json"]

    def test_failed_replace_keeps_original_and_cleans_up(
        self,
        tmp_path: Path,
        path: Path,
        rule_factory: RuleFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        save_rules(path, [rule_factory(1)])
        before = path.read_bytes()

        def boom(src: object, dst: object) -> None:
            raise OSError("disk exploded")

        monkeypatch.setattr(store.os, "replace", boom)
        with pytest.raises(OSError):
            save_rules(path, [rule_factory(2)])
        monkeypatch.undo()

        assert path.read_bytes() == before
        assert sorted(p.name for p in tmp_path.iterdir()) == ["rules.json"]

    def test_duplicate_ids_write_nothing(
        self, path: Path, rule_factory: RuleFactory
    ) -> None:
        rule = rule_factory(1)
        with pytest.raises(ValueError):
            save_rules(path, [rule, rule])
        assert not path.exists()

    def test_duplicate_ids_leave_existing_file_intact(
        self, path: Path, rule_factory: RuleFactory
    ) -> None:
        rule = rule_factory(1)
        save_rules(path, [rule])
        before = path.read_bytes()
        with pytest.raises(ValueError):
            save_rules(path, [rule, rule])
        assert path.read_bytes() == before

    def test_oversized_result_is_refused(
        self,
        path: Path,
        rule_factory: RuleFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(store, "MAX_STORE_BYTES", 10)
        with pytest.raises(ValueError, match="too large"):
            save_rules(path, [rule_factory(1)])
        assert not path.exists()


# --------------------------------------------------------------------------
# Missing files
# --------------------------------------------------------------------------


class TestMissingFile:
    def test_missing_file_raises(self, path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_rules(path)

    def test_missing_ok_returns_empty(self, path: Path) -> None:
        assert load_rules(path, missing_ok=True) == ()

    def test_missing_ok_does_not_hide_bad_files(self, path: Path) -> None:
        path.write_text("not json", encoding="utf-8")
        with pytest.raises(ValueError):
            load_rules(path, missing_ok=True)


# --------------------------------------------------------------------------
# add_rule
# --------------------------------------------------------------------------


class TestAddRule:
    def test_creates_file(self, path: Path, rule_factory: RuleFactory) -> None:
        rule = rule_factory(1)
        add_rule(path, rule)
        assert load_rules(path) == (rule,)

    def test_appends_in_order(self, path: Path, rule_factory: RuleFactory) -> None:
        first, second = rule_factory(1), rule_factory(2)
        add_rule(path, first)
        add_rule(path, second)
        assert load_rules(path) == (first, second)

    def test_duplicate_raises_and_file_unchanged(
        self, path: Path, rule_factory: RuleFactory
    ) -> None:
        rule = rule_factory(1)
        add_rule(path, rule)
        before = path.read_bytes()
        with pytest.raises(ValueError):
            add_rule(path, rule)
        assert path.read_bytes() == before

    def test_bad_existing_file_is_not_overwritten(
        self, path: Path, rule_factory: RuleFactory
    ) -> None:
        path.write_text("garbage", encoding="utf-8")
        with pytest.raises(ValueError):
            add_rule(path, rule_factory(1))
        assert path.read_text(encoding="utf-8") == "garbage"


# --------------------------------------------------------------------------
# Malformed files
# --------------------------------------------------------------------------



class TestMalformedFiles:
    @pytest.mark.parametrize(
        ("content", "message"),
        [
            pytest.param(b"", "not valid JSON", id="empty"),
            pytest.param(b"not json", "not valid JSON", id="plain-text"),
            pytest.param(
                b'{"version": 1, "rules": [', "not valid JSON", id="truncated"
            ),
            pytest.param(
                b'{"version": 1, "rules": [NaN]}', "not valid JSON", id="nan"
            ),
            pytest.param(
                b"[" * 100_000 + b"]" * 100_000,
                "not valid JSON",
                id="deeply-nested",
            ),
            pytest.param(b"\xff\xfe\x00", "not valid UTF-8", id="bad-utf8"),
            pytest.param(b"[]", "must be a JSON object", id="top-level-list"),
            pytest.param(b'"text"', "must be a JSON object", id="top-level-string"),
            pytest.param(b"{}", "top-level keys", id="no-keys"),
            pytest.param(b'{"version": 1}', "top-level keys", id="no-rules-key"),
            pytest.param(b'{"rules": []}', "top-level keys", id="no-version-key"),
            pytest.param(
                b'{"version": 1, "rules": [], "extra": 1}',
                "top-level keys",
                id="extra-key",
            ),
            pytest.param(
                b'{"version": 1, "rules": {}}', "must be a list", id="rules-dict"
            ),
            pytest.param(
                b'{"version": 1, "rules": "x"}', "must be a list", id="rules-string"
            ),
        ],
    )
    def test_bad_document(
        self, path: Path, content: bytes, message: str
    ) -> None:
        path.write_bytes(content)
        with pytest.raises(ValueError, match=message):
            load_rules(path)

    @pytest.mark.parametrize("version", [0, 2, "1", True, 1.0, None])
    def test_bad_version(self, path: Path, version: object) -> None:
        _write_document(path, {"version": version, "rules": []})
        with pytest.raises(ValueError, match="unsupported rule store version"):
            load_rules(path)

    def test_oversized_file_is_refused(
        self, path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path.write_bytes(b" " * 11)
        monkeypatch.setattr(store, "MAX_STORE_BYTES", 10)
        with pytest.raises(ValueError, match="too large"):
            load_rules(path)

    def test_directory_is_not_a_rule_file(self, tmp_path: Path) -> None:
        with pytest.raises(OSError):
            load_rules(tmp_path)



class TestMalformedRules:
    @pytest.mark.parametrize("item", [None, 5, "rule", ["a"], True])
    def test_rule_must_be_object(self, path: Path, item: object) -> None:
        _write_document(path, {"version": 1, "rules": [item]})
        with pytest.raises(ValueError, match="rule 0 must be a JSON object"):
            load_rules(path)

    def test_unknown_field(self, path: Path, rule_factory: RuleFactory) -> None:
        document = _saved_document(path, rule_factory(1))
        _first_rule(document)["zz_unknown"] = 1
        _write_document(path, document)
        with pytest.raises(ValueError, match="unknown fields"):
            load_rules(path)

    def test_missing_required_field(
        self, path: Path, rule_factory: RuleFactory
    ) -> None:
        document = _saved_document(path, rule_factory(1))
        del _first_rule(document)["expression"]
        _write_document(path, document)
        with pytest.raises(ValueError, match="missing required field: expression"):
            load_rules(path)

    @pytest.mark.parametrize("bad", [5, None, ["x"], True])
    def test_wrong_field_type(
        self, path: Path, rule_factory: RuleFactory, bad: object
    ) -> None:
        document = _saved_document(path, rule_factory(1))
        _first_rule(document)["expression"] = bad
        _write_document(path, document)
        with pytest.raises(ValueError, match="invalid value for field expression"):
            load_rules(path)

    def test_unknown_enum_value(self, path: Path, rule_factory: RuleFactory) -> None:
        document = _saved_document(path, rule_factory(1))
        _first_rule(document)["method"] = "bogus-method"
        _write_document(path, document)
        with pytest.raises(ValueError, match="invalid value for field method"):
            load_rules(path)

    def test_rule_rejected_by_pattern_rule_validation(
        self, path: Path, rule_factory: RuleFactory
    ) -> None:
        document = _saved_document(path, rule_factory(1))
        _first_rule(document)["expression"] = ""
        _write_document(path, document)
        with pytest.raises(ValueError, match="rule 0 is invalid"):
            load_rules(path)

    def test_error_names_the_failing_rule_index(
        self, path: Path, rule_factory: RuleFactory
    ) -> None:
        save_rules(path, [rule_factory(1), rule_factory(2)])
        document = _document(path)
        document["rules"][1]["expression"] = 5
        _write_document(path, document)
        with pytest.raises(ValueError, match="rule 1"):
            load_rules(path)

    def test_duplicate_rules_in_file(
        self, path: Path, rule_factory: RuleFactory
    ) -> None:
        document = _saved_document(path, rule_factory(1))
        document["rules"].append(dict(_first_rule(document)))
        _write_document(path, document)
        with pytest.raises(ValueError):
            load_rules(path)


# --------------------------------------------------------------------------
# Secrets must never be echoed
# --------------------------------------------------------------------------


class TestNoSecretEcho:
    SECRET = "hunter2-SuperSecret"

    def test_invalid_json_does_not_echo_content(self, path: Path) -> None:
        path.write_text(f'{{"password": "{self.SECRET}" ', encoding="utf-8")
        with pytest.raises(ValueError) as info:
            load_rules(path)
        assert self.SECRET not in str(info.value)
        assert self.SECRET not in repr(info.value.__cause__)

    def test_bad_enum_value_does_not_echo_content(
        self, path: Path, rule_factory: RuleFactory
    ) -> None:
        document = _saved_document(path, rule_factory(1))
        _first_rule(document)["method"] = self.SECRET
        _write_document(path, document)
        with pytest.raises(ValueError) as info:
            load_rules(path)
        assert self.SECRET not in str(info.value)

    def test_unknown_field_name_is_not_echoed(
        self, path: Path, rule_factory: RuleFactory
    ) -> None:
        document = _saved_document(path, rule_factory(1))
        _first_rule(document)[self.SECRET] = 1
        _write_document(path, document)
        with pytest.raises(ValueError) as info:
            load_rules(path)
        assert self.SECRET not in str(info.value)

    def test_bad_utf8_does_not_echo_content(self, path: Path) -> None:
        path.write_bytes(self.SECRET.encode("utf-8") + b"\xff")
        with pytest.raises(ValueError) as info:
            load_rules(path)
        assert self.SECRET not in str(info.value)


# --------------------------------------------------------------------------
# Argument validation
# --------------------------------------------------------------------------


class TestArgumentValidation:
    def test_save_requires_path_object(self, rule_factory: RuleFactory) -> None:
        with pytest.raises(TypeError, match="path must be pathlib.Path"):
            save_rules(_any("rules.json"), [rule_factory(1)])

    def test_load_requires_path_object(self) -> None:
        with pytest.raises(TypeError, match="path must be pathlib.Path"):
            load_rules(_any("rules.json"))

    def test_add_requires_path_object(self, rule_factory: RuleFactory) -> None:
        with pytest.raises(TypeError, match="path must be pathlib.Path"):
            add_rule(_any("rules.json"), rule_factory(1))

    @pytest.mark.parametrize("bad", ["text", b"bytes", 5, None])
    def test_rules_must_be_iterable_of_rules(self, path: Path, bad: object) -> None:
        with pytest.raises(TypeError, match="rules must be an iterable"):
            save_rules(path, _any(bad))
        assert not path.exists()

    def test_rules_must_contain_pattern_rules(
        self, path: Path, rule_factory: RuleFactory
    ) -> None:
        with pytest.raises(TypeError, match="rules must contain PatternRule"):
            save_rules(path, _any([rule_factory(1), "bad"]))
        assert not path.exists()

    @pytest.mark.parametrize("bad", ["rule", None, 5, {"method": "exact"}])
    def test_add_rule_requires_pattern_rule(self, path: Path, bad: object) -> None:
        with pytest.raises(TypeError, match="rule must be PatternRule"):
            add_rule(path, _any(bad))
        assert not path.exists()


# --------------------------------------------------------------------------
# Module surface
# --------------------------------------------------------------------------


def test_public_api() -> None:
    assert set(store.__all__) == {
        "MAX_STORE_BYTES",
        "STORE_VERSION",
        "add_rule",
        "load_rules",
        "save_rules",
    }
    for name in store.__all__:
        assert hasattr(store, name)


def test_store_version_is_one() -> None:
    assert store.STORE_VERSION == 1