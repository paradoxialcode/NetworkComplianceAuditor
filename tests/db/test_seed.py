"""Tests for auditor.db.seed and the schema in auditor.db.models."""

from __future__ import annotations

import dataclasses
import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest

import auditor.db.seed as seed_module
from auditor.db.schema import MIGRATIONS, ORIGIN_SEED, ORIGIN_USER, ORIGINS
from auditor.db.seed import (
    DEFAULT_MAPPINGS_DIR,
    SeedResult,
    fetch_rules,
    load_mapping_rules,
    seed_database,
    seed_rules,
)
from auditor.db.session import connect, migrate, schema_version
from auditor.parsers.normalizer import Vendor
from auditor.training.patterns import PatternRule
from auditor.training.store import save_rules

SECRET = "hunter2"
EXPECTED_ORDER = ["cisco-http", "cisco-telnet", "forti-host", "forti-telnet"]
_SUGGESTED_CANDIDATES: tuple[object, ...] = (True, "example.com", "example", False)


# --------------------------------------------------------------------------
# Factories and helpers
# --------------------------------------------------------------------------


def make_rule(
    rule_id: str,
    vendor: Vendor,
    method: str,
    expression: str,
    target_field: str,
) -> PatternRule:
    last: Exception | None = None
    for candidate in _SUGGESTED_CANDIDATES:
        kwargs: dict[str, Any] = {
            "rule_id": rule_id,
            "vendor": vendor.value,
            "method": method,
            "expression": expression,
            "target_field": target_field,
            "suggested_value": candidate,
            "confidence": 0.9,
            "explanation": "Example explanation for tests.",
        }
        try:
            return PatternRule(**kwargs)
        except (TypeError, ValueError) as exc:
            last = exc
    raise RuntimeError("could not build a PatternRule for the tests") from last


@pytest.fixture
def rules() -> dict[str, PatternRule]:
    specs = (
        ("cisco-http", Vendor.CISCO_IOS, "exact", "ip http server", "http_management_enabled"),
        ("cisco-telnet", Vendor.CISCO_IOS, "prefix", "transport input telnet", "telnet_enabled"),
        ("forti-telnet", Vendor.FORTIOS, "exact", "set admin-telnet enable", "telnet_enabled"),
        ("forti-host", Vendor.FORTIOS, "prefix", "set hostname", "hostname"),
    )
    return {spec[0]: make_rule(*spec) for spec in specs}


@pytest.fixture
def conn() -> Iterator[sqlite3.Connection]:
    connection = connect()
    migrate(connection, MIGRATIONS)
    try:
        yield connection
    finally:
        connection.close()


@pytest.fixture
def mappings(tmp_path: Path, rules: dict[str, PatternRule]) -> Path:
    directory = tmp_path / "mappings"
    directory.mkdir()
    save_rules(directory / "cisco.json", [rules["cisco-http"], rules["cisco-telnet"]])
    save_rules(directory / "forti.json", [rules["forti-host"], rules["forti-telnet"]])
    return directory


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "app.db"


def ids(items: Iterator[PatternRule] | tuple[PatternRule, ...]) -> list[str]:
    return [rule.rule_id for rule in items]


def run_seed(
    connection: sqlite3.Connection,
    rule_list: object,
    **kwargs: Any,
) -> SeedResult:
    """Seed inside a transaction that is committed on success."""
    connection.execute("BEGIN IMMEDIATE")
    try:
        result = seed_rules(connection, rule_list, **kwargs)  # type: ignore[arg-type]
    except BaseException:
        connection.execute("ROLLBACK")
        raise
    connection.execute("COMMIT")
    return result


def add_user_rule(connection: sqlite3.Connection, rule: PatternRule) -> None:
    connection.execute(
        "INSERT INTO rules (rule_id, vendor, target_field, origin, body) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            rule.rule_id,
            rule.vendor.value,
            rule.target_field,
            ORIGIN_USER,
            seed_module._encode_rule(rule),
        ),
    )


def count(connection: sqlite3.Connection) -> int:
    return int(connection.execute("SELECT COUNT(*) FROM rules").fetchone()[0])


def insert_raw(connection: sqlite3.Connection, rule_id: str, body: str) -> None:
    connection.execute(
        "INSERT INTO rules (rule_id, vendor, target_field, origin, body) "
        "VALUES (?, 'v', 't', 'seed', ?)",
        (rule_id, body),
    )


# --------------------------------------------------------------------------
# Schema (models.py)
# --------------------------------------------------------------------------


class TestSchema:
    def test_migrations_shape(self) -> None:
        assert isinstance(MIGRATIONS, tuple)
        assert len(MIGRATIONS) >= 1
        assert all(isinstance(script, str) and script.strip() for script in MIGRATIONS)

    def test_origin_constants(self) -> None:
        assert ORIGIN_SEED == "seed"
        assert ORIGIN_USER == "user"
        assert ORIGINS == ("seed", "user")

    def test_migration_creates_rules_table(self, conn: sqlite3.Connection) -> None:
        columns = [row["name"] for row in conn.execute("PRAGMA table_info(rules)")]
        assert columns == ["rule_id", "vendor", "target_field", "origin", "body"]
        assert schema_version(conn) == len(MIGRATIONS)

    def test_migration_is_idempotent(self, conn: sqlite3.Connection) -> None:
        assert migrate(conn, MIGRATIONS) == len(MIGRATIONS)

    def test_origin_is_constrained(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO rules VALUES ('a', 'v', 't', 'robot', 'body')"
            )

    @pytest.mark.parametrize(
        "row",
        [
            pytest.param("('', 'v', 't', 'seed', 'b')", id="empty-id"),
            pytest.param("('a', '', 't', 'seed', 'b')", id="empty-vendor"),
            pytest.param("('a', 'v', '', 'seed', 'b')", id="empty-target"),
            pytest.param("('a', 'v', 't', 'seed', '')", id="empty-body"),
            pytest.param("(NULL, 'v', 't', 'seed', 'b')", id="null-id"),
        ],
    )
    def test_empty_values_are_rejected(
        self, conn: sqlite3.Connection, row: str
    ) -> None:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(f"INSERT INTO rules VALUES {row}")

    def test_rule_id_is_unique(self, conn: sqlite3.Connection) -> None:
        conn.execute("INSERT INTO rules VALUES ('a', 'v', 't', 'seed', 'b')")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO rules VALUES ('a', 'v', 't', 'user', 'b')")


# --------------------------------------------------------------------------
# seed_rules
# --------------------------------------------------------------------------


class TestSeedRules:
    def test_inserts_all_rules(
        self, conn: sqlite3.Connection, rules: dict[str, PatternRule]
    ) -> None:
        result = run_seed(conn, list(rules.values()))
        assert result == SeedResult(inserted=4, updated=0, unchanged=0, removed=0)
        assert count(conn) == 4

    def test_rows_have_expected_columns(
        self, conn: sqlite3.Connection, rules: dict[str, PatternRule]
    ) -> None:
        run_seed(conn, [rules["forti-host"]])
        row = conn.execute("SELECT * FROM rules").fetchone()
        assert row["rule_id"] == "forti-host"
        assert row["vendor"] == Vendor.FORTIOS.value
        assert row["target_field"] == "hostname"
        assert row["origin"] == ORIGIN_SEED
        assert isinstance(json.loads(row["body"]), dict)

    def test_round_trip_through_the_database(
        self, conn: sqlite3.Connection, rules: dict[str, PatternRule]
    ) -> None:
        run_seed(conn, list(rules.values()))
        stored = fetch_rules(conn)
        assert ids(stored) == EXPECTED_ORDER
        for rule in stored:
            assert rule == rules[rule.rule_id]

    @pytest.mark.parametrize("kind", ["tuple", "list", "generator"])
    def test_accepts_any_iterable(
        self, conn: sqlite3.Connection, rules: dict[str, PatternRule], kind: str
    ) -> None:
        values = list(rules.values())
        source: object
        if kind == "tuple":
            source = tuple(values)
        elif kind == "list":
            source = values
        else:
            source = (rule for rule in values)
        assert run_seed(conn, source).inserted == 4

    def test_empty_rules_write_nothing(self, conn: sqlite3.Connection) -> None:
        assert run_seed(conn, []) == SeedResult(0, 0, 0, 0)
        assert count(conn) == 0

    def test_is_idempotent(
        self, conn: sqlite3.Connection, rules: dict[str, PatternRule]
    ) -> None:
        run_seed(conn, list(rules.values()))
        again = run_seed(conn, list(rules.values()))
        assert again == SeedResult(inserted=0, updated=0, unchanged=4, removed=0)
        assert count(conn) == 4

    def test_changed_rule_is_updated(
        self, conn: sqlite3.Connection, rules: dict[str, PatternRule]
    ) -> None:
        run_seed(conn, list(rules.values()))
        changed = make_rule(
            "cisco-http", Vendor.CISCO_IOS, "prefix", "ip http", "http_management_enabled"
        )
        later = [changed, *[r for k, r in rules.items() if k != "cisco-http"]]
        result = run_seed(conn, later)
        assert result == SeedResult(inserted=0, updated=1, unchanged=3, removed=0)
        stored = {rule.rule_id: rule for rule in fetch_rules(conn)}
        assert stored["cisco-http"] == changed

    def test_update_refreshes_vendor_and_target_columns(
        self, conn: sqlite3.Connection, rules: dict[str, PatternRule]
    ) -> None:
        run_seed(conn, [rules["cisco-http"]])
        moved = make_rule(
            "cisco-http", Vendor.FORTIOS, "exact", "set admin-telnet enable", "telnet_enabled"
        )
        run_seed(conn, [moved])
        row = conn.execute("SELECT vendor, target_field FROM rules").fetchone()
        assert row["vendor"] == Vendor.FORTIOS.value
        assert row["target_field"] == "telnet_enabled"

    def test_prune_removes_stale_seed_rules(
        self, conn: sqlite3.Connection, rules: dict[str, PatternRule]
    ) -> None:
        run_seed(conn, list(rules.values()))
        result = run_seed(conn, [rules["cisco-http"], rules["forti-host"]])
        assert result == SeedResult(inserted=0, updated=0, unchanged=2, removed=2)
        assert ids(fetch_rules(conn)) == ["cisco-http", "forti-host"]

    def test_prune_false_keeps_stale_rules(
        self, conn: sqlite3.Connection, rules: dict[str, PatternRule]
    ) -> None:
        run_seed(conn, list(rules.values()))
        result = run_seed(conn, [rules["cisco-http"]], prune=False)
        assert result == SeedResult(inserted=0, updated=0, unchanged=1, removed=0)
        assert count(conn) == 4

    def test_user_rules_are_never_pruned(
        self, conn: sqlite3.Connection, rules: dict[str, PatternRule]
    ) -> None:
        add_user_rule(conn, rules["forti-telnet"])
        run_seed(conn, [rules["cisco-http"]])
        result = run_seed(conn, [])
        assert result.removed == 1
        assert ids(fetch_rules(conn)) == ["forti-telnet"]
        assert ids(fetch_rules(conn, origin="user")) == ["forti-telnet"]

    def test_conflict_with_user_rule_writes_nothing(
        self, conn: sqlite3.Connection, rules: dict[str, PatternRule]
    ) -> None:
        add_user_rule(conn, rules["cisco-http"])
        conn.execute("BEGIN IMMEDIATE")
        with pytest.raises(ValueError, match="conflicts with a user rule"):
            seed_rules(conn, [rules["forti-host"], rules["cisco-http"]])
        assert count(conn) == 1  # nothing written, even before the rollback
        conn.execute("ROLLBACK")
        assert ids(fetch_rules(conn)) == ["cisco-http"]

    def test_conflict_leaves_user_rule_unchanged(
        self, conn: sqlite3.Connection, rules: dict[str, PatternRule]
    ) -> None:
        add_user_rule(conn, rules["cisco-http"])
        different = make_rule(
            "cisco-http", Vendor.CISCO_IOS, "prefix", "ip http", "http_management_enabled"
        )
        with pytest.raises(ValueError):
            run_seed(conn, [different])
        assert fetch_rules(conn)[0] == rules["cisco-http"]

    def test_duplicate_incoming_ids_write_nothing(
        self, conn: sqlite3.Connection, rules: dict[str, PatternRule]
    ) -> None:
        conn.execute("BEGIN IMMEDIATE")
        with pytest.raises(ValueError):
            seed_rules(conn, [rules["cisco-http"], rules["cisco-http"]])
        assert count(conn) == 0
        conn.execute("ROLLBACK")

    def test_requires_a_transaction(
        self, conn: sqlite3.Connection, rules: dict[str, PatternRule]
    ) -> None:
        with pytest.raises(ValueError, match="inside a transaction"):
            seed_rules(conn, [rules["cisco-http"]])
        assert count(conn) == 0

    def test_caller_can_roll_back(
        self, conn: sqlite3.Connection, rules: dict[str, PatternRule]
    ) -> None:
        conn.execute("BEGIN IMMEDIATE")
        seed_rules(conn, list(rules.values()))
        conn.execute("ROLLBACK")
        assert count(conn) == 0

    def test_input_is_not_mutated(
        self, conn: sqlite3.Connection, rules: dict[str, PatternRule]
    ) -> None:
        values = list(rules.values())
        snapshot = list(values)
        run_seed(conn, values)
        assert len(values) == len(snapshot)
        assert all(a is b for a, b in zip(values, snapshot))

    # ---- validation ----------------------------------------------------

    @pytest.mark.parametrize("bad", [None, "db", 5, object()])
    def test_conn_must_be_connection(self, bad: object) -> None:
        with pytest.raises(TypeError, match="conn must be sqlite3.Connection"):
            seed_rules(bad, [])  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "bad",
        [
            pytest.param("text", id="str"),
            pytest.param(b"bytes", id="bytes"),
            pytest.param({"a": 1}, id="mapping"),
            pytest.param(5, id="int"),
            pytest.param(None, id="none"),
        ],
    )
    def test_rules_must_be_iterable(
        self, conn: sqlite3.Connection, bad: object
    ) -> None:
        with pytest.raises(TypeError, match="rules must be an iterable"):
            seed_rules(conn, bad)  # type: ignore[arg-type]

    def test_rules_must_contain_pattern_rules(
        self, conn: sqlite3.Connection, rules: dict[str, PatternRule]
    ) -> None:
        with pytest.raises(TypeError, match="rules must contain PatternRule"):
            seed_rules(conn, [rules["cisco-http"], "bad"])  # type: ignore[list-item]

    @pytest.mark.parametrize("bad", ["yes", 1, None])
    def test_prune_must_be_bool(self, conn: sqlite3.Connection, bad: object) -> None:
        with pytest.raises(TypeError, match="prune must be bool"):
            seed_rules(conn, [], prune=bad)  # type: ignore[arg-type]


class TestSeedResult:
    def test_is_frozen(self) -> None:
        result = SeedResult(1, 2, 3, 4)
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(result, "inserted", 9)

    def test_uses_slots(self) -> None:
        assert not hasattr(SeedResult(1, 2, 3, 4), "__dict__")

    def test_fields(self) -> None:
        result = SeedResult(1, 2, 3, 4)
        assert (result.inserted, result.updated, result.unchanged, result.removed) == (
            1,
            2,
            3,
            4,
        )


# --------------------------------------------------------------------------
# fetch_rules
# --------------------------------------------------------------------------


class TestFetchRules:
    def test_empty_table(self, conn: sqlite3.Connection) -> None:
        result = fetch_rules(conn)
        assert result == ()
        assert isinstance(result, tuple)

    def test_orders_by_vendor_target_and_id(
        self, conn: sqlite3.Connection, rules: dict[str, PatternRule]
    ) -> None:
        run_seed(conn, list(reversed(rules.values())))
        assert ids(fetch_rules(conn)) == EXPECTED_ORDER

    def test_origin_filter(
        self, conn: sqlite3.Connection, rules: dict[str, PatternRule]
    ) -> None:
        run_seed(conn, [rules["cisco-http"], rules["forti-host"]])
        add_user_rule(conn, rules["forti-telnet"])
        assert ids(fetch_rules(conn, origin="seed")) == ["cisco-http", "forti-host"]
        assert ids(fetch_rules(conn, origin="user")) == ["forti-telnet"]
        assert len(fetch_rules(conn)) == 3

    def test_unknown_origin(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(ValueError, match="origin must be one of"):
            fetch_rules(conn, origin="robot")

    @pytest.mark.parametrize("bad", [5, b"seed", ["seed"]])
    def test_origin_must_be_str(self, conn: sqlite3.Connection, bad: object) -> None:
        with pytest.raises(TypeError, match="origin must be str or None"):
            fetch_rules(conn, origin=bad)  # type: ignore[arg-type]

    @pytest.mark.parametrize("bad", [None, "db", 5])
    def test_conn_must_be_connection(self, bad: object) -> None:
        with pytest.raises(TypeError, match="conn must be sqlite3.Connection"):
            fetch_rules(bad)  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "body",
        [
            pytest.param("not json", id="not-json"),
            pytest.param("[]", id="list"),
            pytest.param('{"rule_id": 5}', id="wrong-type"),
            pytest.param(json.dumps({SECRET: 1}), id="unknown-field"),
            pytest.param("{}", id="empty-object"),
        ],
    )
    def test_corrupt_row_raises_without_echo(
        self, conn: sqlite3.Connection, body: str
    ) -> None:
        insert_raw(conn, "bad-1", body)
        with pytest.raises(ValueError, match="stored rule is invalid") as info:
            fetch_rules(conn)
        assert SECRET not in str(info.value)


# --------------------------------------------------------------------------
# load_mapping_rules
# --------------------------------------------------------------------------


class TestLoadMappingRules:
    def test_loads_all_files(self, mappings: Path) -> None:
        result = load_mapping_rules(mappings)
        assert isinstance(result, tuple)
        assert ids(result) == EXPECTED_ORDER

    def test_files_are_read_in_name_order(
        self, tmp_path: Path, rules: dict[str, PatternRule]
    ) -> None:
        directory = tmp_path / "m"
        directory.mkdir()
        save_rules(directory / "b.json", [rules["cisco-http"]])
        save_rules(directory / "a.json", [rules["forti-host"]])
        assert ids(load_mapping_rules(directory)) == ["forti-host", "cisco-http"]

    def test_non_json_files_are_ignored(
        self, mappings: Path, rules: dict[str, PatternRule]
    ) -> None:
        (mappings / "notes.txt").write_text("hello", encoding="utf-8")
        (mappings / ".rules.json.abc.tmp").write_text("{", encoding="utf-8")
        assert ids(load_mapping_rules(mappings)) == EXPECTED_ORDER

    def test_directories_named_like_json_are_ignored(self, mappings: Path) -> None:
        (mappings / "weird.json").mkdir()
        assert ids(load_mapping_rules(mappings)) == EXPECTED_ORDER

    def test_sub_directories_are_not_searched(
        self, mappings: Path, rules: dict[str, PatternRule]
    ) -> None:
        sub = mappings / "extra"
        sub.mkdir()
        save_rules(sub / "more.json", [rules["cisco-http"]])
        assert ids(load_mapping_rules(mappings)) == EXPECTED_ORDER

    def test_file_with_no_rules_is_allowed(self, tmp_path: Path) -> None:
        directory = tmp_path / "m"
        directory.mkdir()
        save_rules(directory / "empty.json", [])
        assert load_mapping_rules(directory) == ()

    def test_missing_directory(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError, match="not found"):
            load_mapping_rules(tmp_path / "nope")

    def test_path_is_a_file(self, tmp_path: Path) -> None:
        target = tmp_path / "file.json"
        target.write_text("{}", encoding="utf-8")
        with pytest.raises(NotADirectoryError):
            load_mapping_rules(target)

    def test_directory_without_mapping_files(self, tmp_path: Path) -> None:
        directory = tmp_path / "m"
        directory.mkdir()
        with pytest.raises(ValueError, match="no mapping files found"):
            load_mapping_rules(directory)

    def test_directory_with_only_ignored_entries(self, tmp_path: Path) -> None:
        directory = tmp_path / "m"
        directory.mkdir()
        (directory / "notes.txt").write_text("x", encoding="utf-8")
        (directory / "sub").mkdir()
        with pytest.raises(ValueError, match="no mapping files found"):
            load_mapping_rules(directory)

    def test_invalid_file_is_named_in_the_error(self, mappings: Path) -> None:
        (mappings / "bad.json").write_text("not json", encoding="utf-8")
        with pytest.raises(ValueError, match="invalid mapping file bad.json"):
            load_mapping_rules(mappings)

    def test_duplicate_ids_across_files(
        self, tmp_path: Path, rules: dict[str, PatternRule]
    ) -> None:
        directory = tmp_path / "m"
        directory.mkdir()
        save_rules(directory / "a.json", [rules["cisco-http"]])
        save_rules(directory / "b.json", [rules["cisco-http"]])
        with pytest.raises(ValueError):
            load_mapping_rules(directory)

    @pytest.mark.parametrize("bad", ["mappings", None, 5, b"mappings"])
    def test_directory_must_be_path(self, bad: object) -> None:
        with pytest.raises(TypeError, match="directory must be pathlib.Path"):
            load_mapping_rules(bad)  # type: ignore[arg-type]

    def test_default_directory(self) -> None:
        assert isinstance(DEFAULT_MAPPINGS_DIR, Path)
        assert DEFAULT_MAPPINGS_DIR.parts[-2:] == ("data", "mappings")


# --------------------------------------------------------------------------
# seed_database
# --------------------------------------------------------------------------


class TestSeedDatabase:
    def test_creates_and_seeds(self, mappings: Path, db_path: Path) -> None:
        result = seed_database(db_path, mappings)
        assert result == SeedResult(inserted=4, updated=0, unchanged=0, removed=0)
        with closing(connect(db_path)) as check:
            assert schema_version(check) == len(MIGRATIONS)
            assert ids(fetch_rules(check)) == EXPECTED_ORDER

    def test_is_idempotent(self, mappings: Path, db_path: Path) -> None:
        seed_database(db_path, mappings)
        again = seed_database(db_path, mappings)
        assert again == SeedResult(inserted=0, updated=0, unchanged=4, removed=0)

    def test_accepts_str_database(self, mappings: Path, db_path: Path) -> None:
        assert seed_database(str(db_path), mappings).inserted == 4

    def test_creates_parent_directory(self, mappings: Path, tmp_path: Path) -> None:
        nested = tmp_path / "a" / "b" / "app.db"
        seed_database(nested, mappings)
        assert nested.is_file()

    def test_prune_follows_the_files(
        self, mappings: Path, db_path: Path
    ) -> None:
        seed_database(db_path, mappings)
        (mappings / "forti.json").unlink()
        result = seed_database(db_path, mappings)
        assert result == SeedResult(inserted=0, updated=0, unchanged=2, removed=2)
        with closing(connect(db_path)) as check:
            assert ids(fetch_rules(check)) == ["cisco-http", "cisco-telnet"]

    def test_prune_false_keeps_stale_rules(
        self, mappings: Path, db_path: Path
    ) -> None:
        seed_database(db_path, mappings)
        (mappings / "forti.json").unlink()
        result = seed_database(db_path, mappings, prune=False)
        assert result.removed == 0
        with closing(connect(db_path)) as check:
            assert len(fetch_rules(check)) == 4

    def test_invalid_directory_never_touches_the_database(
        self, tmp_path: Path, db_path: Path
    ) -> None:
        with pytest.raises(FileNotFoundError):
            seed_database(db_path, tmp_path / "missing")
        assert not db_path.exists()

    def test_invalid_file_never_touches_the_database(
        self, mappings: Path, db_path: Path
    ) -> None:
        (mappings / "bad.json").write_text("not json", encoding="utf-8")
        with pytest.raises(ValueError, match="invalid mapping file"):
            seed_database(db_path, mappings)
        assert not db_path.exists()

    def test_conflict_with_user_rule_changes_nothing(
        self, mappings: Path, db_path: Path, rules: dict[str, PatternRule]
    ) -> None:
        with closing(connect(db_path)) as setup:
            migrate(setup, MIGRATIONS)
            add_user_rule(setup, rules["cisco-http"])
        with pytest.raises(ValueError, match="conflicts with a user rule"):
            seed_database(db_path, mappings)
        with closing(connect(db_path)) as check:
            assert ids(fetch_rules(check)) == ["cisco-http"]
            assert ids(fetch_rules(check, origin="user")) == ["cisco-http"]

    def test_memory_database_is_refused(self, mappings: Path) -> None:
        with pytest.raises(ValueError, match="not :memory:"):
            seed_database(":memory:", mappings)
        with pytest.raises(ValueError, match="not :memory:"):
            seed_database(Path(":memory:"), mappings)

    @pytest.mark.parametrize("bad", [5, None, b"app.db"])
    def test_database_type(self, mappings: Path, bad: object) -> None:
        with pytest.raises(TypeError, match="database must be"):
            seed_database(bad, mappings)  # type: ignore[arg-type]

    @pytest.mark.parametrize("bad", ["yes", 1, None])
    def test_prune_must_be_bool(
        self, mappings: Path, db_path: Path, bad: object
    ) -> None:
        with pytest.raises(TypeError, match="prune must be bool"):
            seed_database(db_path, mappings, prune=bad)  # type: ignore[arg-type]
        with closing(connect(db_path)) as check:
            assert count(check) == 0


# --------------------------------------------------------------------------
# Error messages never echo contents
# --------------------------------------------------------------------------


class TestNoSecretEcho:
    def test_invalid_json_file(self, mappings: Path) -> None:
        (mappings / "bad.json").write_text(
            f'{{"password": "{SECRET}" ', encoding="utf-8"
        )
        with pytest.raises(ValueError) as info:
            load_mapping_rules(mappings)
        assert SECRET not in str(info.value)

    def test_unknown_key_in_file(self, mappings: Path) -> None:
        (mappings / "bad.json").write_text(
            json.dumps({"version": 1, "rules": [{SECRET: 1}]}), encoding="utf-8"
        )
        with pytest.raises(ValueError) as info:
            load_mapping_rules(mappings)
        assert SECRET not in str(info.value)

    def test_wrong_type_errors(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(TypeError) as info:
            seed_rules(conn, SECRET)  # type: ignore[arg-type]
        assert SECRET not in str(info.value)
        with pytest.raises(TypeError) as other:
            seed_rules(conn, [SECRET])  # type: ignore[list-item]
        assert SECRET not in str(other.value)


# --------------------------------------------------------------------------
# Module surface
# --------------------------------------------------------------------------


def test_public_api() -> None:
    assert set(seed_module.__all__) == {
        "DEFAULT_MAPPINGS_DIR",
        "SeedResult",
        "fetch_rules",
        "load_mapping_rules",
        "seed_database",
        "seed_rules",
    }
    for name in seed_module.__all__:
        assert hasattr(seed_module, name)