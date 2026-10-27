"""Tests for auditor.db.session."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest

import auditor.db.session as session_module
from auditor.db.session import (
    BUSY_TIMEOUT_SECONDS,
    MEMORY,
    MigrationError,
    connect,
    migrate,
    schema_version,
    session,
)

SECRET = "hunter2"
CREATE_T = "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT);"
THREE = [
    "CREATE TABLE a (x INTEGER);",
    "CREATE TABLE b (x INTEGER);",
    "CREATE TABLE c (x INTEGER);",
]


class _Stop(BaseException):
    """Stands in for KeyboardInterrupt-style exceptions."""


# --------------------------------------------------------------------------
# Fixtures and helpers
# --------------------------------------------------------------------------


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "app.db"


@pytest.fixture
def conn() -> Iterator[sqlite3.Connection]:
    connection = connect()
    try:
        yield connection
    finally:
        connection.close()


def table_names(connection: sqlite3.Connection) -> list[str]:
    rows = connection.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    return sorted(str(row["name"]) for row in rows)


def count(connection: sqlite3.Connection, table: str) -> int:
    return int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


# --------------------------------------------------------------------------
# connect
# --------------------------------------------------------------------------


class TestConnect:
    def test_returns_connection(self, conn: sqlite3.Connection) -> None:
        assert isinstance(conn, sqlite3.Connection)

    def test_autocommit_mode(self, conn: sqlite3.Connection) -> None:
        assert conn.isolation_level is None
        assert conn.in_transaction is False

    def test_rows_support_column_names(self, conn: sqlite3.Connection) -> None:
        row = conn.execute("SELECT 1 AS one, 2 AS two").fetchone()
        assert isinstance(row, sqlite3.Row)
        assert row["one"] == 1
        assert row["two"] == 2

    def test_foreign_keys_pragma_is_on(self, conn: sqlite3.Connection) -> None:
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1

    def test_foreign_keys_are_enforced(self, conn: sqlite3.Connection) -> None:
        conn.executescript(
            "CREATE TABLE parent (id INTEGER PRIMARY KEY);"
            "CREATE TABLE child (id INTEGER PRIMARY KEY,"
            " parent_id INTEGER NOT NULL REFERENCES parent(id));"
        )
        conn.execute("INSERT INTO parent (id) VALUES (1)")
        conn.execute("INSERT INTO child (id, parent_id) VALUES (1, 1)")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO child (id, parent_id) VALUES (2, 99)")

    def test_default_busy_timeout(self, conn: sqlite3.Connection) -> None:
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000

    def test_busy_timeout_follows_module_setting(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(session_module, "BUSY_TIMEOUT_SECONDS", 0.25)
        with closing(connect()) as connection:
            assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == 250

    def test_file_database_is_created_and_persists(self, db_path: Path) -> None:
        with closing(connect(db_path)) as first:
            first.execute(CREATE_T)
            first.execute("INSERT INTO t (name) VALUES ('a')")
        assert db_path.is_file()
        with closing(connect(db_path)) as second:
            assert count(second, "t") == 1

    def test_accepts_str_path(self, db_path: Path) -> None:
        with closing(connect(str(db_path))) as first:
            first.execute(CREATE_T)
        with closing(connect(db_path)) as second:
            assert table_names(second) == ["t"]

    def test_parent_directories_are_created(self, tmp_path: Path) -> None:
        nested = tmp_path / "a" / "b" / "app.db"
        with closing(connect(nested)) as connection:
            connection.execute(CREATE_T)
        assert nested.parent.is_dir()
        assert nested.is_file()

    def test_memory_databases_are_independent(self) -> None:
        with closing(connect()) as first, closing(connect(MEMORY)) as second:
            first.execute(CREATE_T)
            assert table_names(first) == ["t"]
            assert table_names(second) == []

    def test_parent_that_is_a_file_raises_os_error(self, tmp_path: Path) -> None:
        blocker = tmp_path / "blocker"
        blocker.write_text("x", encoding="utf-8")
        with pytest.raises(OSError):
            connect(blocker / "sub" / "app.db")

    def test_directory_is_not_a_database(self, tmp_path: Path) -> None:
        with pytest.raises(sqlite3.OperationalError):
            connect(tmp_path)

    @pytest.mark.parametrize(
        "bad",
        [
            pytest.param(5, id="int"),
            pytest.param(None, id="none"),
            pytest.param(b"app.db", id="bytes"),
            pytest.param(["app.db"], id="list"),
        ],
    )
    def test_wrong_type(self, bad: object) -> None:
        with pytest.raises(TypeError, match="database must be a pathlib.Path or str"):
            connect(bad)  # type: ignore[arg-type]

    @pytest.mark.parametrize("bad", ["", "   ", "\n"])
    def test_blank_string(self, bad: str) -> None:
        with pytest.raises(ValueError, match="database must not be empty"):
            connect(bad)

    def test_null_character(self) -> None:
        with pytest.raises(ValueError, match="null character"):
            connect("a\x00b")


# --------------------------------------------------------------------------
# session
# --------------------------------------------------------------------------


class TestSession:
    def test_commits_on_success(self, db_path: Path) -> None:
        with session(db_path) as connection:
            connection.execute(CREATE_T)
            connection.execute("INSERT INTO t (name) VALUES ('a')")
        with closing(connect(db_path)) as check:
            assert count(check, "t") == 1

    def test_yields_configured_connection(self, db_path: Path) -> None:
        with session(db_path) as connection:
            assert isinstance(connection, sqlite3.Connection)
            assert connection.in_transaction is True
            row = connection.execute("SELECT 1 AS one").fetchone()
            assert row["one"] == 1
            assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1

    def test_default_is_memory(self) -> None:
        with session() as connection:
            connection.execute(CREATE_T)
            assert table_names(connection) == ["t"]

    def test_accepts_str_path(self, db_path: Path) -> None:
        with session(str(db_path)) as connection:
            connection.execute(CREATE_T)
        with closing(connect(db_path)) as check:
            assert table_names(check) == ["t"]

    def test_rolls_back_data_on_error(self, db_path: Path) -> None:
        with session(db_path) as connection:
            connection.execute(CREATE_T)
        with pytest.raises(RuntimeError, match="boom"):
            with session(db_path) as connection:
                connection.execute("INSERT INTO t (name) VALUES ('a')")
                raise RuntimeError("boom")
        with closing(connect(db_path)) as check:
            assert count(check, "t") == 0

    def test_rolls_back_schema_changes_on_error(self, db_path: Path) -> None:
        with pytest.raises(RuntimeError):
            with session(db_path) as connection:
                connection.execute(CREATE_T)
                raise RuntimeError("boom")
        with closing(connect(db_path)) as check:
            assert table_names(check) == []

    def test_rolls_back_on_base_exception(self, db_path: Path) -> None:
        with pytest.raises(_Stop):
            with session(db_path) as connection:
                connection.execute(CREATE_T)
                raise _Stop
        with closing(connect(db_path)) as check:
            assert table_names(check) == []

    def test_sql_error_rolls_back_and_propagates(self, db_path: Path) -> None:
        with session(db_path) as connection:
            connection.execute(CREATE_T)
        with pytest.raises(sqlite3.OperationalError):
            with session(db_path) as connection:
                connection.execute("INSERT INTO t (name) VALUES ('a')")
                connection.execute("INSERT INTO missing_table VALUES (1)")
        with closing(connect(db_path)) as check:
            assert count(check, "t") == 0

    def test_foreign_keys_enforced_inside_session(self, db_path: Path) -> None:
        with pytest.raises(sqlite3.IntegrityError):
            with session(db_path) as connection:
                connection.executescript(
                    "BEGIN;"
                    "CREATE TABLE parent (id INTEGER PRIMARY KEY);"
                    "CREATE TABLE child (id INTEGER PRIMARY KEY,"
                    " parent_id INTEGER NOT NULL REFERENCES parent(id));"
                )
                connection.execute("INSERT INTO child (id, parent_id) VALUES (1, 9)")

    def test_connection_is_closed_after_success(self, db_path: Path) -> None:
        with session(db_path) as connection:
            captured = connection
        with pytest.raises(sqlite3.ProgrammingError):
            captured.execute("SELECT 1")

    def test_connection_is_closed_after_error(self, db_path: Path) -> None:
        captured: list[sqlite3.Connection] = []
        with pytest.raises(RuntimeError):
            with session(db_path) as connection:
                captured.append(connection)
                raise RuntimeError("boom")
        with pytest.raises(sqlite3.ProgrammingError):
            captured[0].execute("SELECT 1")

    def test_body_may_commit_itself(self, db_path: Path) -> None:
        with session(db_path) as connection:
            connection.execute(CREATE_T)
            connection.execute("COMMIT")
        with closing(connect(db_path)) as check:
            assert table_names(check) == ["t"]

    def test_body_may_roll_back_itself(self, db_path: Path) -> None:
        with session(db_path) as connection:
            connection.execute(CREATE_T)
            connection.execute("ROLLBACK")
        with closing(connect(db_path)) as check:
            assert table_names(check) == []

    def test_original_error_survives_a_closed_connection(self, db_path: Path) -> None:
        with pytest.raises(RuntimeError, match="boom"):
            with session(db_path) as connection:
                connection.close()
                raise RuntimeError("boom")

    def test_second_writer_times_out_while_first_holds_the_lock(
        self, db_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(session_module, "BUSY_TIMEOUT_SECONDS", 0.05)
        with session(db_path) as first:
            first.execute(CREATE_T)
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                with session(db_path):
                    pass
        with closing(connect(db_path)) as check:
            assert table_names(check) == ["t"]

    @pytest.mark.parametrize(
        "bad",
        [
            pytest.param(5, id="int"),
            pytest.param(None, id="none"),
            pytest.param(b"app.db", id="bytes"),
        ],
    )
    def test_invalid_database_raises_before_work(self, bad: object) -> None:
        with pytest.raises(TypeError, match="database must be"):
            with session(bad):  # type: ignore[arg-type]
                pytest.fail("the body must not run")

    def test_directory_is_not_a_database(self, tmp_path: Path) -> None:
        with pytest.raises(sqlite3.OperationalError):
            with session(tmp_path):
                pytest.fail("the body must not run")


# --------------------------------------------------------------------------
# schema_version
# --------------------------------------------------------------------------


class TestSchemaVersion:
    def test_new_database_is_zero(self, conn: sqlite3.Connection) -> None:
        assert schema_version(conn) == 0

    def test_reads_user_version(self, conn: sqlite3.Connection) -> None:
        conn.execute("PRAGMA user_version = 7")
        assert schema_version(conn) == 7

    def test_returns_int(self, conn: sqlite3.Connection) -> None:
        assert type(schema_version(conn)) is int

    @pytest.mark.parametrize("bad", [None, "db", 5, object()])
    def test_requires_connection(self, bad: object) -> None:
        with pytest.raises(TypeError, match="conn must be sqlite3.Connection"):
            schema_version(bad)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# migrate
# --------------------------------------------------------------------------


class TestMigrate:
    def test_applies_all_in_order(self, conn: sqlite3.Connection) -> None:
        assert migrate(conn, THREE) == 3
        assert schema_version(conn) == 3
        assert table_names(conn) == ["a", "b", "c"]
        assert conn.in_transaction is False

    def test_empty_list_changes_nothing(self, conn: sqlite3.Connection) -> None:
        assert migrate(conn, []) == 0
        assert schema_version(conn) == 0
        assert table_names(conn) == []

    def test_accepts_tuple(self, conn: sqlite3.Connection) -> None:
        assert migrate(conn, tuple(THREE)) == 3

    def test_is_idempotent(self, conn: sqlite3.Connection) -> None:
        # Plain CREATE TABLE would fail if a migration ran twice.
        assert migrate(conn, THREE) == 3
        assert migrate(conn, THREE) == 3
        assert schema_version(conn) == 3

    def test_applies_only_new_migrations(self, conn: sqlite3.Connection) -> None:
        assert migrate(conn, THREE[:1]) == 1
        assert table_names(conn) == ["a"]
        assert migrate(conn, THREE) == 3
        assert table_names(conn) == ["a", "b", "c"]
        assert schema_version(conn) == 3

    def test_multi_statement_script(self, conn: sqlite3.Connection) -> None:
        migrate(conn, ["CREATE TABLE a (x INTEGER); INSERT INTO a VALUES (7);"])
        assert conn.execute("SELECT x FROM a").fetchone()["x"] == 7

    def test_script_without_trailing_semicolon(self, conn: sqlite3.Connection) -> None:
        assert migrate(conn, ["CREATE TABLE a (x INTEGER)"]) == 1
        assert table_names(conn) == ["a"]

    def test_script_ending_with_a_comment(self, conn: sqlite3.Connection) -> None:
        assert migrate(conn, ["CREATE TABLE a (x INTEGER) -- trailing comment"]) == 1
        assert table_names(conn) == ["a"]
        assert schema_version(conn) == 1

    def test_persists_in_a_file(self, db_path: Path) -> None:
        with closing(connect(db_path)) as first:
            assert migrate(first, THREE) == 3
        with closing(connect(db_path)) as second:
            assert schema_version(second) == 3
            assert table_names(second) == ["a", "b", "c"]
            assert migrate(second, THREE) == 3

    # ---- failures ------------------------------------------------------

    def test_failure_rolls_back_only_the_failing_migration(
        self, conn: sqlite3.Connection
    ) -> None:
        scripts = [
            "CREATE TABLE a (x INTEGER);",
            "CREATE TABLE b (x INTEGER); THIS IS NOT SQL;",
        ]
        with pytest.raises(MigrationError, match="migration 2 failed"):
            migrate(conn, scripts)
        assert schema_version(conn) == 1
        assert table_names(conn) == ["a"]
        assert conn.in_transaction is False

    def test_failure_of_first_migration_leaves_database_empty(
        self, conn: sqlite3.Connection
    ) -> None:
        with pytest.raises(MigrationError, match="migration 1 failed"):
            migrate(conn, ["CREATE TABLE a (x INTEGER); THIS IS NOT SQL;"])
        assert schema_version(conn) == 0
        assert table_names(conn) == []
        assert conn.in_transaction is False

    def test_failure_keeps_the_original_cause(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(MigrationError) as info:
            migrate(conn, ["THIS IS NOT SQL;"])
        assert isinstance(info.value.__cause__, sqlite3.Error)

    def test_migration_error_type(self) -> None:
        assert issubclass(MigrationError, sqlite3.DatabaseError)

    def test_can_retry_with_a_fixed_script(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(MigrationError):
            migrate(conn, [THREE[0], "THIS IS NOT SQL;"])
        assert migrate(conn, [THREE[0], THREE[1]]) == 2
        assert schema_version(conn) == 2
        assert table_names(conn) == ["a", "b"]

    def test_newer_database_is_refused(self, conn: sqlite3.Connection) -> None:
        conn.execute("PRAGMA user_version = 5")
        with pytest.raises(ValueError, match="newer"):
            migrate(conn, THREE)
        assert schema_version(conn) == 5
        assert table_names(conn) == []

    def test_refuses_to_run_inside_a_transaction(
        self, conn: sqlite3.Connection
    ) -> None:
        conn.execute("BEGIN")
        with pytest.raises(ValueError, match="inside a transaction"):
            migrate(conn, THREE)
        conn.execute("ROLLBACK")
        assert table_names(conn) == []

    def test_refuses_to_run_on_a_session_connection(self) -> None:
        with session() as inner:
            with pytest.raises(ValueError, match="inside a transaction"):
                migrate(inner, THREE)

    # ---- validation ----------------------------------------------------

    @pytest.mark.parametrize(
        "bad",
        [
            pytest.param("CREATE TABLE a (x INTEGER);", id="bare-str"),
            pytest.param(b"CREATE TABLE a (x INTEGER);", id="bytes"),
            pytest.param(None, id="none"),
            pytest.param(5, id="int"),
            pytest.param((script for script in THREE), id="generator"),
        ],
    )
    def test_migrations_must_be_a_sequence(
        self, conn: sqlite3.Connection, bad: object
    ) -> None:
        with pytest.raises(TypeError, match="migrations must be a sequence of str"):
            migrate(conn, bad)  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "bad",
        [
            pytest.param(5, id="int"),
            pytest.param(None, id="none"),
            pytest.param(b"x", id="bytes"),
        ],
    )
    def test_each_migration_must_be_str(
        self, conn: sqlite3.Connection, bad: object
    ) -> None:
        with pytest.raises(TypeError, match="migration 1 must be a str"):
            migrate(conn, [bad])  # type: ignore[list-item]

    @pytest.mark.parametrize("blank", ["", "   ", "\n\t "])
    def test_blank_migration_is_rejected(
        self, conn: sqlite3.Connection, blank: str
    ) -> None:
        with pytest.raises(ValueError, match="migration 1 must not be empty"):
            migrate(conn, [blank])

    def test_null_character_is_rejected(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(ValueError, match="null character"):
            migrate(conn, ["CREATE TABLE a (x INTEGER);\x00"])

    def test_validation_happens_before_anything_is_applied(
        self, conn: sqlite3.Connection
    ) -> None:
        with pytest.raises(ValueError, match="migration 2 must not be empty"):
            migrate(conn, [THREE[0], ""])
        assert table_names(conn) == []
        assert schema_version(conn) == 0

    @pytest.mark.parametrize("bad", [None, "db", 5, object()])
    def test_requires_connection(self, bad: object) -> None:
        with pytest.raises(TypeError, match="conn must be sqlite3.Connection"):
            migrate(bad, THREE)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Error messages never echo values
# --------------------------------------------------------------------------


class TestNoValueEcho:
    def test_connect_type_error(self) -> None:
        with pytest.raises(TypeError) as info:
            connect(12345)  # type: ignore[arg-type]
        assert "12345" not in str(info.value)

    def test_migration_failure_does_not_echo_sql(
        self, conn: sqlite3.Connection
    ) -> None:
        with pytest.raises(MigrationError) as info:
            migrate(conn, [f"INSERT INTO missing_table VALUES ('{SECRET}');"])
        assert SECRET not in str(info.value)

    def test_migration_type_error_does_not_echo_value(
        self, conn: sqlite3.Connection
    ) -> None:
        with pytest.raises(TypeError) as info:
            migrate(conn, [SECRET.encode()])  # type: ignore[list-item]
        assert SECRET not in str(info.value)

    def test_blank_migration_error_has_no_sql(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(ValueError) as info:
            migrate(conn, ["   "])
        assert SECRET not in str(info.value)


# --------------------------------------------------------------------------
# Module surface
# --------------------------------------------------------------------------


def test_public_api() -> None:
    assert set(session_module.__all__) == {
        "BUSY_TIMEOUT_SECONDS",
        "MEMORY",
        "MigrationError",
        "connect",
        "migrate",
        "schema_version",
        "session",
    }
    for name in session_module.__all__:
        assert hasattr(session_module, name)


def test_constants() -> None:
    assert MEMORY == ":memory:"
    assert BUSY_TIMEOUT_SECONDS == 5.0