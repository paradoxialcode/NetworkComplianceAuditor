"""SQLite connection, transaction and migration helpers (stdlib only).

Responsibilities:
    - Open configured connections (:func:`connect`).
    - Run a block of work in one transaction that commits on success and
      rolls back on any error, then closes the connection (:func:`session`).
    - Apply ordered schema migrations, tracked in ``PRAGMA user_version``
      (:func:`migrate`).

Non-responsibilities:
    - Table definitions (``models.py`` supplies the migration scripts).
    - Seeding data, querying, or business logic.

Design notes:
    - Connections use ``isolation_level=None`` (autocommit) so this module
      controls every transaction explicitly; Python's implicit transaction
      handling is bypassed. Do not call ``executescript`` inside
      :func:`session`: it commits the open transaction first.
    - Sessions start with ``BEGIN IMMEDIATE`` so a second writer waits (up to
      ``BUSY_TIMEOUT_SECONDS``) instead of failing later with a deadlock.
    - Foreign keys are switched on for every connection (SQLite leaves them
      off by default).
    - Write-ahead logging is not enabled: it adds ``-wal``/``-shm`` side
      files, which cloud-synced folders such as OneDrive handle badly.
    - ``":memory:"`` gives a new, private database per connection.
    - Error messages never include SQL text or field values.
"""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

__all__ = [
    "BUSY_TIMEOUT_SECONDS",
    "MEMORY",
    "MigrationError",
    "connect",
    "migrate",
    "schema_version",
    "session",
]

MEMORY = ":memory:"
BUSY_TIMEOUT_SECONDS = 5.0


class MigrationError(sqlite3.DatabaseError):
    """A schema migration failed and was rolled back."""


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _resolve(database: object) -> str:
    """Validate ``database`` and return it as a string for sqlite3."""
    if isinstance(database, Path):
        text = str(database)
    elif isinstance(database, str):
        if not database.strip():
            raise ValueError("database must not be empty")
        text = database
    else:
        raise TypeError(
            f"database must be a pathlib.Path or str, got {type(database).__name__}"
        )
    if "\x00" in text:
        raise ValueError("database path must not contain a null character")
    return text


def _require_connection(conn: object) -> sqlite3.Connection:
    if not isinstance(conn, sqlite3.Connection):
        raise TypeError(f"conn must be sqlite3.Connection, got {type(conn).__name__}")
    return conn


def _rollback(conn: sqlite3.Connection) -> None:
    """Roll back any open transaction; never raises sqlite3 errors."""
    with contextlib.suppress(sqlite3.Error):
        if conn.in_transaction:
            conn.execute("ROLLBACK")


def _require_migrations(migrations: object) -> tuple[str, ...]:
    if isinstance(migrations, (str, bytes)) or not isinstance(migrations, Sequence):
        raise TypeError(
            f"migrations must be a sequence of str, got {type(migrations).__name__}"
        )
    scripts: list[str] = []
    for number, item in enumerate(migrations, start=1):
        if not isinstance(item, str):
            raise TypeError(
                f"migration {number} must be a str, got {type(item).__name__}"
            )
        if not item.strip():
            raise ValueError(f"migration {number} must not be empty")
        if "\x00" in item:
            raise ValueError(f"migration {number} must not contain a null character")
        scripts.append(item)
    return tuple(scripts)


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def connect(database: Path | str = MEMORY) -> sqlite3.Connection:
    """Open a configured connection to ``database``.

    Missing parent directories are created for file databases. The caller
    owns the connection and must close it.

    Raises:
        TypeError: ``database`` is not a ``Path`` or ``str``.
        ValueError: ``database`` is a blank string or contains a null character.
        OSError: a parent directory cannot be created.
        sqlite3.OperationalError: the database cannot be opened.

    >>> conn = connect()
    >>> print(conn.execute("PRAGMA foreign_keys").fetchone()[0])
    1
    >>> conn.close()
    >>> connect(5)
    Traceback (most recent call last):
        ...
    TypeError: database must be a pathlib.Path or str, got int
    >>> connect("  ")
    Traceback (most recent call last):
        ...
    ValueError: database must not be empty
    """
    target = _resolve(database)
    if target != MEMORY:
        Path(target).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(
        target,
        timeout=BUSY_TIMEOUT_SECONDS,
        isolation_level=None,
    )
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
    except BaseException:
        conn.close()
        raise
    return conn


@contextmanager
def session(database: Path | str = MEMORY) -> Iterator[sqlite3.Connection]:
    """Run a block in one transaction on a fresh connection.

    The transaction commits when the block ends normally and rolls back if it
    raises anything (including ``KeyboardInterrupt``). The original exception
    always propagates. The connection is closed afterwards in every case.

    >>> with session() as conn:
    ...     _ = conn.execute("CREATE TABLE t (x INTEGER)")
    ...     _ = conn.execute("INSERT INTO t VALUES (1)")
    ...     print(conn.execute("SELECT x FROM t").fetchone()["x"])
    1
    """
    conn = connect(database)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except BaseException:
            _rollback(conn)
            raise
        else:
            try:
                if conn.in_transaction:
                    conn.execute("COMMIT")
            except BaseException:
                _rollback(conn)
                raise
    finally:
        conn.close()


def schema_version(conn: sqlite3.Connection) -> int:
    """Return the schema version stored in ``PRAGMA user_version`` (0 if new).

    >>> conn = connect()
    >>> schema_version(conn)
    0
    >>> conn.close()
    """
    connection = _require_connection(conn)
    row = connection.execute("PRAGMA user_version").fetchone()
    return int(row[0])


def migrate(conn: sqlite3.Connection, migrations: Sequence[str]) -> int:
    """Apply the migrations the database has not seen yet.

    ``migrations[0]`` is version 1, ``migrations[1]`` is version 2, and so on.
    Each migration runs in its own transaction together with the version
    update, so a failure leaves the database exactly at the last good version.
    Migration scripts must not contain ``BEGIN``, ``COMMIT`` or ``ROLLBACK``.

    Args:
        conn: A connection from :func:`connect`, not inside a transaction
            (so not the connection yielded by :func:`session`).
        migrations: SQL scripts, oldest first. Never reorder or edit one that
            has shipped; append a new one instead.

    Returns:
        The schema version after the call (``len(migrations)``).

    Raises:
        TypeError: bad argument types.
        ValueError: a script is blank or contains a null character, the
            database is already inside a transaction, or the database schema
            is newer than ``migrations`` knows about.
        MigrationError: a script failed; it was rolled back.

    >>> conn = connect()
    >>> migrate(conn, ["CREATE TABLE t (id INTEGER PRIMARY KEY);"])
    1
    >>> migrate(conn, ["CREATE TABLE t (id INTEGER PRIMARY KEY);"])
    1
    >>> try:
    ...     migrate(conn, ["CREATE TABLE t (id INTEGER PRIMARY KEY);", "NOT SQL;"])
    ... except MigrationError as exc:
    ...     print(exc)
    migration 2 failed
    >>> schema_version(conn)
    1
    >>> conn.close()
    """
    connection = _require_connection(conn)
    scripts = _require_migrations(migrations)
    if connection.in_transaction:
        raise ValueError("migrate must not run inside a transaction")

    current = schema_version(connection)
    if current > len(scripts):
        raise ValueError("database schema is newer than this program supports")

    for number in range(current + 1, len(scripts) + 1):
        script = scripts[number - 1]
        # "\n;\n" closes a final statement that lacks a semicolon, even if the
        # script ends with a "--" comment.
        sql = (
            "BEGIN IMMEDIATE;\n"
            f"{script}\n;\n"
            f"PRAGMA user_version = {number};\n"
            "COMMIT;"
        )
        try:
            connection.executescript(sql)
        except sqlite3.Error as exc:
            _rollback(connection)
            raise MigrationError(f"migration {number} failed") from exc
    return len(scripts)


if __name__ == "__main__":
    import doctest

    doctest.testmod()