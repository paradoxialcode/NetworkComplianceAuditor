"""Load pre-trained rule files into the database (stdlib only).

Mapping files are the JSON documents written by ``store.save_rules``; every
``*.json`` file directly inside the mappings directory is read (sorted by
name, sub-directories ignored) and validated by ``store.load_rules``.

Responsibilities:
    - Read and validate mapping files (:func:`load_mapping_rules`).
    - Sync them into the ``rules`` table as ``seed`` rows (:func:`seed_rules`,
      :func:`seed_database`). Seeding is idempotent.
    - Read rules back out (:func:`fetch_rules`).

Non-responsibilities:
    - Matching, training, suggestions, compliance evaluation.
    - Schema definition (see ``models.py``).

Sync rules:
    - A rule id not in the table is inserted; a ``seed`` row with different
      content is updated; an identical one is left alone.
    - With ``prune=True`` (default), ``seed`` rows whose id is no longer in
      the incoming rules are deleted.
    - ``user`` rows are never modified or deleted. If an incoming rule has the
      same id as a ``user`` row, nothing is written and ``ValueError`` is
      raised.
    - An empty or missing mappings directory raises instead of seeding
      nothing, so a wrong path can never wipe the seeded rules.

Safety:
    - Every check runs before the first write, so a failed call leaves the
      table untouched even if the caller does not roll back.
    - Error messages never include rule content or file contents.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from auditor.db.schema import MIGRATIONS, ORIGIN_SEED, ORIGINS
from auditor.db.session import MEMORY, connect, migrate, session
from auditor.training.patterns import PatternRule, ensure_unique_rule_ids
from auditor.training.store import _dict_to_rule, _rule_to_dict, load_rules

__all__ = [
    "DEFAULT_MAPPINGS_DIR",
    "SeedResult",
    "fetch_rules",
    "load_mapping_rules",
    "seed_database",
    "seed_rules",
]

DEFAULT_MAPPINGS_DIR = Path(__file__).resolve().parents[2] / "data" / "mappings"


@dataclass(frozen=True, slots=True)
class SeedResult:
    """What one :func:`seed_rules` call changed."""

    inserted: int
    updated: int
    unchanged: int
    removed: int


# --------------------------------------------------------------------------
# Validation helpers
# --------------------------------------------------------------------------


def _require_connection(conn: object) -> sqlite3.Connection:
    if not isinstance(conn, sqlite3.Connection):
        raise TypeError(f"conn must be sqlite3.Connection, got {type(conn).__name__}")
    return conn


def _require_rules(rules: object) -> tuple[PatternRule, ...]:
    if isinstance(rules, (str, bytes, Mapping)) or not isinstance(rules, Iterable):
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


def _require_prune(prune: object) -> bool:
    """Return ``prune`` if it is a bool.

    >>> _require_prune(True)
    True
    >>> _require_prune("yes")
    Traceback (most recent call last):
        ...
    TypeError: prune must be bool, got str
    """
    if not isinstance(prune, bool):
        raise TypeError(f"prune must be bool, got {type(prune).__name__}")
    return prune


def _require_origin(origin: object) -> str | None:
    """Return ``origin`` if it is None or a known origin.

    >>> _require_origin(None) is None
    True
    >>> _require_origin("seed")
    'seed'
    >>> _require_origin("other")
    Traceback (most recent call last):
        ...
    ValueError: origin must be one of: seed, user
    >>> _require_origin(5)
    Traceback (most recent call last):
        ...
    TypeError: origin must be str or None, got int
    """
    if origin is None:
        return None
    if not isinstance(origin, str):
        raise TypeError(f"origin must be str or None, got {type(origin).__name__}")
    if origin not in ORIGINS:
        raise ValueError("origin must be one of: " + ", ".join(ORIGINS))
    return origin


# --------------------------------------------------------------------------
# Rule <-> JSON text
# --------------------------------------------------------------------------


def _encode_rule(rule: PatternRule) -> str:
    return json.dumps(
        _rule_to_dict(rule),
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    )


def _decode_rule(body: object) -> PatternRule:
    if not isinstance(body, str):
        raise ValueError("stored rule is invalid")
    try:
        return _dict_to_rule(json.loads(body), 0)
    except (ValueError, TypeError, RecursionError):
        raise ValueError("stored rule is invalid") from None


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def load_mapping_rules(
    directory: Path = DEFAULT_MAPPINGS_DIR,
) -> tuple[PatternRule, ...]:
    """Read and validate every ``*.json`` mapping file in ``directory``.

    Files are read in name order and each file's rules keep their order.

    Raises:
        TypeError: ``directory`` is not a ``Path``.
        FileNotFoundError: the directory does not exist.
        NotADirectoryError: ``directory`` is not a directory.
        ValueError: no mapping files exist, a file is invalid, or rule ids
            repeat (also across files).
    """
    if not isinstance(directory, Path):
        raise TypeError(f"directory must be pathlib.Path, got {type(directory).__name__}")
    if not directory.exists():
        raise FileNotFoundError("mappings directory not found")
    if not directory.is_dir():
        raise NotADirectoryError("mappings path is not a directory")

    files = sorted(
        (path for path in directory.glob("*.json") if path.is_file()),
        key=lambda path: path.name,
    )
    if not files:
        raise ValueError("no mapping files found")

    collected: list[PatternRule] = []
    for path in files:
        try:
            collected.extend(load_rules(path))
        except ValueError as exc:
            raise ValueError(f"invalid mapping file {path.name}: {exc}") from None
    rules = tuple(collected)
    ensure_unique_rule_ids(rules)
    return rules


def seed_rules(
    conn: sqlite3.Connection,
    rules: Iterable[PatternRule],
    *,
    prune: bool = True,
) -> SeedResult:
    """Sync ``rules`` into the ``rules`` table as ``seed`` rows.

    Must run inside a transaction opened by the caller (for example the
    connection from ``session()``), so the caller decides when to commit.

    Raises:
        TypeError: bad argument types.
        ValueError: not inside a transaction, duplicate rule ids, or an
            incoming rule id belongs to a ``user`` row. Nothing is written.

    >>> conn = connect()
    >>> migrate(conn, MIGRATIONS)
    1
    >>> _ = conn.execute("BEGIN IMMEDIATE")
    >>> seed_rules(conn, [])
    SeedResult(inserted=0, updated=0, unchanged=0, removed=0)
    >>> _ = conn.execute("ROLLBACK")
    >>> seed_rules(conn, [])
    Traceback (most recent call last):
        ...
    ValueError: seed_rules must run inside a transaction
    >>> conn.close()
    """
    connection = _require_connection(conn)
    prune = _require_prune(prune)
    incoming = _require_rules(rules)
    if not connection.in_transaction:
        raise ValueError("seed_rules must run inside a transaction")
    ensure_unique_rule_ids(incoming)

    existing: dict[str, tuple[str, str]] = {
        str(rule_id): (str(origin), str(body))
        for rule_id, origin, body in connection.execute(
            "SELECT rule_id, origin, body FROM rules"
        )
    }

    inserts: list[tuple[str, str, str, str, str]] = []
    updates: list[tuple[str, str, str, str]] = []
    unchanged = 0
    for rule in incoming:
        vendor = rule.vendor.value
        body = _encode_rule(rule)
        current = existing.get(rule.rule_id)
        if current is None:
            inserts.append((rule.rule_id, vendor, rule.target_field, ORIGIN_SEED, body))
        elif current[0] != ORIGIN_SEED:
            raise ValueError(f"seed rule {rule.rule_id} conflicts with a user rule")
        elif current[1] == body:
            unchanged += 1
        else:
            updates.append((vendor, rule.target_field, body, rule.rule_id))

    incoming_ids = {rule.rule_id for rule in incoming}
    stale = (
        sorted(
            rule_id
            for rule_id, (origin, _body) in existing.items()
            if origin == ORIGIN_SEED and rule_id not in incoming_ids
        )
        if prune
        else []
    )

    connection.executemany(
        "INSERT INTO rules (rule_id, vendor, target_field, origin, body) "
        "VALUES (?, ?, ?, ?, ?)",
        inserts,
    )
    connection.executemany(
        "UPDATE rules SET vendor = ?, target_field = ?, body = ? WHERE rule_id = ?",
        updates,
    )
    connection.executemany(
        "DELETE FROM rules WHERE rule_id = ?",
        [(rule_id,) for rule_id in stale],
    )
    return SeedResult(
        inserted=len(inserts),
        updated=len(updates),
        unchanged=unchanged,
        removed=len(stale),
    )


def fetch_rules(
    conn: sqlite3.Connection,
    *,
    origin: str | None = None,
) -> tuple[PatternRule, ...]:
    """Return stored rules ordered by vendor, target field and rule id.

    Raises:
        TypeError: bad argument types.
        ValueError: ``origin`` is unknown, or a stored row is corrupt (the
            message never includes the stored text).

    >>> conn = connect()
    >>> migrate(conn, MIGRATIONS)
    1
    >>> fetch_rules(conn)
    ()
    >>> conn.close()
    """
    connection = _require_connection(conn)
    wanted = _require_origin(origin)
    sql = "SELECT body FROM rules"
    params: tuple[str, ...] = ()
    if wanted is not None:
        sql += " WHERE origin = ?"
        params = (wanted,)
    sql += " ORDER BY vendor, target_field, rule_id"
    return tuple(_decode_rule(row[0]) for row in connection.execute(sql, params))


def seed_database(
    database: Path | str,
    directory: Path = DEFAULT_MAPPINGS_DIR,
    *,
    prune: bool = True,
) -> SeedResult:
    """Create or upgrade the schema in ``database`` and seed it from files.

    The mapping files are read and validated first, so an invalid or missing
    directory never creates or touches the database. The write happens in one
    transaction.

    Raises:
        ValueError: ``database`` is ``":memory:"`` (each connection would get
            its own empty database; use :func:`seed_rules` instead), or any
            error from :func:`load_mapping_rules` / :func:`seed_rules`.
    """
    if isinstance(database, (str, Path)) and str(database) == MEMORY:
        raise ValueError("seed_database needs a file database, not :memory:")
    rules = load_mapping_rules(directory)
    with closing(connect(database)) as setup:
        migrate(setup, MIGRATIONS)
    with session(database) as conn:
        return seed_rules(conn, rules, prune=prune)


if __name__ == "__main__":
    import doctest

    doctest.testmod()