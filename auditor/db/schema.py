
"""Database schema (stdlib sqlite3), applied with ``session.migrate``.

``MIGRATIONS[0]`` is schema version 1. Never edit a migration that has
shipped; append a new one instead.

The ``rules`` table keeps each rule as validated JSON text in ``body`` (the
same encoding ``store.py`` uses) plus the columns needed for lookups. A new
``PatternRule`` field therefore needs no schema change.

``origin`` says who owns a row: ``seed`` rows are managed by ``seed.py`` and
may be replaced or pruned by it; ``user`` rows (confirmed in training) are
never touched by seeding.
"""


__all__ = [
    "MIGRATIONS",
    "ORIGINS",
    "ORIGIN_SEED",
    "ORIGIN_USER",
]

ORIGIN_SEED = "seed"
ORIGIN_USER = "user"
ORIGINS = (ORIGIN_SEED, ORIGIN_USER)

MIGRATIONS: tuple[str, ...] = (
    """
    CREATE TABLE rules (
        rule_id      TEXT PRIMARY KEY NOT NULL
                     CHECK (length(rule_id) > 0),
        vendor       TEXT NOT NULL CHECK (length(vendor) > 0),
        target_field TEXT NOT NULL CHECK (length(target_field) > 0),
        origin       TEXT NOT NULL CHECK (origin IN ('seed', 'user')),
        body         TEXT NOT NULL CHECK (length(body) > 0)
    );
    CREATE INDEX idx_rules_vendor_target
        ON rules (vendor, target_field);
    """,
)
