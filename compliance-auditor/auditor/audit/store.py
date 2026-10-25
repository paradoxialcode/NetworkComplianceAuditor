from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path, PurePath
from typing import Any, Final

from pydantic import BaseModel, ConfigDict

from auditor.compliance.models import CheckResult
from auditor.compliance.scoring import AuditSummary, FrameworkScore
from auditor.db.session import connect, migrate, session
from auditor.schema.baseline import SecurityBaseline

MAX_LIST_LIMIT: Final = 500
_MAX_FILENAME_LEN: Final = 255

MIGRATIONS: Final[tuple[str, ...]] = (
    """
CREATE TABLE devices (
    id INTEGER PRIMARY KEY,
    hostname TEXT NOT NULL,
    vendor TEXT NOT NULL,
    platform TEXT NOT NULL,
    version TEXT,
    source_sha256 TEXT,
    source_filename TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE (hostname, vendor)
);
CREATE TABLE audits (
    id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    frameworks TEXT NOT NULL,
    summary_json TEXT NOT NULL,
    scores_json TEXT NOT NULL
);
CREATE INDEX idx_audits_device ON audits(device_id, created_at);
CREATE TABLE findings (
    id INTEGER PRIMARY KEY,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    check_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    status TEXT NOT NULL CHECK (status IN
        ('pass', 'fail', 'not_configured', 'not_applicable', 'unknown', 'error')),
    evidence_json TEXT NOT NULL,
    mappings_json TEXT NOT NULL,
    remediation_key TEXT,
    UNIQUE (audit_id, check_id)
);
CREATE INDEX idx_findings_audit ON findings(audit_id, status);
""",
)


class StoreError(Exception):
    pass


class DeviceRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int
    hostname: str
    vendor: str
    platform: str
    version: str | None
    source_sha256: str | None
    source_filename: str | None
    first_seen: str
    last_seen: str


class StoredAudit(BaseModel):
    model_config = ConfigDict(frozen=True)

    audit_id: int
    created_at: str
    device: DeviceRecord
    frameworks: tuple[str, ...]
    summary: AuditSummary
    scores: dict[str, FrameworkScore]
    results: list[CheckResult]


class AuditListItem(BaseModel):
    model_config = ConfigDict(frozen=True)

    audit_id: int
    created_at: str
    hostname: str
    vendor: str
    frameworks: tuple[str, ...]
    summary: AuditSummary


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _safe_filename(name: str | None) -> str | None:
    if not name:
        return None
    base = PurePath(name.replace("\\", "/")).name
    return base[:_MAX_FILENAME_LEN] or None


def _loads(text: str, what: str) -> Any:
    try:
        return json.loads(text)
    except (TypeError, ValueError) as exc:
        raise StoreError(f"stored {what} is corrupt") from exc


def _require_id(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("audit_id must be an int")
    return value


def init_db(database: Path | str) -> None:
    conn = connect(database)
    try:
        migrate(conn, MIGRATIONS)
    finally:
        conn.close()


def save_audit(
    conn: sqlite3.Connection,
    baseline: SecurityBaseline,
    results: Sequence[CheckResult],
    scores: Mapping[str, FrameworkScore],
    summary: AuditSummary,
) -> int:
    device = baseline.device
    now = _now()
    conn.execute(
        """
        INSERT INTO devices (hostname, vendor, platform, version, source_sha256,
                             source_filename, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (hostname, vendor) DO UPDATE SET
            platform = excluded.platform,
            version = excluded.version,
            source_sha256 = excluded.source_sha256,
            source_filename = excluded.source_filename,
            last_seen = excluded.last_seen
        """,
        (
            device.hostname,
            device.vendor.value,
            device.platform,
            device.version,
            device.sha256,
            _safe_filename(device.filename),
            now,
            now,
        ),
    )
    (device_id,) = conn.execute(
        "SELECT id FROM devices WHERE hostname = ? AND vendor = ?",
        (device.hostname, device.vendor.value),
    ).fetchone()
    cursor = conn.execute(
        "INSERT INTO audits (device_id, created_at, frameworks, summary_json, scores_json) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            device_id,
            now,
            json.dumps(list(scores)),
            json.dumps(summary.model_dump(mode="json")),
            json.dumps({fw: score.model_dump(mode="json") for fw, score in scores.items()}),
        ),
    )
    audit_id = cursor.lastrowid
    if audit_id is None:
        raise StoreError("audit row was not created")
    conn.executemany(
        "INSERT INTO findings (audit_id, seq, check_id, title, severity, status, "
        "evidence_json, mappings_json, remediation_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                audit_id,
                seq,
                r.check_id,
                r.title,
                r.severity.value,
                r.status.value,
                json.dumps(r.evidence),
                json.dumps({fw: list(ids) for fw, ids in r.mappings.items()}),
                r.remediation_key,
            )
            for seq, r in enumerate(results)
        ],
    )
    return audit_id


def persist_audit(
    database: Path | str,
    baseline: SecurityBaseline,
    results: Sequence[CheckResult],
    scores: Mapping[str, FrameworkScore],
    summary: AuditSummary,
) -> int:
    with session(database) as conn:
        return save_audit(conn, baseline, results, scores, summary)


def load_audit(conn: sqlite3.Connection, audit_id: int) -> StoredAudit | None:
    audit_id = _require_id(audit_id)
    row = conn.execute(
        """
        SELECT a.id, a.created_at, a.frameworks, a.summary_json, a.scores_json,
               d.id, d.hostname, d.vendor, d.platform, d.version, d.source_sha256,
               d.source_filename, d.first_seen, d.last_seen
        FROM audits a JOIN devices d ON d.id = a.device_id
        WHERE a.id = ?
        """,
        (audit_id,),
    ).fetchone()
    if row is None:
        return None
    (aid, created_at, frameworks, summary_json, scores_json, *device_cols) = tuple(row)
    finding_rows = conn.execute(
        "SELECT check_id, title, severity, status, evidence_json, mappings_json, remediation_key "
        "FROM findings WHERE audit_id = ? ORDER BY seq",
        (audit_id,),
    ).fetchall()
    results = [
        CheckResult.model_validate(
            {
                "check_id": check_id,
                "title": title,
                "severity": severity,
                "status": status,
                "evidence": _loads(evidence_json, "evidence"),
                "mappings": _loads(mappings_json, "mappings"),
                "remediation_key": remediation_key,
            }
        )
        for check_id, title, severity, status, evidence_json, mappings_json, remediation_key in map(
            tuple, finding_rows
        )
    ]
    return StoredAudit(
        audit_id=aid,
        created_at=created_at,
        device=DeviceRecord(**dict(zip(DeviceRecord.model_fields, device_cols, strict=True))),
        frameworks=tuple(_loads(frameworks, "frameworks")),
        summary=AuditSummary.model_validate(_loads(summary_json, "summary")),
        scores={
            fw: FrameworkScore.model_validate(data) for fw, data in _loads(scores_json, "scores").items()
        },
        results=results,
    )


def list_audits(conn: sqlite3.Connection, limit: int = 50) -> list[AuditListItem]:
    limit = max(1, min(int(limit), MAX_LIST_LIMIT))
    rows = conn.execute(
        """
        SELECT a.id, a.created_at, d.hostname, d.vendor, a.frameworks, a.summary_json
        FROM audits a JOIN devices d ON d.id = a.device_id
        ORDER BY a.created_at DESC, a.id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [
        AuditListItem(
            audit_id=aid,
            created_at=created_at,
            hostname=hostname,
            vendor=vendor,
            frameworks=tuple(_loads(frameworks, "frameworks")),
            summary=AuditSummary.model_validate(_loads(summary_json, "summary")),
        )
        for aid, created_at, hostname, vendor, frameworks, summary_json in map(tuple, rows)
    ]


def delete_audit(conn: sqlite3.Connection, audit_id: int) -> bool:
    audit_id = _require_id(audit_id)
    return conn.execute("DELETE FROM audits WHERE id = ?", (audit_id,)).rowcount > 0
