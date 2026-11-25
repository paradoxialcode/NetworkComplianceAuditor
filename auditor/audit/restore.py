from __future__ import annotations

import re
from pathlib import Path
from typing import Final

from auditor.audit.store import StoredAudit, load_audit, load_report
from auditor.db.session import connect

MAX_RESTORE_IDS: Final = 50
_IDS_RE: Final = re.compile(r"[0-9]{1,9}(?:,[0-9]{1,9}){0,%d}" % (MAX_RESTORE_IDS - 1), re.ASCII)


def parse_audit_ids(raw: object) -> tuple[int, ...]:
    if not isinstance(raw, str) or _IDS_RE.fullmatch(raw) is None:
        return ()
    seen: dict[int, None] = {}
    for part in raw.split(","):
        value = int(part)
        if value > 0:
            seen[value] = None
    return tuple(seen)


def format_audit_ids(ids: object) -> str:
    return ",".join(str(i) for i in ids if isinstance(i, int) and not isinstance(i, bool) and i > 0)


def fetch_audits(database: Path | str, ids: tuple[int, ...]) -> list[tuple[StoredAudit, bytes | None]]:
    conn = connect(database)
    try:
        found: list[tuple[StoredAudit, bytes | None]] = []
        for audit_id in ids[:MAX_RESTORE_IDS]:
            stored = load_audit(conn, audit_id)
            if stored is not None:
                found.append((stored, load_report(conn, audit_id)))
        return found
    finally:
        conn.close()
