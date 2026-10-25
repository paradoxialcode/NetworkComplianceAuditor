import sqlite3

import pytest

from auditor.audit.store import (
    MIGRATIONS,
    StoreError,
    delete_audit,
    init_db,
    list_audits,
    load_audit,
    persist_audit,
    save_audit,
)
from auditor.compliance.catalog import Catalog
from auditor.compliance.engine import run_audit
from auditor.compliance.models import Check, Severity, Status
from auditor.compliance.scoring import score_framework, summarize
from auditor.db.session import connect, schema_version, session
from auditor.schema.baseline import (
    AuthenticationSettings,
    DeviceMetadata,
    LoggingSettings,
    ManagementAccess,
    SecurityBaseline,
    SecurityFact,
    SecurityState,
    TimeSync,
    Vendor,
)

SECRET = "s3cr3t-community-value"


def make_baseline(hostname="sw1", vendor=Vendor.Cisco, filename=None):
    return SecurityBaseline(
        device=DeviceMetadata(hostname=hostname, vendor=vendor, platform="ios-xe", filename=filename),
        management=ManagementAccess(
            ssh=SecurityState.ENABLED,
            telnet=SecurityState.DISABLED,
            http=SecurityState.UNKNOWN,
            https=SecurityState.ENABLED,
        ),
        auth=AuthenticationSettings(),
        logging=LoggingSettings(enabled=SecurityState.ENABLED),
        time_sync=TimeSync(enabled=SecurityState.ENABLED),
        facts=[SecurityFact(key="snmp_community", value=SECRET)],
    )


CHECKS = [
    Check.model_validate(
        {
            "id": "CHK-TELNET-OFF",
            "title": "Telnet disabled",
            "severity": "high",
            "condition": {"field": "management.telnet", "op": "eq", "value": "DISABLED"},
            "mappings": {"nist": ["AC-17"]},
            "remediation_key": "disable_telnet",
        }
    ),
    Check.model_validate(
        {
            "id": "CHK-SNMP-COMMUNITY",
            "title": "SNMP community not default",
            "severity": "critical",
            "condition": {"field": "facts.snmp_community.value", "op": "ne", "value": "public"},
            "mappings": {"nist": ["AC-17", "SC-8"]},
        }
    ),
    Check.model_validate(
        {
            "id": "CHK-HTTP-OFF",
            "title": "HTTP disabled",
            "severity": "medium",
            "condition": {"field": "management.http", "op": "eq", "value": "DISABLED"},
        }
    ),
    Check.model_validate(
        {
            "id": "CHK-NTP",
            "title": "NTP server configured",
            "severity": "low",
            "condition": {"field": "time_sync.servers", "op": "non_empty"},
        }
    ),
]
NIST = Catalog.model_validate(
    {
        "framework": "nist",
        "name": "NIST subset",
        "controls": [{"id": "AC-17", "title": "Remote Access"}, {"id": "SC-8", "title": "Transmission"}],
    }
)


def audit_inputs(baseline=None):
    baseline = baseline or make_baseline()
    results = run_audit(CHECKS, baseline)
    scores = {"nist": score_framework(NIST, results)}
    return baseline, results, scores, summarize(results)


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "data" / "audits.db"
    init_db(path)
    return path


def test_init_db_creates_schema_and_is_idempotent(tmp_path):
    path = tmp_path / "nested" / "audits.db"
    init_db(path)
    init_db(path)
    conn = connect(path)
    try:
        assert schema_version(conn) == len(MIGRATIONS)
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        conn.close()
    assert {"devices", "audits", "findings"} <= tables


def test_round_trip(db):
    baseline, results, scores, summary = audit_inputs()
    audit_id = persist_audit(db, baseline, results, scores, summary)
    with session(db) as conn:
        stored = load_audit(conn, audit_id)
    assert stored is not None
    assert stored.audit_id == audit_id
    assert stored.device.hostname == "sw1"
    assert stored.device.vendor == "Cisco"
    assert stored.frameworks == ("nist",)
    assert stored.results == results
    assert stored.scores == scores
    assert stored.summary == summary


def test_findings_keep_check_order(db):
    baseline, results, scores, summary = audit_inputs()
    audit_id = persist_audit(db, baseline, results, scores, summary)
    with session(db) as conn:
        stored = load_audit(conn, audit_id)
    assert [r.check_id for r in stored.results] == [c.id for c in CHECKS]


def test_unknown_audit_returns_none(db):
    with session(db) as conn:
        assert load_audit(conn, 999) is None


def test_device_upsert_reuses_row_and_updates_last_seen(db):
    first = persist_audit(db, *audit_inputs())
    second = persist_audit(db, *audit_inputs(make_baseline(filename="C:\\configs\\sw1-new.cfg")))
    with session(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM audits").fetchone()[0] == 2
        stored = load_audit(conn, second)
    assert first != second
    assert stored.device.source_filename == "sw1-new.cfg"


def test_same_hostname_different_vendor_is_separate_device(db):
    persist_audit(db, *audit_inputs(make_baseline(vendor=Vendor.Cisco)))
    persist_audit(db, *audit_inputs(make_baseline(vendor=Vendor.Juniper)))
    with session(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 2


def test_list_audits_newest_first_and_limit(db):
    ids = [persist_audit(db, *audit_inputs()) for _ in range(3)]
    with session(db) as conn:
        items = list_audits(conn)
        assert [i.audit_id for i in items] == list(reversed(ids))
        assert len(list_audits(conn, limit=2)) == 2
        assert len(list_audits(conn, limit=-5)) == 1
    assert items[0].hostname == "sw1"
    assert items[0].summary.total == len(CHECKS)


def test_delete_cascades_to_findings(db):
    audit_id = persist_audit(db, *audit_inputs())
    with session(db) as conn:
        assert delete_audit(conn, audit_id) is True
        assert delete_audit(conn, audit_id) is False
        assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM audits").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1


def test_secrets_never_reach_the_database(db):
    persist_audit(db, *audit_inputs())
    conn = connect(db)
    try:
        dump = "\n".join(conn.iterdump())
    finally:
        conn.close()
    assert SECRET not in dump
    assert "[REDACTED]" in dump


def test_sql_injection_in_hostname_is_stored_as_data(db):
    nasty = "x'); DROP TABLE devices;--"
    audit_id = persist_audit(db, *audit_inputs(make_baseline(hostname=nasty)))
    with session(db) as conn:
        stored = load_audit(conn, audit_id)
        assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
    assert stored.device.hostname == nasty


def test_filename_is_reduced_to_basename(db):
    audit_id = persist_audit(db, *audit_inputs(make_baseline(filename="../../etc/passwd")))
    with session(db) as conn:
        assert load_audit(conn, audit_id).device.source_filename == "passwd"


def test_database_rejects_invalid_status(db):
    audit_id = persist_audit(db, *audit_inputs())
    with session(db) as conn, pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO findings (audit_id, seq, check_id, title, severity, status, evidence_json, mappings_json) "
            "VALUES (?, 99, 'X', 't', 'high', 'bogus', '{}', '{}')",
            (audit_id,),
        )


def test_failed_save_rolls_back_everything(db):
    baseline, results, scores, summary = audit_inputs()
    with pytest.raises(sqlite3.IntegrityError), session(db) as conn:
        save_audit(conn, baseline, results + results[:1], scores, summary)
    with session(db) as conn:
        for table in ("devices", "audits", "findings"):
            assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0  # noqa: S608


def test_corrupt_json_raises_store_error(db):
    audit_id = persist_audit(db, *audit_inputs())
    with session(db) as conn:
        conn.execute("UPDATE findings SET evidence_json = 'not json' WHERE audit_id = ?", (audit_id,))
    with session(db) as conn, pytest.raises(StoreError):
        load_audit(conn, audit_id)


@pytest.mark.parametrize("bad", ["1", 1.5, None, True])
def test_audit_id_must_be_int(db, bad):
    with session(db) as conn, pytest.raises(TypeError):
        load_audit(conn, bad)
    with session(db) as conn, pytest.raises(TypeError):
        delete_audit(conn, bad)


def test_statuses_and_severities_survive_round_trip(db):
    baseline, results, scores, summary = audit_inputs()
    audit_id = persist_audit(db, baseline, results, scores, summary)
    with session(db) as conn:
        stored = load_audit(conn, audit_id)
    by_id = {r.check_id: r for r in stored.results}
    assert by_id["CHK-HTTP-OFF"].status is Status.UNKNOWN
    assert by_id["CHK-NTP"].status is Status.FAIL
    assert by_id["CHK-SNMP-COMMUNITY"].severity is Severity.CRITICAL
    assert by_id["CHK-TELNET-OFF"].mappings == {"nist": ("AC-17",)}
