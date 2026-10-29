import pytest

from auditor.audit.batch import MAX_FILES_PER_BATCH, audit_batch
from auditor.audit.pipeline import Backends
from auditor.audit.service import RuleSet
from auditor.audit.store import init_db, load_audit, load_report
from auditor.compliance.catalog import Catalog
from auditor.compliance.models import Check, Status
from auditor.db.session import session
from auditor.parsers import normalizer as parsed

CISCO_TEXT = "version 17.9\nhostname edge-rtr-1\nservice password-encryption\nline vty 0 4\nend\n"
JUNOS_TEXT = "set system host-name junos-1\nset system services ssh\n"
SECRET = "hunter2-top-secret"


def make_rules():
    check = Check.model_validate(
        {
            "id": "CHK-TELNET-OFF",
            "title": "Telnet must be disabled",
            "severity": "high",
            "condition": {"field": "management.telnet", "op": "eq", "value": "DISABLED"},
            "mappings": {"nist": ["AC-17"]},
        }
    )
    catalog = Catalog.model_validate(
        {"framework": "nist", "name": "NIST subset", "controls": [{"id": "AC-17", "title": "Remote Access"}]}
    )
    return RuleSet(checks=(check,), catalogs={"nist": catalog}, templates={}, warnings=())


def detect(text):
    if "config system" in text:
        return parsed.Vendor.FORTIOS
    if "hostname" in text or "version" in text:
        return parsed.Vendor.CISCO_IOS
    return None


def backends(telnet=False, fail_on=None):
    def tokenizer(text, name):
        if fail_on and fail_on in text:
            raise ValueError(f"bad line: password {SECRET}")
        return ["token"]

    def normalize(tokens, vendor):
        evidence = parsed.Evidence("x", 1, 1, "line")
        return parsed.SecurityBaseline(
            vendor=vendor,
            hostname=parsed.Fact("edge-rtr-1", evidence),
            telnet_enabled=parsed.Fact(telnet, evidence),
        )

    return Backends(tokenizers={parsed.Vendor.CISCO_IOS: tokenizer}, normalize=normalize, detect=detect)


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "audits.db"
    init_db(path)
    return path


def test_successful_file_is_audited_saved_and_reported(db):
    (item,) = audit_batch([("router.cfg", CISCO_TEXT.encode())], make_rules(), database=db, backends=backends())
    assert item.error is None
    assert item.filename == "router.cfg"
    assert item.pdf.startswith(b"%PDF-")
    assert item.audit.outcome.results[0].status is Status.PASS
    with session(db) as conn:
        assert load_audit(conn, item.audit.outcome.audit_id) is not None
        assert load_report(conn, item.audit.outcome.audit_id) == item.pdf


def test_unknown_vendor_asks_for_training(db):
    (item,) = audit_batch([("junos.set", JUNOS_TEXT.encode())], make_rules(), database=db, backends=backends())
    assert item.needs_training is True
    assert item.audit is None
    assert "Training" in item.error


def test_one_bad_file_does_not_stop_the_others(db):
    files = [
        ("a.cfg", CISCO_TEXT.encode()),
        ("empty.cfg", b""),
        ("binary.cfg", b"\x00\x01\x02binary"),
        ("b.cfg", CISCO_TEXT.encode()),
    ]
    items = audit_batch(files, make_rules(), database=db, backends=backends())
    assert [i.error is None for i in items] == [True, False, False, True]
    assert "empty" in items[1].error
    with session(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM audits").fetchone()[0] == 2


def test_parser_errors_do_not_leak_config_content(db, caplog):
    text = CISCO_TEXT + "boom\n"
    (item,) = audit_batch([("x.cfg", text.encode())], make_rules(), database=db, backends=backends(fail_on="boom"))
    assert SECRET not in item.error
    assert SECRET not in caplog.text
    assert item.audit is None


def test_unexpected_exception_is_contained(db, monkeypatch, caplog):
    import auditor.audit.batch as batch_module

    def explode(*args, **kwargs):
        raise RuntimeError(f"contains {SECRET}")

    monkeypatch.setattr(batch_module, "audit_config_upload", explode)
    (item,) = audit_batch([("x.cfg", CISCO_TEXT.encode())], make_rules(), database=db, backends=backends())
    assert item.error == "Unexpected error while auditing this file."
    assert SECRET not in caplog.text


def test_pdf_failure_keeps_the_saved_audit(db, monkeypatch):
    import auditor.audit.batch as batch_module

    def explode(outcome):
        raise RuntimeError("render failed")

    monkeypatch.setattr(batch_module, "build_report_bytes", explode)
    (item,) = audit_batch([("x.cfg", CISCO_TEXT.encode())], make_rules(), database=db, backends=backends())
    assert item.audit is not None
    assert item.pdf is None
    assert "PDF report could not be generated" in item.error


def test_unknown_framework_is_reported(db):
    (item,) = audit_batch(
        [("x.cfg", CISCO_TEXT.encode())], make_rules(), database=db, frameworks=["cis"], backends=backends()
    )
    assert "unknown framework" in item.error


def test_framework_selection_is_applied(db):
    (item,) = audit_batch(
        [("x.cfg", CISCO_TEXT.encode())], make_rules(), database=db, frameworks=["NIST"], backends=backends()
    )
    assert item.audit.outcome.frameworks == ("nist",)


def test_explicit_vendor_is_passed_through(db):
    (item,) = audit_batch(
        [("junos.set", JUNOS_TEXT.encode())],
        make_rules(),
        database=db,
        vendor=parsed.Vendor.CISCO_IOS,
        backends=backends(),
    )
    assert item.error is None
    assert item.audit.parse.vendor_detected is False


def test_batch_size_limit(db):
    files = [(f"{i}.cfg", CISCO_TEXT.encode()) for i in range(MAX_FILES_PER_BATCH + 1)]
    with pytest.raises(ValueError, match="at most"):
        audit_batch(files, make_rules(), database=db, backends=backends())


def test_unsafe_filename_is_sanitized_in_results(db):
    (item,) = audit_batch([("..\\..\\evil\x00.cfg", CISCO_TEXT.encode())], make_rules(), database=db, backends=backends())
    assert item.filename == "evil.cfg"


def test_per_file_size_limit(db):
    (item,) = audit_batch([("x.cfg", CISCO_TEXT.encode())], make_rules(), database=db, backends=backends(), max_bytes=10)
    assert "larger" in item.error
