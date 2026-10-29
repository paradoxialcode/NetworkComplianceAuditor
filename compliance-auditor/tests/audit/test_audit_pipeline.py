import logging

import pytest

from auditor.audit.pipeline import (
    Backends,
    ConfigInputError,
    UnsupportedVendorError,
    audit_config_upload,
    parse_config_upload,
)
from auditor.audit.service import RuleSet
from auditor.audit.store import init_db, load_audit
from auditor.compliance.catalog import Catalog
from auditor.compliance.models import Check, Status
from auditor.db.session import session
from auditor.parsers import normalizer as parsed
from auditor.schema import baseline as schema

CISCO_TEXT = (
    "version 17.9\nhostname edge-rtr-1\nservice password-encryption\n"
    "interface GigabitEthernet0/1\n description uplink\nip route 0.0.0.0 0.0.0.0 10.0.0.254\n"
    "line vty 0 4\n transport input ssh\nend\n"
)
FORTI_TEXT = (
    "#config-version=FGT60F-7.2.5\nconfig system global\n    set hostname \"fw-1\"\nend\n"
    "config system interface\n    edit \"wan1\"\n    next\nend\n"
)
JUNOS_TEXT = "set system host-name junos-1\nset system services ssh\n"
SECRET = "hunter2-top-secret"


def ev(raw, line=1):
    return parsed.Evidence("cfg.txt", line, line, raw)


def detect(text):
    if "config system" in text:
        return parsed.Vendor.FORTIOS
    if "hostname" in text or "version" in text:
        return parsed.Vendor.CISCO_IOS
    return None


class Recorder:
    def __init__(self, telnet=False):
        self.tokenizer_calls = []
        self.normalize_calls = []
        self.telnet = telnet

    def tokenizer(self, text, name):
        self.tokenizer_calls.append((text, name))
        return ["token"]

    def normalize(self, tokens, vendor):
        self.normalize_calls.append((tokens, vendor))
        return parsed.SecurityBaseline(
            vendor=vendor,
            hostname=parsed.Fact("edge-rtr-1", ev("hostname edge-rtr-1")),
            telnet_enabled=parsed.Fact(self.telnet, ev("no ip telnet", 3)),
            warnings=(parsed.NormalizationWarning("unrecognized block", 9),),
        )

    def backends(self):
        return Backends(
            tokenizers={parsed.Vendor.CISCO_IOS: self.tokenizer, parsed.Vendor.FORTIOS: self.tokenizer},
            normalize=self.normalize,
            detect=detect,
        )


def test_cisco_is_detected_and_routed():
    rec = Recorder()
    result = parse_config_upload(CISCO_TEXT.encode(), "router.cfg", backends=rec.backends())
    assert result.vendor is parsed.Vendor.CISCO_IOS
    assert result.vendor_detected is True
    assert rec.tokenizer_calls == [(CISCO_TEXT, "router.cfg")]
    assert rec.normalize_calls == [(["token"], parsed.Vendor.CISCO_IOS)]
    assert result.baseline.device.hostname == "edge-rtr-1"
    assert result.baseline.device.vendor is schema.Vendor.Cisco
    assert result.baseline.device.filename == "router.cfg"
    assert result.baseline.device.sha256 == result.upload.sha256
    assert len(result.baseline.unrecognized) == 1


def test_fortinet_is_detected():
    rec = Recorder()
    result = parse_config_upload(FORTI_TEXT.encode(), "fw.conf", backends=rec.backends())
    assert result.vendor is parsed.Vendor.FORTIOS
    assert result.baseline.device.vendor is schema.Vendor.Fortinet


def test_explicit_vendor_overrides_detection():
    rec = Recorder()
    result = parse_config_upload(CISCO_TEXT.encode(), "x.cfg", vendor=parsed.Vendor.FORTIOS, backends=rec.backends())
    assert result.vendor is parsed.Vendor.FORTIOS
    assert result.vendor_detected is False


def test_unknown_vendor_points_to_training():
    with pytest.raises(UnsupportedVendorError, match="Training"):
        parse_config_upload(JUNOS_TEXT.encode(), "junos.set", backends=Recorder().backends())


def test_vendor_without_backend_is_unsupported():
    backends = Backends(
        tokenizers={parsed.Vendor.CISCO_IOS: Recorder().tokenizer}, normalize=Recorder().normalize, detect=detect
    )
    with pytest.raises(UnsupportedVendorError):
        parse_config_upload(FORTI_TEXT.encode(), "fw.conf", backends=backends)


@pytest.mark.parametrize("data", [b"", b"\x00\x01\x02binary"])
def test_upload_problems_become_input_errors(data):
    with pytest.raises(ConfigInputError):
        parse_config_upload(data, "x.cfg", backends=Recorder().backends())


def test_oversized_upload_rejected():
    with pytest.raises(ConfigInputError, match="larger"):
        parse_config_upload(CISCO_TEXT.encode(), "x.cfg", backends=Recorder().backends(), max_bytes=10)


def test_parser_value_errors_do_not_leak_config_content(caplog):
    class Boom(Recorder):
        def tokenizer(self, text, name):
            raise ValueError(f"bad line: username admin password {SECRET}")

    with caplog.at_level(logging.DEBUG), pytest.raises(ConfigInputError) as info:
        parse_config_upload(CISCO_TEXT.encode(), "x.cfg", backends=Boom().backends())
    assert SECRET not in str(info.value)
    assert SECRET not in caplog.text
    assert "could not be parsed" in str(info.value)


def test_programming_errors_are_not_masked():
    class Bug(Recorder):
        def normalize(self, tokens, vendor):
            raise TypeError("internal bug")

    with pytest.raises(TypeError):
        parse_config_upload(CISCO_TEXT.encode(), "x.cfg", backends=Bug().backends())


def make_rules():
    checks = [
        Check.model_validate(
            {
                "id": "CHK-TELNET-OFF",
                "title": "Telnet must be disabled",
                "severity": "high",
                "condition": {"field": "management.telnet", "op": "eq", "value": "DISABLED"},
                "mappings": {"nist": ["AC-17"]},
            }
        ),
        Check.model_validate(
            {
                "id": "CHK-SSH-ON",
                "title": "SSH must be enabled",
                "severity": "high",
                "condition": {"field": "management.ssh", "op": "eq", "value": "ENABLED"},
            }
        ),
    ]
    catalog = Catalog.model_validate(
        {"framework": "nist", "name": "NIST subset", "controls": [{"id": "AC-17", "title": "Remote Access"}]}
    )
    return RuleSet(checks=tuple(checks), catalogs={"nist": catalog}, templates={}, warnings=())


def test_end_to_end_audit_of_upload():
    result = audit_config_upload(CISCO_TEXT.encode(), "router.cfg", make_rules(), backends=Recorder(telnet=False).backends())
    status = {r.check_id: r.status for r in result.outcome.results}
    assert status == {"CHK-TELNET-OFF": Status.PASS, "CHK-SSH-ON": Status.UNKNOWN}
    assert result.parse.upload.filename == "router.cfg"
    assert result.outcome.audit_id is None


def test_end_to_end_failing_device():
    result = audit_config_upload(CISCO_TEXT.encode(), "router.cfg", make_rules(), backends=Recorder(telnet=True).backends())
    status = {r.check_id: r.status for r in result.outcome.results}
    assert status["CHK-TELNET-OFF"] is Status.FAIL


def test_audit_upload_is_persisted(tmp_path):
    db = tmp_path / "audits.db"
    init_db(db)
    result = audit_config_upload(
        CISCO_TEXT.encode(), "router.cfg", make_rules(), database=db, backends=Recorder().backends()
    )
    with session(db) as conn:
        stored = load_audit(conn, result.outcome.audit_id)
    assert stored.device.source_sha256 == result.parse.upload.sha256
    assert stored.device.source_filename == "router.cfg"


def test_unsafe_upload_name_never_reaches_the_database(tmp_path):
    db = tmp_path / "audits.db"
    init_db(db)
    result = audit_config_upload(
        CISCO_TEXT.encode(), "..\\..\\evil\x00.cfg", make_rules(), database=db, backends=Recorder().backends()
    )
    with session(db) as conn:
        assert load_audit(conn, result.outcome.audit_id).device.source_filename == "evil.cfg"


def test_explicit_vendor_never_calls_the_detector():
    def forbidden(text):
        raise AssertionError("detector must not run when a vendor is chosen")

    rec = Recorder()
    backends = Backends(tokenizers=rec.backends().tokenizers, normalize=rec.normalize, detect=forbidden)
    result = parse_config_upload(JUNOS_TEXT.encode(), "x.set", vendor=parsed.Vendor.CISCO_IOS, backends=backends)
    assert result.vendor is parsed.Vendor.CISCO_IOS
