import time

import pytest

from auditor.audit import generic
from auditor.audit.generic import BASICS, build_generic_baseline
from auditor.schema.baseline import SecurityState, Vendor

JUNOS_SET = """set version 21.4R3-S3.4
set system host-name junos-fw-1
set system services ssh protocol-version v2
set system services netconf ssh
set system ntp server 10.0.0.5
set system ntp server 10.0.0.6
set system syslog host 10.0.0.9 any any
set system login user admin class super-user authentication encrypted-password "$6$abc$HASHVALUE"
set snmp community hunter2 authorization read-only
set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24
set routing-options static route 0.0.0.0/0 next-hop 10.0.0.254
"""
JUNOS_BRACE = """version 21.4R3-S3.4;
system {
    host-name junos-fw-1;
    services {
        ssh {
            protocol-version v2;
        }
        netconf {
            ssh;
        }
    }
    ntp {
        server 10.0.0.5;
        server 10.0.0.6;
    }
    syslog {
        host 10.0.0.9 {
            any any;
        }
    }
}
routing-options {
    static {
        route 0.0.0.0/0 next-hop 10.0.0.254;
    }
}
"""
CISCOLIKE = """hostname edge-sw-9
version 15.2
no ip http server
ip http secure-server
ip ssh version 2
ntp server 10.1.1.1
logging host 10.1.1.2
logging buffered 4096
line vty 0 4
 transport input ssh
username admin secret 5 $1$abc$HASHVALUE
snmp-server community hunter2 RO
"""
FORTILIKE = """#config-version=FGT60F-7.2.5-FW-build1517-230223:opmode=0:vdom=0
config system global
    set hostname "fw-1"
    set admin-telnet disable
    set admin-ssh-v1 disable
end
"""
SECRETS = ("HASHVALUE", "hunter2")


def build(text):
    return build_generic_baseline(text)


def test_junos_set_style():
    result = build(JUNOS_SET)
    b = result.baseline
    assert b.device.hostname == "junos-fw-1"
    assert b.device.vendor is Vendor.Juniper
    assert b.device.version == "21.4R3-S3.4"
    assert b.device.platform == "Junos (generic parser)"
    assert b.management.ssh is SecurityState.ENABLED
    assert b.management.telnet is SecurityState.DISABLED
    assert b.management.http is SecurityState.DISABLED
    assert b.management.https is SecurityState.DISABLED
    assert b.time_sync.servers == ["10.0.0.5", "10.0.0.6"]
    assert b.logging.destinations == ["10.0.0.9"]
    assert set(result.mapped) == {"hostname", "os_version", "ssh", "telnet", "http", "https", "syslog", "ntp"}
    assert result.total_basics == len(BASICS) == 10


def test_junos_brace_style_matches_set_style():
    set_result, brace_result = build(JUNOS_SET), build(JUNOS_BRACE)
    assert brace_result.baseline.device.hostname == "junos-fw-1"
    assert brace_result.baseline.device.vendor is Vendor.Juniper
    assert brace_result.baseline.management == set_result.baseline.management
    assert brace_result.baseline.time_sync.servers == set_result.baseline.time_sync.servers
    assert brace_result.baseline.logging.destinations == set_result.baseline.logging.destinations
    assert set(brace_result.mapped) == set(set_result.mapped)


def test_junos_absence_rule_is_explained_in_evidence():
    facts = {f.key: f for f in build(JUNOS_SET).baseline.facts}
    telnet = facts["telnet_enabled"]
    assert telnet.value is False
    assert telnet.evidence.mapping_id == "generic:junos-services-absence"
    assert telnet.evidence.confidence == 0.75
    assert "system services" in telnet.evidence.text


def test_telnet_stays_unknown_without_a_services_stanza():
    b = build("set system host-name x\nset system ntp server 10.0.0.5\n").baseline
    assert b.management.telnet is SecurityState.UNKNOWN
    assert b.management.ssh is SecurityState.UNKNOWN


def test_junos_explicit_telnet_is_enabled():
    b = build("set system services ssh\nset system services telnet\n").baseline
    assert b.management.telnet is SecurityState.ENABLED


def test_inactive_stanza_counts_as_absent():
    text = "system {\n    services {\n        ssh;\n        inactive: telnet;\n    }\n}\n"
    assert build(text).baseline.management.telnet is SecurityState.DISABLED


def test_cisco_like_polarity():
    b = build(CISCOLIKE).baseline
    assert b.device.hostname == "edge-sw-9"
    assert b.device.version == "15.2"
    assert b.management.http is SecurityState.DISABLED
    assert b.management.https is SecurityState.ENABLED
    assert b.management.ssh is SecurityState.ENABLED
    assert b.management.telnet is SecurityState.DISABLED
    assert b.time_sync.servers == ["10.1.1.1"]
    assert b.logging.destinations == ["10.1.1.2"]
    assert b.device.vendor is Vendor.Unknown


def test_bare_logging_requires_an_ip_address():
    b = build("logging 10.0.0.9\nlogging buffered 4096\nlogging console\n").baseline
    assert b.logging.destinations == ["10.0.0.9"]


def test_forti_header_gives_model_and_version_and_telnet_off():
    result = build(FORTILIKE)
    facts = {f.key: f for f in result.baseline.facts}
    assert facts["hardware_model"].value == "FGT60F"
    assert facts["os_version"].value == "7.2.5"
    assert result.baseline.device.hostname == "fw-1"
    assert result.baseline.management.telnet is SecurityState.DISABLED


def test_serial_and_model_lines():
    text = "Processor board ID FDO1234ABCD\nModel number : C9300-48P\n"
    facts = {f.key: f.value for f in build(text).baseline.facts}
    assert facts["serial_number"] == "FDO1234ABCD"
    assert facts["hardware_model"] == "C9300-48P"


def test_serial_label_without_a_value_is_ignored():
    facts = {f.key for f in build("serial number\nmodel\n").baseline.facts}
    assert "serial_number" not in facts
    assert "hardware_model" not in facts


def test_conflicting_evidence_prefers_enabled_and_is_reported():
    text = "line vty 0 4\n transport input ssh\nline vty 5 15\n transport input telnet\n"
    result = build(text)
    assert result.baseline.management.telnet is SecurityState.ENABLED
    assert any("telnet" in c for c in result.conflicts)
    assert any(u.reason == "conflict" for u in result.baseline.unrecognized)


def test_low_confidence_is_not_applied(monkeypatch):
    monkeypatch.setattr(generic, "MIN_CONFIDENCE", 0.95)
    b = build(CISCOLIKE).baseline
    assert b.management.ssh is SecurityState.UNKNOWN
    assert b.management.http is SecurityState.UNKNOWN


def test_evidence_records_line_rule_and_confidence():
    facts = {f.key: f for f in build(CISCOLIKE).baseline.facts}
    http = facts["http_management_enabled"]
    assert http.evidence.line == 3
    assert http.evidence.text == "no ip http server"
    assert http.evidence.mapping_id == "generic:no-ip-http-server"
    assert http.evidence.confidence == 0.9


@pytest.mark.parametrize("text", [JUNOS_SET, CISCOLIKE, JUNOS_BRACE])
def test_secrets_never_appear_in_the_baseline(text):
    dump = build(text).baseline.model_dump_json()
    for secret in SECRETS:
        assert secret not in dump


def test_unrecognized_lines_are_listed_with_secrets_redacted():
    result = build(JUNOS_SET)
    texts = [u.text for u in result.baseline.unrecognized]
    assert "<redacted>" in texts
    assert any("routing-options" in t for t in texts)
    assert result.unmatched_count >= 3


def test_unrecognized_list_is_capped_but_count_is_exact():
    text = "".join(f"set protocols thing{i} value\n" for i in range(500))
    result = build(text)
    assert len(result.baseline.unrecognized) == generic.MAX_UNRECOGNIZED
    assert result.unmatched_count == 500


def test_ntp_with_vrf_and_non_host_values():
    b = build("ntp server vrf MGMT 10.0.0.7\nntp server vrf\nntp peer ntp.example.com\n").baseline
    assert b.time_sync.servers == ["10.0.0.7", "ntp.example.com"]


@pytest.mark.parametrize(
    "text",
    ["", "   \n\n", "}}}}\n{\n", "garbage ;;; {{{ \"unterminated", "\x01\x02 weird \u00e9\u4e2d", "set\nset set\n}"],
)
def test_hostile_or_empty_input_does_not_crash(text):
    b = build(text).baseline
    assert b.device.hostname == "unknown-device"
    assert b.management.telnet is SecurityState.UNKNOWN


def test_deeply_nested_braces_are_bounded():
    text = "a {\n" * 5000 + "host-name deep;\n" + "}\n" * 5000
    assert build(text).baseline.device.vendor is Vendor.Unknown


def test_large_file_is_fast():
    text = "set protocols bgp group x neighbor 10.0.0.1 peer-as 65000\n" * 50_000
    start = time.time()
    result = build(text)
    assert time.time() - start < 5.0
    assert result.unmatched_count == 50_000


def test_long_values_are_clipped():
    b = build("hostname " + "h" * 5000 + "\n").baseline
    assert len(b.device.hostname) <= 255


def test_type_error_for_non_text():
    with pytest.raises(TypeError):
        build_generic_baseline(b"hostname x")


def test_filename_and_hash_are_recorded():
    result = build_generic_baseline("hostname x\n", filename="x.cfg", sha256="a" * 64)
    assert result.baseline.device.filename == "x.cfg"
    assert result.baseline.device.sha256 == "a" * 64
