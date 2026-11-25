import pytest

from auditor.ingestion.junos_detector import detect_junos, detect_vendor_with_junos
from auditor.parsers.normalizer import Vendor

JUNOS_SET = """\
set version 21.4R3-S3.4
set system host-name SRX-BRANCH-01
set system root-authentication encrypted-password "$6$salt$WeakRootHashValue"
set system login user admin class super-user
set system login user admin authentication encrypted-password "$6$salt$WeakAdminHashValue"
set system services ssh
set system services telnet
set system services web-management http port 80
set system ntp server 10.10.10.1
set interfaces ge-0/0/0 unit 0 family inet address 203.0.113.20/30
"""

JUNOS_BRACE = """\
## Last commit: 2026-11-01 10:00:00 UTC by admin
version 21.4R3-S3.4;
system {
    host-name SRX-BRANCH-01;
    services {
        ssh;
    }
}
interfaces {
    ge-0/0/0 {
        unit 0;
    }
}
security {
    zones {
        security-zone trust;
    }
}
"""

CISCO = """\
version 15.2
hostname EDGE-R1
!
service password-encryption
enable secret 5 x
ntp server 10.0.0.1
interface GigabitEthernet0/0
 ip address 10.0.0.2 255.255.255.0
line vty 0 4
 transport input ssh
"""

FORTI = """\
#config-version=FGT60F-7.2.5-FW-build1517:opmode=0:vdom=0
config system global
    set hostname "FW-HQ-01"
end
config system interface
    edit "port1"
        set status up
        set allowaccess ping https ssh
    next
end
"""


@pytest.mark.parametrize("text", [JUNOS_SET, JUNOS_BRACE])
def test_junos_text_is_detected(text):
    assert detect_junos(text).score >= 6
    assert detect_vendor_with_junos(text) is Vendor.JUNOS


def test_set_format_score_and_signals():
    detection = detect_junos(JUNOS_SET)
    assert [(s.name, s.line_number, s.hits, s.points) for s in detection.signals] == [
        ("junos-version", 1, 1, 6),
        ("junos-host-name", 2, 1, 4),
        ("junos-set-hierarchy", 2, 9, 8),
    ]
    assert detection.score == 18


def test_minimal_snippet_is_detected():
    assert detect_vendor_with_junos("set system host-name R1\n") is Vendor.JUNOS


@pytest.mark.parametrize("text", ["", "   \n", "hello world\n", "set system\n", "system {\n", "hostname R1\n"])
def test_weak_or_unrelated_text_is_unknown(text):
    assert detect_vendor_with_junos(text) is None


def test_cisco_and_fortios_are_unchanged():
    assert detect_junos(CISCO).score == 0
    assert detect_junos(FORTI).score == 0
    assert detect_vendor_with_junos(CISCO) is Vendor.CISCO_IOS
    assert detect_vendor_with_junos(FORTI) is Vendor.FORTIOS


def test_cisco_version_is_not_junos():
    assert detect_junos("version 15.2(4)M\n").score == 0
    assert detect_junos("version 16.9\n").score == 0


def test_forti_set_lines_alone_are_not_junos():
    text = "set status up\nset allowaccess ping https\nset security wpa2-personal\n"
    assert detect_junos(text).score == 0


def test_junos_wins_over_incidental_forti_set_hits():
    assert detect_vendor_with_junos(JUNOS_SET) is Vendor.JUNOS


def test_dominant_builtin_dialect_beats_junos_noise():
    assert detect_vendor_with_junos(CISCO + "set system host-name R1\n") is Vendor.CISCO_IOS
    assert detect_vendor_with_junos(FORTI + "set system host-name R1\n") is Vendor.FORTIOS


def test_line_endings_and_bom():
    base = detect_junos(JUNOS_SET)
    assert detect_junos(JUNOS_SET.replace("\n", "\r\n")) == base
    assert detect_junos("\ufeff" + JUNOS_SET) == base


def test_hit_caps():
    assert detect_junos("set system services ssh\n" * 1000).score == 8
    assert detect_junos("interfaces {\n" * 1000).score == 9


def test_indented_set_lines_still_count_but_indented_blocks_do_not():
    assert detect_junos("  set system host-name R1\n").score == 6
    assert detect_junos("  system {\n").score == 0


def test_non_str_input():
    for bad in (None, b"set system host-name R1", 5):
        with pytest.raises(TypeError):
            detect_junos(bad)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            detect_vendor_with_junos(bad)  # type: ignore[arg-type]


def test_signals_never_contain_config_text():
    assert "WeakRootHashValue" not in repr(detect_junos(JUNOS_SET))
