import pytest

from auditor.audit.pipeline import (
    GENERIC_PARSER,
    UnsupportedVendorError,
    default_detector,
    parse_config_upload,
)
from auditor.parsers.normalizer import Vendor

JUNOS_SET = (
    "set version 21.4R3-S3.4\n"
    "set system host-name SRX-BRANCH-01\n"
    "set system services ssh\n"
    "set system ntp server 10.10.10.1\n"
    "set interfaces ge-0/0/0 unit 0 family inet address 203.0.113.20/30\n"
)
CISCO = "hostname R1\n!\nservice password-encryption\nenable secret 5 x\ninterface Gi0/0\n shutdown\n"


def test_default_detector_recognizes_junos_and_keeps_cisco():
    assert default_detector(JUNOS_SET) is Vendor.JUNOS
    assert default_detector(CISCO) is Vendor.CISCO_IOS
    assert default_detector("hello world\n") is None


def test_auto_detected_junos_without_rules_falls_back_to_generic():
    result = parse_config_upload(JUNOS_SET.encode(), "srx.set")
    assert result.parser == GENERIC_PARSER


def test_explicit_junos_without_rules_is_still_rejected():
    with pytest.raises(UnsupportedVendorError):
        parse_config_upload(JUNOS_SET.encode(), "srx.set", vendor=Vendor.JUNOS)
