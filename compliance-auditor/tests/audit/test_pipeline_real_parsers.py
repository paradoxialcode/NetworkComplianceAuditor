import pytest

pytest.importorskip("auditor.parsers.tokenizers.indented")
pytest.importorskip("auditor.parsers.tokenizers.fortinet")

from auditor.audit.pipeline import parse_config_upload  # noqa: E402
from auditor.schema.baseline import Vendor  # noqa: E402

CISCO = b"""version 17.9
service password-encryption
hostname edge-rtr-1
!
interface GigabitEthernet0/1
 description uplink
 no shutdown
!
line vty 0 4
 transport input ssh
end
"""
FORTI = b"""#config-version=FGT60F-7.2.5-FW-build1517
config system global
    set hostname "fw-1"
end
config system interface
    edit "wan1"
        set allowaccess ping https ssh
    next
end
"""


def test_cisco_through_real_tokenizer_and_normalizer():
    result = parse_config_upload(CISCO, "edge.cfg")
    assert result.baseline.device.vendor is Vendor.Cisco
    assert result.baseline.device.hostname == "edge-rtr-1"
    assert result.baseline.device.filename == "edge.cfg"


def test_fortinet_through_real_tokenizer_and_normalizer():
    result = parse_config_upload(FORTI, "fw.conf")
    assert result.baseline.device.vendor is Vendor.Fortinet
    assert result.baseline.device.hostname.strip('"') == "fw-1"
