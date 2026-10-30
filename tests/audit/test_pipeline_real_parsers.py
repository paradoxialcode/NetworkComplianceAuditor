import pytest

pytest.importorskip("auditor.parsers.tokenizers.indented")
pytest.importorskip("auditor.parsers.tokenizers.fortinet")

from auditor.audit.pipeline import default_detector, parse_config_upload  # noqa: E402
from auditor.parsers.normalizer import Vendor as ParserVendor  # noqa: E402
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
    result = parse_config_upload(CISCO, "edge.cfg", vendor=ParserVendor.CISCO_IOS)
    assert result.baseline.device.vendor is Vendor.Cisco
    assert result.baseline.device.hostname == "edge-rtr-1"
    assert result.baseline.device.filename == "edge.cfg"


def test_fortinet_through_real_tokenizer_and_normalizer():
    result = parse_config_upload(FORTI, "fw.conf", vendor=ParserVendor.FORTIOS)
    assert result.baseline.device.vendor is Vendor.Fortinet
    assert result.baseline.device.hostname.strip('"') == "fw-1"


REALISTIC_CISCO = """version 17.9
service timestamps log datetime msec
service password-encryption
hostname edge-rtr-1
enable secret 9 $9$abc$HASH
aaa new-model
username admin privilege 15 secret 9 $9$def$HASH
ip domain-name example.local
ip ssh version 2
ip route 0.0.0.0 0.0.0.0 10.0.0.254
no ip http server
interface GigabitEthernet0/0
 description uplink
 ip address 10.0.0.1 255.255.255.0
interface Vlan10
 ip address 10.10.10.1 255.255.255.0
router ospf 1
 network 10.0.0.0 0.0.0.255 area 0
ntp server 10.0.0.5
logging host 10.0.0.9
snmp-server community notpublic RO
banner motd ^Authorized use only^
line con 0
line vty 0 4
 transport input ssh
end
"""

REALISTIC_FORTI = """#config-version=FGT60F-7.2.5-FW-build1517
config system global
    set hostname "fw-1"
    set admin-telnet disable
end
config system interface
    edit "wan1"
        set ip 203.0.113.2 255.255.255.0
        set allowaccess ping https ssh
    next
end
config firewall policy
    edit 1
        set name "lan-to-wan"
        set action accept
    next
end
config system ntp
    set ntpsync enable
end
"""


def test_default_detector_recognizes_realistic_configs():
    assert default_detector(REALISTIC_CISCO) is ParserVendor.CISCO_IOS
    assert default_detector(REALISTIC_FORTI) is ParserVendor.FORTIOS
    assert default_detector("set system host-name junos-1\nset system services ssh\n") is None
