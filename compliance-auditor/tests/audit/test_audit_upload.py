import codecs
import hashlib

import pytest

from auditor.audit.upload import (
    DEFAULT_FILENAME,
    MAX_LINE_LENGTH,
    MAX_LINES,
    UploadError,
    detect_vendor,
    read_config_upload,
)
from auditor.parsers.normalizer import Vendor

CISCO = """!
version 17.9
service timestamps log datetime
service password-encryption
hostname edge-rtr-1
!
interface GigabitEthernet0/1
 description uplink
 ip address 10.0.0.1 255.255.255.0
!
ip route 0.0.0.0 0.0.0.0 10.0.0.254
line vty 0 4
 transport input ssh
end
"""
FORTI = """#config-version=FGT60F-7.2.5-FW-build1517
config system global
    set hostname "fw-1"
    set admin-telnet disable
end
config system interface
    edit "wan1"
        set allowaccess ping https ssh
    next
end
"""
JUNOS = """set system host-name junos-1
set system services ssh
set system ntp server 10.0.0.1
set system syslog host 10.0.0.9 any any
"""


def test_reads_plain_text_and_hashes_raw_bytes():
    raw = CISCO.encode()
    up = read_config_upload(raw, "router.cfg")
    assert up.text == CISCO
    assert up.filename == "router.cfg"
    assert up.sha256 == hashlib.sha256(raw).hexdigest()
    assert up.size == len(raw)
    assert up.lossy is False


def test_accepts_bytearray():
    assert read_config_upload(bytearray(b"hostname a\n")).text == "hostname a\n"


@pytest.mark.parametrize("bad", ["text", None, 5, ["a"]])
def test_non_bytes_is_a_type_error(bad):
    with pytest.raises(TypeError):
        read_config_upload(bad)


@pytest.mark.parametrize("data", [b"", b"   \n\t\n"])
def test_empty_file_rejected(data):
    with pytest.raises(UploadError, match="empty"):
        read_config_upload(data)


def test_size_limit():
    with pytest.raises(UploadError, match="larger"):
        read_config_upload(b"a" * 101, max_bytes=100)
    assert read_config_upload(b"a" * 100, max_bytes=100)


def test_binary_rejected():
    with pytest.raises(UploadError, match="binary"):
        read_config_upload(b"\x7fELF\x02\x01\x00\x00hostname")


def test_utf8_bom_removed():
    up = read_config_upload(codecs.BOM_UTF8 + b"hostname a\n")
    assert up.text == "hostname a\n"


@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be"])
def test_utf16_with_bom_decoded(encoding):
    bom = codecs.BOM_UTF16_LE if encoding == "utf-16-le" else codecs.BOM_UTF16_BE
    up = read_config_upload(bom + "hostname sw1\nntp server 10.0.0.1\n".encode(encoding))
    assert up.text == "hostname sw1\nntp server 10.0.0.1\n"
    assert up.lossy is False


def test_cp1252_fallback_is_flagged_lossy():
    up = read_config_upload("banner motd caf\u00e9\n".encode("cp1252"))
    assert "caf\u00e9" in up.text
    assert up.lossy is True


def test_invalid_bytes_do_not_crash():
    up = read_config_upload(b"hostname a\n\x81\x8d\x8f\n")
    assert up.lossy is True


def test_newlines_normalized_and_line_count_preserved():
    up = read_config_upload(b"a\r\nb\rc\nd")
    assert up.text == "a\nb\nc\nd"
    assert up.text.count("\n") == 3


def test_terminal_control_characters_removed():
    up = read_config_upload(b"hostname a\x1b[K\n\tindent\n")
    assert "\x1b" not in up.text
    assert "\tindent" in up.text


def test_too_many_lines_rejected():
    with pytest.raises(UploadError, match="lines"):
        read_config_upload(b"a\n" * (MAX_LINES + 1))


def test_overlong_line_rejected_with_line_number():
    data = b"ok\nok\n" + b"a" * (MAX_LINE_LENGTH + 1) + b"\n"
    with pytest.raises(UploadError, match="line 3"):
        read_config_upload(data)


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("router.cfg", "router.cfg"),
        ("../../etc/passwd", "passwd"),
        ("C:\\Users\\me\\sw 1.cfg", "sw 1.cfg"),
        ("evil\x00name\n.cfg", "evilname.cfg"),
        ("we<ird>|name?.txt", "we_ird_name_.txt"),
        ("...", DEFAULT_FILENAME),
        ("", DEFAULT_FILENAME),
        (None, DEFAULT_FILENAME),
        (123, DEFAULT_FILENAME),
        ("a" * 400 + ".cfg", "a" * 100),
    ],
)
def test_filename_sanitized(name, expected):
    assert read_config_upload(b"hostname a\n", name).filename == expected


def test_detect_cisco():
    assert detect_vendor(CISCO) is Vendor.CISCO_IOS


def test_detect_fortinet():
    assert detect_vendor(FORTI) is Vendor.FORTIOS


def test_unknown_vendor_returns_none():
    assert detect_vendor(JUNOS) is None
    assert detect_vendor("") is None
    assert detect_vendor("just some text\nwith lines\n") is None


def test_single_weak_signal_is_not_enough():
    assert detect_vendor("hostname only-one-signal\n") is None


def test_ambiguous_mix_returns_none():
    mixed = "hostname a\nversion 15.2\n#config-version=FGT\nconfig system global\n"
    assert detect_vendor(mixed) is None


def test_detection_handles_crlf_via_upload():
    up = read_config_upload(CISCO.replace("\n", "\r\n").encode(), "r.cfg")
    assert detect_vendor(up.text) is Vendor.CISCO_IOS


def test_detect_requires_text():
    with pytest.raises(TypeError):
        detect_vendor(b"hostname a")
