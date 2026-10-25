"""Tests for auditor.ingestion.loader."""

from __future__ import annotations

import codecs
import contextlib
import dataclasses
import hashlib
import os
import random
import stat
import time
import types
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from auditor.ingestion import loader as loader_module
from auditor.ingestion.detector import Detection, detect_vendor
from auditor.ingestion.loader import (
    ALLOWED_ENCODINGS,
    DEFAULT_MAX_BYTES,
    HARD_MAX_BYTES,
    LoadedConfig,
    LoadError,
    LoadErrorCode,
    load_file,
    load_text,
)
from auditor.parsers.normalizer import Vendor, normalize
from auditor.parsers.tokenizers.fortinet import tokenize_fortinet
from auditor.parsers.tokenizers.indented import tokenize_indented

CISCO = Vendor.CISCO_IOS
FORTI = Vendor.FORTIOS
CISCO_CFG = "hostname R1\n!\ninterface Gi0/0\n shutdown\n"
FORTI_CFG = 'config system global\n    set hostname "FW"\nend\n'
SECRET_CFG = CISCO_CFG + "username admin secret hunter2\n"


def write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


@contextlib.contextmanager
def expect(code: LoadErrorCode) -> Iterator[Any]:
    """Assert the block raises LoadError with ``code``; yields the ExceptionInfo."""

    with pytest.raises(LoadError) as info:
        yield info
    assert info.value.code is code, info.value.code


def symlink_or_skip(target: Path, link: Path, is_dir: bool = False) -> None:
    try:
        os.symlink(target, link, target_is_directory=is_dir)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")


# ============================================================= basic loading ====
def test_loads_a_cisco_file(tmp_path: Path) -> None:
    raw = CISCO_CFG.encode()
    loaded = load_file(write(tmp_path, "r1.cfg", raw))
    assert loaded.content == CISCO_CFG
    assert loaded.encoding == "utf-8"
    assert loaded.size_bytes == len(raw)
    assert loaded.sha256 == hashlib.sha256(raw).hexdigest()
    assert loaded.source_name == "r1.cfg"
    assert loaded.vendor is CISCO
    assert loaded.detection == detect_vendor(CISCO_CFG)


def test_loads_a_forti_file(tmp_path: Path) -> None:
    loaded = load_file(write(tmp_path, "fw.conf", FORTI_CFG.encode()))
    assert loaded.vendor is FORTI and loaded.source_name == "fw.conf"


def test_accepts_str_and_pathlike(tmp_path: Path) -> None:
    path = write(tmp_path, "r1.cfg", CISCO_CFG.encode())
    assert load_file(str(path)) == load_file(path)


def test_source_name_defaults_to_the_file_name_and_can_be_overridden(tmp_path: Path) -> None:
    path = write(tmp_path, "r1.cfg", CISCO_CFG.encode())
    assert load_file(path).source_name == "r1.cfg"
    assert str(tmp_path) not in (load_file(path).source_name or "")
    assert load_file(path, source_name="  edge\u0301  ").source_name == "edgé"


def test_unknown_vendor_is_reported_not_raised(tmp_path: Path) -> None:
    loaded = load_file(write(tmp_path, "x.cfg", b"hello world\n"))
    assert loaded.vendor is None and loaded.content == "hello world\n"


# ================================================================= decoding ====
def test_utf8_bom(tmp_path: Path) -> None:
    raw = codecs.BOM_UTF8 + CISCO_CFG.encode()
    loaded = load_file(write(tmp_path, "r1.cfg", raw))
    assert loaded.encoding == "utf-8-sig"
    assert loaded.content == CISCO_CFG
    assert loaded.size_bytes == len(raw)
    assert loaded.sha256 == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("bom, codec", [(codecs.BOM_UTF16_LE, "utf-16-le"), (codecs.BOM_UTF16_BE, "utf-16-be")])
def test_utf16_with_bom(tmp_path: Path, bom: bytes, codec: str) -> None:
    loaded = load_file(write(tmp_path, "r1.cfg", bom + CISCO_CFG.encode(codec)))
    assert loaded.encoding == "utf-16"
    assert loaded.content == CISCO_CFG
    assert loaded.vendor is CISCO


def test_line_endings_are_preserved_but_do_not_change_detection(tmp_path: Path) -> None:
    loaded = load_file(write(tmp_path, "r1.cfg", CISCO_CFG.replace("\n", "\r\n").encode()))
    assert "\r\n" in loaded.content
    assert loaded.detection == detect_vendor(CISCO_CFG)


def test_invalid_utf8_needs_an_explicit_encoding(tmp_path: Path) -> None:
    path = write(tmp_path, "r1.cfg", "hostname caf\u00e9\n!\ninterface Gi0/0\n".encode("cp1252"))
    with expect(LoadErrorCode.ENCODING):
        load_file(path)
    assert load_file(path, encoding="cp1252").content.startswith("hostname caf\u00e9")
    assert load_file(path, encoding="latin1").encoding == "iso8859-1"
    assert load_file(path, encoding=" Windows-1252 ").encoding == "cp1252"


def test_explicit_encodings_and_aliases(tmp_path: Path) -> None:
    path = write(tmp_path, "r1.cfg", CISCO_CFG.encode())
    assert load_file(path, encoding="UTF8").encoding == "utf-8"
    assert load_file(path, encoding="ascii").content == CISCO_CFG
    with expect(LoadErrorCode.ENCODING):
        load_file(write(tmp_path, "uni.cfg", "caf\u00e9".encode()), encoding="ascii")
    # an explicit utf-8 still drops a BOM character from the text
    bom_file = write(tmp_path, "bom.cfg", codecs.BOM_UTF8 + CISCO_CFG.encode())
    assert load_file(bom_file, encoding="utf-8").content == CISCO_CFG


@pytest.mark.parametrize("bom", [codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE])
def test_utf32_is_refused(tmp_path: Path, bom: bytes) -> None:
    with expect(LoadErrorCode.ENCODING) as caught:
        load_file(write(tmp_path, "r1.cfg", bom + b"\x00\x00\x00\x00"))
    assert "UTF-32" in str(caught.value)


def test_truncated_utf16_is_an_encoding_error(tmp_path: Path) -> None:
    with expect(LoadErrorCode.ENCODING):
        load_file(write(tmp_path, "r1.cfg", codecs.BOM_UTF16_LE + b"h"))


def test_nul_bytes_mean_binary(tmp_path: Path) -> None:
    with expect(LoadErrorCode.BINARY):
        load_file(write(tmp_path, "a.bin", b"hostname R1\x00\n"))
    with expect(LoadErrorCode.BINARY):  # UTF-16 without a BOM looks like NUL-laced UTF-8
        load_file(write(tmp_path, "b.cfg", CISCO_CFG.encode("utf-16-le")))


@pytest.mark.parametrize("data", [b"", b"  \n\t\n", codecs.BOM_UTF8, codecs.BOM_UTF16_LE])
def test_empty_files_are_rejected_unless_allowed(tmp_path: Path, data: bytes) -> None:
    path = write(tmp_path, "e.cfg", data)
    with expect(LoadErrorCode.EMPTY):
        load_file(path)
    loaded = load_file(path, allow_empty=True)
    assert loaded.content.strip() == "" and loaded.vendor is None
    assert loaded.size_bytes == len(data)


# ============================================================ size limits ====
def test_size_limit_is_inclusive(tmp_path: Path) -> None:
    data = (CISCO_CFG * 10)[:200].encode()
    path = write(tmp_path, "r1.cfg", data)
    assert load_file(path, max_bytes=200).size_bytes == 200
    with expect(LoadErrorCode.TOO_LARGE) as caught:
        load_file(path, max_bytes=199)
    assert "199-byte limit" in str(caught.value)


def test_default_and_hard_limits() -> None:
    assert DEFAULT_MAX_BYTES == 10 * 1024 * 1024
    assert HARD_MAX_BYTES == 256 * 1024 * 1024
    assert loader_module._clean_max_bytes(HARD_MAX_BYTES) == HARD_MAX_BYTES
    assert loader_module._clean_max_bytes(1) == 1


@pytest.mark.parametrize("value", [0, -1, HARD_MAX_BYTES + 1])
def test_max_bytes_range(tmp_path: Path, value: int) -> None:
    with pytest.raises(ValueError, match="max_bytes must be between"):
        load_file(write(tmp_path, "r1.cfg", b"x"), max_bytes=value)


@pytest.mark.parametrize("value", [True, "5", 1.5, None])
def test_max_bytes_type(tmp_path: Path, value: object) -> None:
    with pytest.raises(TypeError, match="max_bytes must be an int"):
        load_file(write(tmp_path, "r1.cfg", b"x"), max_bytes=value)  # type: ignore[arg-type]


def test_limit_is_enforced_while_reading_not_only_from_the_reported_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write(tmp_path, "big.cfg", b"x" * 5000)
    real_fstat = os.fstat

    def lying_fstat(fd: int) -> Any:
        real = real_fstat(fd)
        return types.SimpleNamespace(st_mode=real.st_mode, st_size=0)

    monkeypatch.setattr(os, "fstat", lying_fstat)
    with expect(LoadErrorCode.TOO_LARGE):
        load_file(path, max_bytes=100)


def test_a_file_that_stops_being_regular_before_it_is_read_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write(tmp_path, "swap.cfg", CISCO_CFG.encode())

    def now_a_fifo(fd: int) -> Any:
        return types.SimpleNamespace(st_mode=stat.S_IFIFO, st_size=0)

    monkeypatch.setattr(os, "fstat", now_a_fifo)
    with expect(LoadErrorCode.NOT_A_FILE):
        load_file(path)


# =========================================================== filesystem cases ====
def test_missing_file_and_missing_parent(tmp_path: Path) -> None:
    with expect(LoadErrorCode.NOT_FOUND) as caught:
        load_file(tmp_path / "missing.cfg")
    assert "'missing.cfg'" in str(caught.value)
    file_path = write(tmp_path, "plain.cfg", b"x")
    with expect(LoadErrorCode.NOT_FOUND):
        load_file(file_path / "child.cfg")


def test_directory_is_not_a_file(tmp_path: Path) -> None:
    with expect(LoadErrorCode.NOT_A_FILE):
        load_file(tmp_path)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are not available")
def test_fifo_is_rejected_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe.cfg"
    os.mkfifo(fifo)
    with expect(LoadErrorCode.NOT_A_FILE):
        load_file(fifo)


def test_symlinks_are_refused_unless_allowed(tmp_path: Path) -> None:
    target = write(tmp_path, "real.cfg", CISCO_CFG.encode())
    link = tmp_path / "link.cfg"
    symlink_or_skip(target, link)
    with expect(LoadErrorCode.SYMLINK):
        load_file(link)
    followed = load_file(link, follow_symlinks=True)
    assert followed.vendor is CISCO and followed.source_name == "link.cfg"


def test_followed_symlinks_still_must_reach_a_regular_file(tmp_path: Path) -> None:
    folder = tmp_path / "dir"
    folder.mkdir()
    to_dir = tmp_path / "to_dir"
    symlink_or_skip(folder, to_dir, is_dir=True)
    with expect(LoadErrorCode.NOT_A_FILE):
        load_file(to_dir, follow_symlinks=True)
    dangling = tmp_path / "dangling.cfg"
    symlink_or_skip(tmp_path / "nowhere.cfg", dangling)
    with expect(LoadErrorCode.NOT_FOUND):
        load_file(dangling, follow_symlinks=True)


def test_os_errors_become_io_errors_with_the_cause_kept(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = write(tmp_path, "r1.cfg", CISCO_CFG.encode())
    real_lstat = os.lstat

    def denied(p: Any, *args: Any, **kwargs: Any) -> Any:
        if str(p) == str(path):
            raise PermissionError(13, "Permission denied")
        return real_lstat(p, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", denied)
    with expect(LoadErrorCode.IO) as caught:
        load_file(path)
    assert isinstance(caught.value.__cause__, PermissionError)
    assert "Permission denied" in str(caught.value)
    assert str(tmp_path) not in str(caught.value)

    def bare(p: Any, *args: Any, **kwargs: Any) -> Any:
        raise OSError()

    monkeypatch.setattr(os, "lstat", bare)
    with expect(LoadErrorCode.IO) as bare_caught:
        load_file(path)
    assert "I/O error" in str(bare_caught.value)


# ======================================================== argument validation ====
class BytesPath:
    def __fspath__(self) -> bytes:
        return b"/tmp/x"


@pytest.mark.parametrize("bad", [None, 5, b"/tmp/x", ["a"], BytesPath()])
def test_path_type(bad: object) -> None:
    with pytest.raises(TypeError, match="path must be a str or PathLike"):
        load_file(bad)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad, message", [("", "must not be empty"), ("   ", "must not be empty"), ("a\x00b", "NUL")])
def test_path_value(bad: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        load_file(bad)


@pytest.mark.parametrize("bad", ["rot13", "base64", "zlib", "nonexistent", "utf-32", "", "utf-7"])
def test_unsupported_encodings_are_refused_before_reading(bad: str) -> None:
    with pytest.raises(ValueError, match="unsupported encoding; expected one of"):
        load_file("/definitely/missing", encoding=bad)


def test_encoding_type_and_allowed_set() -> None:
    with pytest.raises(TypeError, match="encoding must be a str"):
        load_file("x", encoding=5)  # type: ignore[arg-type]
    assert "utf-8" in ALLOWED_ENCODINGS and "rot-13" not in ALLOWED_ENCODINGS
    assert all(name == codecs.lookup(name).name for name in ALLOWED_ENCODINGS)


@pytest.mark.parametrize("kwargs", [{"follow_symlinks": 1}, {"allow_empty": "yes"}])
def test_flags_must_be_bools(kwargs: dict[str, Any]) -> None:
    with pytest.raises(TypeError, match="must be a bool"):
        load_file("x", **kwargs)


@pytest.mark.parametrize(
    ("name", "exc", "message"),
    [
        ("", ValueError, "must not be empty"),
        ("  ", ValueError, "must not be empty"),
        ("a\nb", ValueError, "control or invisible"),
        ("a\u200bb", ValueError, "control or invisible"),
        ("x" * 256, ValueError, "at most 255"),
        (5, TypeError, "must be a str"),
    ],
)
def test_source_name_validation(tmp_path: Path, name: object, exc: type[Exception], message: str) -> None:
    path = write(tmp_path, "r1.cfg", CISCO_CFG.encode())
    with pytest.raises(exc, match=message):
        load_file(path, source_name=name)  # type: ignore[arg-type]


def test_errors_never_leak_directories_or_content(tmp_path: Path) -> None:
    cases: list[tuple[Path, dict[str, Any]]] = [
        (write(tmp_path, "secret.cfg", SECRET_CFG.encode() + b"\x00"), {}),
        (write(tmp_path, "big.cfg", SECRET_CFG.encode()), {"max_bytes": 10}),
        (write(tmp_path, "bad.cfg", SECRET_CFG.encode() + b"\xff"), {}),
        (tmp_path / "missing.cfg", {}),
    ]
    for path, kwargs in cases:
        with pytest.raises(LoadError) as info:
            load_file(path, **kwargs)
        assert "hunter2" not in str(info.value)
        assert str(tmp_path) not in str(info.value)


# ================================================================= load_text ====
def test_load_text_basics() -> None:
    loaded = load_text(CISCO_CFG, source_name="r1.cfg")
    raw = CISCO_CFG.encode()
    assert (loaded.source_name, loaded.encoding, loaded.size_bytes) == ("r1.cfg", "utf-8", len(raw))
    assert loaded.sha256 == hashlib.sha256(raw).hexdigest()
    assert loaded.vendor is CISCO and loaded.content == CISCO_CFG
    assert load_text(CISCO_CFG).source_name is None


def test_load_text_drops_a_bom_character_and_counts_utf8_bytes() -> None:
    assert load_text("\ufeff" + CISCO_CFG).content == CISCO_CFG
    assert load_text("caf\u00e9 hostname").size_bytes == len("caf\u00e9 hostname".encode())


def test_load_text_limits_and_errors() -> None:
    with expect(LoadErrorCode.TOO_LARGE):
        load_text("\u00e9" * 100, max_bytes=199)
    assert load_text("\u00e9" * 100, max_bytes=200).size_bytes == 200
    with expect(LoadErrorCode.BINARY):
        load_text("hostname R1\x00")
    with expect(LoadErrorCode.EMPTY):
        load_text("  \n ")
    assert load_text("", allow_empty=True).content == ""
    with expect(LoadErrorCode.ENCODING):
        load_text("bad \ud800 text")


def test_load_text_argument_validation() -> None:
    for bad in (None, b"hostname R1", 5):
        with pytest.raises(TypeError, match="content must be a str"):
            load_text(bad)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="max_bytes"):
        load_text("x", max_bytes=0)
    with pytest.raises(TypeError, match="allow_empty must be a bool"):
        load_text("x", allow_empty=1)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="source_name must not be empty"):
        load_text("x", source_name=" ")


def test_load_file_and_load_text_agree(tmp_path: Path) -> None:
    from_file = load_file(write(tmp_path, "r1.cfg", CISCO_CFG.encode()), source_name="n")
    assert from_file == load_text(CISCO_CFG, source_name="n")


# ============================================================== result model ====
def good() -> LoadedConfig:
    return load_text(CISCO_CFG, source_name="r1.cfg")


@pytest.mark.parametrize(
    ("overrides", "exc", "message"),
    [
        ({"source_name": ""}, ValueError, "source_name must not be empty"),
        ({"content": 5}, TypeError, "content must be a str"),
        ({"encoding": "rot-13"}, ValueError, "encoding must be one of"),
        ({"size_bytes": -1}, ValueError, "size_bytes must be >= 0"),
        ({"size_bytes": True}, TypeError, "size_bytes must be an int"),
        ({"size_bytes": 1.5}, TypeError, "size_bytes must be an int"),
        ({"sha256": "ABC"}, ValueError, "sha256 must be 64 lowercase hex"),
        ({"sha256": "A" * 64}, ValueError, "sha256 must be 64 lowercase hex"),
        ({"sha256": 5}, ValueError, "sha256 must be 64 lowercase hex"),
        ({"detection": "cisco"}, TypeError, "detection must be a Detection"),
    ],
)
def test_loaded_config_validation(overrides: dict[str, Any], exc: type[Exception], message: str) -> None:
    with pytest.raises(exc, match=message):
        dataclasses.replace(good(), **overrides)


def test_loaded_config_hides_and_ignores_content() -> None:
    loaded = load_text(SECRET_CFG, source_name="r1.cfg")
    assert "hunter2" not in repr(loaded)
    assert dataclasses.replace(loaded, content="other text") == loaded  # sha256 identifies the text
    assert isinstance(hash(loaded), int)
    assert loaded.detection.vendor is loaded.vendor


def test_loaded_config_is_frozen_and_slotted() -> None:
    loaded = good()
    with pytest.raises(dataclasses.FrozenInstanceError):
        loaded.content = "x"  # type: ignore[misc]
    assert not hasattr(loaded, "__dict__")
    assert isinstance(loaded.detection, Detection)


def test_load_error_carries_its_code() -> None:
    error = LoadError(LoadErrorCode.EMPTY, "nothing here")
    assert error.code is LoadErrorCode.EMPTY and str(error) == "nothing here"
    assert [c.value for c in LoadErrorCode] == [
        "not_found", "not_a_file", "symlink", "too_large", "empty", "encoding", "binary", "io",
    ]


def test_module_scope() -> None:
    assert set(loader_module.__all__) == {
        "DEFAULT_MAX_BYTES", "HARD_MAX_BYTES", "ALLOWED_ENCODINGS", "LoadErrorCode", "LoadError",
        "LoadedConfig", "load_file", "load_text",
    }


# ================================================================ pipeline ====
def test_end_to_end_with_tokenizers_and_normalizer(tmp_path: Path) -> None:
    cisco = load_file(write(tmp_path, "r1.cfg", CISCO_CFG.encode()))
    assert cisco.vendor is CISCO
    baseline = normalize(tokenize_indented(cisco.content, source_file=cisco.source_name), cisco.vendor)
    assert baseline.hostname is not None and baseline.hostname.evidence.source_file == "r1.cfg"

    forti = load_file(write(tmp_path, "fw.conf", FORTI_CFG.encode()))
    assert forti.vendor is FORTI
    fortinet = normalize(tokenize_fortinet(forti.content, source_file=forti.source_name), forti.vendor)
    assert fortinet.hostname is not None and fortinet.hostname.evidence.source_file == "fw.conf"


# ================================================================= fuzzing ====
PIECES = [
    b"hostname R1\n", b"!\n", b"interface Gi0/0\n", b"config system global\n", b"\x00", b"\xff", b"\xef\xbb\xbf",
    b"\xff\xfe", b"\xfe\xff", b"\n", b"  ", "\u00e9".encode(), b"\r\n", b"\xed\xa0\x80", b"set a b c\n",
]


def test_fuzz_files_only_raise_load_errors_and_hold_invariants(tmp_path: Path) -> None:
    rng = random.Random(97531)
    path = tmp_path / "fuzz.cfg"
    loaded_count = 0
    for _ in range(1200):
        data = b"".join(rng.choice(PIECES) for _ in range(rng.randint(0, 12)))
        path.write_bytes(data)
        kwargs: dict[str, Any] = {}
        if rng.random() < 0.3:
            kwargs["encoding"] = rng.choice(sorted(ALLOWED_ENCODINGS))
        if rng.random() < 0.2:
            kwargs["allow_empty"] = True
        if rng.random() < 0.2:
            kwargs["max_bytes"] = rng.randint(1, 40)
        try:
            loaded = load_file(path, **kwargs)
        except LoadError:
            continue
        loaded_count += 1
        assert loaded.sha256 == hashlib.sha256(data).hexdigest()
        assert loaded.size_bytes == len(data) <= kwargs.get("max_bytes", DEFAULT_MAX_BYTES)
        assert "\x00" not in loaded.content and not loaded.content.startswith("\ufeff")
        assert loaded.encoding in ALLOWED_ENCODINGS
        assert loaded.detection == detect_vendor(loaded.content)
    assert loaded_count > 50


def test_fuzz_text_only_raises_load_errors() -> None:
    rng = random.Random(24680)
    pool = ["hostname R1\n", "!\n", "\x00", "\ufeff", "\ud800", "\u00e9", " ", "\n", "config system global\n"]
    ok = 0
    for _ in range(1500):
        text = "".join(rng.choice(pool) for _ in range(rng.randint(0, 10)))
        try:
            loaded = load_text(text, max_bytes=rng.choice([20, 1000]), allow_empty=rng.random() < 0.3)
        except LoadError:
            continue
        ok += 1
        assert "\x00" not in loaded.content and loaded.size_bytes == len(text.encode())
    assert ok > 50


# ============================================================ performance ====
# Regression guard against accidental O(n^2) behaviour, NOT a benchmark.
def test_a_multi_megabyte_file_loads_quickly(tmp_path: Path) -> None:
    data = (CISCO_CFG * 200_000).encode()  # ~7.6 MiB, ~800k lines
    assert len(data) < DEFAULT_MAX_BYTES
    path = write(tmp_path, "big.cfg", data)
    start = time.perf_counter()
    loaded = load_file(path)
    assert time.perf_counter() - start < 10
    assert loaded.vendor is CISCO and loaded.size_bytes == len(data)