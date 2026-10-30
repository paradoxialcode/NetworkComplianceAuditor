from __future__ import annotations

import codecs
import hashlib
import re
from dataclasses import dataclass
from pathlib import PurePath
from typing import Final

MAX_UPLOAD_BYTES: Final = 5 * 1024 * 1024
MAX_LINES: Final = 100_000
MAX_LINE_LENGTH: Final = 10_000
DEFAULT_FILENAME: Final = "uploaded-config.txt"
_MAX_FILENAME_LEN: Final = 100
_CONTROL: Final = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_ANY_CONTROL: Final = re.compile(r"[\x00-\x1f\x7f]")
_FILENAME_UNSAFE: Final = re.compile(r"[^A-Za-z0-9._ -]+")

class UploadError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class UploadedConfig:
    text: str
    filename: str
    sha256: str
    size: int
    lossy: bool


def safe_filename(name: str | None) -> str:
    if not isinstance(name, str):
        return DEFAULT_FILENAME
    base = PurePath(name.replace("\\", "/")).name
    cleaned = _FILENAME_UNSAFE.sub("_", _ANY_CONTROL.sub("", base)).strip(" .")
    return cleaned[:_MAX_FILENAME_LEN] or DEFAULT_FILENAME


def _decode(data: bytes) -> tuple[str, bool]:
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        try:
            return data.decode("utf-16"), False
        except UnicodeDecodeError as exc:
            raise UploadError("file looks like UTF-16 but could not be decoded") from exc
    try:
        return data.decode("utf-8-sig"), False
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace"), True


def read_config_upload(
    data: bytes,
    filename: str | None = None,
    *,
    max_bytes: int = MAX_UPLOAD_BYTES,
) -> UploadedConfig:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"data must be bytes, got {type(data).__name__}")
    raw = bytes(data)
    if not raw.strip():
        raise UploadError("the file is empty")
    if len(raw) > max_bytes:
        raise UploadError(f"the file is larger than the {max_bytes // (1024 * 1024)} MB limit")

    text, lossy = _decode(raw)
    if "\x00" in text:
        raise UploadError("the file looks binary, not a text configuration")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _CONTROL.sub("", text)

    lines = text.split("\n")
    if len(lines) > MAX_LINES:
        raise UploadError(f"the file has more than {MAX_LINES} lines")
    for number, line in enumerate(lines, start=1):
        if len(line) > MAX_LINE_LENGTH:
            raise UploadError(f"line {number} is longer than {MAX_LINE_LENGTH} characters")

    return UploadedConfig(
        text=text,
        filename=safe_filename(filename),
        sha256=hashlib.sha256(raw).hexdigest(),
        size=len(raw),
        lossy=lossy,
    )
