"""
Safe loading of configuration files for the ingestion pipeline.

:func:`load_file` reads a configuration file from disk and :func:`load_text`
accepts text that is already in memory (for example an upload). Both return a
:class:`LoadedConfig`: the decoded text, its provenance (source name, encoding,
size, SHA-256 of the original bytes) and the vendor detection from
:mod:`auditor.ingestion.detector`. Tokenizing and everything after it belong
elsewhere; pass ``loaded.source_name`` as the tokenizers' ``source_file`` so
evidence points back at the file.

Error model:
    - Bad ARGUMENTS (wrong types, invalid limits, unsupported encodings, bad
      names) raise ``TypeError`` or ``ValueError``.
    - Problems with the FILE or its DATA raise :class:`LoadError`, whose
      ``code`` (a :class:`LoadErrorCode`) says what happened: not found, not a
      regular file, symlink, too large, empty, undecodable, binary, or I/O.
    - Messages never contain file content or directory names, only the file
      name, so a failure cannot leak configuration text or a user's path.

Safety rules:
    - Only regular files are read; a FIFO or device is rejected before it can
      block. Symlinks are refused unless ``follow_symlinks=True``.
    - The size limit (default 10 MiB, never above ``HARD_MAX_BYTES``) is
      checked on the OPEN file and enforced again while reading, so a file
      that grows after the check, or reports a wrong size, still cannot exceed
      it.
    - Decoding is explicit, never guessed: a UTF-8, UTF-16 LE or UTF-16 BE BOM
      is honored; without a BOM the file must be valid UTF-8 unless a
      whitelisted ``encoding`` is passed. UTF-32 is refused. Text containing
      NUL is rejected as binary (this also catches UTF-16 without a BOM).
    - ``LoadedConfig`` keeps the text out of ``repr`` and out of equality and
      hashing (the SHA-256 identifies it), so logging or comparing a result
      neither prints secrets nor hashes megabytes.

Known limitations:
    - Symlink and regular-file checks happen before opening, and the open file
      is re-checked, but a path swapped by another process between the two is
      not fully preventable with portable code.
    - Line endings are preserved as read; the tokenizers normalize them.
    - Terminal escape sequences and other non-NUL control characters are not
      rejected.

Example:
    >>> loaded = load_text("hostname R1\\n!\\ninterface Gi0/0\\n shutdown\\n", source_name="r1.cfg")
    >>> loaded.vendor
    <Vendor.CISCO_IOS: 'cisco_ios'>
    >>> (loaded.source_name, loaded.encoding, loaded.size_bytes)
    ('r1.cfg', 'utf-8', 40)
"""

from __future__ import annotations

import codecs
import hashlib
import os
import re
import stat
import unicodedata
from dataclasses import dataclass, field
from enum import StrEnum

from auditor.ingestion.detector import Detection, detect_vendor
from auditor.parsers.normalizer import Vendor

__all__ = [
    "DEFAULT_MAX_BYTES",
    "HARD_MAX_BYTES",
    "ALLOWED_ENCODINGS",
    "LoadErrorCode",
    "LoadError",
    "LoadedConfig",
    "load_file",
    "load_text",
]

DEFAULT_MAX_BYTES = 10 * 1024 * 1024
HARD_MAX_BYTES = 256 * 1024 * 1024
MAX_NAME_LENGTH = 255

# Canonical codec names (``codecs.lookup(name).name``) that may be requested.
ALLOWED_ENCODINGS: frozenset[str] = frozenset(
    {"utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "ascii", "iso8859-1", "cp1252"}
)

_SHA256 = re.compile(r"[0-9a-f]{64}")


class LoadErrorCode(StrEnum):
    """Why a file or text could not be loaded."""

    NOT_FOUND = "not_found"
    NOT_A_FILE = "not_a_file"
    SYMLINK = "symlink"
    TOO_LARGE = "too_large"
    EMPTY = "empty"
    ENCODING = "encoding"
    BINARY = "binary"
    IO = "io"


class LoadError(Exception):
    """The file or its data cannot be loaded.

    Attributes:
        code: The reason, for programmatic handling.
    """

    def __init__(self, code: LoadErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code


# --------------------------------------------------------------------------
# Argument validation
# --------------------------------------------------------------------------


def _require_bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{name} must be a bool, got {type(value).__name__}")
    return value


def _clean_max_bytes(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"max_bytes must be an int, got {type(value).__name__}")
    if not 1 <= value <= HARD_MAX_BYTES:
        raise ValueError(f"max_bytes must be between 1 and {HARD_MAX_BYTES}")
    return value


def _clean_encoding(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"encoding must be a str, got {type(value).__name__}")
    try:
        canonical = codecs.lookup(value.strip()).name
    except LookupError:
        canonical = ""
    if canonical not in ALLOWED_ENCODINGS:
        allowed = ", ".join(sorted(ALLOWED_ENCODINGS))
        raise ValueError(f"unsupported encoding; expected one of: {allowed}")
    return canonical


def _clean_source_name(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"source_name must be a str, got {type(value).__name__}")
    text = unicodedata.normalize("NFC", value).strip()
    if not text:
        raise ValueError("source_name must not be empty")
    if len(text) > MAX_NAME_LENGTH:
        raise ValueError(f"source_name must be at most {MAX_NAME_LENGTH} characters")
    if any(unicodedata.category(ch).startswith("C") for ch in text):
        raise ValueError("source_name must not contain control or invisible characters")
    return text


def _clean_path(value: object) -> str:
    if not isinstance(value, (str, os.PathLike)):
        raise TypeError(f"path must be a str or PathLike, got {type(value).__name__}")
    location = os.fspath(value)
    if not isinstance(location, str):
        raise TypeError("path must be a str or PathLike[str], not bytes")
    if not location.strip():
        raise ValueError("path must not be empty")
    if "\x00" in location:
        raise ValueError("path must not contain NUL characters")
    return location


# --------------------------------------------------------------------------
# Result model
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LoadedConfig:
    """A decoded configuration with its provenance and vendor detection.

    Attributes:
        source_name: File name (never a directory) to pass to the tokenizers
            as ``source_file``; None when the text had no name.
        content: The decoded text. Excluded from ``repr``, equality and
            hashing; ``sha256`` identifies it.
        encoding: Canonical codec used to decode.
        size_bytes: Size of the original bytes.
        sha256: Hex SHA-256 of the original bytes (UTF-8 bytes for
            ``load_text``).
        detection: Vendor detection for ``content``.
    """

    source_name: str | None
    content: str = field(repr=False, compare=False)
    encoding: str
    size_bytes: int
    sha256: str
    detection: Detection

    def __post_init__(self) -> None:
        if self.source_name is not None:
            object.__setattr__(self, "source_name", _clean_source_name(self.source_name))
        if not isinstance(self.content, str):
            raise TypeError(f"content must be a str, got {type(self.content).__name__}")
        if self.encoding not in ALLOWED_ENCODINGS:
            raise ValueError("encoding must be one of the allowed canonical encodings")
        if isinstance(self.size_bytes, bool) or not isinstance(self.size_bytes, int):
            raise TypeError("size_bytes must be an int")
        if self.size_bytes < 0:
            raise ValueError("size_bytes must be >= 0")
        if not isinstance(self.sha256, str) or _SHA256.fullmatch(self.sha256) is None:
            raise ValueError("sha256 must be 64 lowercase hex characters")
        if not isinstance(self.detection, Detection):
            raise TypeError("detection must be a Detection")

    @property
    def vendor(self) -> Vendor | None:
        """The detected vendor, or None when unknown or ambiguous."""

        return self.detection.vendor


# --------------------------------------------------------------------------
# Reading and decoding
# --------------------------------------------------------------------------


def _read_regular_file(location: str, limit: int, follow_symlinks: bool, name: str) -> bytes:
    """Read at most ``limit`` bytes from a regular file, or raise LoadError."""

    try:
        link_info = os.lstat(location)
        if stat.S_ISLNK(link_info.st_mode):
            if not follow_symlinks:
                raise LoadError(LoadErrorCode.SYMLINK, f"{name} is a symbolic link; pass follow_symlinks=True to allow it")
            target_info = os.stat(location)
        else:
            target_info = link_info
        if not stat.S_ISREG(target_info.st_mode):
            raise LoadError(LoadErrorCode.NOT_A_FILE, f"{name} is not a regular file")

        with open(location, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise LoadError(LoadErrorCode.NOT_A_FILE, f"{name} is not a regular file")
            if opened.st_size > limit:
                raise LoadError(LoadErrorCode.TOO_LARGE, f"{name} is larger than the {limit}-byte limit")
            data = handle.read(limit + 1)
    except (FileNotFoundError, NotADirectoryError) as exc:
        raise LoadError(LoadErrorCode.NOT_FOUND, f"{name} was not found") from exc
    except IsADirectoryError as exc:
        raise LoadError(LoadErrorCode.NOT_A_FILE, f"{name} is not a regular file") from exc
    except OSError as exc:
        raise LoadError(LoadErrorCode.IO, f"could not read {name}: {exc.strerror or 'I/O error'}") from exc

    if len(data) > limit:
        raise LoadError(LoadErrorCode.TOO_LARGE, f"{name} is larger than the {limit}-byte limit")
    return data


def _decode(data: bytes, encoding: str | None, name: str) -> tuple[str, str]:
    """Decode bytes to text, returning the text and the canonical codec used."""

    if encoding is not None:
        codec = encoding
    elif data.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        raise LoadError(LoadErrorCode.ENCODING, f"{name} is UTF-32, which is not supported")
    elif data.startswith(codecs.BOM_UTF8):
        codec = "utf-8-sig"
    elif data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        codec = "utf-16"
    else:
        codec = "utf-8"

    try:
        return data.decode(codec), codec
    except UnicodeDecodeError:
        raise LoadError(
            LoadErrorCode.ENCODING,
            f"{name} is not valid {codec}; pass encoding= to choose another",
        ) from None


def _build(text: str, raw: bytes, codec: str, source_name: str | None, allow_empty: bool, name: str) -> LoadedConfig:
    if text.startswith("\ufeff"):
        text = text[1:]
    if "\x00" in text:
        raise LoadError(
            LoadErrorCode.BINARY,
            f"{name} contains NUL characters (binary data, or UTF-16 without a BOM)",
        )
    if not allow_empty and (not text or text.isspace()):
        raise LoadError(LoadErrorCode.EMPTY, f"{name} is empty")
    return LoadedConfig(
        source_name=source_name,
        content=text,
        encoding=codec,
        size_bytes=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(),
        detection=detect_vendor(text),
    )


def load_file(
    path: str | os.PathLike[str],
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    encoding: str | None = None,
    follow_symlinks: bool = False,
    allow_empty: bool = False,
    source_name: str | None = None,
) -> LoadedConfig:
    """Read, decode and detect a configuration file.

    Args:
        path: File to load.
        max_bytes: Largest file accepted, 1 to ``HARD_MAX_BYTES``.
        encoding: Force a decoding (one of ``ALLOWED_ENCODINGS``, aliases
            accepted); by default a BOM is honored and otherwise UTF-8 is
            required.
        follow_symlinks: Allow ``path`` to be a symbolic link.
        allow_empty: Accept an empty or whitespace-only file.
        source_name: Name recorded as the source; defaults to the file name.

    Returns:
        The loaded configuration.

    Raises:
        TypeError: If an argument has the wrong type.
        ValueError: If an argument is invalid (empty path, bad limit,
            unsupported encoding, bad name).
        LoadError: If the file cannot be read or decoded (see
            :class:`LoadErrorCode`).
    """

    location = _clean_path(path)
    limit = _clean_max_bytes(max_bytes)
    codec = None if encoding is None else _clean_encoding(encoding)
    follow = _require_bool(follow_symlinks, "follow_symlinks")
    empty_ok = _require_bool(allow_empty, "allow_empty")
    base = os.path.basename(location)
    recorded = _clean_source_name(source_name if source_name is not None else base)
    name = repr(base or location)

    raw = _read_regular_file(location, limit, follow, name)
    text, used = _decode(raw, codec, name)
    return _build(text, raw, used, recorded, empty_ok, name)


def load_text(
    content: str,
    *,
    source_name: str | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    allow_empty: bool = False,
) -> LoadedConfig:
    """Wrap configuration text that is already in memory.

    The same size, NUL and emptiness rules as :func:`load_file` apply; the
    size is measured as UTF-8 bytes.

    Args:
        content: The configuration text.
        source_name: Optional name to record.
        max_bytes: Largest size accepted, 1 to ``HARD_MAX_BYTES``.
        allow_empty: Accept empty or whitespace-only text.

    Raises:
        TypeError: If an argument has the wrong type.
        ValueError: If an argument is invalid.
        LoadError: If the text is too large, empty, binary or cannot be
            encoded as UTF-8.
    """

    if not isinstance(content, str):
        raise TypeError(f"content must be a str, got {type(content).__name__}")
    limit = _clean_max_bytes(max_bytes)
    empty_ok = _require_bool(allow_empty, "allow_empty")
    recorded = None if source_name is None else _clean_source_name(source_name)

    try:
        raw = content.encode("utf-8")
    except UnicodeEncodeError:
        raise LoadError(LoadErrorCode.ENCODING, "the text contains characters that cannot be encoded as UTF-8") from None
    if len(raw) > limit:
        raise LoadError(LoadErrorCode.TOO_LARGE, f"the text is larger than the {limit}-byte limit")
    return _build(content, raw, "utf-8", recorded, empty_ok, "the text")


if __name__ == "__main__":
    import doctest

    doctest.testmod()