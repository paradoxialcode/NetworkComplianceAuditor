from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from auditor.parsers import normalizer as parsed
from auditor.schema.baseline import SecurityBaseline

from .adapter import to_schema_baseline
from .service import AuditOutcome, RuleSet, run_device_audit
from .upload import MAX_UPLOAD_BYTES, UploadedConfig, UploadError, read_config_upload

logger = logging.getLogger(__name__)

Tokenizer = Callable[[str, str | None], Sequence[Any]]
Normalizer = Callable[[Sequence[Any], parsed.Vendor], parsed.SecurityBaseline]
Detector = Callable[[str], parsed.Vendor | None]

_NO_PARSER_MESSAGE = (
    "No built-in parser matches this file. Choose a supported vendor, or use the Training page "
    "to teach the system this vendor's format."
)


class ConfigInputError(ValueError):
    pass


class UnsupportedVendorError(ConfigInputError):
    pass


@dataclass(frozen=True)
class Backends:
    tokenizers: Mapping[parsed.Vendor, Tokenizer]
    normalize: Normalizer
    detect: Detector | None = None


@dataclass(frozen=True)
class ParseResult:
    baseline: SecurityBaseline
    vendor: parsed.Vendor
    upload: UploadedConfig
    vendor_detected: bool


@dataclass(frozen=True)
class UploadAudit:
    outcome: AuditOutcome
    parse: ParseResult


def default_detector(text: str) -> parsed.Vendor | None:
    from auditor.ingestion.detector import detect_vendor

    return detect_vendor(text).vendor


def default_backends() -> Backends:
    from auditor.parsers.normalizer import normalize
    from auditor.parsers.tokenizers.fortinet import tokenize_fortinet
    from auditor.parsers.tokenizers.indented import tokenize_indented

    return Backends(
        tokenizers={
            parsed.Vendor.CISCO_IOS: lambda text, name: tokenize_indented(text, source_file=name),
            parsed.Vendor.FORTIOS: lambda text, name: tokenize_fortinet(text, source_file=name),
        },
        normalize=normalize,
        detect=default_detector,
    )


def parse_config_upload(
    data: bytes,
    filename: str | None = None,
    *,
    vendor: parsed.Vendor | None = None,
    backends: Backends | None = None,
    max_bytes: int = MAX_UPLOAD_BYTES,
) -> ParseResult:
    try:
        upload = read_config_upload(data, filename, max_bytes=max_bytes)
    except UploadError as exc:
        raise ConfigInputError(str(exc)) from exc

    active = backends or default_backends()
    chosen = vendor or (active.detect or default_detector)(upload.text)
    if chosen is None:
        raise UnsupportedVendorError(_NO_PARSER_MESSAGE)

    tokenizer = active.tokenizers.get(chosen)
    if tokenizer is None:
        raise UnsupportedVendorError(_NO_PARSER_MESSAGE)

    try:
        tokens = tokenizer(upload.text, upload.filename)
        result = active.normalize(tokens, chosen)
    except ValueError as exc:
        logger.warning("config parse failed for vendor %s: %s", chosen.value, type(exc).__name__)
        raise ConfigInputError(f"The file could not be parsed as {chosen.value}. Check that it is a complete export.") from exc

    baseline = to_schema_baseline(result, filename=upload.filename, sha256=upload.sha256)
    return ParseResult(baseline=baseline, vendor=chosen, upload=upload, vendor_detected=vendor is None)


def audit_config_upload(
    data: bytes,
    filename: str | None,
    rules: RuleSet,
    *,
    vendor: parsed.Vendor | None = None,
    frameworks: Iterable[str] | None = None,
    database: Path | str | None = None,
    backends: Backends | None = None,
    max_bytes: int = MAX_UPLOAD_BYTES,
) -> UploadAudit:
    parse = parse_config_upload(data, filename, vendor=vendor, backends=backends, max_bytes=max_bytes)
    outcome = run_device_audit(parse.baseline, rules, frameworks, database)
    return UploadAudit(outcome=outcome, parse=parse)
