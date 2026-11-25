from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from auditor.parsers import normalizer as parsed
from auditor.schema.baseline import SecurityBaseline
from auditor.training.patterns import PatternRule

from .adapter import to_schema_baseline
from .generic import build_generic_baseline
from .trained import build_trained_baseline
from .service import AuditOutcome, RuleSet, run_device_audit
from .upload import MAX_UPLOAD_BYTES, UploadedConfig, UploadError, read_config_upload

logger = logging.getLogger(__name__)

Tokenizer = Callable[[str, str | None], Sequence[Any]]
Normalizer = Callable[[Sequence[Any], parsed.Vendor], parsed.SecurityBaseline]
Detector = Callable[[str], parsed.Vendor | None]

GENERIC_PARSER: Final = "generic"
TRAINED_PARSER: Final = "trained"

_NO_PARSER_MESSAGE = (
    "No built-in parser is available for the selected vendor. Choose another vendor, use the generic parser, "
    "or use the Training page to teach the system this vendor's format."
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
    vendor: parsed.Vendor | None
    upload: UploadedConfig
    vendor_detected: bool
    parser: str = "builtin"
    completeness: tuple[int, int] | None = None
    rules_matched: tuple[int, int] | None = None


@dataclass(frozen=True)
class UploadAudit:
    outcome: AuditOutcome
    parse: ParseResult


def default_detector(text: str) -> parsed.Vendor | None:
    from auditor.ingestion.junos_detector import detect_vendor_with_junos

    return detect_vendor_with_junos(text)


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


def _parse_generic(upload: UploadedConfig) -> ParseResult:
    result = build_generic_baseline(upload.text, filename=upload.filename, sha256=upload.sha256)
    return ParseResult(
        baseline=result.baseline,
        vendor=None,
        upload=upload,
        vendor_detected=False,
        parser=GENERIC_PARSER,
        completeness=(len(result.mapped), result.total_basics),
    )


def _parse_trained(upload: UploadedConfig, vendor: parsed.Vendor, rules: Sequence[PatternRule]) -> ParseResult:
    try:
        result = build_trained_baseline(
            upload.text, rules, vendor, filename=upload.filename, sha256=upload.sha256
        )
    except ValueError as exc:
        logger.warning("trained parse failed for vendor %s: %s", vendor.value, type(exc).__name__)
        raise ConfigInputError("The file could not be parsed with the trained rules.") from exc
    return ParseResult(
        baseline=result.baseline,
        vendor=vendor,
        upload=upload,
        vendor_detected=False,
        parser=TRAINED_PARSER,
        completeness=(len(result.mapped), result.total_basics),
        rules_matched=(result.rules_matched, result.rules_total),
    )


def parse_config_upload(
    data: bytes,
    filename: str | None = None,
    *,
    vendor: parsed.Vendor | str | None = None,
    backends: Backends | None = None,
    max_bytes: int = MAX_UPLOAD_BYTES,
    trained_rules: Sequence[PatternRule] | None = None,
) -> ParseResult:
    try:
        upload = read_config_upload(data, filename, max_bytes=max_bytes)
    except UploadError as exc:
        raise ConfigInputError(str(exc)) from exc

    if vendor == GENERIC_PARSER:
        return _parse_generic(upload)

    active = backends or default_backends()
    auto_detected = vendor is None
    chosen = vendor or (active.detect or default_detector)(upload.text)
    if chosen is None:
        return _parse_generic(upload)
    if not isinstance(chosen, parsed.Vendor):
        raise ConfigInputError("Unknown vendor selection.")

    tokenizer = active.tokenizers.get(chosen)
    if tokenizer is None:
        usable = [rule for rule in trained_rules or () if isinstance(rule, PatternRule) and rule.vendor is chosen]
        if usable:
            return _parse_trained(upload, chosen, usable)
        if auto_detected and chosen is parsed.Vendor.JUNOS:
            return _parse_generic(upload)
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
    vendor: parsed.Vendor | str | None = None,
    frameworks: Iterable[str] | None = None,
    database: Path | str | None = None,
    backends: Backends | None = None,
    max_bytes: int = MAX_UPLOAD_BYTES,
    trained_rules: Sequence[PatternRule] | None = None,
) -> UploadAudit:
    parse = parse_config_upload(
        data, filename, vendor=vendor, backends=backends, max_bytes=max_bytes, trained_rules=trained_rules
    )
    outcome = run_device_audit(parse.baseline, rules, frameworks, database)
    return UploadAudit(outcome=outcome, parse=parse)
