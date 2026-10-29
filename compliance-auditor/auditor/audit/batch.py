from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from auditor.parsers import normalizer as parsed
from auditor.reporting.pdf_builder import build_report_bytes

from .pipeline import (
    Backends,
    ConfigInputError,
    UnsupportedVendorError,
    UploadAudit,
    audit_config_upload,
)
from .service import AuditError, RuleSet
from .store import persist_report
from .upload import MAX_UPLOAD_BYTES, safe_filename

logger = logging.getLogger(__name__)

MAX_FILES_PER_BATCH = 20


@dataclass(frozen=True)
class BatchItem:
    filename: str
    audit: UploadAudit | None = None
    pdf: bytes | None = None
    error: str | None = None
    needs_training: bool = False


def _audit_one(
    name: str,
    data: bytes,
    rules: RuleSet,
    database: Path | str,
    vendor: parsed.Vendor | None,
    frameworks: list[str] | None,
    backends: Backends | None,
    max_bytes: int,
) -> BatchItem:
    display = safe_filename(name)
    try:
        result = audit_config_upload(
            data,
            name,
            rules,
            vendor=vendor,
            frameworks=frameworks,
            database=database,
            backends=backends,
            max_bytes=max_bytes,
        )
    except UnsupportedVendorError as exc:
        return BatchItem(filename=display, error=str(exc), needs_training=True)
    except (ConfigInputError, AuditError) as exc:
        return BatchItem(filename=display, error=str(exc))
    except Exception as exc:
        logger.error("unexpected audit failure: %s", type(exc).__name__)
        return BatchItem(filename=display, error="Unexpected error while auditing this file.")

    audit_id = result.outcome.audit_id
    try:
        pdf = build_report_bytes(result.outcome)
        if audit_id is not None:
            persist_report(database, audit_id, pdf)
    except Exception as exc:
        logger.error("report generation failed: %s", type(exc).__name__)
        return BatchItem(
            filename=display,
            audit=result,
            error="The audit was saved, but its PDF report could not be generated.",
        )
    return BatchItem(filename=display, audit=result, pdf=pdf)


def audit_batch(
    files: Sequence[tuple[str, bytes]],
    rules: RuleSet,
    *,
    database: Path | str,
    vendor: parsed.Vendor | None = None,
    frameworks: Iterable[str] | None = None,
    backends: Backends | None = None,
    max_bytes: int = MAX_UPLOAD_BYTES,
) -> list[BatchItem]:
    if len(files) > MAX_FILES_PER_BATCH:
        raise ValueError(f"at most {MAX_FILES_PER_BATCH} files can be audited at once")
    selected = None if frameworks is None else list(frameworks)
    return [
        _audit_one(name, data, rules, database, vendor, selected, backends, max_bytes) for name, data in files
    ]
