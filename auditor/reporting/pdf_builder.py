from __future__ import annotations

import hashlib
import io
import re
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final
from xml.sax.saxutils import escape  # nosec B406 - string escaping only, no XML parsing

from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    CondPageBreak,
    Flowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from auditor.audit.service import AuditOutcome
from auditor.compliance.models import NONCOMPLIANT, CheckResult, Severity, Status
from auditor.compliance.scoring import ControlStatus
from auditor.remediation.renderer import Remediation, RemediationKind

from .styles import (
    CONTENT_WIDTH,
    FRAMEWORK_LABELS,
    GRID,
    HEADER_BG,
    MARGIN,
    MUTED,
    PAGE_SIZE,
    SEVERITY_COLORS,
    STATUS_COLORS,
    STATUS_LABELS,
    WARN_BG,
    ZEBRA,
    build_styles,
)

MAX_APPENDIX_ROWS: Final = 400
MAX_NOT_ASSESSABLE_IDS: Final = 150
_MAX_EVIDENCE_LEN: Final = 220
_CONTROL: Final = re.compile(r"[\x00-\x1f\x7f]")
_SEVERITY_RANK: Final = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
_STATUS_RANK: Final = {
    Status.FAIL: 0,
    Status.NOT_CONFIGURED: 0,
    Status.ERROR: 1,
    Status.UNKNOWN: 2,
    Status.PASS: 3,
    Status.NOT_APPLICABLE: 4,
}
_CONTROL_LABELS: Final = {
    ControlStatus.COMPLIANT: "Compliant",
    ControlStatus.NON_COMPLIANT: "Non-compliant",
    ControlStatus.INDETERMINATE: "Indeterminate",
    ControlStatus.NOT_APPLICABLE: "N/A",
    ControlStatus.NOT_ASSESSABLE: "Not assessable",
}
_SERIAL_KEYS: Final = ("serial_number", "serial", "chassis_serial")
_MODEL_KEYS: Final = ("hardware_model", "model", "chassis_model")
_NA_TEXT: Final = "Not available in configuration"

Story = list[Flowable]
Styles = dict[str, Any]


def _plain(value: object, limit: int | None = None) -> str:
    text = _CONTROL.sub(" ", str(value))
    if limit is not None and len(text) > limit:
        text = text[: limit - 3] + "..."
    return text.encode("cp1252", "replace").decode("cp1252")


def _clean(value: object, limit: int | None = None) -> str:
    return escape(_plain(value, limit))


def _para(value: object, style: Any, limit: int | None = None) -> Paragraph:
    return Paragraph(_clean(value, limit), style)


def _markup(value: str, style: Any) -> Paragraph:
    return Paragraph(value, style)


def _status_cell(status: Status, styles: Styles) -> Paragraph:
    fg, _bg = STATUS_COLORS[status]
    return _markup(f'<font color="{fg}"><b>{STATUS_LABELS[status]}</b></font>', styles["cell"])


def _severity_cell(severity: Severity, styles: Styles) -> Paragraph:
    return _markup(f'<font color="{SEVERITY_COLORS[severity]}"><b>{severity.value.upper()}</b></font>', styles["cell"])


def _table(rows: Sequence[Sequence[Any]], widths: Sequence[float], extra: Sequence[tuple[Any, ...]] = ()) -> Table:
    table = Table(list(rows), colWidths=list(widths), repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.4, GRID),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ZEBRA]),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                *extra,
            ]
        )
    )
    return table


def _fact(outcome: AuditOutcome, keys: Sequence[str]) -> str | None:
    for fact in outcome.baseline.facts:
        if fact.key in keys and fact.value not in (None, ""):
            return _plain(fact.value, 100)
    return None


def _framework_label(framework: str) -> str:
    return FRAMEWORK_LABELS.get(framework, framework.upper())


def _evidence_text(evidence: dict[str, Any]) -> str:
    if not evidence:
        return "-"
    return "; ".join(f"{key} = {value}" for key, value in evidence.items())


def _count(outcome: AuditOutcome, *statuses: Status) -> int:
    return sum(outcome.summary.by_status.get(s, 0) for s in statuses)


def _device_section(outcome: AuditOutcome, styles: Styles, generated_at: datetime) -> Story:
    device = outcome.baseline.device
    rows = [
        ("Hostname", device.hostname),
        ("Vendor", device.vendor.value),
        ("Platform", device.platform),
        ("Software version", device.version or "Not detected"),
        ("Serial number", _fact(outcome, _SERIAL_KEYS) or _NA_TEXT),
        ("Hardware model", _fact(outcome, _MODEL_KEYS) or _NA_TEXT),
        ("Source file", Path(device.filename.replace("\\", "/")).name if device.filename else "-"),
        ("Source SHA-256", device.sha256 or "-"),
        ("Audit ID", outcome.audit_id if outcome.audit_id is not None else "Not saved"),
        ("Generated (UTC)", generated_at.strftime("%Y-%m-%d %H:%M:%S")),
        ("Frameworks assessed", ", ".join(_framework_label(f) for f in outcome.frameworks) or "-"),
    ]
    data = [[_para(k, styles["cell_bold"]), _para(v, styles["cell"])] for k, v in rows]
    table = Table(data, colWidths=[40 * mm, CONTENT_WIDTH - 40 * mm])
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.4, GRID),
                ("BACKGROUND", (0, 0), (0, -1), ZEBRA),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return [_para("1. Device identification", styles["h1"]), table]


def _summary_section(outcome: AuditOutcome, styles: Styles) -> Story:
    applicable = outcome.summary.total - _count(outcome, Status.NOT_APPLICABLE)
    failing = _count(outcome, *NONCOMPLIANT)
    story: Story = [
        _para("2. Executive summary", styles["h1"]),
        _para(
            f"{failing} of {applicable} applicable checks are non-compliant; "
            f"{_count(outcome, Status.PASS)} passed and "
            f"{_count(outcome, Status.UNKNOWN, Status.ERROR)} could not be determined automatically.",
            styles["body"],
        ),
    ]
    head = ["Total", "Pass", "Fail", "Not configured", "Unknown", "Error", "N/A"]
    values = [
        outcome.summary.total,
        _count(outcome, Status.PASS),
        _count(outcome, Status.FAIL),
        _count(outcome, Status.NOT_CONFIGURED),
        _count(outcome, Status.UNKNOWN),
        _count(outcome, Status.ERROR),
        _count(outcome, Status.NOT_APPLICABLE),
    ]
    width = CONTENT_WIDTH / len(head)
    story.append(
        _table(
            [[_para(h, styles["head"]) for h in head], [_para(v, styles["cell"]) for v in values]],
            [width] * len(head),
        )
    )
    severities = [(s, outcome.summary.failing_by_severity.get(s, 0)) for s in Severity]
    story.append(Spacer(1, 5))
    story.append(
        _markup(
            "Non-compliant checks by severity: "
            + ", ".join(
                f'<font color="{SEVERITY_COLORS[s]}"><b>{s.value.capitalize()}</b></font> {n}' for s, n in severities
            ),
            styles["body"],
        )
    )
    unrecognized = len(outcome.baseline.unrecognized)
    if unrecognized:
        story.append(
            _para(
                f"Note: {unrecognized} configuration block(s) were not recognized by the parser, so results may be "
                "incomplete. Their content is intentionally not reproduced in this report.",
                styles["body"],
            )
        )
    inferred = sum(
        1
        for fact in outcome.baseline.facts
        if fact.evidence is not None and (fact.evidence.mapping_id or "").startswith("generic:")
    )
    trained = sum(
        1
        for fact in outcome.baseline.facts
        if fact.evidence is not None and (fact.evidence.mapping_id or "").startswith("trained:")
    )
    if trained:
        story.append(
            _para(
                f"Note: {trained} value(s) were derived from trained mapping rules (taught by an administrator) rather "
                "than a built-in parser, each carrying the rule's confidence score. Verify them before relying on pass "
                "results that depend on them; the evidence column shows the rule and the line used.",
                styles["body"],
            )
        )
    if inferred:
        story.append(
            _para(
                f"Note: {inferred} value(s) were inferred by the generic parser (no vendor-specific parser was used), "
                "each with a confidence score below certainty. Verify them before relying on pass results that depend "
                "on them; the evidence column shows the values used.",
                styles["body"],
            )
        )
    story.append(
        _para(
            "Scope: these results come from technical checks of the submitted configuration file only. For NIST, "
            "ISO/IEC 27001, SOC 2 and DPDP they show technical alignment of mapped controls; they are not a "
            "certification or audit opinion. Controls that depend on policy, process or organizational evidence "
            "cannot be assessed from a device configuration.",
            styles["small"],
        )
    )
    return story


def _framework_section(outcome: AuditOutcome, styles: Styles) -> Story:
    head = ["Framework", "Controls", "Compliant", "Non-compliant", "Indeterminate", "Not assessable", "Coverage", "Pass rate"]
    widths = [34 * mm, 16 * mm, 20 * mm, 22 * mm, 22 * mm, 26 * mm, 16 * mm, 18 * mm]
    rows: list[list[Paragraph]] = [[_para(h, styles["head"]) for h in head]]
    for framework, score in outcome.scores.items():
        pass_rate = "n/a" if score.pass_pct is None else f"{score.pass_pct:.1f}%"
        values = [
            _framework_label(framework),
            score.total,
            score.compliant,
            score.non_compliant,
            score.indeterminate,
            score.not_assessable,
            f"{score.coverage_pct:.1f}%",
            pass_rate,
        ]
        rows.append([_para(v, styles["cell_bold"] if i == 0 else styles["cell"]) for i, v in enumerate(values)])
    return [
        _para("3. Framework alignment", styles["h1"]),
        _para(
            "Coverage is the share of in-scope controls that at least one applicable check could assess. "
            "Pass rate is computed only over assessed controls.",
            styles["small"],
        ),
        _table(rows, widths),
    ]


def _sorted_results(results: Sequence[CheckResult]) -> list[CheckResult]:
    return sorted(results, key=lambda r: (_STATUS_RANK[r.status], _SEVERITY_RANK[r.severity], r.check_id))


def _findings_section(outcome: AuditOutcome, styles: Styles) -> Story:
    head = ["Check ID", "Check", "Severity", "Status", "Evidence"]
    widths = [39 * mm, 48 * mm, 17 * mm, 22 * mm, CONTENT_WIDTH - 126 * mm]
    rows: list[list[Paragraph]] = [[_para(h, styles["head"]) for h in head]]
    extra: list[tuple[Any, ...]] = []
    for index, result in enumerate(_sorted_results(outcome.results), start=1):
        rows.append(
            [
                _para(result.check_id, styles["cell_bold"]),
                _para(result.title, styles["cell"], 200),
                _severity_cell(result.severity, styles),
                _status_cell(result.status, styles),
                _para(_evidence_text(result.evidence), styles["cell"], _MAX_EVIDENCE_LEN),
            ]
        )
        extra.append(("BACKGROUND", (3, index), (3, index), colors.HexColor(STATUS_COLORS[result.status][1])))
    return [_para("4. Findings", styles["h1"]), _table(rows, widths, extra)]


def _mapped_controls(result: CheckResult, frameworks: Sequence[str]) -> str:
    parts = [
        f"{_framework_label(fw)}: {', '.join(result.mappings[fw])}"
        for fw in frameworks
        if result.mappings.get(fw)
    ]
    return " | ".join(parts) if parts else "No mapped controls in the selected frameworks"


def _details_section(outcome: AuditOutcome, styles: Styles) -> Story:
    failing = [r for r in _sorted_results(outcome.results) if r.status in NONCOMPLIANT]
    story: Story = [_para("5. Non-compliant findings in detail", styles["h1"])]
    if not failing:
        story.append(_para("No non-compliant findings.", styles["body"]))
        return story
    for result in failing:
        fg, _ = STATUS_COLORS[result.status]
        story.append(
            KeepTogether(
                [
                    _markup(
                        f"<b>{_clean(result.check_id)}</b> - {_clean(result.title, 200)} "
                        f'<font color="{fg}"><b>[{STATUS_LABELS[result.status]}]</b></font> '
                        f'<font color="{SEVERITY_COLORS[result.severity]}">'
                        f"{result.severity.value.upper()}</font>",
                        styles["h2"],
                    ),
                    _para(f"Evidence: {_evidence_text(result.evidence)}", styles["body"], _MAX_EVIDENCE_LEN),
                    _para(f"Mapped controls: {_mapped_controls(result, outcome.frameworks)}", styles["small"]),
                ]
            )
        )
    return story


def _code_block(commands: Sequence[str], styles: Styles) -> Story:
    return [_markup(_clean(line).replace(" ", "&nbsp;") or "&nbsp;", styles["code"]) for line in commands]


def _group_remediations(items: Sequence[Remediation]) -> list[list[Remediation]]:
    groups: dict[tuple[Any, ...], list[Remediation]] = {}
    for item in items:
        key = (item.step_title, item.commands) if item.kind is RemediationKind.COMMANDS else (item.check_id,)
        groups.setdefault(key, []).append(item)
    return list(groups.values())


def _remediation_section(outcome: AuditOutcome, styles: Styles) -> Story:
    story: Story = [CondPageBreak(60 * mm), _para("6. Remediation", styles["h1"])]
    if not outcome.remediations:
        story.append(_para("No remediation required.", styles["body"]))
        return story
    story.append(
        _para(
            f"Steps are ordered to reduce the risk of losing management access. The commands below are suggestions "
            f"for {_plain(outcome.baseline.device.vendor.value)} devices: review them, adapt them to your "
            f"environment and test them in a maintenance window before applying.",
            styles["body"],
        )
    )
    commands = [r for r in outcome.remediations if r.kind is RemediationKind.COMMANDS]
    manual = [r for r in outcome.remediations if r.kind is RemediationKind.MANUAL]
    verify = [r for r in outcome.remediations if r.kind is RemediationKind.VERIFY]

    for number, group in enumerate(_group_remediations(commands), start=1):
        first = group[0]
        block: Story = [
            _markup(f"Step {number}: {_clean(first.step_title, 200)}", styles["h2"]),
            _para("Resolves: " + ", ".join(r.check_id for r in group), styles["small"]),
        ]
        if first.warning:
            warn = Table([[_para("Caution: " + first.warning, styles["warning"])]], colWidths=[CONTENT_WIDTH])
            warn.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), WARN_BG), ("BOX", (0, 0), (-1, -1), 0.4, GRID)]))
            block.append(warn)
            block.append(Spacer(1, 2))
        block.extend(_code_block(first.commands, styles))
        story.append(KeepTogether(block) if len(first.commands) <= 15 else block[0])
        if len(first.commands) > 15:
            story.extend(block[1:])
        story.append(Spacer(1, 4))

    for title, items in (("Manual action required", manual), ("Manual verification required", verify)):
        if not items:
            continue
        story.append(_para(title, styles["h2"]))
        rows = [[_para(h, styles["head"]) for h in ("Check ID", "Check", "Severity", "Note")]]
        for item in items:
            rows.append(
                [
                    _para(item.check_id, styles["cell_bold"]),
                    _para(item.check_title, styles["cell"], 200),
                    _severity_cell(item.severity, styles),
                    _para(item.note or "-", styles["cell"], 300),
                ]
            )
        story.append(_table(rows, [30 * mm, 55 * mm, 17 * mm, CONTENT_WIDTH - 102 * mm]))
        story.append(Spacer(1, 4))
    return story


def _appendix_section(outcome: AuditOutcome, styles: Styles) -> Story:
    story: Story = [CondPageBreak(60 * mm), _para("7. Appendix: control-level results", styles["h1"])]
    if not outcome.scores:
        story.append(_para("No frameworks were selected.", styles["body"]))
        return story
    for framework, score in outcome.scores.items():
        story.append(_para(f"{_framework_label(framework)} - {score.name}", styles["h2"]))
        assessed = [c for c in score.controls if c.status is not ControlStatus.NOT_ASSESSABLE]
        if assessed:
            rows = [[_para(h, styles["head"]) for h in ("Control", "Title", "Status", "Checks")]]
            for control in assessed[:MAX_APPENDIX_ROWS]:
                rows.append(
                    [
                        _para(control.control_id, styles["cell_bold"]),
                        _para(control.title, styles["cell"], 160),
                        _para(_CONTROL_LABELS[control.status], styles["cell"]),
                        _para(", ".join(control.check_ids) or "-", styles["cell"], 200),
                    ]
                )
            story.append(_table(rows, [24 * mm, 70 * mm, 24 * mm, CONTENT_WIDTH - 118 * mm]))
            if len(assessed) > MAX_APPENDIX_ROWS:
                story.append(
                    _para(f"Showing {MAX_APPENDIX_ROWS} of {len(assessed)} assessed controls.", styles["small"])
                )
        unassessable = [c.control_id for c in score.controls if c.status is ControlStatus.NOT_ASSESSABLE]
        if unassessable:
            shown = ", ".join(unassessable[:MAX_NOT_ASSESSABLE_IDS])
            more = len(unassessable) - MAX_NOT_ASSESSABLE_IDS
            suffix = f" ... and {more} more" if more > 0 else ""
            story.append(
                _para(
                    f"Not assessable from device configuration ({len(unassessable)}): {shown}{suffix}",
                    styles["small"],
                )
            )
        story.append(Spacer(1, 4))
    return story


class _NumberedCanvas(canvas.Canvas):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._saved_states: list[dict[str, Any]] = []

    def showPage(self) -> None:  # noqa: N802
        self._saved_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        total = len(self._saved_states)
        for state in self._saved_states:
            self.__dict__.update(state)
            self.setFont("Helvetica", 7.5)
            self.setFillColor(MUTED)
            self.drawRightString(PAGE_SIZE[0] - MARGIN, 10 * mm, f"Page {self._pageNumber} of {total}")
            super().showPage()
        super().save()


def _decorate(canv: canvas.Canvas, _doc: Any) -> None:
    canv.saveState()
    canv.setStrokeColor(GRID)
    canv.setLineWidth(0.4)
    canv.line(MARGIN, 14 * mm, PAGE_SIZE[0] - MARGIN, 14 * mm)
    canv.setFont("Helvetica", 7.5)
    canv.setFillColor(MUTED)
    canv.drawString(MARGIN, 10 * mm, "CONFIDENTIAL - network security compliance report")
    canv.restoreState()


def build_report_bytes(outcome: AuditOutcome, generated_at: datetime | None = None) -> bytes:
    generated = (generated_at or datetime.now(UTC)).astimezone(UTC)
    styles = build_styles()
    hostname = outcome.baseline.device.hostname
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=PAGE_SIZE,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=16 * mm,
        bottomMargin=20 * mm,
        title=_plain(f"Compliance report - {hostname}", 120),
        author="Network Compliance Auditor",
        subject="Network device security compliance report",
        creator="Network Compliance Auditor",
    )
    story: Story = [
        _para("Network Security Compliance Report", styles["title"]),
        _para(f"{hostname} ({outcome.baseline.device.vendor.value})", styles["subtitle"], 150),
        *_device_section(outcome, styles, generated),
        *_summary_section(outcome, styles),
        *_framework_section(outcome, styles),
        *_findings_section(outcome, styles),
        *_details_section(outcome, styles),
        *_remediation_section(outcome, styles),
        *_appendix_section(outcome, styles),
    ]
    doc.build(story, onFirstPage=_decorate, onLaterPages=_decorate, canvasmaker=_NumberedCanvas)
    return buffer.getvalue()


def write_report(outcome: AuditOutcome, directory: Path | str, generated_at: datetime | None = None) -> Path:
    data = build_report_bytes(outcome, generated_at)
    folder = Path(directory)
    folder.mkdir(parents=True, exist_ok=True)
    stem = f"audit-{outcome.audit_id}" if outcome.audit_id is not None else f"report-{hashlib.sha256(data).hexdigest()[:12]}"
    target = folder / f"{stem}.pdf"
    temp = folder / f".{stem}.pdf.tmp"
    temp.write_bytes(data)
    temp.replace(target)
    return target
