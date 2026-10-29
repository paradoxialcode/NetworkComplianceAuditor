from typing import Final

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm

from auditor.compliance.models import Severity, Status

PAGE_SIZE: Final = A4
MARGIN: Final = 18 * mm
CONTENT_WIDTH: Final = PAGE_SIZE[0] - 2 * MARGIN

INK: Final = colors.HexColor("#1F2933")
MUTED: Final = colors.HexColor("#52606D")
HEADER_BG: Final = colors.HexColor("#243B53")
GRID: Final = colors.HexColor("#CBD2D9")
ZEBRA: Final = colors.HexColor("#F5F7FA")
WARN_BG: Final = colors.HexColor("#FFF4D6")
CODE_BG: Final = colors.HexColor("#F0F4F8")

FRAMEWORK_LABELS: Final = {
    "cis": "CIS Benchmarks",
    "stig": "DISA STIG",
    "nist": "NIST SP 800-53",
    "iso27001": "ISO/IEC 27001",
    "soc2": "SOC 2",
    "dpdp": "DPDP Act",
}

STATUS_LABELS: Final = {
    Status.PASS: "PASS",
    Status.FAIL: "FAIL",
    Status.NOT_CONFIGURED: "NOT CONFIGURED",
    Status.NOT_APPLICABLE: "N/A",
    Status.UNKNOWN: "UNKNOWN",
    Status.ERROR: "ERROR",
}

STATUS_COLORS: Final = {
    Status.PASS: ("#1B7F3B", "#E3F4E8"),
    Status.FAIL: ("#B42318", "#FDE8E6"),
    Status.NOT_CONFIGURED: ("#B42318", "#FDE8E6"),
    Status.NOT_APPLICABLE: ("#52606D", "#EEF1F4"),
    Status.UNKNOWN: ("#9A5B00", "#FFF1D6"),
    Status.ERROR: ("#9A5B00", "#FFF1D6"),
}

SEVERITY_COLORS: Final = {
    Severity.CRITICAL: "#8E1B10",
    Severity.HIGH: "#B42318",
    Severity.MEDIUM: "#9A5B00",
    Severity.LOW: "#52606D",
}


def build_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()["Normal"]

    def style(name: str, **kwargs: object) -> ParagraphStyle:
        kwargs.setdefault("fontName", "Helvetica")
        kwargs.setdefault("textColor", INK)
        return ParagraphStyle(name, parent=base, **kwargs)

    return {
        "title": style("title", fontName="Helvetica-Bold", fontSize=20, leading=24, spaceAfter=4),
        "subtitle": style("subtitle", fontSize=11, leading=14, textColor=MUTED, spaceAfter=10),
        "h1": style("h1", fontName="Helvetica-Bold", fontSize=13, leading=16, spaceBefore=14, spaceAfter=6),
        "h2": style("h2", fontName="Helvetica-Bold", fontSize=10.5, leading=13, spaceBefore=8, spaceAfter=3),
        "body": style("body", fontSize=9, leading=12, spaceAfter=4),
        "small": style("small", fontSize=7.5, leading=10, textColor=MUTED, spaceAfter=3),
        "cell": style("cell", fontSize=7.5, leading=9.5, wordWrap="CJK"),
        "cell_bold": style("cell_bold", fontName="Helvetica-Bold", fontSize=7.5, leading=9.5, wordWrap="CJK"),
        "head": style(
            "head", fontName="Helvetica-Bold", fontSize=7.5, leading=9.5, textColor=colors.white, wordWrap="CJK"
        ),
        "code": style(
            "code", fontName="Courier", fontSize=7.5, leading=9.5, wordWrap="CJK", backColor=CODE_BG, leftIndent=4
        ),
        "warning": style("warning", fontSize=8, leading=10.5),
    }
