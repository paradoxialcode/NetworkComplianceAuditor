import pytest

from auditor.compliance.catalog import (
    Catalog,
    CatalogLoadError,
    load_catalogs,
    unknown_mappings,
)
from auditor.compliance.models import Check, CheckResult, Severity, Status
from auditor.compliance.scoring import ControlStatus, score_all, score_framework, summarize

NIST = Catalog.model_validate(
    {
        "framework": "nist",
        "name": "NIST SP 800-53 Rev. 5 (subset)",
        "controls": [
            {"id": "AC-17", "title": "Remote Access"},
            {"id": "AU-2", "title": "Event Logging"},
            {"id": "SC-8", "title": "Transmission Confidentiality"},
            {"id": "IA-5", "title": "Authenticator Management"},
            {"id": "PE-3", "title": "Physical Access Control"},
        ],
    }
)


def res(check_id, status, nist=(), severity=Severity.HIGH):
    return CheckResult(
        check_id=check_id,
        title="t",
        severity=severity,
        status=status,
        evidence={},
        mappings={"nist": tuple(nist)} if nist else {},
        remediation_key=None,
    )


def statuses(score):
    return {c.control_id: c.status for c in score.controls}


def test_control_aggregation():
    results = [
        res("C1", Status.PASS, ["AC-17"]),
        res("C2", Status.FAIL, ["AC-17", "AU-2"]),
        res("C3", Status.PASS, ["AU-2"]),
        res("C4", Status.UNKNOWN, ["SC-8"]),
        res("C5", Status.NOT_APPLICABLE, ["IA-5"]),
    ]
    got = statuses(score_framework(NIST, results))
    assert got == {
        "AC-17": ControlStatus.NON_COMPLIANT,
        "AU-2": ControlStatus.NON_COMPLIANT,
        "SC-8": ControlStatus.INDETERMINATE,
        "IA-5": ControlStatus.NOT_APPLICABLE,
        "PE-3": ControlStatus.NOT_ASSESSABLE,
    }


def test_fail_outranks_unknown_and_error():
    results = [res("C1", Status.UNKNOWN, ["AC-17"]), res("C2", Status.FAIL, ["AC-17"]), res("C3", Status.ERROR, ["AC-17"])]
    assert statuses(score_framework(NIST, results))["AC-17"] is ControlStatus.NON_COMPLIANT


def test_not_configured_counts_as_non_compliant():
    results = [res("C1", Status.NOT_CONFIGURED, ["AU-2"])]
    assert statuses(score_framework(NIST, results))["AU-2"] is ControlStatus.NON_COMPLIANT


def test_percentages():
    results = [
        res("C1", Status.PASS, ["AC-17"]),
        res("C2", Status.FAIL, ["AU-2"]),
        res("C3", Status.UNKNOWN, ["SC-8"]),
        res("C4", Status.NOT_APPLICABLE, ["IA-5"]),
    ]
    score = score_framework(NIST, results)
    assert (score.compliant, score.non_compliant, score.indeterminate) == (1, 1, 1)
    assert (score.not_applicable, score.not_assessable, score.total) == (1, 1, 5)
    assert score.coverage_pct == 75.0
    assert score.pass_pct == 33.3


def test_nothing_assessed_gives_no_pass_pct():
    score = score_framework(NIST, [])
    assert score.pass_pct is None
    assert score.coverage_pct == 0.0
    assert score.not_assessable == 5


def test_control_ids_match_case_insensitively():
    results = [res("C1", Status.PASS, ["ac-17"])]
    assert statuses(score_framework(NIST, results))["AC-17"] is ControlStatus.COMPLIANT


def test_check_ids_listed_per_control():
    results = [res("C2", Status.PASS, ["AC-17"]), res("C1", Status.PASS, ["AC-17"])]
    control = score_framework(NIST, results).controls[0]
    assert control.check_ids == ("C1", "C2")


def test_score_all_selection_and_missing_catalog():
    assert list(score_all({"nist": NIST}, [], ["NIST"])) == ["nist"]
    with pytest.raises(KeyError):
        score_all({"nist": NIST}, [], ["cis"])


def test_summarize():
    summary = summarize(
        [
            res("C1", Status.PASS),
            res("C2", Status.FAIL, severity=Severity.CRITICAL),
            res("C3", Status.NOT_CONFIGURED, severity=Severity.LOW),
            res("C4", Status.UNKNOWN),
        ]
    )
    assert summary.total == 4
    assert summary.by_status[Status.FAIL] == 1
    assert summary.failing_by_severity == {Severity.CRITICAL: 1, Severity.LOW: 1}


GOOD_CATALOG = """
framework: NIST
name: NIST SP 800-53 Rev. 5 (subset)
controls:
  - {id: AC-17, title: Remote Access}
  - {id: "AC-17(2)", title: Protection of Confidentiality and Integrity}
"""


def test_load_catalogs(tmp_path):
    (tmp_path / "nist.yaml").write_text(GOOD_CATALOG, encoding="utf-8")
    catalogs = load_catalogs(tmp_path)
    assert list(catalogs) == ["nist"]
    assert len(catalogs["nist"].controls) == 2


@pytest.mark.parametrize(
    "text",
    [
        "framework: pci\nname: x\ncontrols: [{id: A1, title: t}]",
        "framework: nist\nname: x\ncontrols: []",
        "framework: nist\nname: x\ncontrols: [{id: A1, title: t}, {id: a1, title: dup}]",
        "framework: nist\nname: x\ncontrols: [{id: '<script>', title: t}]",
        "- not a mapping",
        "framework: [",
    ],
)
def test_bad_catalogs_rejected(tmp_path, text):
    (tmp_path / "bad.yaml").write_text(text, encoding="utf-8")
    with pytest.raises(CatalogLoadError):
        load_catalogs(tmp_path)


def test_duplicate_framework_catalogs_rejected(tmp_path):
    (tmp_path / "a.yaml").write_text(GOOD_CATALOG, encoding="utf-8")
    (tmp_path / "b.yaml").write_text(GOOD_CATALOG, encoding="utf-8")
    with pytest.raises(CatalogLoadError, match="duplicate"):
        load_catalogs(tmp_path)


def test_unknown_mappings_reported():
    check = Check.model_validate(
        {
            "id": "CHK-MAP-01",
            "title": "Mapping test",
            "severity": "low",
            "condition": {"field": "a.b", "op": "present"},
            "mappings": {"nist": ["AC-17", "AC-99"], "cis": ["anything"]},
        }
    )
    problems = unknown_mappings([check], {"nist": NIST})
    assert problems == ["CHK-MAP-01: nist control 'AC-99' not in catalog"]
