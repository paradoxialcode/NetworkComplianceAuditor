from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pandas as pd
import streamlit as st

from auditor.audit.pipeline import Backends
from auditor.audit.service import AuditError, RuleSet, load_rule_set
from auditor.audit.settings import AppSettings, load_settings
from auditor.audit.store import init_db
from auditor.compliance.models import CheckResult
from auditor.compliance.scoring import FrameworkScore
from auditor.reporting.styles import FRAMEWORK_LABELS, STATUS_LABELS

BACKENDS: Backends | None = None
_MAX_EVIDENCE_CELL = 200


@st.cache_resource(show_spinner=False)
def get_settings() -> AppSettings:
    return load_settings()


@st.cache_resource(show_spinner=False)
def get_database() -> Path:
    database = get_settings().database
    init_db(database)
    return database


@st.cache_resource(show_spinner="Loading rules...")
def _load_rules(data_dir: str) -> RuleSet:
    return load_rule_set(Path(data_dir))


def get_rules() -> RuleSet | None:
    try:
        return _load_rules(str(get_settings().data_dir))
    except AuditError as exc:
        st.error("The rule set could not be loaded. Fix the problems below and reload.")
        st.code(str(exc), language="text")
        reload_button()
        return None


def require_rules() -> RuleSet:
    rules = get_rules()
    if rules is None:
        st.stop()
    return rules


def reload_button() -> None:
    if st.button("Reload rules", key="reload-rules"):
        st.cache_resource.clear()
        st.rerun()


def framework_label(framework: str) -> str:
    return FRAMEWORK_LABELS.get(framework, framework.upper())


def results_frame(results: Sequence[CheckResult]) -> pd.DataFrame:
    rows = [
        {
            "Check ID": r.check_id,
            "Check": r.title,
            "Severity": r.severity.value.upper(),
            "Status": STATUS_LABELS[r.status],
            "Evidence": "; ".join(f"{k} = {v}" for k, v in r.evidence.items())[:_MAX_EVIDENCE_CELL],
        }
        for r in results
    ]
    return pd.DataFrame(rows, columns=["Check ID", "Check", "Severity", "Status", "Evidence"])


def scores_frame(scores: dict[str, FrameworkScore]) -> pd.DataFrame:
    rows = [
        {
            "Framework": framework_label(fw),
            "Controls": s.total,
            "Compliant": s.compliant,
            "Non-compliant": s.non_compliant,
            "Indeterminate": s.indeterminate,
            "Not assessable": s.not_assessable,
            "Coverage %": s.coverage_pct,
            "Pass rate %": s.pass_pct,
        }
        for fw, s in scores.items()
    ]
    return pd.DataFrame(rows)
