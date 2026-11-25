import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pandas as pd
import streamlit as st

from auditor.compliance.catalog import mapping_completeness
from auditor.ui import common

st.set_page_config(page_title="Rules and Frameworks", layout="wide")
st.title("Rules and frameworks")

rules = common.require_rules()
common.reload_button()

checks_tab, frameworks_tab, remediation_tab, warnings_tab = st.tabs(
    ["Checks", "Frameworks", "Remediation templates", "Warnings"]
)

with checks_tab:
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "ID": c.id,
                    "Title": c.title,
                    "Severity": c.severity.value.upper(),
                    "Vendors": ", ".join(c.vendors) if c.vendors else "all",
                    "Frameworks": ", ".join(common.framework_label(f) for f in c.mappings) or "-",
                    "Remediation key": c.remediation_key or "-",
                }
                for c in rules.checks
            ]
        ),
        hide_index=True,
    )

with frameworks_tab:
    all_checks = "All checks"
    vendors = sorted({v for c in rules.checks for v in (c.vendors or ())})
    scope = st.selectbox(
        "Vendor scope",
        [all_checks, *vendors],
        key="mapping-scope",
        help="Count only checks that apply to this vendor. Checks without a vendor list apply to every vendor.",
    )
    report = mapping_completeness(rules.checks, rules.catalogs, None if scope == all_checks else scope)
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "Framework": common.framework_label(fw),
                    "Catalog": catalog.name,
                    "Version": catalog.version or "-",
                    "Controls": item.total,
                    "Controls with a mapped check": item.mapped,
                    "Mapped %": item.pct,
                }
                for fw, catalog in rules.catalogs.items()
                for item in (report[fw],)
            ]
        ),
        hide_index=True,
    )
    st.caption("Mapped % is rule-set coverage of the catalog. It is not a device compliance score.")
    for fw, item in report.items():
        if item.unmapped:
            with st.expander(f"{common.framework_label(fw)}: {len(item.unmapped)} controls without a mapped check"):
                st.text(", ".join(item.unmapped))

with remediation_tab:
    if rules.templates:
        st.dataframe(
            pd.DataFrame(
                [
                    {"Vendor": vendor, "Steps": len(templates.steps), "Keys": ", ".join(sorted(templates.steps))}
                    for vendor, templates in sorted(rules.templates.items())
                ]
            ),
            hide_index=True,
        )
    else:
        st.info("No remediation templates are loaded.")

with warnings_tab:
    if rules.warnings:
        st.code("\n".join(rules.warnings), language="text")
    else:
        st.success("No warnings.")
