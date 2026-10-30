import pandas as pd
import streamlit as st

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
    mapped: dict[str, set[str]] = {fw: set() for fw in rules.catalogs}
    for check in rules.checks:
        for fw, ids in check.mappings.items():
            if fw in mapped:
                mapped[fw].update(i.casefold() for i in ids)
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "Framework": common.framework_label(fw),
                    "Catalog": catalog.name,
                    "Version": catalog.version or "-",
                    "Controls": len(catalog.controls),
                    "Controls with a mapped check": sum(1 for c in catalog.controls if c.id.casefold() in mapped[fw]),
                }
                for fw, catalog in rules.catalogs.items()
            ]
        ),
        hide_index=True,
    )

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
