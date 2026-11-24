import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import streamlit as st

from auditor.ui import common

st.set_page_config(page_title="Network Compliance Auditor", layout="wide")
st.title("Network Security Compliance Auditor")
st.caption("Upload device configurations, assess them against security frameworks, and get a PDF report per device.")

rules = common.get_rules()
if rules is not None:
    cols = st.columns(4)
    cols[0].metric("Checks", len(rules.checks))
    cols[1].metric("Frameworks", len(rules.catalogs))
    cols[2].metric("Remediation vendors", len(rules.templates))
    cols[3].metric("Rule warnings", len(rules.warnings))
    if rules.warnings:
        st.warning("Some checks have no remediation template for a vendor. See the Rules and Frameworks page.")

common.get_database()
st.subheader("How it works")
st.markdown(
    "1. **Upload and Audit**: upload one or more configuration files.\n"
    "2. **Training**: teach the system a vendor it does not know yet.\n"
    "3. **Findings**: review results, evidence and mapped controls.\n"
    "4. **Reports**: download the PDF report for any past audit.\n"
    "5. **Rules and Frameworks**: inspect the checks, catalogs and remediation templates in use."
)
st.caption(
    "Results reflect technical checks of the submitted configuration only. They show technical alignment, "
    "not certification."
)
