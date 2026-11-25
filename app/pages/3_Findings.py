import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import streamlit as st

from auditor.audit.store import delete_audit, list_audits, load_audit
from auditor.compliance.models import NONCOMPLIANT, Severity, Status
from auditor.db.session import session
from auditor.reporting.styles import STATUS_LABELS
from auditor.ui import common

st.set_page_config(page_title="Findings", layout="wide")
st.title("Findings")

database = common.get_database()
with session(database) as conn:
    items = list_audits(conn, 200)
if not items:
    st.info("No audits yet. Upload a configuration on the Upload and Audit page.")
    st.stop()

labels = {i.audit_id: f"#{i.audit_id} | {i.hostname} | {i.vendor} | {i.created_at}" for i in items}
selected = st.selectbox("Audit", list(labels), format_func=labels.__getitem__)
with session(database) as conn:
    audit = load_audit(conn, selected)
if audit is None:
    st.warning("That audit no longer exists.")
    st.stop()

st.text(f"Device: {audit.device.hostname}")
st.caption(
    f"{audit.device.vendor} | {audit.device.platform} | audited {audit.created_at} | "
    f"frameworks: {', '.join(common.framework_label(f) for f in audit.frameworks) or '-'}"
)
counts = audit.summary.by_status
cols = st.columns(4)
cols[0].metric("Checks", audit.summary.total)
cols[1].metric("Non-compliant", sum(counts.get(s, 0) for s in NONCOMPLIANT))
cols[2].metric("Could not determine", counts.get(Status.UNKNOWN, 0) + counts.get(Status.ERROR, 0))
cols[3].metric("Passed", counts.get(Status.PASS, 0))

st.subheader("Framework alignment")
st.dataframe(common.scores_frame(audit.scores), hide_index=True)

st.subheader("Checks")
status_filter = st.multiselect("Status", list(Status), default=list(Status), format_func=STATUS_LABELS.__getitem__)
severity_filter = st.multiselect("Severity", list(Severity), default=list(Severity), format_func=lambda s: s.value.upper())
query = st.text_input("Search check ID or title").strip().lower()
visible = [
    r
    for r in audit.results
    if r.status in status_filter
    and r.severity in severity_filter
    and (not query or query in r.check_id.lower() or query in r.title.lower())
]
st.dataframe(common.results_frame(visible), hide_index=True)

failing = [r for r in visible if r.status in NONCOMPLIANT]
if failing:
    st.subheader("Non-compliant details")
    for result in failing:
        with st.expander(f"{result.check_id} - {result.title}"):
            st.text("Evidence:")
            st.json(result.evidence)
            mapped = {common.framework_label(fw): list(ids) for fw, ids in result.mappings.items() if fw in audit.frameworks}
            st.text("Mapped controls:")
            st.json(mapped or {})

st.subheader("Delete audit")
confirm = st.checkbox("I understand this permanently deletes the audit and its report.")
if st.button("Delete audit", disabled=not confirm):
    with session(database) as conn:
        delete_audit(conn, selected)
    st.rerun()
