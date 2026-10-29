import streamlit as st

from auditor.audit.store import list_audits, load_report
from auditor.db.session import session
from auditor.ui import common

st.set_page_config(page_title="Reports", layout="wide")
st.title("Reports")

database = common.get_database()
with session(database) as conn:
    items = list_audits(conn, 200)
if not items:
    st.info("No reports yet. Run an audit first.")
    st.stop()

labels = {i.audit_id: f"#{i.audit_id} | {i.hostname} | {i.vendor} | {i.created_at}" for i in items}
selected = st.selectbox("Audit", list(labels), format_func=labels.__getitem__)
with session(database) as conn:
    pdf = load_report(conn, selected)

if pdf is None:
    st.warning("No stored PDF exists for this audit.")
else:
    st.download_button(
        "Download PDF report",
        data=pdf,
        file_name=f"audit-{selected}.pdf",
        mime="application/pdf",
        key=f"report-{selected}",
    )
    st.caption(f"{len(pdf) // 1024 + 1} KB. Reports are stored exactly as generated at audit time.")
