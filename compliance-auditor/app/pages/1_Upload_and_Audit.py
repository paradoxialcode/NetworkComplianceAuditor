import streamlit as st

from auditor.audit.batch import MAX_FILES_PER_BATCH, audit_batch
from auditor.compliance.models import NONCOMPLIANT, Status
from auditor.parsers.normalizer import Vendor
from auditor.ui import common

st.set_page_config(page_title="Upload and Audit", layout="wide")
st.title("Upload and audit")

rules = common.require_rules()
settings = common.get_settings()
database = common.get_database()

VENDOR_CHOICES = {"Auto-detect": None, "Cisco IOS": Vendor.CISCO_IOS, "FortiOS": Vendor.FORTIOS}

frameworks = st.multiselect(
    "Frameworks to assess",
    options=list(rules.catalogs),
    default=list(rules.catalogs),
    format_func=common.framework_label,
)
vendor_label = st.selectbox("Vendor", list(VENDOR_CHOICES))
files = st.file_uploader(
    "Configuration files",
    accept_multiple_files=True,
    help=f"Plain-text configuration exports, up to {settings.max_upload_bytes // (1024 * 1024)} MB each.",
)
run = st.button("Run audit", type="primary", disabled=not files or not frameworks)

if run and files:
    if len(files) > MAX_FILES_PER_BATCH:
        st.error(f"Please upload at most {MAX_FILES_PER_BATCH} files at a time.")
    else:
        payload = [(f.name, f.getvalue()) for f in files]
        with st.spinner("Auditing..."):
            st.session_state["batch"] = audit_batch(
                payload,
                rules,
                database=database,
                vendor=VENDOR_CHOICES[vendor_label],
                frameworks=frameworks,
                backends=common.BACKENDS,
                max_bytes=settings.max_upload_bytes,
            )

items = st.session_state.get("batch")
if items:
    st.subheader("Results")
    for index, item in enumerate(items):
        with st.expander(item.filename, expanded=len(items) == 1):
            if item.error:
                st.error(item.error)
                if item.needs_training:
                    st.info("Open the Training page to teach the system this vendor's format, then upload again.")
            if item.audit is None:
                continue
            outcome, parse = item.audit.outcome, item.audit.parse
            st.text(f"Device: {outcome.baseline.device.hostname}")
            st.caption(
                f"Vendor: {parse.vendor.value} ({'auto-detected' if parse.vendor_detected else 'selected'})"
                f" - audit #{outcome.audit_id}"
            )
            if parse.upload.lossy:
                st.warning("The file was not valid UTF-8, so some characters were replaced during reading.")
            counts = outcome.summary.by_status
            cols = st.columns(4)
            cols[0].metric("Checks", outcome.summary.total)
            cols[1].metric("Non-compliant", sum(counts.get(s, 0) for s in NONCOMPLIANT))
            cols[2].metric("Could not determine", counts.get(Status.UNKNOWN, 0) + counts.get(Status.ERROR, 0))
            cols[3].metric("Passed", counts.get(Status.PASS, 0))
            if outcome.baseline.unrecognized:
                st.warning(
                    f"{len(outcome.baseline.unrecognized)} configuration block(s) were not recognized, "
                    "so results may be incomplete."
                )
            st.dataframe(common.scores_frame(outcome.scores), hide_index=True)
            if item.pdf:
                st.download_button(
                    "Download PDF report",
                    data=item.pdf,
                    file_name=f"audit-{outcome.audit_id}.pdf",
                    mime="application/pdf",
                    key=f"download-{index}-{outcome.audit_id}",
                )
