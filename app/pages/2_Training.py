
"""Training page for creating, testing, and saving pattern rules."""

import streamlit as st

from auditor.parsers.normalizer import Vendor
from auditor.training.matcher import matching_rules, resolve
from auditor.training.patterns import (
    MatchMethod,
    PatternRule,
    RuleSource,
    TARGET_FIELD_TYPES,
    ensure_unique_rule_ids,
)
from auditor.training.store import load_rules, save_rules
from auditor.ui import common

st.set_page_config(page_title="Training", page_icon="🧠", layout="wide")

st.title("Pattern Rule Training")
st.caption("Create validated rules, test configuration lines, and save your rule set.")

RULE_FILE = common.training_rules_path()

if "training_rules" not in st.session_state:
    st.session_state["training_rules"] = list(
        load_rules(RULE_FILE, missing_ok=True)
    )

rules = st.session_state["training_rules"]

st.metric("Rules loaded", len(rules))
st.caption(f"Rule file: {RULE_FILE}")

st.subheader("Create a rule")

vendor_value = st.selectbox(
    "Vendor",
    options=[v.value for v in Vendor],
    format_func=lambda v: {
        "cisco_ios": "Cisco IOS",
        "fortios": "Fortinet FortiOS",
        "junos": "Juniper Junos",
    }.get(v, v),
)

method_value = st.selectbox(
    "Matching method",
    options=[m.value for m in MatchMethod],
)

available_targets = [
    name for name in TARGET_FIELD_TYPES
    if not (
        name == "password_encryption"
        and vendor_value != Vendor.CISCO_IOS.value
    )
]

target_field = st.selectbox("Target field", available_targets)
value_type = TARGET_FIELD_TYPES[target_field]
can_capture = method_value == MatchMethod.REGEX.value and value_type is str
can_be_absent = value_type is bool

with st.form("create_rule_form"):
    rule_id = st.text_input("Rule ID", placeholder="cisco-disable-http")

    if can_capture:
        capture_group = st.number_input(
            "Capture group (optional)",
            min_value=0,
            max_value=9,
            value=0,
            step=1,
            help="0 uses the suggested value; 1 or more takes that group of the matching line as the value, "
            "for example (\\S+) in 'set system ntp server (\\S+)'.",
        )
    else:
        capture_group = 0

    if value_type is bool:
        suggested_value = st.selectbox(
            "Suggested value",
            options=[True, False],
            format_func=lambda v: "True / Enabled" if v else "False / Disabled",
        )
    else:
        suggested_value = st.text_input("Suggested value", help="Ignored when a capture group is set.")

    expression = st.text_input(
        "Configuration expression",
        help="Never include real passwords, private keys, or credentials. "
        "For Junos, write the line as it appears in 'set' form, for example 'set system services telnet'.",
    )
    if can_be_absent:
        absent_choice = st.selectbox(
            "Value when no line matches (optional)",
            options=["Not set", "True / Enabled", "False / Disabled"],
            help="Used only when other lines of the file matched this vendor's rules, so an unrelated file is "
            "never reported as compliant.",
        )
    else:
        absent_choice = "Not set"
    confidence = st.slider(
        "Confidence", min_value=0.0, max_value=1.0,
        value=0.8, step=0.05,
    )
    explanation = st.text_area("Explanation")

    with st.expander("Optional source information"):
        source_name = st.text_input("Source name")
        source_reference = st.text_input("Source reference")
        source_version = st.text_input("Source version")

    submitted = st.form_submit_button("Validate and add rule")

if submitted:
    try:
        source = None
        if source_name.strip():
            source = RuleSource(
                name=source_name,
                reference=source_reference or None,
                version=source_version or None,
            )
        elif source_reference.strip() or source_version.strip():
            raise ValueError("Enter a source name for the source details.")

        new_rule = PatternRule(
            rule_id=rule_id,
            vendor=Vendor(vendor_value),
            method=MatchMethod(method_value),
            expression=expression,
            target_field=target_field,
            suggested_value=None if capture_group else suggested_value,
            confidence=confidence,
            explanation=explanation,
            source=source,
            capture_group=int(capture_group) or None,
            absent_value={"Not set": None, "True / Enabled": True, "False / Disabled": False}[absent_choice],
        )

        ensure_unique_rule_ids([*rules, new_rule])
        st.session_state["training_rules"] = [*rules, new_rule]
        st.success(f"Added rule: {new_rule.rule_id}")
        st.rerun()

    except (TypeError, ValueError) as exc:
        st.error(f"Could not add rule: {exc}")

st.divider()
st.subheader("Review rules")

rules = st.session_state["training_rules"]

if not rules:
    st.info("No rules yet. Create a rule above.")
else:
    for index, rule in enumerate(rules):
        with st.expander(f"{rule.rule_id} — {rule.vendor.value}"):
            st.write(f"**Method:** {rule.method.value}")
            st.code(rule.expression)
            st.write(f"**Target:** {rule.target_field}")
            if rule.capture_group is None:
                st.write(f"**Suggested value:** {rule.suggested_value}")
            else:
                st.write(f"**Value:** captured from group {rule.capture_group}")
            if rule.absent_value is not None:
                st.write(f"**When no line matches:** {rule.absent_value}")
            st.write(f"**Confidence:** {rule.confidence:.0%}")
            st.write(f"**Explanation:** {rule.explanation}")

            if rule.source:
                st.write(f"**Source:** {rule.source.name}")

            if st.button("Remove rule", key=f"remove_{index}"):
                st.session_state["training_rules"] = [
                    item for i, item in enumerate(rules) if i != index
                ]
                st.rerun()

st.divider()
st.subheader("Test a configuration line")

test_vendor = st.selectbox(
    "Vendor to test",
    options=[v.value for v in Vendor],
    format_func=lambda v: {
        "cisco_ios": "Cisco IOS",
        "fortios": "Fortinet FortiOS",
        "junos": "Juniper Junos",
    }.get(v, v),
    key="test_vendor",
)
test_line = st.text_input("Configuration line")

if st.button("Find matching rules"):
    try:
        candidates = [
            rule for rule in st.session_state["training_rules"]
            if rule.vendor.value == test_vendor
        ]
        matches = matching_rules(candidates, test_line)

        if matches:
            st.success(f"Found {len(matches)} matching rule(s).")
            for rule in matches:
                value = resolve(rule, test_line).value
                shown = "(no usable value captured)" if value is None else f"`{value}`"
                st.write(f"**{rule.rule_id}** → {rule.target_field} = {shown}")
        else:
            st.info("No rules matched this line.")

    except (TypeError, ValueError) as exc:
        st.error(f"Could not test the line: {exc}")

st.divider()
st.subheader("Save or reload rules")

left, right = st.columns(2)

with left:
    if st.button("Save rules to JSON", type="primary"):
        try:
            current_rules = st.session_state["training_rules"]
            ensure_unique_rule_ids(current_rules)
            RULE_FILE.parent.mkdir(parents=True, exist_ok=True)
            save_rules(RULE_FILE, current_rules)
            st.success("Rules saved successfully.")
        except (OSError, TypeError, ValueError) as exc:
            st.error(f"Could not save rules: {exc}")

with right:
    if st.button("Reload saved rules"):
        try:
            st.session_state["training_rules"] = list(
                load_rules(RULE_FILE, missing_ok=True)
            )
            st.success("Saved rules reloaded.")
            st.rerun()
        except (OSError, TypeError, ValueError) as exc:
            st.error(f"Could not reload rules: {exc}")
