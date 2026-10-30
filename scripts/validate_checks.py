#!/usr/bin/env python3
"""Self-check for data/checks/*.yaml. Run from the project root:

    python scripts/validate_checks.py

Exit code 0 = all good, 1 = problems found.
"""
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CHECKS_DIR = ROOT / "data" / "checks"
REMEDIATION_FILE = ROOT / "data" / "remediation" / "remediation_keys.yaml"

REQUIRED = ["id", "title", "category", "severity", "description", "applies_to",
            "field", "operator", "expected", "on_missing", "nist", "remediation_key"]
SEVERITIES = {"critical", "high", "medium", "low"}
VENDORS = {"cisco", "fortinet", "junos"}
ON_MISSING = {"pass", "fail", "skip"}
# Keep in sync with auditor/compliance/operators.py
OPERATORS = {"equals", "not_equals", "gte", "lte", "gt", "lt",
             "in", "not_in", "contains", "not_contains", "matches"}
NUMERIC_OPS = {"gte", "lte", "gt", "lt"}
LIST_OPS = {"in", "not_in"}
FIELD_RE = re.compile(r"^[a-z_]+\.[a-z0-9_]+$")
ID_RE = re.compile(r"^[A-Z]+-\d{3}$")
NIST_RE = re.compile(r"^[A-Z]{2}-\d+(\(\d+\))?$")


def validate_check_fields(check: dict, category: str, remediation_keys: set) -> list:
    """Return a list of error strings for one check (empty list = valid)."""
    errs = []
    for k in REQUIRED:
        if k not in check:
            errs.append(f"missing field '{k}'")
    if errs:
        return errs
    if not ID_RE.match(str(check["id"])):
        errs.append(f"bad id format '{check['id']}' (use e.g. MGT-001)")
    if check["category"] != category:
        errs.append(f"category '{check['category']}' != file name '{category}'")
    if check["severity"] not in SEVERITIES:
        errs.append(f"bad severity '{check['severity']}'")
    if not isinstance(check["applies_to"], list) or not check["applies_to"] \
            or not set(check["applies_to"]) <= VENDORS:
        errs.append(f"applies_to must be a non-empty list from {sorted(VENDORS)}")
    if not FIELD_RE.match(str(check["field"])):
        errs.append(f"bad field path '{check['field']}' (use group.name)")
    op = check["operator"]
    if op not in OPERATORS:
        errs.append(f"unknown operator '{op}'")
    else:
        exp = check["expected"]
        if op in NUMERIC_OPS and (isinstance(exp, bool) or not isinstance(exp, (int, float))):
            errs.append(f"operator '{op}' needs a number for 'expected'")
        if op in LIST_OPS and not isinstance(exp, list):
            errs.append(f"operator '{op}' needs a list for 'expected'")
    if check["on_missing"] not in ON_MISSING:
        errs.append(f"on_missing must be one of {sorted(ON_MISSING)}")
    if not isinstance(check["nist"], list) or not check["nist"] \
            or not all(NIST_RE.match(str(c)) for c in check["nist"]):
        errs.append("nist must be a non-empty list like [AC-17, SC-8]")
    if check["remediation_key"] not in remediation_keys:
        errs.append(f"remediation_key '{check['remediation_key']}' not in remediation_keys.yaml")
    return errs


def main() -> int:
    remediation = yaml.safe_load(REMEDIATION_FILE.read_text(encoding="utf-8")) or {}
    keys = set(remediation)
    problems, seen_ids, used_keys, total = 0, set(), set(), 0

    files = sorted(CHECKS_DIR.glob("*.yaml"))
    if not files:
        print(f"No YAML files found in {CHECKS_DIR}")
        return 1

    for f in files:
        checks = yaml.safe_load(f.read_text(encoding="utf-8")) or []
        for c in checks:
            total += 1
            errs = validate_check_fields(c, f.stem, keys)
            cid = c.get("id", "?")
            if cid in seen_ids:
                errs.append("duplicate id")
            seen_ids.add(cid)
            used_keys.add(c.get("remediation_key"))
            for e in errs:
                problems += 1
                print(f"ERROR {f.name} [{cid}]: {e}")

    for k in sorted(keys - used_keys):
        print(f"WARN  remediation key '{k}' is not used by any check")

    print(f"\n{len(files)} files, {total} checks, {problems} error(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
