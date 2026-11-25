from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from auditor.audit.service import AuditError, load_rule_set  # noqa: E402
from auditor.audit.settings import load_settings  # noqa: E402
from auditor.compliance.catalog import mapping_completeness  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Report framework control mapping completeness.")
    parser.add_argument("--unmapped", action="store_true", help="list controls with no mapped check")
    args = parser.parse_args()
    try:
        rules = load_rule_set(load_settings().data_dir)
    except AuditError as exc:
        print(exc, file=sys.stderr)
        return 1
    vendors = sorted({v for check in rules.checks for v in (check.vendors or ())})
    scopes: list[tuple[str, str | None]] = [("all", None), *[(v, v) for v in vendors]]
    print(f"{'scope':<12}{'framework':<12}{'mapped':>8}{'total':>7}{'pct':>8}")
    for label, vendor in scopes:
        for framework, item in mapping_completeness(rules.checks, rules.catalogs, vendor).items():
            print(f"{label:<12}{framework:<12}{item.mapped:>8}{item.total:>7}{item.pct:>7.1f}%")
            if args.unmapped and item.unmapped:
                print("  unmapped: " + ", ".join(item.unmapped))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
