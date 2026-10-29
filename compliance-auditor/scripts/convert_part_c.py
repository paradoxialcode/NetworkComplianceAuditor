from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Any

import yaml

CHECKS_DIR = Path("data/checks")
PENDING_DIR = Path("data/checks_pending")
MAX_FILE_BYTES = 1_000_000
FIELD_RE = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+)*$")
FRAMEWORKS = ("cis", "stig", "nist", "iso27001", "soc2", "dpdp")
ALL_VENDORS = frozenset({"cisco", "fortinet", "juniper"})
VENDOR_ALIASES = {"junos": "juniper"}
ON_MISSING = {"pass": "pass", "fail": "fail", "skip": "not_configured"}
OPS = {
    "equals": "eq",
    "not_equals": "ne",
    "gte": "gte",
    "lte": "lte",
    "gt": "gt",
    "lt": "lt",
    "in": "in",
    "not_in": "not_in",
    "contains": "contains",
    "matches": "regex",
}
STATE_FIELDS = {
    "management.telnet_enabled": "management.telnet",
    "management.ssh_enabled": "management.ssh",
    "management.http_server_enabled": "management.http",
    "auth.aaa_enabled": "auth.aaa",
    "logging.enabled": "logging.enabled",
}
LIST_FIELDS = {
    "logging.remote_server_count": "logging.destinations",
    "logging.ntp_server_count": "time_sync.servers",
}
FACT_KEYS = {"auth.password_encryption_enabled": "password_encryption"}
ALLOWED_KEYS = frozenset(
    {
        "id", "title", "category", "severity", "description", "applies_to",
        "field", "operator", "expected", "on_missing", "remediation_key",
        *FRAMEWORKS,
    }
)
HEADER = "# Engine format (auditor/compliance/models.py). Converted from Part C format.\n"


class Unconvertible(Exception):
    pass


def convert_condition(raw: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    field = raw.get("field")
    op_name = raw.get("operator")
    expected = raw.get("expected")
    if not isinstance(field, str) or "." not in field or not FIELD_RE.fullmatch(field):
        raise Unconvertible(f"bad field {field!r}")
    if op_name not in OPS:
        raise Unconvertible(f"unsupported operator {op_name!r}")
    on_missing = ON_MISSING.get(raw.get("on_missing", "fail"))
    if on_missing is None:
        raise Unconvertible(f"bad on_missing {raw.get('on_missing')!r}")
    op = OPS[op_name]
    notes: dict[str, str] = {}
    if raw.get("on_missing") == "skip":
        notes["on_missing skip"] = "not_configured"

    is_int = type(expected) is int
    if field in LIST_FIELDS and is_int and (
        (op == "gte" and expected == 1) or (op == "gt" and expected == 0)
    ):
        cond = {"field": LIST_FIELDS[field], "op": "non_empty", "on_missing": on_missing}
        return cond, notes
    if field in STATE_FIELDS and op in ("eq", "ne") and isinstance(expected, bool):
        cond = {
            "field": STATE_FIELDS[field],
            "op": op,
            "value": "ENABLED" if expected else "DISABLED",
            "on_missing": on_missing,
        }
        return cond, notes

    key = FACT_KEYS.get(field, field.split(".", 1)[1].replace(".", "_"))
    target = f"facts.{key}.value"
    notes[field] = target
    cond = {"field": target, "op": op, "value": expected, "on_missing": on_missing}
    return cond, notes


def convert_check(raw: Any) -> tuple[dict[str, Any], dict[str, str]]:
    if not isinstance(raw, dict):
        raise Unconvertible("entry is not a mapping")
    extra = set(raw) - ALLOWED_KEYS
    if extra:
        raise Unconvertible(f"unknown keys {sorted(extra)}")

    condition, notes = convert_condition(raw)
    out: dict[str, Any] = {
        "id": raw.get("id"),
        "title": raw.get("title"),
        "severity": raw.get("severity"),
    }

    applies = raw.get("applies_to")
    if applies is not None:
        if not isinstance(applies, list) or not applies:
            raise Unconvertible("applies_to must be a non-empty list")
        mapped = {
            VENDOR_ALIASES.get(str(v).strip().lower(), str(v).strip().lower())
            for v in applies
        }
        if mapped != ALL_VENDORS:
            out["vendors"] = sorted(mapped)

    out["condition"] = condition

    mappings: dict[str, list[str]] = {}
    for fw in FRAMEWORKS:
        if fw in raw:
            vals = raw[fw]
            if not isinstance(vals, list):
                raise Unconvertible(f"{fw} must be a list")
            mappings[fw] = [str(v) for v in vals]
    if mappings:
        out["mappings"] = mappings

    if raw.get("remediation_key") is not None:
        out["remediation_key"] = raw["remediation_key"]
    return out, notes


def write_atomic(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    os.replace(tmp, path)


def dump(data: Any) -> str:
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True, default_flow_style=False, width=100)


def main() -> int:
    if not CHECKS_DIR.is_dir():
        print(f"missing {CHECKS_DIR}; run from the project folder", file=sys.stderr)
        return 2

    failed = False
    notes_all: dict[str, str] = {}
    pending_total = 0

    for path in sorted(CHECKS_DIR.glob("*.yaml")):
        if path.stat().st_size > MAX_FILE_BYTES:
            print(f"{path.name}: too large")
            failed = True
            continue
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError) as exc:
            print(f"{path.name}: unreadable ({type(exc).__name__})")
            failed = True
            continue
        if isinstance(doc, dict):
            print(f"{path.name}: already in engine format, skipped")
            continue
        if not isinstance(doc, list):
            print(f"{path.name}: unexpected top level")
            failed = True
            continue

        converted: list[dict[str, Any]] = []
        pending: list[Any] = []
        for raw in doc:
            try:
                item, notes = convert_check(raw)
            except Unconvertible as exc:
                pending.append(raw)
                ident = raw.get("id") if isinstance(raw, dict) else "?"
                print(f"  pending {ident}: {exc}")
                continue
            converted.append(item)
            notes_all.update(notes)

        write_atomic(path, HEADER + dump({"checks": converted}))
        if pending:
            PENDING_DIR.mkdir(parents=True, exist_ok=True)
            write_atomic(PENDING_DIR / path.name, dump(pending))
        pending_total += len(pending)
        print(f"{path.name}: {len(converted)} converted, {len(pending)} pending")

    if notes_all:
        print("\nfact fallbacks (UNKNOWN until the normalizer provides them):")
        for src, dst in sorted(notes_all.items()):
            print(f"  {src} -> {dst}")
    print(f"\npending total: {pending_total} (written to {PENDING_DIR})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())