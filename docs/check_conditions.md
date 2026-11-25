# Check condition grammar

`condition` in `data/checks/*.yaml` is exactly one of the forms below. `docs/check_schema.md` is stale; this file reflects the code (`auditor/compliance/models.py`).

| Form | Keys | Result |
|---|---|---|
| Leaf | `field`, `op`, `value` | Compares one baseline value |
| All | `all_of: [condition, ...]` | Fail beats not_configured, error, unknown; else pass |
| Any | `any_of: [condition, ...]` | Pass if any passes; then error, unknown; else fail |
| Any item | `field`, `any_match: condition` | Pass if at least one list item satisfies the sub-condition |
| No item | `field`, `none_match: condition` | Pass if no list item satisfies the sub-condition |

## any_match and none_match

- `field` must resolve to a list (`policies`, `interfaces`, `facts`, `logging.destinations`, `time_sync.servers`). Field validation rejects non-list fields at load time.
- The sub-condition is evaluated against each item. Field paths in it are relative to the item (`action`, `src`).
- List items that are not objects (for example `logging.destinations`) are exposed as `value`.
- `on_missing` on the outer condition applies when the list is absent. `value` and `op` are not allowed alongside `any_match` or `none_match`.
- Empty list: `any_match` fails, `none_match` passes.
- Item results: a matching item decides first (`any_match` passes, `none_match` fails). Otherwise any item error gives error, any UNKNOWN gives unknown, else the negative outcome. UNKNOWN is never turned into pass or fail.
- Evidence holds counts only (`<field>.count`, `<field>.matched`), so list contents are never copied into evidence, the database or the PDF.

```yaml
condition:
  field: policies
  none_match:
    all_of:
      - {field: action, op: eq, value: permit}
      - {field: src, op: eq, value: any}
      - {field: dst, op: eq, value: any}
```

```yaml
condition:
  field: logging.destinations
  any_match: {field: value, op: regex, value: '^10\.'}
```

## Mapping completeness

`python scripts/mapping_report.py [--unmapped]` prints, per scope (all checks, then each vendor) and framework, how many catalog controls have at least one mapped check. This is static rule-set coverage, unrelated to a device's `coverage_pct`.
