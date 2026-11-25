# Architecture

## Goal

Vendor-agnostic compliance auditing: any configuration in, a normalized security baseline, framework-mapped findings, PDF report with remediation out.

## Pipeline

```
upload -> detector -> tokenizer -> parser -> adapter -> SecurityBaseline
       -> compliance engine -> scoring -> remediation -> PDF -> SQLite
```

| Stage | Module | Behavior |
|---|---|---|
| Upload | `audit/upload.py` | 5 MB, 100,000 lines, 10,000 chars/line; UTF-8/16/cp1252; NUL rejected; SHA-256; safe filename |
| Detect | `ingestion/detector.py` | Weighted signals, minimum score and ratio |
| Tokenize | `parsers/tokenizers/` | Indented, Fortinet `config/edit/set`, flat |
| Parse | `parsers/normalizer.py`, `audit/trained.py`, `audit/generic.py` | Built-in (Cisco IOS, FortiOS), trained rules (confidence >= 0.7), generic inference |
| Adapt | `audit/adapter.py` | Maps parser facts to the shared Pydantic schema |
| Assess | `compliance/` | YAML checks, strict operators, `on_missing`, vendor scoping; UNKNOWN never pass or fail |
| Score | `compliance/scoring.py` | Control statuses per framework; coverage over in-scope, pass rate over assessed |
| Remediate | `remediation/` | Sandboxed Jinja2, validated params, secret placeholders |
| Report | `reporting/` | ReportLab PDF |
| Store | `audit/store.py`, `db/` | SQLite, versioned migrations, cascading deletes |

## Unknown vendors

1. Detector fails or user picks a vendor with no parser.
2. Training page: user maps sample lines to baseline fields; rules saved to `training_rules.json`.
3. Trained parser applies rules with confidence and evidence; results flag trained-rule provenance.
4. Fallback: generic parser with per-field confidence.

## Data model

`devices (hostname, vendor unique)` -> `audits` -> `findings`; `reports (audit_id)` holds the PDF. Foreign keys on, cascade delete.

## Security design

- Hostile input: size, line and NUL limits; regex timeout and probe checks for trained rules.
- Secrets redacted before evidence storage, DB and PDF.
- Remediation templates sandboxed; parameters validated by regex.
- Parameterized SQL only; audit ID parameters validated as bounded integers.
- Container: non-root, read-only rootfs, dropped capabilities, loopback-only publish.
- No authentication: single-user tool.
