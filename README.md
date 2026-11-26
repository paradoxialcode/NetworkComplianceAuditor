# AI-Driven Multi-Vendor Network Security Compliance Auditor

Upload network device configurations, normalize them to a vendor-neutral schema, assess them against NIST SP 800-53, CIS Controls v8 and ISO/IEC 27001 mappings, and get per-device PDF reports with CLI remediation.

Scores describe technical alignment of mapped controls only. They are not a compliance certification.

## Features

- Built-in parsers: Cisco IOS, FortiOS. Unknown vendors: trained rules (Training page) or a generic inferred parser.
- Compliance engine: YAML checks, type-strict operators, UNKNOWN is never pass or fail, per-vendor scoping.
- Scoring: coverage over in-scope controls, pass rate over assessed controls.
- Remediation: sandboxed Jinja2 templates with placeholders for secrets.
- Storage: SQLite (devices, audits, findings, reports). Secrets are redacted from evidence, DB and PDF.
- Upload limits: 5 MB, 100,000 lines, 10,000 characters per line, NUL bytes rejected.

## Run locally

Python 3.12 (3.11+ supported by `pyproject.toml`).

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt -r requirements-dev.txt
python -m streamlit run app/main.py
```

Linux or macOS: `source .venv/bin/activate`.

## Run with Docker

```bash
docker compose up --build
```

- UI: http://127.0.0.1:8501 (published on loopback only; there is no authentication).
- Container: non-root (uid 10001), read-only root filesystem, all capabilities dropped, `no-new-privileges`.
- Persistent state in the `auditor-data` volume: the SQLite DB and `training_rules.json`.
- Reproducible build: dependencies install from `requirements.lock` with `--require-hashes`.
- Pin the base image: `docker build --build-arg PYTHON_IMAGE=python:3.12-slim@sha256:<digest> .`

Regenerate the lock after changing `requirements.txt`:

```bash
pip install pip-tools
pip-compile --generate-hashes --allow-unsafe --strip-extras -o requirements.lock requirements.txt
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `AUDITOR_DATA_DIR` | `<repo>/data` | Checks, frameworks, remediation, samples |
| `AUDITOR_DB_PATH` | `<repo>/instance/audits.db` | SQLite file |
| `AUDITOR_TRAINING_RULES` | `<data dir>/training_rules.json` | Trained rule file |
| `AUDITOR_MAX_UPLOAD_MB` | `5` | Upload cap, 1 to 50 |

`.streamlit/config.toml` `maxUploadSize` is a separate browser-level cap; raise both together.

## Demo data

Samples: `data/samples/{cisco,fortinet,junos}/`. For Junos, enable the trained rules first:

```powershell
Copy-Item data\samples\junos\junos-demo-rules.json data\training_rules.json
```

See `docs/demo-script.md` for expected results.

## Tests and checks

```bash
python -m pytest -q
bandit -q -r auditor app
pip-audit --require-hashes --disable-pip --no-deps -r requirements.lock
```

`test_large_file_is_fast` can fail under coverage overhead only.

## Layout

| Path | Content |
|---|---|
| `app/` | Streamlit entry point and pages |
| `auditor/` | Library: ingestion, parsers, audit pipeline, compliance, remediation, reporting, db, training |
| `data/` | YAML checks, framework catalogs, remediation templates, samples |
| `docs/` | Architecture, check schema, demo script |
| `tests/` | pytest suite |

## Security notes

- No authentication or multi-user isolation. Run locally or behind an authenticating reverse proxy.
- Audit IDs in the URL (`?audits=`) grant read access to stored audits for anyone who can reach the app.
- Jinja2 remediation templates run sandboxed; user regexes are timeout- and probe-checked.

## Authors

- Maitrey Suthar
- Omkar Jaiswal
- Aditya Vishwakarma
- Ashish Yadav

Built as a B.Tech Cyber Security and Digital Forensics project.

## License

MIT. See [LICENSE](LICENSE).
