# Demo script (about 2 minutes)

Setup: `python -m streamlit run app/main.py`. Start with `data\training_rules.json` absent.

| Step | Action | Expected |
|---|---|---|
| 1 | Upload `cisco/edge-r1-weak.cfg`, all frameworks | Cisco IOS auto-detected; 1 pass / 22 fail / 1 unknown |
| 2 | Upload `cisco/edge-r1-hardened.cfg` | 24 pass, 100% |
| 3 | Upload `fortinet/fw-hq-weak.conf` | 4 pass / 15 fail / 1 unknown / 4 N-A; NIST 4.8, CIS 0, ISO 0 |
| 4 | Upload `fortinet/fw-hq-hardened.conf` | 20 pass / 4 N-A, 100% |
| 5 | Upload `junos/srx-branch-weak.set` | Vendor not recognized: generic parser or Training prompt |
| 6 | Training page: load `junos-demo-rules.json` (or copy to `data\training_rules.json`) | Rules loaded |
| 7 | Re-upload both Junos files, vendor "Juniper Junos (trained rules)" | Weak 5/18/1 (NIST 8.3, CIS 13.3, ISO 9.1); hardened 9 pass / 15 fail (NIST 20.8, CIS 33.3, ISO 9.1) |
| 8 | Download PDF, open Findings and Reports pages | Findings with severity, evidence, remediation; no plaintext secrets |
| 9 | Refresh the browser | Saved results reload from `?audits=` |

Talking points: UNKNOWN is never pass or fail; scores are technical alignment, not certification; secrets are redacted.
