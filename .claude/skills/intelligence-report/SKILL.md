---
name: intelligence-report
description: Structure and standards for THREATINTEL-X intelligence products — technical report, threat actor profile, campaign report, CISO brief and IOC bulletin. Use when creating or modifying report templates or writing any finished intelligence.
---
# Intelligence product standards

Every product (templates in `src/threatintel/reporting/templates/`):
- Header: title, **TLP**, generation time, producer, ATT&CK version, IRs answered.
- **SYNTHETIC DATA NOTICE** whenever any input is synthetic.
- Footer: analytic standards + "No LLM determined any judgement in this product."
- Estimative language with confidence levels; source claims shown as claims.

| Product | Audience | Must contain |
|---|---|---|
| Technical report | SOC / DE | exec summary, observed activity, IOC table w/ confidence, infrastructure, malware, ATT&CK, evidence, confidence + alternatives, detection opportunities, recommended actions, sources |
| Campaign report | CTI | timeline, actor (claims vs assessment), infrastructure, malware/CVEs, TTPs, related campaigns (correlation), sources |
| Actor profile | CTI / leadership | aliases, assessed motivation, targets, campaigns (source-reported + our assessment), capabilities (commodity flagged), TTPs, infrastructure, HUMINT (raw vs assessment) |
| CISO brief | Executives | bottom line, decisions needed (P1/P2), sector landscape, credential exposure (no secrets), recommended decisions — no raw IOCs |
| IOC bulletin | Tooling | actionable IOCs above threshold, confidence, first/last seen, lifecycle; CSV with formula-injection protection |

Rendering: Jinja2 with `StrictUndefined` and `_md_safe` finalize (neutralises HTML in untrusted values).
Test each product for its required sections (`tests/integration/test_reporting.py`).
