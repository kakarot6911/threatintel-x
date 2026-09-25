# CTI methodology

## Intelligence cycle
Requirements (IR-001..008) → collection → processing (redaction, extraction, validation, enrichment)
→ analysis (correlation, attribution, confidence, priority) → production (reports, STIX) →
dissemination (TAXII, MISP, OpenCTI) → feedback (lifecycle: review, confirm, archive).

## Separation of layers
| Layer | Where | Rule |
|---|---|---|
| Raw source report | `collected_items` | stored as received (after secret redaction); `RAW_SOURCE_REPORT` |
| Observable | `observables` | normalised, validated, deduplicated; many provenance rows |
| Evidence | `Evidence` objects | one weighted reason, with source and category |
| Assessment | `assessments` | a judgement with score, level, factors, caveats; never a fact |
| Confirmed fact | lifecycle `CONFIRMED` | only a named human reviewer |

## Source evaluation (Admiralty / NATO)
Reliability A–F (source track record) and credibility 1–6 (the specific claim) are recorded and
scored separately. F and 6 are treated conservatively (0.3), not as neutral. Sources declare
`derived_from`; aggregators re-posting a vendor do not add corroboration.

## Confidence model (`config/scoring.yaml`)
| Factor | Weight | Value |
|---|---|---|
| Source reliability | 20% | best reporting source (A=1.0 … E=0.2, F=0.3) |
| Information credibility | 20% | best claim (1=1.0 … 5=0.2, 6=0.3) |
| Corroboration | 25% | independent origins: 1→0, 2→0.5, 3→0.8, 4+→1.0 |
| Recency | 10% | 0.5^(age/half-life); IP/URL 30 d, domain 120 d, hash 365 d |
| Specificity | 10% | hash 1.0 … IP 0.5, CVE 0.3; name servers 0.2 |
| Technical evidence | 15% | strongest enrichment signal (reputation, abuse score, new registration) |

Bands: 0–39 LOW · 40–69 MEDIUM · 70–89 HIGH · 90–100 VERY HIGH. Every factor is explained.

## Correlation
Noisy-OR over shared features: hash 0.90, URL 0.85, certificate 0.80, crypto 0.80, domain 0.75,
email 0.70, IP 0.55, distinctive malware 0.60, CVE 0.25, name server 0.20, commodity malware 0.15,
ASN 0.10, sector 0.10, time window 0.10, technique 0.05 each (capped at 0.45 total).

## Attribution
Evidence categories: infrastructure, malware, tooling, TTP, targeting, temporal, language, campaign,
public reporting. Score = noisy-OR of (category weight × category strength). Gates:
- LOW ≥ 0.25 · MEDIUM ≥ 0.55 with ≥ 2 categories · HIGH ≥ 0.80 with ≥ 3 categories, ≥ 2 independent
  sources and non-infrastructure technical evidence.
- Single-category evidence cannot exceed LOW; infrastructure-only gets an explicit caveat.
- Top two hypotheses within 0.10 ⇒ leading one downgraded; both reported.
- Timing/sector coincidence alone is never listed as a hypothesis.
- Source claims (`reported-attribution`) are evidence; our result (`attributed-to`) is written only at MEDIUM+.
- Actor profiles are built from source claims only — our conclusions never become their own evidence.

## Free-text linking rules
Text co-occurrence is weak structure. From free text the pipeline derives only IOC→named campaign/actor
`indicates`, hash→single named family, techniques→single named campaign, and single-actor attribution
claims. Everything else is `related-to` for analyst review. (This rule exists because the synthetic
"Midnight Relay" report mentions a second actor in passing — naive co-mention linking mis-attributed it.)

## Priority
`impact × confidence × recency(half-life 14 d) × relevance`, bands P1 ≥ .45, P2 ≥ .28, P3 ≥ .14, P4 ≥ .05.
Escalations (freshness-gated): ransomware inside the organisation → P1; org credential exposure,
sector-relevant active exploitation, recent sector ransomware → P2. Internal telemetry is always org-relevant.

## Estimative language
HIGH: "We assess with HIGH confidence that…" · MEDIUM: "…is likely associated with…" · LOW: "…is
possibly associated with…; the evidence does not support attribution" · otherwise "Insufficient evidence…".

## Evidence integrity
No fabricated actors, campaigns, IOCs, CVEs, techniques, sources or API responses. Failed enrichment is
recorded as an error. Synthetic data is marked at every layer and excluded from the "real" TAXII collection.

## Legal & safety boundaries
No access to illegal marketplaces, no interaction with threat actors, no purchase of data, no credential
validation, no unauthorised scanning, no Telegram scraping outside the Bot API, no storage of secrets.
Underground, ransomware-leak and credential-leak intelligence in this repository is synthetic.
