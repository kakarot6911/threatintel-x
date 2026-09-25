---
paths: ["src/threatintel/analysis/**", "src/threatintel/pipeline.py", "src/threatintel/reporting/**", "data/synthetic/**", "scripts/build_synthetic_world.py"]
---
# CTI methodology rules

## Evidence integrity
Never fabricate threat actors, campaigns, IOCs, malware, CVEs, ATT&CK techniques, sources, API
responses or enrichment results. When external data is unavailable use synthetic fixtures and mark them
synthetic. Never present synthetic intelligence as real. When attribution is uncertain, preserve the
uncertainty. When sources disagree, keep both claims and document the conflict. When an API is
unreachable, record the error; do not invent its answer.

## Scoring
- Confidence = weighted sum of reliability, credibility, corroboration (independent ORIGINS only),
  recency, specificity, technical evidence. Every factor carries an explanation string.
- Attribution: noisy-OR over evidence categories with hard gates (see `config/scoring.yaml`):
  single category ⇒ ≤ LOW; HIGH needs ≥3 categories, ≥2 independent sources and non-infrastructure evidence;
  contested top-2 ⇒ downgrade. Commodity tooling and name servers are weak signals.
- Priority = impact × confidence × recency × relevance, with explicit, freshness-gated escalations.
- ATT&CK: only ids present in the loaded release; keyword mappings are labelled "suggestion".
- Lifecycle: automation may reach UNDER_REVIEW; CONFIRMED/DISSEMINATED need a named human.

## Synthetic data
IPs from 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32; domains under `.example`;
ASNs AS64496–AS64511; invented actor/campaign/malware names; real CVE ids only as referenced vulnerabilities.
