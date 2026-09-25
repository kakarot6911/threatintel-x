---
name: cti-analysis
description: Apply professional CTI methodology (source evaluation, IOC lifecycle, confidence, corroboration, intelligence requirements) when designing or changing analysis logic, triaging intelligence, or reviewing analytic output in THREATINTEL-X.
---
# CTI analysis procedure

Use this when touching `analysis/`, `pipeline.py`, scoring config, or when asked to assess intelligence.

## 1. Frame against requirements
Identify which Intelligence Requirement(s) (IR-001..IR-008, `config/intelligence_requirements.yaml`)
the work serves. Intelligence without a requirement is collection, not intelligence.

## 2. Evaluate the source and the information separately
- Source reliability A–F reflects track record; information credibility 1–6 reflects the claim.
- A reliable source can report doubtful information and vice versa. Never collapse them.
- Check independence: `derived_from` (re-posts, aggregators) is NOT corroboration.

## 3. Walk the IOC lifecycle
extract (defang-aware) → normalise → validate (syntax, TLD, routability, empty-file hashes, unknown ATT&CK ids)
→ enrich (passive first) → correlate → score → decay (half-lives per type) → review → disseminate → expire.
Documentation-range / private IPs from real sources are *not actionable*.

## 4. Score confidence transparently
Use `score_confidence`; report every factor. Corroboration counts independent origins only; enrichment
context is not a report. Name servers and commodity infrastructure get low specificity.

## 5. State judgements in estimative language
"assessed", "likely", "possibly", "insufficient evidence" + level. Separate RAW SOURCE REPORT,
ANALYST ASSESSMENT and CONFIRMED FACT (only a named human can confirm).

## 6. Check your work
- Would the judgement survive if the single strongest source were wrong?
- Is anything synthetic presented as real? Is any secret persisted?
- Add a behavioural test for the analytic rule you changed.
