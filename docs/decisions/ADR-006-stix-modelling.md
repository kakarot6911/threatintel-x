# ADR-006: STIX 2.1 modelling choices
Status: Accepted · 2026-09-25

- Tracked groups → `intrusion-set`; individual personas (e.g. an access broker handle) → `threat-actor`.
- Observables → SCO + `indicator` linked with `based-on`; indicator confidence = our confidence score.
- ATT&CK → `attack-pattern` reusing MITRE's STIX ids (merges cleanly with ATT&CK in MISP/OpenCTI).
- A source's attribution claim → `attributed-to` **created_by_ref the source's identity**; our assessment
  → `attributed-to` created_by THREATINTEL-X, plus an `opinion` (strongly-agree/agree).
- Collected items → `report` created_by the source; assessments → `note`.
- Synthetic objects: `labels: ["synthetic"]`, `x_threatintel_synthetic: true`; a TAXII collection excludes them.
- Deterministic uuid5 ids for stable re-exports. Every bundle passes `validate_bundle()` before leaving.
