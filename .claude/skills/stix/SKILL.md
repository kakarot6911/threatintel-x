---
name: stix
description: STIX 2.1 modelling, bundle construction, markings, external references, validation and import rules for THREATINTEL-X. Use when editing stix/export.py, stix/importer.py, the TAXII server, or anything that produces/consumes STIX.
---
# STIX 2.1 procedure

- Build objects with the official `stix2` library (v21 classes); custom properties are `x_threatintel_*`
  with `allow_custom=True`.
- Mapping: groups → `intrusion-set`; personas → `threat-actor`; campaigns → `campaign`; families →
  `malware` (`is_family: true`); CVEs → `vulnerability` with `external_references[source_name=cve]`;
  observables → SCO + `indicator` (`pattern_type: stix`) + `based-on`; techniques → `attack-pattern`
  reusing MITRE's STIX id and `mitre-attack` external reference; sectors → `identity` (class) +
  `targets`; regions → `location` + `targets`; collected items → `report` (created_by the source identity);
  assessments → `note`; our attributions → `attributed-to` + `opinion`.
- Source claims: `attributed-to` with `created_by_ref` = the claiming source's identity.
- Every SDO/SRO: `created_by_ref`, TLP `object_marking_refs`, confidence where meaningful; synthetic
  objects get `labels: ["synthetic"]` and `x_threatintel_synthetic: true`.
- Deterministic ids: `stix_id(type, internal_id)` (uuid5) so re-exports are stable.
- Pattern values must escape `\` and `'` (`pattern_for`).
- Always run `validate_bundle()` (per-object parse + referential integrity) before export/push; a
  bundle with errors must not be pushed to OpenCTI.
- Import: parse each object, skip (and report) invalid ones; imported `attributed-to` ⇒ `reported-attribution`.
