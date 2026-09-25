---
paths: ["src/threatintel/models/**", "src/threatintel/storage/**"]
---
# Data model rules

- Tables mirror analytic layers: `collected_items` (raw), `observables`, `provenance`, `entities`
  (+ `entity_aliases`), `relationships`, `enrichments`, `assessments`, `lifecycle` + `status_history`, `records`.
- Ids: `stable_id(prefix, *parts)` → `<prefix>--<uuid5>`; STIX ids are derived again with `stix_id()`.
- Entities mirror STIX SDOs; add fields only with an export mapping in `stix/export.py`.
- Datetimes are timezone-aware UTC (`utcnow()`); SQLite returns naive values — normalise with `_aware`.
- `Assessment.statement_type` is always ANALYST_ASSESSMENT; raw reports stay RAW_SOURCE_REPORT.
- `credential_exposure` records never contain secrets.
