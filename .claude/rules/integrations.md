---
paths: ["src/threatintel/integrations/**", "src/threatintel/enrichment/**", "src/threatintel/collectors/**", "src/threatintel/api/taxii.py"]
---
# Integration rules

- Every integration must work offline in tests via a fake client or HTTP mock and must be optional at runtime.
- Endpoints come only from configuration; never hard-code third-party URLs other than a provider's
  fixed public API base.
- MISP: use PyMISP objects and real taxonomies/galaxies (`tlp:`, `admiralty-scale:`,
  `estimative-language:`, `misp-galaxy:threat-actor`, `misp-galaxy:mitre-attack-pattern`). Distribution 0 by default.
- OpenCTI: push the same validated STIX bundle (pycti `stix2.import_bundle_from_json`); refuse invalid bundles.
- TAXII: read-only server under `/taxii2/`; client via `taxii2-client`. Two collections: all vs real-only.
- Imported third-party attributions become `reported-attribution`, never `attributed-to`.
- New enrichment providers subclass `EnrichmentProvider`, declare `supported`, `rate_per_minute`,
  `configured()`, and implement `_lookup` returning (result, confidence, reference).
