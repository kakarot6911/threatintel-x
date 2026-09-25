---
paths: ["src/threatintel/**/*.py"]
---
# Architecture rules

- Layering (import direction only flows downward):
  `api`, `web`, `cli` → `workflows` → `pipeline` → `analysis`, `enrichment`, `extraction`, `attack`, `stix`,
  `integrations`, `graph` → `storage` → `models`.
- `platform.Platform` is the composition root; do not construct engines ad hoc in handlers.
- `storage/repository.py` is the only module that issues SQL. Everything above speaks Pydantic models.
- Collectors only yield `CollectedItem`; they never extract, enrich or store (decoupling).
- Pipeline stages are deterministic and idempotent: ids are uuid5-derived (`stable_id`), re-ingesting the
  same content from the same source is a no-op.
- MISP, OpenCTI and TAXII are integrations at the edge; our data model is the core.
- Scoring constants live in `config/scoring.yaml`, never inline. Changing them needs an ADR note.
- Relationship vocabulary: `indicates`, `uses`, `exploits`, `related-to`, `resolves-to`, `belongs-to`,
  `uses-nameserver`, `exhibits-technique`, `reported-attribution` (source claim), `attributed-to` (ours).
- Free text yields only: IOC→campaign/actor `indicates`, hash→single named family, techniques→single
  campaign, single-actor `reported-attribution`. Anything else from text is `related-to`.
