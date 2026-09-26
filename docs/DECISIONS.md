# Architecture decision log

Non-trivial decisions are recorded as ADRs in `docs/decisions/`. Do not silently reverse one — supersede it
with a new ADR.

| ADR | Decision |
|---|---|
| [001](decisions/ADR-001-storage.md) | SQLAlchemy; SQLite default, PostgreSQL supported |
| [002](decisions/ADR-002-graph-networkx.md) | In-process NetworkX graph instead of Neo4j |
| [003](decisions/ADR-003-integrations-at-the-edge.md) | MISP / OpenCTI / TAXII are integrations, not the core |
| [004](decisions/ADR-004-confidence-model.md) | Transparent weighted confidence, Admiralty dimensions kept separate |
| [005](decisions/ADR-005-llm-boundaries.md) | LLMs may assist but never judge |
| [006](decisions/ADR-006-stix-modelling.md) | STIX 2.1 modelling (intrusion-set vs threat-actor, claims vs assessments) |
| [007](decisions/ADR-007-attribution-gates.md) | Gated competing-hypothesis attribution, no circular reporting |
| [008](decisions/ADR-008-synthetic-world.md) | Synthetic world in reserved documentation space |
| [009](decisions/ADR-009-free-text-linking.md) | Conservative entity linking from free text |
| [010](decisions/ADR-010-server-rendered-ui.md) | Server-rendered workbench, strict CSP |
| [011](decisions/ADR-011-offline-by-default.md) | Offline by default, SSRF-guarded when online |
| [012](decisions/ADR-012-real-data-ingestion.md) | Rules for ingesting real-world intelligence (derived from measured data) |
