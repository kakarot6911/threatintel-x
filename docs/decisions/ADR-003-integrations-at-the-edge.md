# ADR-003: MISP, OpenCTI and TAXII are integrations, not the core
Status: Accepted · 2026-09-25

**Context.** It is tempting to build on OpenCTI/MISP directly, but that outsources the analysis the
project exists to demonstrate and makes the demo depend on a multi-container stack.

**Decision.** Our data model and deterministic pipeline are the core. STIX 2.1 is the interchange format:
the same validated bundle feeds TAXII (served locally), OpenCTI (pycti) and informs MISP mapping (PyMISP
with native taxonomies/galaxies). Imported third-party attributions are stored as claims.

**Consequences.** + Runs offline; mappings defined once; testable with fakes. − Live-instance contract tests
still to do (roadmap).
