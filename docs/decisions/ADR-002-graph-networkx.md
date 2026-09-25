# ADR-002: In-process NetworkX graph instead of Neo4j
Status: Accepted · 2026-09-25

**Context.** Pivoting (IOC → infrastructure → campaign → actor → TTP) needs graph traversal. Neo4j adds a
service, a query language and data duplication.

**Decision.** Build a `MultiDiGraph` from the repository on demand (`graph/graph.py`); use it for pivots
and SVG neighbourhood rendering. The node/edge model maps 1:1 to a property graph.

**Consequences.** + No extra infrastructure; deterministic tests. − Rebuilt per request (fine at
thousands of nodes; would need caching or Neo4j/OpenCTI at hundreds of thousands).
