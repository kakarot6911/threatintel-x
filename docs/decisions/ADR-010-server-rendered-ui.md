# ADR-010: Server-rendered workbench (Jinja2) instead of a React SPA
Status: Accepted · 2026-09-25

**Decision.** FastAPI + Jinja2 templates, one CSS file, no JavaScript, SVG graphs rendered server-side.
Strict CSP (`script-src 'self'`, no inline styles/scripts), autoescaping everywhere.

**Consequences.** + No build chain, tiny attack surface, every page testable with TestClient.
− Less interactive (no client-side graph manipulation). The REST API remains available for a future SPA.
