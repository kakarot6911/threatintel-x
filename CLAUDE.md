# THREATINTEL-X — Claude Code Instructions

## Mission
THREATINTEL-X is an evidence-first Cyber Threat Intelligence platform: collection → redaction →
IOC extraction → validation → enrichment → correlation → attribution → confidence → priority →
lifecycle → STIX 2.1 / TAXII 2.1 / MISP / OpenCTI → intelligence products.
It is a portfolio/research project. Favour correctness, provenance and explainability over feature count.

## Commands
- `make install` — venv (Python 3.12) + dev extras · `make check` — everything CI runs
- `make test` / `make lint` / `make type` / `make security`
- `.venv/bin/threatintel demo` — synthetic end-to-end run · `.venv/bin/threatintel serve` — API + TAXII + UI
- `python scripts/build_synthetic_world.py` — regenerate `data/synthetic/world.json`

## Engineering principles
1. Build incrementally; one roadmap phase at a time (see @docs/ROADMAP.md).
2. Inspect existing code before modifying it; match its idiom.
3. Keep components modular and testable; the repository (`storage/repository.py`) is the only SQL.
4. Never hard-code secrets. Config comes from `TIX_*` env vars (`config.py`).
5. External APIs have mocked tests (respx / fake clients). Tests never touch the network.
6. Deterministic security logic must not depend on an LLM.
7. Every intelligence object keeps provenance (`Provenance` rows).
8. Never silently convert uncertain intelligence into fact.
9. Attribution is evidence-based and multi-category; IOC overlap alone is never attribution.
10. Synthetic data is always marked (`synthetic=True`, `labels: ["synthetic"]`) and lives only in
    RFC 5737 / RFC 2606 / RFC 5398 documentation space.
11. Never store plaintext credentials — redaction runs before persistence.
12. Never interact with unauthorised infrastructure, bypass access controls or scrape in violation of ToS.
13. Network access is off by default (`TIX_ONLINE`); outbound HTTP goes through `net.safe_get` (SSRF guard).
14. Run tests after meaningful changes; run `make check` before calling a phase done.
15. Update docs and ADRs when architecture changes (`docs/decisions/`). Do not silently reverse an ADR.

## CTI principles
SOURCE → INFORMATION → OBSERVABLE → EVIDENCE → CORRELATION → ASSESSMENT → PRODUCT are distinct
layers (distinct tables). Always preserve source, collection time, processing time, provenance,
confidence and analyst assessment. Source reliability (A–F) and information credibility (1–6) are
scored separately. Republished sources (`derived_from`) are not independent corroboration.
Source attribution claims (`reported-attribution`) are never merged with our assessments (`attributed-to`),
and our own conclusions are never fed back into actor profiles (no circular reporting).

## Intelligence language
Use: assessed, likely, possibly, evidence indicates, corroborated, insufficient evidence, with a
confidence level. Avoid unsupported definitive attribution.

## LLM rules
LLMs may assist with extraction, summarisation, clustering, drafting and ATT&CK *suggestions*.
They may NOT determine attribution, IOC validity, vulnerability existence, final confidence or
actor identity. Enforced in `llm/boundary.py`; LLM evidence is unscored until a named human validates it.

## Workflow per phase
inspect → plan → implement → test → security-review → document → verify → summarise.
Do not advance while the current phase has known critical failures.

## Definition of done
Implementation + tests + error handling + security validation + docs + representative fixtures +
observable output (CLI/API/UI). "It runs" is not done.

## Where things are
- Architecture: @docs/ARCHITECTURE.md · Roadmap/current phase: @docs/ROADMAP.md
- Methodology: @docs/CTI_METHODOLOGY.md · Decisions: @docs/DECISIONS.md · Spec: docs/PROJECT_SPEC.md
- Path-specific rules: `.claude/rules/` · Specialised procedures: `.claude/skills/`
