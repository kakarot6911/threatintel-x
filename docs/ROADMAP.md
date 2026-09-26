# Roadmap

Status legend: ✅ complete · 🟡 partial · ⬜ not started

## Phase 0 — Architecture & control plane ✅
CLAUDE.md, `.claude/rules`, `.claude/skills`, ADRs, spec traceability.

## Phase 1 — Repository foundation ✅
Python 3.12 package, config (`TIX_*`), structured logging with secret scrubbing, SQLAlchemy 2.0
(SQLite/PostgreSQL), pytest, ruff, mypy, bandit, pip-audit, CI, Docker.

## Phase 2 — Intelligence data model ✅
Source, CollectedItem, Observable, Provenance, ThreatActor, Campaign, Malware, Tool, Vulnerability,
Infrastructure, Relationship, Evidence, Assessment, IntelligenceRequirement, HumintReport,
CredentialExposure, RansomwareClaim, StatusChange, IntelProduct.

## Phase 3 — IOC pipeline ✅
Redaction, defang-aware extraction (IPv4/6, domain, URL, email, MD5/SHA1/SHA256, CVE, ATT&CK, BTC/ETH,
Telegram), normalisation, validation, dedup, provenance.

## Phase 4 — Collection ✅
RSS/Atom, STIX, TAXII 2.1, MISP, permitted Telegram (Bot API), HUMINT intake, MITRE sync, synthetic world.

## Phase 5 — Enrichment ✅
RDAP, DNS, Team Cymru ASN/GeoIP, VirusTotal, URLScan, AbuseIPDB, Shodan, Censys, synthetic fixtures;
cache, rate limit, retry, SSRF guard, reserved-space refusal.

## Phase 6 — Correlation & attribution ✅
Profiles, noisy-OR correlation, competing-hypothesis attribution with hard gates, graph pivots.

## Phase 7 — ATT&CK ✅
Real Enterprise ATT&CK release (version from bundle), explicit + keyword mapping, coverage matrix.

## Phase 8 — STIX 2.1 / TAXII 2.1 ✅
Validated export/import, local read-only TAXII server, taxii2-client round-trip test.

## Phase 9 — MISP / OpenCTI ✅ (live instance testing: 🟡)
PyMISP event mapping with MISP taxonomies/galaxies; pycti bundle push. Verified with fake clients;
not yet exercised against live MISP/OpenCTI instances.

## Phase 10 — Intelligence production ✅
Technical report, campaign report, actor profile, CISO brief, IOC bulletin (MD + CSV); IR-001..008 answers.

## Phase 11 — Analyst UI ✅
Server-rendered workbench: dashboard, review queue, item assessment + lifecycle, actors (graph), campaigns,
IOCs, investigation with pivots, ATT&CK matrix, reports, IRs, sources, integrations, collection.

## Phase 12 — Security / DevSecOps ✅
Auth (key/Basic/Bearer, fail-closed), CSP, CSRF, body limits, XSS/CSV/Markdown output encoding,
defusedxml, SSRF guard, container hardening, bandit + pip-audit in CI.

## Phase 13 — Real-world intelligence ✅
`threatintel collect-real`: full MITRE ATT&CK knowledge (groups, software, campaigns, ~18k relationships),
CISA KEV (with ransomware-use flag), abuse.ch Feodo Tracker + URLhaus, eight public research RSS feeds
(full article bodies), live RDAP + Team Cymru enrichment. Precision rules from measured data (ADR-012).

## Next (not started)
- ⬜ Live MISP + OpenCTI docker lab and contract tests against real instances
- ⬜ Alembic migrations (schema is currently created via `create_all`)
- ⬜ Background job runner for scheduled collection (currently CLI/cron-driven)
- ⬜ Sightings from internal telemetry (STIX `sighting`) and IOC expiry automation
- ⬜ Analyst-validated LLM assistant (summaries/ATT&CK suggestions) behind `llm/boundary.py`
- ⬜ Role-based access control (single shared API key today)
- ⬜ Pin resolved IP per request to close the DNS-rebinding TOCTOU window in `net.safe_get`
