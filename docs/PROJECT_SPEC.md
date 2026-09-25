# Project specification & traceability

The functional specification is the "THREATINTEL-X master build prompt" (sections 1–34). The copy
provided for this build was **truncated inside §34** (after "PRODUCT 2: Threat Actor Profile"); the
remaining products (campaign report, CISO brief, IOC bulletin) were implemented from the list in §1
("Analyst brief → Executive/CISO brief → machine-readable STIX → TAXII").

Each requirement below maps to where it is implemented and how it is verified.

| § | Requirement | Implementation | Verified by |
|---|---|---|---|
| 1 | End-to-end CTI pipeline; raw / processed / enriched / assessment / product separated | `pipeline.py`, separate tables in `storage/db.py` | `tests/integration/test_pipeline.py` |
| 2 | Safety & legal boundaries; synthetic underground data, clearly marked | `collectors/synthetic.py`, `scripts/build_synthetic_world.py`, ADR-008 | `test_synthetic_marking_everywhere`, `test_real_collection_excludes_synthetic` |
| 3 | Modular Python 3.12+, type hints, Pydantic, structured logging, pytest, ruff, mypy | `src/threatintel/*`, `logging_setup.py`, `pyproject.toml` | CI `quality` job (ruff, mypy strict-ish) |
| 4 | Intelligence requirements IR-001..008, linkable to products | `config/intelligence_requirements.yaml`, `analysis/requirements.py`, `IntelProduct.requirements` | `test_every_requirement_answers`, `test_requirement_content` |
| 5 | Common collector interface: RSS, STIX, TAXII, MISP, Telegram, MITRE, synthetic | `collectors/` | `tests/unit/test_collectors.py`, `test_taxii_collector_pulls_from_live_server` |
| 6 | Source reliability (A–F) separate from credibility (1–6); combined confidence | `models/common.py`, `analysis/confidence.py` | `tests/unit/test_confidence.py` |
| 7 | IOC extraction incl. crypto, Telegram, names; credentials redacted, never stored | `extraction/extractor.py`, `extraction/redaction.py` | `test_extractor.py`, `test_redaction.py`, `test_no_plaintext_secret_is_persisted` |
| 8 | Canonicalisation, dedup, provenance | `extraction/normalize.py`, `Repository.upsert_observable` | `test_normalize.py`, `test_dedup_and_merge` |
| 9 | Passive validation incl. staleness | `extraction/validate.py` | `test_validate.py` |
| 10 | Pluggable enrichment (RDAP, DNS, ASN, GeoIP, VT, URLScan, AbuseIPDB, Shodan, Censys); env keys; cache; rate limit; retry | `enrichment/` | `tests/unit/test_enrichment.py` |
| 11 | WHOIS/RDAP, DNS, ASN; resolves-to / belongs-to / nameserver relationships | `enrichment/providers.py`, `EnrichmentEngine._derive` | `test_engine_caches_and_derives` |
| 12 | Threat actor model with aliases; no attribution from IOC overlap | `models/entities.py`, ADR-007 | `test_infrastructure_only_never_exceeds_low` |
| 13 | Evidence-based attribution (typed, weighted evidence; LOW/MEDIUM/HIGH) | `analysis/attribution.py` | `tests/unit/test_attribution.py` |
| 14 | Campaign model and relationships | `models/entities.py`, `pipeline._link_entities` | `test_pipeline.py` |
| 15 | Malware model (RAT, stealer, ransomware, loader, botnet, backdoor, wiper); no malware handling | `Malware`, synthetic world | STIX export tests |
| 16 | Synthetic ransomware intelligence; no leak-site interaction | `RansomwareClaim`, world `ransomware_claims` | CISO brief test |
| 17 | Credential exposure without credentials | `CredentialExposure`, redaction | `test_ingest_validation_and_processing`, IR-003 test |
| 18 | Telegram via permitted mechanisms only; pseudonymised authors | `collectors/telegram.py` | `test_telegram_bot_allowlist_and_pseudonymisation` |
| 19 | HUMINT-style intake; raw vs assessment vs fact | `collectors/humint.py`, `StatementType`, lifecycle | `test_humint_separates_raw_and_assessment`, `test_confirmation_requires_human` |
| 20 | ATT&CK from STIX, version from data, tactic/technique/sub-technique | `attack/knowledge_base.py`, `data/attack/` | `test_attack.py` |
| 21 | STIX 2.1 with official library; export/import; validation | `stix/` | `tests/integration/test_stix.py` |
| 22 | TAXII 2.1 client (taxii2-client) + local demo workflow | `collectors/taxii.py`, `api/taxii.py` | `test_taxii.py` (incl. official client round-trip) |
| 23 | MISP via PyMISP using MISP's data model | `integrations/misp.py` | `test_integrations.py` |
| 24 | OpenCTI integration | `integrations/opencti.py` | `test_opencti_adapter` |
| 25 | Graph layer (NetworkX) with IOC→infra→campaign→actor→TTP queries | `graph/graph.py` | `test_graph_pivot_and_svg` |
| 26 | Deterministic correlation with explanations | `analysis/correlation.py` | `test_correlation.py` |
| 27 | Transparent confidence scoring; LLM cannot set attribution | `analysis/confidence.py`, `llm/boundary.py` | `test_confidence.py`, `test_llm_evidence_is_not_scored` |
| 28 | Prioritisation P1–P5 | `analysis/priority.py` | `test_priority.py` |
| 29 | Lifecycle statuses with history, reviewer | `analysis/lifecycle.py`, `lifecycle`/`status_history` tables | `test_lifecycle.py` |
| 30 | Analyst workbench | `web/` (server-rendered, ADR-010) | `test_every_ui_page_renders` |
| 31 | Threat actor dashboard with graph | `/actors/{id}` | UI test + screenshot |
| 32 | IOC investigation page with "why relevant" | `/investigate`, `workflows.investigate` | `test_query_endpoints` |
| 33 | Campaign view (timeline, sources, related campaigns) | `/campaigns/{id}`, campaign report | `test_all_products_render` |
| 34 | Intelligence products | `reporting/` | `test_all_products_render` |
