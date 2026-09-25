# Threat model

A CTI platform ingests attacker-influenced content by design. Assets, entry points and controls:

| Threat | Entry point | Control | Test |
|---|---|---|---|
| SSRF to internal services / cloud metadata | feed URLs, TAXII/MISP/OpenCTI URLs, redirects | `net.safe_get`: scheme allow-list, public-unicast check on every hop, offline default | `tests/unit/test_net.py` |
| Enriching attacker-chosen internal targets | observables | providers refuse private/reserved/special-use values | `test_refuses_reserved_observables` |
| XML entity expansion / XXE | RSS/Atom | `defusedxml` | `test_rss_rejects_entity_expansion` |
| Malformed STIX / poisoned bundles | STIX upload, TAXII | per-object `stix2.parse`, invalid objects skipped, referential validation | `test_invalid_objects_are_skipped_not_imported` |
| Stored XSS via CTI text | titles, content, IOCs | Jinja autoescape, escaped SVG, CSP without inline script/style | `test_stored_xss_is_escaped`, `test_svg_escapes_labels` |
| HTML injection via Markdown products | report fields | `_md_safe` finalize | `test_markdown_products_neutralise_html` |
| CSV formula injection | IOC bulletin CSV | `_csv_safe` | `test_reports_and_csv_injection` |
| Secret leakage | pasted dumps, logs | redaction before persistence; log scrubbing; `SecretStr` | `test_no_plaintext_secret_is_persisted`, `test_redaction.py` |
| Unauthenticated access | API/UI/TAXII | API key (header/Basic/Bearer), constant-time compare, fail-closed 503 | `test_auth_modes`, `test_no_key_configured_fails_closed` |
| CSRF via browser Basic auth | UI forms | same-origin (Origin/Referer) check on unsafe methods without custom header | `test_csrf_protection_for_browser_auth` |
| Resource exhaustion | large bodies | `TIX_MAX_BODY_BYTES` (413), response size caps, pagination limits | `test_security_headers_and_body_limit` |
| Attribution manipulation (planted IOCs, fake claims, echo chambers) | any source | multi-category gates, independence via `derived_from`, claims ≠ assessments, no circular reporting | `test_attribution.py`, `test_republished_source_is_not_independent` |
| Synthetic data leaking as real | exports | synthetic flags at every layer; real-only TAXII collection; `--no-synthetic` export | `test_synthetic_objects_are_labelled_and_filterable` |
| LLM hallucination becoming intelligence | future assistant | `llm/boundary.py` | `test_llm_boundary.py` |
| Container escape / privilege | runtime | non-root, read-only FS, caps dropped, no-new-privileges | CI docker job asserts non-root |

**Residual risks:** DNS-rebinding TOCTOU between resolution and connection; single shared API key (no RBAC);
SQLite not suited to concurrent multi-writer production use (use PostgreSQL).
