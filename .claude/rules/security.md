---
paths: ["src/**/*.py", "Dockerfile", "docker-compose.yml", ".github/workflows/*.yml"]
---
# Security rules

- Secrets: only from `TIX_*` env vars as `SecretStr`; never log them (`logging_setup` scrubs common forms).
- Outbound HTTP: always `net.safe_get` / `EnrichmentProvider.http_get`. They enforce `TIX_ONLINE`,
  scheme allow-list, public-unicast resolution on EVERY redirect hop, size limits and timeouts.
- Enrichment must refuse private/documentation/special-use observables and must return
  `EnrichmentResult(error=...)` on failure — never a fabricated result.
- XML: `defusedxml` only. STIX: parse with `stix2.parse(..., allow_custom=True)` and skip invalid objects.
- HTML: Jinja2 autoescape (web templates); no inline scripts/styles (CSP `script-src 'self'`); graph SVG
  labels are `html.escape`d. Markdown products use `_md_safe` finalize.
- CSV exports neutralise formula injection (`_csv_safe`).
- API: key auth (X-API-Key / Basic / Bearer), constant-time compare, fails closed (503) with no key,
  body-size limit, security headers, same-origin check for browser (Basic) unsafe methods.
- Credentials: `extraction/redaction.py` runs before any persistence; only accounts + optional keyed
  HMAC fingerprints are stored.
- Telegram: Bot API only, allow-listed chats, pseudonymised authors. No MTProto scraping.
- Containers: non-root user, read-only root FS, `cap_drop: ALL`, `no-new-privileges`.
- Every security fix gets a regression test.
