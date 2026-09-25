---
name: security-review
description: Adversarial security and architecture review checklist for the THREATINTEL-X codebase (SSRF, injection, secrets, authn/z, unsafe fetching/parsing, dependency and container risk, data poisoning, LLM risk, provenance and attribution overconfidence). Use before closing any phase or when asked for a security review.
---
# Security review procedure

Do not modify code during the review. Produce a severity-ranked list (CRITICAL/HIGH/MEDIUM/LOW) with:
finding · evidence (file:line) · impact · recommended fix · regression test required.

Checklist:
1. **SSRF / unsafe fetching** — any `httpx`/`requests`/`urllib` call not via `net.safe_get`? Redirects re-checked? DNS rebinding noted?
2. **Injection** — raw SQL (only fixed identifiers allowed), STIX pattern escaping, CSV formula injection, command execution (none allowed).
3. **Parsing** — XML via defusedxml only; JSON size limits; STIX objects parsed individually.
4. **Secrets** — env only, `SecretStr`, never logged; redaction before persistence; `.env` git-ignored.
5. **AuthN/Z** — every non-public route behind the middleware; fails closed; constant-time compare; CSRF on Basic-auth form posts.
6. **Output encoding** — autoescape on HTML, SVG labels escaped, no inline JS/CSS (CSP), Markdown `_md_safe`.
7. **Data poisoning / malicious CTI** — hostile text in titles/IOCs, fake attribution claims, circular reporting, republished sources counted twice, synthetic leaking into "real" collections.
8. **Attribution overconfidence** — single-category HIGH? commodity tools weighted? contested hypotheses reported?
9. **LLM paths** — can any LLM output reach attribution/confidence without human validation?
10. **Dependencies & containers** — `pip-audit`, `bandit`, non-root, read-only FS, dropped caps, pinned base image.
11. **Missing tests** — each finding must name the test that would catch a regression.
