# Security policy

## Reporting a vulnerability
Please open a private security advisory on GitHub ("Security" → "Report a vulnerability") rather than a
public issue. Include reproduction steps and impact. I aim to respond within 7 days.

## Scope & design
THREATINTEL-X processes attacker-influenced content by design. Its controls are documented in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): SSRF-guarded outbound HTTP (off by default), defusedxml,
per-object STIX validation, secret redaction before persistence, fail-closed API-key auth, CSP without
inline script, CSRF origin checks, output encoding for HTML/SVG/Markdown/CSV, and a hardened container.

## Responsible use
This is a defensive research tool. Do not use it to access criminal marketplaces, interact with threat
actors, validate leaked credentials, scan systems you are not authorised to test, or scrape platforms in
violation of their terms. Demonstration data is synthetic.
