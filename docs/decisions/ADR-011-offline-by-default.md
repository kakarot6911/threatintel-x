# ADR-011: Offline by default, SSRF-guarded when online
Status: Accepted · 2026-09-25

**Decision.** `TIX_ONLINE=false` by default. When enabled, all outbound HTTP goes through `net.safe_get`:
http/https only, every hop (incl. redirects) must resolve to public unicast addresses (unless
`TIX_ALLOW_PRIVATE_DESTINATIONS` for a lab), bounded size and timeouts. Providers refuse reserved observables.

**Known limitation.** Resolution and connection are separate steps (DNS-rebinding TOCTOU). Mitigation
(pinning the resolved IP per request) is on the roadmap.
