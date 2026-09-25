# ADR-008: Synthetic world in reserved documentation space
Status: Accepted · 2026-09-25

**Decision.** Demo data uses RFC 5737 IPs, RFC 3849 IPv6, RFC 2606 `.example` domains and RFC 5398 ASNs,
invented actor/malware names and hashes of `synthetic:<label>`. Real CVE ids and real ATT&CK techniques are
referenced (they are public facts), but their association with fictional actors is invented. Dates are
relative (`days_ago`) so the demo never goes stale.

**Consequences.** + Synthetic IOCs can never collide with, or be blocked as, real infrastructure; online
enrichment providers refuse them automatically. − Documentation-space IOCs in *real* reports are flagged
non-actionable, so the pipeline treats synthetic items specially (explicit, tested rule).
