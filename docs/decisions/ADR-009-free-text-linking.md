# ADR-009: Conservative entity linking from free text
Status: Accepted · 2026-09-25

**Context.** During the build, a report saying "…the same address later used by KestrelLock operators"
caused naive co-mention linking to record *Midnight Relay uses KestrelLock* and a second attribution
claim, flipping the campaign's attribution to the wrong actor.

**Decision.** Free text yields only: IOC→named campaign (or actor if no campaign) `indicates`;
hash→family when exactly one family/tool is named; techniques→campaign when exactly one campaign and at
most one actor are named; `reported-attribution` when exactly one actor is named. All other co-mentions
become `related-to` (weak, ignored by profiles). Structured sources (STIX/MISP/feeds) or analysts create
`uses`/`exploits`.
