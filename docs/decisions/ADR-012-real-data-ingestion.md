# ADR-012: Rules for ingesting real-world intelligence
Status: Accepted · 2026-09-26

**Context.** Switching from the synthetic world to real sources (MITRE ATT&CK, CISA KEV, abuse.ch
Feodo Tracker / URLhaus, public research RSS) exposed failure modes synthetic data never showed.
Each rule below was derived from measuring real items, not assumed.

**Decisions.**
1. **Separate database.** Real data lives in its own DB (`data/threatintel-real.db`); it never mixes with
   the synthetic world.
2. **Structured feeds bypass free-text extraction.** KEV, Feodo, URLhaus and ATT&CK records map straight to
   entities/observables with provenance; each pull is recorded as one raw "snapshot" item for audit.
3. **Word-like aliases.** ~200 real ATT&CK names are ordinary words (Play, Royal, Silence, Carbon, Net, Ping).
   They match only in ALL CAPS when the KB writes them so (HAFNIUM) or when followed by a qualifier
   ("Play ransomware", "Silence group"); aliases under 4 characters never match
   (`config/ambiguous_aliases.txt`).
4. **Citations are not indicators.** Known-benign reference domains (`config/benign_domains.txt`) and the
   publisher's own domain are non-actionable unless defanged.
5. **Defanging publishers.** Per source `plain_indicators`: measured on real items, CISA, Talos, Securelist,
   ESET, Unit 42, the DFIR Report and BleepingComputer defang their IOCs, and their plain matches were
   references, Android package names (`com.abc.nexus`) or AV detection names (`trojan-dropper.androidos.agent.vu`).
   Microsoft lists real IOCs undefanged. For defanging publishers, plain network indicators are `reference-link`.
6. **Derived infrastructure is context.** Name servers / ASNs from enrichment are non-actionable
   (`infrastructure-context`) — `*.ns.cloudflare.com` is not an IOC.
7. **RDAP walks to the registered domain** (registries return 400 for sub-domains).
8. **No active DNS by default.** Resolving suspicious domains sends queries towards attacker-controlled name
   servers; `TIX_ACTIVE_DNS=true` opts in. RDAP/Team Cymru only query registries.
9. **Honest User-Agent.** CISA's CDN rejected a custom agent carried over httpx's TLS fingerprint; the agent
   now names the real client (`THREATINTEL-X/0.1 python-httpx/x.y`). We do not spoof browsers.
10. **Fetch errors are errors.** Non-2xx responses raise and are reported per source; an error page is never
    parsed as a feed.

**Consequences.** Precision over recall: some real IOCs published undefanged by a defanging publisher are
kept as non-actionable references (visible, searchable, not blocked). Lists are heuristics and are
versioned in `config/`.

## Evidence: blind attribution on real ATT&CK campaigns
With MITRE's claim hidden (`scripts/evaluate_attribution.py`), 25 campaigns: MEDIUM 8 (8 correct), LOW 7
(5 correct), insufficient evidence 10 (0 correct). Before knowledge-base relationship provenance counted as a
source, every campaign abstained (0 sources) — fixed in `ProfileBuilder._add_rel_sources`.
