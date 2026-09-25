# Demo walkthrough (≈10 minutes)

```bash
make install
.venv/bin/threatintel demo      # seeds + processes the synthetic world
.venv/bin/threatintel serve     # prints an ephemeral API key; open http://127.0.0.1:8000
```
Browser login: any username, the printed key as password.

1. **Dashboard → review queue.** One P1: *SOC incident INC-SYN-0042*. Point out: internal telemetry
   is always org-relevant; ransomware + active exploitation → escalated to P1 with the arithmetic shown.
2. **Open the incident.** Raw report vs assessment are separate. Attribution is **MEDIUM → HOLLOW KESTREL**,
   with **VANTA MOTH** as a competing hypothesis; gating text says why it is not HIGH (single independent
   source). Correlation lists the exact shared hash / IP / CVE / name server and their weights. Confidence
   shows six factors. Lifecycle: try to CONFIRM as "system" (refused), then as your name.
3. **Campaigns → Midnight Relay.** Deliberately ambiguous: a vendor claims VANTA MOTH, infrastructure
   overlaps HOLLOW KESTREL. The platform says *insufficient evidence; competing hypotheses unresolved*.
   Explain ADR-009 (the co-mention bug found during development) and ADR-007 (no circular reporting).
4. **Investigate `sso-examplecorp.example`.** "Why is this IOC relevant?" + pivot paths
   IOC → IP → campaign → actor; enrichment shows the synthetic fixture (never a fabricated API answer).
5. **Intelligence → examplecorp combolist.** Passwords were redacted before storage; only the accounts and
   the *fact* of exposure remain (IR-003). Source is E/5 (paste site) so it is P3 with review, not P1.
6. **Sources.** The aggregator `derived_from` Vendor Alpha — it adds no corroboration.
7. **ATT&CK.** Version comes from the bundle (Enterprise ATT&CK v19.2 with the new *Stealth* tactic).
8. **Reports.** Technical report (detection opportunities, alternatives), CISO brief (decisions, no IOCs),
   IOC bulletin CSV (formula-injection safe), STIX bundle (valid; synthetic labelled; real-only filter).
9. **TAXII.** `curl -u x:$KEY http://127.0.0.1:8000/taxii2/api1/collections/`
10. **Safety.** `TIX_ONLINE=false` by default; enrichment refuses reserved/private observables; SSRF guard.
