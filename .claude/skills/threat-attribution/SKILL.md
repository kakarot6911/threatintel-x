---
name: threat-attribution
description: Evidence-based attribution methodology — infrastructure/malware/TTP/targeting/temporal overlap, alternative hypotheses and confidence gating. Use when changing the attribution engine or writing/reviewing any attribution statement.
---
# Attribution procedure

1. **Collect evidence by category**: infrastructure, malware (distinctive), tooling (commodity), TTP,
   targeting, temporal, language/timezone, campaign, public reporting. Each item: type, weight, source,
   confidence, timestamp, description (`models.intel.Evidence`).
2. **Discount weak signals**: commodity tools (Cobalt Strike, Mimikatz), shared hosting/ASNs, name servers,
   common ATT&CK techniques (capped), sector/timing coincidences (never a hypothesis on their own).
3. **Score every candidate** (competing hypotheses), not just the favourite. Use leave-one-out actor
   profiles when assessing a campaign already linked to an actor.
4. **Gate the level** (`config/scoring.yaml`): single category ⇒ ≤ LOW; HIGH ⇒ ≥3 categories,
   ≥2 independent sources, and malware/tooling/TTP evidence beyond infrastructure. Top-2 within the
   contested margin ⇒ downgrade and report both.
5. **Keep claims separate**: a vendor saying "X did it" is `reported-attribution` (public_reporting
   evidence). Our result is `attributed-to` only at MEDIUM+. Never feed our conclusions back into profiles.
6. **Consider alternatives explicitly**: shared/sold infrastructure, affiliate models (IAB → ransomware),
   false flags, tool leaks. Put them in caveats.
7. **LLM output** is `llm_generated` evidence, excluded from scoring until a named analyst validates it.
8. **Write it**: "We assess with HIGH confidence…", "…is likely associated with… (MEDIUM)", "…possibly
   associated… (LOW); the evidence does not support attribution", "Insufficient evidence…".
