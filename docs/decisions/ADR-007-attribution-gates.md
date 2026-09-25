# ADR-007: Gated, competing-hypothesis attribution without circular reporting
Status: Accepted · 2026-09-25

**Context.** Naive "IOC overlap ⇒ actor" is the most common CTI error; so is echoing vendor attributions.

**Decision.** Score every candidate actor from categorised evidence; hard gates (single category ≤ LOW;
HIGH needs ≥ 3 categories, ≥ 2 independent sources, non-infrastructure evidence); contested top-2 ⇒
downgrade; campaign assessments use leave-one-out profiles and are persisted only after all are computed;
actor profiles are built from **source claims only**, never from our own `attributed-to` output.

**Consequences.** Found and fixed during build: order-dependent results and a self-reinforcing feedback
loop (our MEDIUM verdicts inflating the next campaign's evidence). Attribution is deliberately conservative:
shared sample + family + domain + TTPs scores 0.77 — MEDIUM, not HIGH — until corroborated further.
