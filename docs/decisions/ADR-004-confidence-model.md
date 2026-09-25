# ADR-004: Transparent weighted confidence model with separate Admiralty dimensions
Status: Accepted · 2026-09-25

**Decision.** Six weighted factors (reliability 20, credibility 20, corroboration 25, recency 10,
specificity 10, technical 15) configured in `config/scoring.yaml`, each returned with an explanation.
Corroboration counts independent *origins* (`derived_from` collapses re-posts); enrichment is context,
not corroboration. Unknown ratings (F/6) score 0.3, not neutral.

**Alternatives.** Bayesian model (harder to explain in review); ML classifier (opaque; no ground truth).

**Consequences.** + Every number is defensible line-by-line. − Weights are expert judgement; changes must be
recorded here.
