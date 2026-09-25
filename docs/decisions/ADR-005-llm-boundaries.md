# ADR-005: LLMs may assist but never judge
Status: Accepted · 2026-09-25

**Decision.** No LLM in the analysis path. `llm/boundary.py` defines the only entry point: forbidden tasks
(attribution, IOC validity, vulnerability existence, final confidence, actor identity) raise; suggestions are
`llm_generated` and unvalidated; the attribution engine refuses to score unvalidated LLM evidence; only a
named human can validate. Default assistant is `NullAssistant`.

**Consequences.** + Hallucinations cannot become intelligence. − Useful drafting/summarisation is not yet
wired (roadmap), by design behind this boundary.
