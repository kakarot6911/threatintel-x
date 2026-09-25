"""Evidence-based attribution with competing hypotheses.

Rules enforced in code (not just in documentation):

1. Overlap in a single evidence category (e.g. shared IPs only) can never exceed LOW.
2. HIGH requires >= 3 categories, >= 2 independent sources, and at least one
   non-infrastructure technical category (malware / tooling / TTP / campaign).
3. Every candidate actor is scored; when the top two are within the contested
   margin the leading hypothesis is downgraded one level and both are reported.
4. LLM-generated evidence is listed but never scored until an analyst validates it.
5. Output uses estimative language; the result is an Assessment, never a fact.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from threatintel.analysis.correlation import CorrelationEngine, CorrelationResult, Profile, noisy_or
from threatintel.analysis.scoring_config import load_scoring
from threatintel.models.common import AttributionLevel, utcnow
from threatintel.models.intel import Assessment, Evidence

SIGNAL_TO_CATEGORY = {"identity": "public_reporting"}
TECHNICAL_NON_INFRA = {"malware", "tooling", "ttp", "campaign"}
_LEVEL_ORDER = [
    AttributionLevel.INSUFFICIENT,
    AttributionLevel.LOW,
    AttributionLevel.MEDIUM,
    AttributionLevel.HIGH,
]
_WEP = {
    AttributionLevel.HIGH: "We assess with HIGH confidence that {subject} is attributable to {actor}.",
    AttributionLevel.MEDIUM: "{subject} is likely associated with {actor} (MEDIUM confidence).",
    AttributionLevel.LOW: "{subject} is possibly associated with {actor} (LOW confidence); "
    "the evidence does not support attribution.",
}


@dataclass
class Hypothesis:
    actor_id: str
    actor_label: str
    score: float
    level: AttributionLevel
    evidence: list[Evidence]
    categories: set[str]
    independent_sources: int
    gating: list[str]


def _downgrade(level: AttributionLevel) -> AttributionLevel:
    return _LEVEL_ORDER[max(_LEVEL_ORDER.index(level) - 1, 0)]


class AttributionEngine:
    def __init__(
        self, correlation: CorrelationEngine | None = None, config: dict[str, Any] | None = None
    ) -> None:
        self.correlation = correlation or CorrelationEngine()
        cfg = config or load_scoring()["attribution"]
        self.category_weights: dict[str, float] = dict(cfg["category_weights"])
        self.thresholds: dict[str, dict[str, Any]] = dict(cfg["thresholds"])
        self.contested_margin = float(cfg["contested_margin"])

    # ------------------------------------------------------------------ evidence
    def evidence_from_correlation(self, result: CorrelationResult, source: str) -> list[Evidence]:
        out = []
        for sig in result.signals:
            category = SIGNAL_TO_CATEGORY.get(sig.category, sig.category)
            out.append(
                Evidence(
                    type=category,
                    weight=self.category_weights.get(category, 0.1),
                    confidence=min(sig.weight, 1.0),
                    source=source,
                    description=sig.explanation,
                    values=sig.values[:10],
                )
            )
        return out

    def _score(self, evidence: list[Evidence]) -> tuple[float, set[str]]:
        by_cat: dict[str, list[float]] = defaultdict(list)
        for ev in evidence:
            if ev.llm_generated and not ev.validated:
                continue
            by_cat[ev.type].append(ev.confidence)
        cat_scores = [self.category_weights.get(cat, 0.1) * noisy_or(vals) for cat, vals in by_cat.items()]
        return round(noisy_or(cat_scores), 3), set(by_cat)

    def _level(self, score: float, categories: set[str], sources: int) -> tuple[AttributionLevel, list[str]]:
        gating: list[str] = []
        for name in ("HIGH", "MEDIUM", "LOW"):
            t = self.thresholds[name]
            reasons = []
            if score < float(t["min_score"]):
                reasons.append(f"score {score:.2f} < {t['min_score']}")
            if len(categories) < int(t["min_categories"]):
                reasons.append(
                    f"{len(categories)} evidence categor{'y' if len(categories) == 1 else 'ies'} "
                    f"< {t['min_categories']}"
                )
            if sources < int(t["min_independent_sources"]):
                reasons.append(f"{sources} independent source(s) < {t['min_independent_sources']}")
            if t.get("requires_non_infrastructure") and not categories & TECHNICAL_NON_INFRA:
                reasons.append("no malware/tooling/TTP evidence beyond infrastructure")
            if not reasons:
                return AttributionLevel(name), gating
            gating.append(f"not {name}: " + "; ".join(reasons))
        return AttributionLevel.INSUFFICIENT, gating

    def evaluate(
        self,
        subject: Profile,
        candidates: list[Profile],
        extra_evidence: dict[str, list[Evidence]] | None = None,
    ) -> list[Hypothesis]:
        hypotheses = []
        extra_evidence = extra_evidence or {}
        for cand in candidates:
            result = self.correlation.compare(subject, cand)
            evidence = self.evidence_from_correlation(result, source=f"correlation:{subject.subject_id}")
            evidence.extend(extra_evidence.get(cand.subject_id, []))
            if not {e.type for e in evidence} & (
                TECHNICAL_NON_INFRA | {"infrastructure", "public_reporting"}
            ):
                continue  # timing / sector coincidence alone is not a hypothesis worth reporting
            score, cats = self._score(evidence)
            validated_sources = {
                e.source_origin or e.source
                for e in evidence
                if not (e.llm_generated and not e.validated) and not e.source.startswith("correlation:")
            }
            n_sources = len(subject.sources | validated_sources)
            level, gating = self._level(score, cats, n_sources)
            hypotheses.append(
                Hypothesis(cand.subject_id, cand.label, score, level, evidence, cats, n_sources, gating)
            )
        return sorted(hypotheses, key=lambda h: (-h.score, h.actor_label))

    def assess(
        self,
        subject: Profile,
        candidates: list[Profile],
        extra_evidence: dict[str, list[Evidence]] | None = None,
    ) -> Assessment:
        hyps = self.evaluate(subject, candidates, extra_evidence)
        caveats = [
            "Attribution is an analytic judgement, not a fact; it is revised as evidence changes.",
        ]
        llm_items = [e for h in hyps for e in h.evidence if e.llm_generated and not e.validated]
        if llm_items:
            caveats.append(
                f"{len(llm_items)} LLM-generated evidence item(s) excluded from scoring pending "
                f"analyst validation."
            )
        if not hyps or hyps[0].level == AttributionLevel.INSUFFICIENT:
            best = hyps[0] if hyps else None
            return Assessment(
                subject_id=subject.subject_id,
                kind="attribution",
                score=best.score if best else 0.0,
                level=AttributionLevel.INSUFFICIENT.value,
                statement=f"Insufficient evidence to associate {subject.label} with any tracked "
                "threat actor.",
                evidence=best.evidence if best else [],
                caveats=caveats + (best.gating if best else []),
                alternatives=[self._alt(h) for h in hyps[:5]],
            )

        top = hyps[0]
        level = top.level
        if (
            len(hyps) > 1
            and hyps[1].level != AttributionLevel.INSUFFICIENT
            and top.score - hyps[1].score < self.contested_margin
        ):
            level = _downgrade(level)
            caveats.append(
                f"Competing hypothesis: {hyps[1].actor_label} scores {hyps[1].score:.2f} vs "
                f"{top.score:.2f}; leading hypothesis downgraded to {level.value}."
            )
        if top.categories <= {"infrastructure"}:
            caveats.append(
                "Evidence is infrastructure overlap only; shared hosting, re-used or sold "
                "infrastructure and false flags cannot be excluded."
            )
        caveats.extend(top.gating)
        if level == AttributionLevel.INSUFFICIENT:
            names = " / ".join(h.actor_label for h in hyps[:2])
            statement = (
                f"Insufficient evidence to attribute {subject.label}; competing hypotheses "
                f"({names}) remain unresolved."
            )
        else:
            statement = _WEP[level].format(subject=subject.label, actor=top.actor_label)
        return Assessment(
            subject_id=subject.subject_id,
            kind="attribution",
            score=top.score,
            level=level.value,
            statement=statement,
            evidence=top.evidence,
            caveats=caveats,
            alternatives=[self._alt(h) for h in hyps[:5]],
            created_at=utcnow(),
        )

    @staticmethod
    def _alt(h: Hypothesis) -> dict[str, object]:
        return {
            "actor_id": h.actor_id,
            "actor": h.actor_label,
            "score": h.score,
            "level": h.level.value,
            "categories": sorted(h.categories),
            "independent_sources": h.independent_sources,
        }
