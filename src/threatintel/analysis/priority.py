"""Risk prioritisation:  priority = impact x confidence x recency x relevance  (each 0..1).

A small set of explicit escalation rules sit on top of the product so that, for
example, a confirmed exposed credential for one of *our* domains is never P4 just
because it is a few weeks old. Rules are listed in the explanation when they fire.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from threatintel.analysis.scoring_config import load_scoring
from threatintel.models.common import PRIORITY_LABELS, Priority


@dataclass
class PriorityInput:
    impact_factors: list[str] = field(default_factory=list)  # keys of scoring.yaml priority.impact
    confidence: float = 0.5  # 0..1
    recency: float = 1.0  # 0..1
    sector_match: bool = False
    region_match: bool = False
    org_asset_match: bool = False  # touches our own domains / accounts
    cvss: float | None = None


@dataclass
class PriorityResult:
    priority: Priority
    score: float
    components: dict[str, float]
    explanation: list[str]

    @property
    def label(self) -> str:
        return f"{self.priority.value} {PRIORITY_LABELS[self.priority.value]}"


def relevance(inp: PriorityInput) -> tuple[float, str]:
    if inp.org_asset_match:
        return 1.0, "directly involves organisation assets"
    if inp.sector_match and inp.region_match:
        return 0.85, "matches organisation sector and region"
    if inp.sector_match:
        return 0.7, "matches organisation sector"
    if inp.region_match:
        return 0.5, "matches organisation region"
    return 0.3, "no direct organisational relevance established"


def score_priority(inp: PriorityInput) -> PriorityResult:
    cfg = load_scoring()["priority"]
    impacts = cfg["impact"]
    factors = [f for f in inp.impact_factors if f in impacts]
    impact = max((impacts[f] for f in factors), default=impacts["default"])
    if inp.cvss is not None and inp.cvss >= 9.0:
        impact = max(impact, impacts["critical_vulnerability"])
    rel, rel_x = relevance(inp)
    score = round(impact * inp.confidence * inp.recency * rel, 4)

    bands = sorted(cfg["bands"].items(), key=lambda kv: kv[1], reverse=True)
    priority = next(Priority(name) for name, lower in bands if score >= lower)
    explanation = [
        f"impact {impact:.2f} ({', '.join(factors) or 'default'})",
        f"confidence {inp.confidence:.2f}",
        f"recency {inp.recency:.2f}",
        f"relevance {rel:.2f} ({rel_x})",
        f"product {score:.3f} -> {priority.value}",
    ]
    order = [Priority.P1, Priority.P2, Priority.P3, Priority.P4, Priority.P5]

    def escalate(to: Priority, why: str) -> None:
        nonlocal priority
        if order.index(to) < order.index(priority):
            priority = to
            explanation.append(f"escalated to {to.value}: {why}")

    fresh = inp.recency >= 0.25  # escalation rules only apply to current intelligence
    if "exposed_credential" in factors and inp.org_asset_match and inp.confidence >= 0.4 and fresh:
        escalate(Priority.P2, "credential exposure affecting organisation accounts")
    if "active_exploitation" in factors and inp.sector_match and inp.confidence >= 0.4 and fresh:
        escalate(Priority.P2, "active exploitation relevant to organisation sector")
    if "ransomware" in factors and inp.org_asset_match and inp.confidence >= 0.4 and fresh:
        escalate(Priority.P1, "ransomware activity inside the organisation")
    if "ransomware" in factors and inp.sector_match and inp.recency >= 0.5 and inp.confidence >= 0.55:
        escalate(Priority.P2, "recent ransomware activity in organisation sector")
    return PriorityResult(
        priority,
        score,
        {"impact": impact, "confidence": inp.confidence, "recency": inp.recency, "relevance": rel},
        explanation,
    )
