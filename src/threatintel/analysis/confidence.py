"""Transparent confidence model.

    score = 100 * sum(weight_f * value_f)   for f in
            source reliability, information credibility, corroboration,
            recency, specificity, technical evidence

Every factor carries a human-readable explanation, so any score can be defended
line-by-line. No factor can be set by an LLM.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from threatintel.analysis.scoring_config import load_scoring
from threatintel.models.common import (
    CREDIBILITY_LABELS,
    RELIABILITY_LABELS,
    ConfidenceLevel,
    ObservableType,
    Provenance,
    SourceType,
    utcnow,
)
from threatintel.models.intel import ConfidenceResult, FactorScore

# Enrichment context is not an independent *report* of maliciousness.
NON_REPORTING_SOURCES = {SourceType.ENRICHMENT, SourceType.MITRE}


def band(score: float, bands: dict[str, float] | None = None) -> ConfidenceLevel:
    cfg = bands or load_scoring()["confidence"]["bands"]
    for name, lower in sorted(cfg.items(), key=lambda kv: kv[1], reverse=True):
        if score >= lower:
            return ConfidenceLevel(name)
    return ConfidenceLevel.LOW


def independent_origins(provenance: Sequence[Provenance]) -> set[str]:
    return {p.origin for p in provenance if p.source_type not in NON_REPORTING_SOURCES}


def score_confidence(
    provenance: Sequence[Provenance],
    *,
    observable_type: ObservableType | None = None,
    last_seen: datetime | None = None,
    technical_evidence: float = 0.0,
    technical_explanation: str = "no corroborating technical evidence",
    specificity_override: float | None = None,
    now: datetime | None = None,
) -> ConfidenceResult:
    cfg = load_scoring()["confidence"]
    w = cfg["weights"]
    now = now or utcnow()
    reporting = [p for p in provenance if p.source_type not in NON_REPORTING_SOURCES] or list(provenance)

    if reporting:
        best_rel = max(reporting, key=lambda p: cfg["reliability"][p.reliability.value])
        rel_v = cfg["reliability"][best_rel.reliability.value]
        rel_x = (
            f"best source '{best_rel.source_name}' rated {best_rel.reliability.value} "
            f"({RELIABILITY_LABELS[best_rel.reliability.value]})"
        )
        best_cred = max(reporting, key=lambda p: cfg["credibility"][p.credibility.value])
        cred_v = cfg["credibility"][best_cred.credibility.value]
        cred_label = CREDIBILITY_LABELS[best_cred.credibility.value]
        cred_x = f"information rated {best_cred.credibility.value} ({cred_label})"
    else:
        rel_v, rel_x = 0.0, "no source"
        cred_v, cred_x = 0.0, "no source"

    origins = independent_origins(provenance)
    n = len(origins)
    corr_table = cfg["corroboration"]
    corr_v = float(corr_table[str(min(max(n, 1), 4))]) if n else 0.0
    corr_x = f"{n} independent origin(s): {', '.join(sorted(origins))}" if n else "no independent reporting"

    type_key = observable_type.value if observable_type else "default"
    half_life = cfg["half_life_days"].get(type_key, cfg["half_life_days"]["default"])
    if last_seen is not None:
        age_days = max((now - last_seen).total_seconds() / 86400.0, 0.0)
        rec_v = 0.5 ** (age_days / half_life)
        rec_x = f"last seen {age_days:.0f} day(s) ago; half-life {half_life} days"
    else:
        rec_v, rec_x = 0.5, "last-seen time unknown; neutral recency applied"

    if specificity_override is not None:
        spec_v, spec_x = specificity_override, f"specificity {specificity_override:.2f} (context-adjusted)"
    else:
        spec_v = cfg["specificity"].get(type_key, cfg["specificity"]["default"])
        spec_x = f"observable type '{type_key}' specificity {spec_v:.2f}"

    tech_v = min(max(technical_evidence, 0.0), 1.0)

    factors = [
        FactorScore(
            name="source_reliability",
            weight=w["source_reliability"],
            value=rel_v,
            contribution=w["source_reliability"] * rel_v * 100,
            explanation=rel_x,
        ),
        FactorScore(
            name="information_credibility",
            weight=w["information_credibility"],
            value=cred_v,
            contribution=w["information_credibility"] * cred_v * 100,
            explanation=cred_x,
        ),
        FactorScore(
            name="corroboration",
            weight=w["corroboration"],
            value=corr_v,
            contribution=w["corroboration"] * corr_v * 100,
            explanation=corr_x,
        ),
        FactorScore(
            name="recency",
            weight=w["recency"],
            value=rec_v,
            contribution=w["recency"] * rec_v * 100,
            explanation=rec_x,
        ),
        FactorScore(
            name="specificity",
            weight=w["specificity"],
            value=spec_v,
            contribution=w["specificity"] * spec_v * 100,
            explanation=spec_x,
        ),
        FactorScore(
            name="technical_evidence",
            weight=w["technical_evidence"],
            value=tech_v,
            contribution=w["technical_evidence"] * tech_v * 100,
            explanation=technical_explanation,
        ),
    ]
    score = round(sum(f.contribution for f in factors), 1)
    level = band(score, cfg["bands"])
    top = sorted(factors, key=lambda f: f.contribution, reverse=True)
    weakest = min(factors, key=lambda f: f.value)
    explanation = (
        f"{level.value} confidence ({score}/100). Strongest factor: {top[0].name.replace('_', ' ')} "
        f"({top[0].explanation}). Weakest: {weakest.name.replace('_', ' ')} ({weakest.explanation})."
    )
    return ConfidenceResult(score=score, level=level, factors=factors, explanation=explanation)
