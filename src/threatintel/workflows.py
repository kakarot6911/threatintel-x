"""High-level workflows shared by the CLI, API and web UI."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from threatintel.analysis.lifecycle import PIPELINE_PATH
from threatintel.collectors.synthetic import SyntheticIntelligenceCollector, load_world, seed_knowledge
from threatintel.models.common import LifecycleStatus, SourceType, utcnow
from threatintel.models.entities import Campaign, Relationship, ThreatActor
from threatintel.models.intel import Assessment, CollectedItem, Source
from threatintel.pipeline import Pipeline, ProcessResult
from threatintel.platform import Platform

ANALYST_SOURCE = Source(
    id="src-analyst-intake",
    name="Analyst intake",
    source_type=SourceType.ANALYST,
    description="Text pasted or uploaded by an analyst.",
)


@dataclass
class DemoSummary:
    seeded: dict[str, int]
    items: int = 0
    duplicates: int = 0
    observables: int = 0
    credential_exposures: int = 0
    under_review: int = 0
    campaign_attributions: list[dict[str, Any]] = field(default_factory=list)


def assess_campaign_attributions(platform: Platform) -> list[Assessment]:
    """Re-assess every campaign against all actors (leave-one-out) and persist the result.

    Our own ``attributed-to`` relationship is written only at MEDIUM or above; below that the
    vendor's reported claim stays a claim.
    """
    out = []
    for camp in platform.repo.list_typed(Campaign):
        subject = platform.profiles.campaign(camp)
        subject.names = set()  # judge on technical evidence; reporting is added explicitly below
        candidates = platform.profiles.all_actor_profiles(exclude_campaign=camp.id)
        extra: dict[str, list[Any]] = {}
        for rel in platform.repo.list_relationships(
            source_ref=camp.id, relationship_type="reported-attribution"
        ):
            from threatintel.models.intel import Evidence

            for p in platform.repo.provenance_for(rel.id):
                extra.setdefault(rel.target_ref, []).append(
                    Evidence(
                        type="public_reporting",
                        weight=0.45,
                        confidence=rel.confidence / 100,
                        source=p.source_name,
                        source_origin=p.origin,
                        description=f"{p.source_name} reports attribution ({rel.confidence}/100)",
                    )
                )
        out.append(platform.attribution.assess(subject, candidates, extra))
    # Persist only after every campaign is assessed, so results never depend on iteration order.
    for assessment in out:
        platform.repo.save_assessment(assessment)
        campaign = platform.repo.get_entity(assessment.subject_id)
        if not isinstance(campaign, Campaign):
            continue
        if assessment.level in ("MEDIUM", "HIGH") and assessment.alternatives:
            actor_id = str(assessment.alternatives[0]["actor_id"])
            platform.repo.upsert_relationship(
                Relationship(
                    source_ref=campaign.id,
                    target_ref=actor_id,
                    relationship_type="attributed-to",
                    confidence=int(assessment.score * 100),
                    description=assessment.statement,
                    evidence=[e.description for e in assessment.evidence[:8]],
                    synthetic=campaign.synthetic,
                )
            )
    return out


def run_demo(platform: Platform, now: datetime | None = None) -> DemoSummary:
    now = now or utcnow()
    world = load_world(platform.settings.data_dir / "synthetic" / "world.json")
    seeded = seed_knowledge(platform.repo, platform.kb, world, now)
    summary = DemoSummary(seeded=seeded)
    pipeline = Pipeline(platform)
    source = Source(
        id="src-syn-collector", name="Synthetic collector", source_type=SourceType.SYNTHETIC, synthetic=True
    )
    for item in SyntheticIntelligenceCollector(source, world=world, now=now).collect():
        res = pipeline.process(item, now=now)
        summary.items += 1
        summary.duplicates += int(res.duplicate)
        summary.credential_exposures += res.credential_exposures
    summary.observables = sum(platform.repo.count_observables().values())
    summary.under_review = len(platform.repo.subjects_with_status([LifecycleStatus.UNDER_REVIEW]))
    for a in assess_campaign_attributions(platform):
        camp = platform.repo.get_entity(a.subject_id)
        summary.campaign_attributions.append(
            {
                "campaign": camp.name if camp else a.subject_id,
                "level": a.level,
                "score": a.score,
                "statement": a.statement,
            }
        )
    for ent in platform.repo.list_entities():
        platform.lifecycle.advance(ent.id, [LifecycleStatus.NEW, LifecycleStatus.TRIAGED], by="pipeline")
    return summary


def ingest_text(
    platform: Platform,
    title: str,
    content: str,
    *,
    source: Source | None = None,
    reliability: str | None = None,
    credibility: str | None = None,
    url: str | None = None,
) -> ProcessResult:
    src = source or ANALYST_SOURCE
    platform.repo.upsert_source(src)
    data: dict[str, Any] = {
        "source_id": src.id,
        "source_name": src.name,
        "source_type": src.source_type,
        "source_reliability": reliability or src.reliability.value,
        "title": title,
        "content": content,
        "url": url,
    }
    if credibility:
        data["information_credibility"] = credibility
    return Pipeline(platform).process(CollectedItem.model_validate(data))


def investigate(platform: Platform, value: str) -> dict[str, Any]:
    """Everything known about an observable, with the 'why is this relevant' narrative."""
    from threatintel.extraction.extractor import IOCExtractor

    repo = platform.repo
    candidates = repo.find_observables(value.strip())
    if not candidates:
        ex = IOCExtractor().extract(value)
        for o in ex.observables:
            found = repo.get_observable(o.type, o.value)
            if found:
                candidates.append(found)
    if not candidates:
        return {"found": False, "query": value}
    obs = candidates[0]
    related: list[dict[str, Any]] = []
    entities: dict[str, list[dict[str, Any]]] = {}
    for rel in repo.list_relationships(involving=obs.id):
        other_id = rel.target_ref if rel.source_ref == obs.id else rel.source_ref
        other_obs = repo.get_observable_by_id(other_id)
        if other_obs:
            related.append(
                {
                    "relationship": rel.relationship_type,
                    "type": other_obs.type.value,
                    "value": other_obs.value,
                    "confidence": rel.confidence,
                    "direction": "out" if rel.source_ref == obs.id else "in",
                }
            )
            continue
        ent = repo.get_entity(other_id)
        if ent:
            entities.setdefault(ent.entity_type, []).append(
                {
                    "id": ent.id,
                    "name": ent.name,
                    "relationship": rel.relationship_type,
                    "confidence": rel.confidence,
                    "evidence": rel.evidence,
                }
            )
    # second hop: campaign -> actor
    actors: list[dict[str, Any]] = []
    for camp in entities.get("campaign", []):
        for rel in repo.list_relationships(source_ref=camp["id"]):
            if rel.relationship_type in ("attributed-to", "reported-attribution"):
                actor = repo.get_entity(rel.target_ref)
                if isinstance(actor, ThreatActor):
                    actors.append(
                        {
                            "name": actor.name,
                            "via": camp["name"],
                            "relationship": rel.relationship_type,
                            "confidence": rel.confidence,
                        }
                    )
    techniques: set[str] = set()
    stix_to_tid = {t.stix_id: t for t in platform.kb.techniques.values()}
    for camp in entities.get("campaign", []):
        for rel in repo.list_relationships(source_ref=camp["id"], relationship_type="uses"):
            t = stix_to_tid.get(rel.target_ref)
            if t:
                techniques.add(f"{t.technique_id} {t.name}")
    conf = repo.latest_assessment(obs.id, "confidence")
    enrich = repo.enrichments_for(obs.type, obs.value)
    why = _why_relevant(obs.value, entities, actors, conf, enrich, obs.synthetic)
    return {
        "found": True,
        "observable": obs.model_dump(mode="json"),
        "confidence": conf.model_dump(mode="json") if conf else None,
        "enrichment": [e.model_dump(mode="json") for e in enrich],
        "related": related,
        "entities": entities,
        "actors": actors,
        "techniques": sorted(techniques),
        "why_relevant": why,
        "status": (repo.get_status(obs.id) or LifecycleStatus.NEW).value,
        "history": [h.model_dump(mode="json") for h in repo.status_history(obs.id)],
        "sources": [p.model_dump(mode="json") for p in obs.provenance],
    }


def _why_relevant(
    value: str,
    entities: dict[str, list[dict[str, Any]]],
    actors: list[dict[str, Any]],
    conf: Assessment | None,
    enrich: list[Any],
    synthetic: bool,
) -> list[str]:
    out = []
    if synthetic:
        out.append("SYNTHETIC: this observable belongs to the fictional demonstration dataset.")
    for camp in entities.get("campaign", []):
        out.append(
            f"Observed in reporting on campaign {camp['name']} (link confidence {camp['confidence']}/100)."
        )
    for mal in entities.get("malware", []):
        out.append(f"Associated with malware {mal['name']} ({mal['relationship']}).")
    for a in actors:
        verb = (
            "assessed as attributed to" if a["relationship"] == "attributed-to" else "reported by a source as"
        )
        out.append(
            f"Via {a['via']}: {verb} {a['name']} ({a['confidence']}/100) - an association, not proof "
            f"that {value} is operated by that actor."
        )
    if conf:
        out.append(f"Confidence {conf.level} ({conf.score}/100): {conf.statement}")
    if enrich:
        out.append(f"Enriched by {', '.join(sorted({e.provider for e in enrich}))}.")
    if not out:
        out.append("No links to tracked campaigns, malware or actors yet.")
    return out


def pipeline_path() -> list[str]:
    return [s.value for s in PIPELINE_PATH]
