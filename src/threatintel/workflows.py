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


# ============================================================ real-world collection
@dataclass
class RealRunSummary:
    feeds: list[dict[str, Any]] = field(default_factory=list)
    rss: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    campaign_attributions: dict[str, int] = field(default_factory=dict)


def load_rss_sources(platform: Platform) -> list[Source]:
    import yaml

    from threatintel.models.common import SourceReliability

    path = platform.settings.config_dir / "sources.yaml"
    spec = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return [
        Source(
            id=s["id"],
            name=s["name"],
            source_type=SourceType.RSS,
            url=s["url"],
            reliability=SourceReliability(s.get("reliability", "C")),
            plain_indicators=bool(s.get("plain_indicators", True)),
            collection_policy="Public RSS/Atom syndication feed",
        )
        for s in spec.get("rss", [])
    ]


def run_real(
    platform: Platform,
    *,
    attack: bool = True,
    kev: bool = True,
    abusech: bool = True,
    rss: bool = True,
    rss_per_feed: int = 10,
    urlhaus_limit: int = 300,
    progress: Any = None,
) -> RealRunSummary:
    """Collect from real, publicly permitted sources. Requires TIX_ONLINE=true.

    Every fetch goes through the SSRF-guarded client; a failing source is recorded and skipped
    - its data is never guessed.
    """
    import json

    from threatintel.collectors.feeds import (
        FEODO_URL,
        KEV_URL,
        URLHAUS_URL,
        import_attack_knowledge,
        import_feodo,
        import_kev,
        import_urlhaus,
        parse_urlhaus_csv,
    )
    from threatintel.collectors.rss import RSSCollector
    from threatintel.collectors.synthetic import load_requirements
    from threatintel.net import require_online, safe_get

    def say(msg: str) -> None:
        if progress:
            progress(msg)

    settings = require_online(platform.settings)
    out = RealRunSummary()
    load_requirements(platform.repo, settings.config_dir / "intelligence_requirements.yaml")

    def _fetch(url: str) -> Any:
        resp = safe_get(url, settings=settings)
        resp.raise_for_status()
        return resp

    def step(name: str, fn: Any) -> None:
        say(f"-> {name}")
        try:
            res = fn()
            out.feeds.append(res.__dict__ if hasattr(res, "__dict__") else {"feed": name, "result": res})
        except Exception as exc:  # one broken source must not stop the run; the error is recorded
            out.errors.append(f"{name}: {type(exc).__name__}: {exc}")

    if attack:

        def _attack() -> Any:
            path = settings.data_dir / "attack" / "enterprise-attack.json"
            if not path.exists():
                from threatintel.collectors.mitre import MITRECollector

                MITRECollector(
                    Source(id="src-mitre-attack", name="MITRE ATT&CK", source_type=SourceType.MITRE), settings
                ).sync()
            return import_attack_knowledge(platform.repo, json.loads(path.read_text(encoding="utf-8")))

        step("MITRE ATT&CK groups/software/campaigns", _attack)
    if kev:
        step("CISA KEV", lambda: import_kev(platform.repo, _fetch(KEV_URL).json()))
    if abusech:
        step(
            "abuse.ch Feodo Tracker",
            lambda: import_feodo(platform.repo, _fetch(FEODO_URL).json()),
        )
        step(
            "abuse.ch URLhaus",
            lambda: import_urlhaus(
                platform.repo,
                parse_urlhaus_csv(_fetch(URLHAUS_URL).text),
                limit=urlhaus_limit,
                family_aliases=platform.repo.alias_dictionary().get("malware", {}),
            ),
        )
    if rss:
        pipeline = Pipeline(platform)
        for src in load_rss_sources(platform):
            say(f"-> RSS {src.name}")
            platform.repo.upsert_source(src)
            try:
                resp = safe_get(str(src.url), settings=settings)
                resp.raise_for_status()
                payload = resp.content
                items = sorted(
                    RSSCollector(src, payload=payload).collect(),
                    key=lambda i: i.published_at or i.collection_timestamp,
                    reverse=True,
                )[:rss_per_feed]
            except Exception as exc:
                out.errors.append(f"RSS {src.name}: {type(exc).__name__}: {exc}")
                continue
            stats: dict[str, Any] = {"feed": src.name, "items": 0, "new": 0, "observables": 0, "p1_p2": 0}
            for item in reversed(items):  # oldest first so knowledge accumulates in order
                try:
                    res = pipeline.process(item)
                except Exception as exc:  # one bad item must not abort the run; it is reported
                    out.errors.append(f"RSS {src.name} item '{item.title[:60]}': {type(exc).__name__}: {exc}")
                    continue
                stats["items"] += 1
                stats["new"] += int(not res.duplicate)
                stats["observables"] += len(res.observables)
                stats["p1_p2"] += int(bool(res.priority and res.priority["priority"] in ("P1", "P2")))
            out.rss.append(stats)
    say("-> campaign attribution")
    for a in assess_campaign_attributions(platform):
        out.campaign_attributions[a.level] = out.campaign_attributions.get(a.level, 0) + 1
    return out
