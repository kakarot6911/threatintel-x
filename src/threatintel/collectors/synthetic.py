"""Synthetic intelligence: seeds prior knowledge and yields fictional raw intelligence.

Every object produced here is marked synthetic (source_type=synthetic, labels ["synthetic"]).
Dates are materialised relative to ``now`` so the demo world never goes stale.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from threatintel.attack.knowledge_base import AttackKnowledgeBase
from threatintel.collectors.base import Collector
from threatintel.collectors.humint import pseudonymise_source
from threatintel.collectors.telegram import pseudonymise
from threatintel.config import get_settings
from threatintel.models.common import (
    TLP,
    InformationCredibility,
    Provenance,
    SourceReliability,
    SourceType,
    utcnow,
)
from threatintel.models.entities import (
    Campaign,
    HumintReport,
    IntelligenceRequirement,
    Malware,
    RansomwareClaim,
    Relationship,
    ThreatActor,
    Tool,
    Vulnerability,
)
from threatintel.models.intel import CollectedItem, Source
from threatintel.storage.repository import Repository

SYN_LABELS = ["synthetic"]


def load_world(path: Path | None = None) -> dict[str, Any]:
    p = path or get_settings().data_dir / "synthetic" / "world.json"
    return dict(json.loads(p.read_text(encoding="utf-8")))


def _ago(now: datetime, days: int | None) -> datetime | None:
    return None if days is None else now - timedelta(days=days)


def sources_from_world(world: dict[str, Any]) -> dict[str, Source]:
    return {
        s["id"]: Source(
            id=s["id"],
            name=s["name"],
            source_type=SourceType(s["source_type"]),
            reliability=SourceReliability(s["reliability"]),
            description=s.get("description", ""),
            collection_policy=s.get("collection_policy", ""),
            derived_from=s.get("derived_from"),
            internal=bool(s.get("internal")),
            synthetic=True,
        )
        for s in world["sources"]
    }


def load_requirements(repo: Repository, path: Path | None = None) -> list[IntelligenceRequirement]:
    p = path or get_settings().config_dir / "intelligence_requirements.yaml"
    reqs = [IntelligenceRequirement(**r) for r in yaml.safe_load(p.read_text("utf-8"))["requirements"]]
    for r in reqs:
        repo.put_record("intelligence_requirement", r.id, r.model_dump(mode="json"))
    return reqs


def seed_knowledge(
    repo: Repository,
    kb: AttackKnowledgeBase,
    world: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, int]:
    """Load the synthetic *prior knowledge* (as if imported from vendor feeds)."""
    world = world or load_world()
    now = now or utcnow()
    sources = sources_from_world(world)
    for s in sources.values():
        repo.upsert_source(s)
    vendor = sources["src-syn-vendor-alpha"]
    prov = Provenance(
        source_id=vendor.id,
        source_name=vendor.name,
        source_type=vendor.source_type,
        collected_at=now,
        reliability=vendor.reliability,
        credibility=InformationCredibility.PROBABLY_TRUE,
        synthetic=True,
        reference="world.json",
    )
    counts = {"actors": 0, "malware": 0, "tools": 0, "vulnerabilities": 0, "campaigns": 0, "relationships": 0}
    for a in world["actors"]:
        repo.upsert_entity(
            ThreatActor(
                name=a["name"],
                aliases=a["aliases"],
                actor_kind=a["actor_kind"],
                motivation=a["motivation"],
                sophistication=a["sophistication"],
                target_sectors=a["target_sectors"],
                target_regions=a["target_regions"],
                description=a["description"],
                first_seen=_ago(now, a["first_seen_days_ago"]),
                last_seen=_ago(now, a["last_seen_days_ago"]),
                synthetic=True,
                labels=SYN_LABELS,
                confidence=60,
                tlp=TLP.AMBER,
            ),
            prov,
        )
        counts["actors"] += 1
    for m in world["malware"]:
        repo.upsert_entity(
            Malware(
                name=m["name"],
                aliases=m["aliases"],
                malware_types=m["malware_types"],
                platforms=m["platforms"],
                synthetic=True,
                labels=SYN_LABELS,
            ),
            prov,
        )
        counts["malware"] += 1
    for t in world["tools"]:
        # Real, public tools: the entity itself is not synthetic; associations below are.
        repo.upsert_entity(
            Tool(
                name=t["name"],
                aliases=t["aliases"],
                tool_types=t["tool_types"],
                commodity=t["commodity"],
                description=t["description"],
                tlp=TLP.CLEAR,
            )
        )
        counts["tools"] += 1
    for v in world["vulnerabilities"]:
        repo.upsert_entity(
            Vulnerability(
                name=v["name"],
                affected_product=v["affected_product"],
                cvss=v.get("cvss"),
                known_exploited=v["known_exploited"],
                tlp=TLP.CLEAR,
                external_references=[
                    {
                        "source_name": "cve",
                        "external_id": v["name"],
                        "url": f"https://nvd.nist.gov/vuln/detail/{v['name']}",
                    }
                ],
            )
        )
        counts["vulnerabilities"] += 1

    def rel(src: str, target: str, rtype: str, conf: int, desc: str = "") -> None:
        repo.upsert_relationship(
            Relationship(
                source_ref=src,
                target_ref=target,
                relationship_type=rtype,
                confidence=conf,
                description=desc,
                provenance=[prov],
                synthetic=True,
                evidence=["synthetic prior knowledge (world.json)"],
            )
        )
        counts["relationships"] += 1

    for c in world["campaigns"]:
        camp = repo.upsert_entity(
            Campaign(
                name=c["name"],
                campaign_status=c["status"],
                start_date=_ago(now, c["start_days_ago"]),
                end_date=_ago(now, c["end_days_ago"]),
                first_seen=_ago(now, c["start_days_ago"]),
                last_seen=_ago(now, c["end_days_ago"] if c["end_days_ago"] is not None else 0),
                target_sectors=c["target_sectors"],
                target_regions=c["target_regions"],
                objective=c["objective"],
                synthetic=True,
                labels=SYN_LABELS,
                confidence=60,
            ),
            prov,
        )
        counts["campaigns"] += 1
        if c["actor"]:
            actor = repo.require_entity("threat-actor", c["actor"])
            rel(
                camp.id,
                actor.id,
                "reported-attribution",
                c["attribution_confidence"],
                f"{vendor.name} attributes {c['name']} to {c['actor']}",
            )
        for name in c["malware"]:
            ent = repo.require_entity("malware", name)
            rel(camp.id, ent.id, "uses", 70)
        for name in c["tools"]:
            ent = repo.require_entity("tool", name)
            rel(camp.id, ent.id, "uses", 60)
        for name in c["vulnerabilities"]:
            ent = repo.require_entity("vulnerability", name)
            rel(camp.id, ent.id, "exploits", 70)
        for tid in c["techniques"]:
            tech = kb.get(tid)
            if tech:  # never reference a technique missing from the loaded release
                rel(camp.id, tech.stix_id, "uses", 65, f"{tid} {tech.name}")

    for claim in world["ransomware_claims"]:
        rc = RansomwareClaim(
            group=claim["group"],
            victim_label=claim["victim_label"],
            victim_sector=claim["victim_sector"],
            victim_region=claim["victim_region"],
            claimed_date=now - timedelta(days=claim["days_ago"]),
            leak_site_reference=claim["leak_site_reference"],
            ttps=claim["ttps"],
            malware=claim["malware"],
            confidence=claim["confidence"],
            synthetic=True,
        )
        repo.put_record("ransomware_claim", rc.id, rc.model_dump(mode="json"), synthetic=True)
    for h in world["humint_reports"]:
        hr = HumintReport(
            source_identifier=pseudonymise_source(h["source_identifier"]),
            source_reliability=SourceReliability(h["source_reliability"]),
            information_credibility=InformationCredibility(h["information_credibility"]),
            collection_method=h["collection_method"],
            date_observed=now - timedelta(days=h["days_ago"]),
            raw_note=h["raw_note"],
            analyst_assessment=h["analyst_assessment"],
            corroborating_sources=h["corroborating_sources"],
            synthetic=True,
        )
        repo.put_record("humint_report", hr.id, hr.model_dump(mode="json"), synthetic=True)
    load_requirements(repo)
    return counts


class SyntheticIntelligenceCollector(Collector):
    """Yields every synthetic raw item (reports, forum posts, pastes, Telegram, HUMINT), oldest first."""

    name = "synthetic"

    def __init__(
        self, source: Source, world: dict[str, Any] | None = None, now: datetime | None = None
    ) -> None:
        super().__init__(source)
        self.world = world or load_world()
        self.now = now or utcnow()
        self.sources = sources_from_world(self.world)

    def _for(self, source_id: str, **kwargs: Any) -> CollectedItem:
        src = self.sources[source_id]
        published = kwargs.pop("published_at")
        data = {
            "source_id": src.id,
            "source_name": src.name,
            "source_type": src.source_type,
            "source_reliability": src.reliability,
            "derived_from": src.derived_from,
            "collection_timestamp": published,
            "published_at": published,
            "tags": SYN_LABELS,
            **kwargs,
        }
        data["metadata"] = {"synthetic": True, **data.get("metadata", {})}
        return CollectedItem.model_validate(data).finalise()

    def collect(self) -> Iterator[CollectedItem]:
        items: list[CollectedItem] = []
        w, now = self.world, self.now
        for r in w["reports"]:
            items.append(
                self._for(
                    r["source"],
                    title=r["title"],
                    content=r["content"],
                    published_at=now - timedelta(days=r["days_ago"]),
                    information_credibility=InformationCredibility(r["credibility"]),
                    raw_reference=f"synthetic-report:{r['title'][:40]}",
                )
            )
        for p in w["underground_posts"]:
            items.append(
                self._for(
                    p["source"],
                    title=p["title"],
                    content=p["content"],
                    published_at=now - timedelta(days=p["days_ago"]),
                    information_credibility=InformationCredibility(p["credibility"]),
                    raw_reference=f"synthetic-post:{p['forum']}",
                    metadata={"forum": p["forum"], "author_reference": pseudonymise(p["author"])},
                )
            )
        for m in w["telegram_messages"]:
            items.append(
                self._for(
                    "src-syn-telegram",
                    title=f"Telegram {m['channel_reference']} #{m['message_id']}",
                    content=m["text"],
                    published_at=now - timedelta(days=m["days_ago"]),
                    raw_reference=f"telegram:{m['channel_reference']}/{m['message_id']}",
                    metadata={
                        "channel_reference": m["channel_reference"],
                        "message_id": m["message_id"],
                        "author_reference": pseudonymise(m["author_reference"]),
                    },
                )
            )
        for h in w["humint_reports"]:
            items.append(
                self._for(
                    "src-syn-humint",
                    title=f"HUMINT report {pseudonymise_source(h['source_identifier'])}",
                    content=h["raw_note"],
                    published_at=now - timedelta(days=h["days_ago"]),
                    source_reliability=SourceReliability(h["source_reliability"]),
                    information_credibility=InformationCredibility(h["information_credibility"]),
                    metadata={
                        "source_identifier": pseudonymise_source(h["source_identifier"]),
                        "analyst_assessment": h["analyst_assessment"],
                        "collection_method": h["collection_method"],
                    },
                )
            )
        yield from sorted(items, key=lambda i: (i.published_at or i.collection_timestamp, i.title))
