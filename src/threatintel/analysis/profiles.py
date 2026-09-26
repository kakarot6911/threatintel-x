"""Builds correlation profiles for campaigns, actors and new intelligence.

Profiles are built from an in-memory index of the knowledge graph (one bulk read), reloaded
automatically whenever the repository's revision changes. With a real ATT&CK import (~190 groups,
~800 software, ~20k relationships) per-row queries would be far too slow.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from threatintel.analysis.confidence import NON_REPORTING_SOURCES
from threatintel.analysis.correlation import Profile
from threatintel.attack.knowledge_base import AttackKnowledgeBase
from threatintel.models.common import ObservableType
from threatintel.models.entities import Campaign, Entity, Malware, ThreatActor, Tool
from threatintel.storage.repository import Repository

INDICATOR_RELS = {"indicates"}
# Actor profiles are built from SOURCE CLAIMS only. Our own "attributed-to" conclusions are never fed
# back into the evidence base, which would make assessments self-reinforcing (circular reporting).
ATTRIBUTION_RELS = {"reported-attribution"}
_NON_REPORTING = {s.value for s in NON_REPORTING_SOURCES}


class ProfileBuilder:
    def __init__(self, repo: Repository, kb: AttackKnowledgeBase) -> None:
        self.repo = repo
        self.kb = kb
        self._stix_to_tid = {t.stix_id: t.technique_id for t in kb.techniques.values()}
        self._loaded_revision = -1
        self._by_source: dict[str, list[tuple[str, str, int]]] = {}
        self._by_target: dict[str, list[tuple[str, str, int]]] = {}
        self._entities: dict[str, Entity] = {}
        self._observables: dict[str, tuple[ObservableType, str, bool]] = {}
        self._origins: dict[str, set[tuple[str, str]]] = {}
        self._certs: dict[tuple[str, str], set[str]] = {}
        self._rel_ids: dict[tuple[str, str, str], str] = {}

    # ------------------------------------------------------------------ index
    def refresh(self, force: bool = False) -> None:
        if not force and self._loaded_revision == self.repo.revision:
            return
        snap: dict[str, Any] = self.repo.graph_snapshot()
        by_source: dict[str, list[tuple[str, str, int]]] = defaultdict(list)
        by_target: dict[str, list[tuple[str, str, int]]] = defaultdict(list)
        rel_ids: dict[tuple[str, str, str], str] = {}
        for src, dst, rtype, conf, rid in snap["relationships"]:
            by_source[src].append((dst, rtype, conf))
            by_target[dst].append((src, rtype, conf))
            rel_ids[(src, rtype, dst)] = rid
        self._rel_ids = rel_ids
        self._by_source, self._by_target = dict(by_source), dict(by_target)
        self._entities = snap["entities"]
        self._observables = snap["observables"]
        self._origins = snap["origins"]
        self._certs = snap["certificates"]
        self._loaded_revision = self.repo.revision

    def _out(self, node: str) -> list[tuple[str, str, int]]:
        return self._by_source.get(node, [])

    def _in(self, node: str) -> list[tuple[str, str, int]]:
        return self._by_target.get(node, [])

    # ---------------------------------------------------------------- helpers
    def is_nameserver(self, obs_id: str) -> bool:
        """A domain other domains delegate to: weak shared-hosting signal, not a distinctive IOC."""
        self.refresh()
        return any(rtype == "uses-nameserver" for _, rtype, _ in self._in(obs_id))

    def add_observable(self, profile: Profile, obs_id: str, obs_type: ObservableType, value: str) -> None:
        if obs_type == ObservableType.DOMAIN and self.is_nameserver(obs_id):
            profile.nameservers.add(value)
        else:
            profile.add_observable(obs_type, value)

    def add_observable_with_context(self, profile: Profile, obs_id: str) -> None:
        self.refresh()
        obs = self._observables.get(obs_id)
        if obs is None or not obs[2]:
            return
        obs_type, value, _ = obs
        self.add_observable(profile, obs_id, obs_type, value)
        for origin, source_type in self._origins.get(obs_id, set()):
            if source_type not in _NON_REPORTING:
                profile.sources.add(origin)
        self.add_infrastructure_context(profile, obs_id, obs_type, value)

    def add_infrastructure_context(
        self, profile: Profile, obs_id: str, obs_type: ObservableType, value: str
    ) -> None:
        """Pivot one hop through enrichment: resolved IPs, name servers, ASN, certificates."""
        self.refresh()
        for target_id, rtype, _ in self._out(obs_id):
            target = self._observables.get(target_id)
            if target is None:
                continue
            if rtype == "uses-nameserver":
                profile.nameservers.add(target[1])
            elif rtype == "resolves-to":
                profile.ips.add(target[1])
                for asn_id, sub_type, _ in self._out(target_id):
                    asn = self._observables.get(asn_id)
                    if sub_type == "belongs-to" and asn:
                        profile.asns.add(asn[1])
            elif rtype == "belongs-to":
                profile.asns.add(target[1])
        profile.certificates |= self._certs.get((obs_type.value, value), set())

    def _add_rel_sources(self, profile: Profile, src: str, rtype: str, dst: str) -> None:
        """Knowledge-base links are evidence too: count the sources that asserted them.

        MITRE ATT&CK counts here (it is curated reporting about who uses what) even though it is not a
        reporting source for individual indicators; enrichment never counts.
        """
        rid = self._rel_ids.get((src, rtype, dst))
        for origin, source_type in self._origins.get(rid or "", set()):
            if source_type == "mitre" or source_type not in _NON_REPORTING:
                profile.sources.add(origin)

    def _add_related_entities(self, profile: Profile, subject_id: str) -> None:
        for target_id, rtype, _ in self._out(subject_id):
            if rtype not in {"uses", "exploits"}:
                continue
            self._add_rel_sources(profile, subject_id, rtype, target_id)
            if target_id.startswith("attack-pattern--"):
                tid = self._stix_to_tid.get(target_id)
                if tid:
                    profile.techniques.add(tid)
                continue
            ent = self._entities.get(target_id)
            if isinstance(ent, Malware | Tool):
                profile.malware.add(ent.name)
                if getattr(ent, "commodity", False):
                    profile.commodity_malware.add(ent.name)
            elif ent is not None and ent.entity_type == "vulnerability":
                profile.cves.add(ent.name)
        for source_id, rtype, _ in self._in(subject_id):
            if rtype in INDICATOR_RELS:
                self.add_observable_with_context(profile, source_id)

    # --------------------------------------------------------------- profiles
    def campaign(self, campaign: Campaign) -> Profile:
        self.refresh()
        p = Profile(
            subject_id=campaign.id,
            label=campaign.name,
            names=campaign.all_names(),
            target_sectors=set(campaign.target_sectors),
            start=campaign.start_date or campaign.first_seen,
            end=campaign.end_date or campaign.last_seen,
        )
        self._add_related_entities(p, campaign.id)
        return p

    def actor(self, actor: ThreatActor, *, exclude_campaign: str | None = None) -> Profile:
        self.refresh()
        p = Profile(
            subject_id=actor.id,
            label=actor.name,
            names=actor.all_names(),
            target_sectors=set(actor.target_sectors),
            start=actor.first_seen,
            end=actor.last_seen,
        )
        self._add_related_entities(p, actor.id)
        for campaign_id in self.campaigns_of(actor.id):
            if campaign_id == exclude_campaign:
                continue
            c = self._entities.get(campaign_id)
            if isinstance(c, Campaign):
                cp = self.campaign(c)
                cp.names = set()  # a campaign's name is not evidence about a different subject
                p.merge(cp)
        return p

    def campaigns_of(self, actor_id: str) -> list[str]:
        self.refresh()
        return sorted(
            {src for src, rtype, conf in self._in(actor_id) if rtype in ATTRIBUTION_RELS and conf >= 50}
        )

    def _typed(self, cls: type[Entity]) -> list[Any]:
        self.refresh()
        return sorted((e for e in self._entities.values() if isinstance(e, cls)), key=lambda e: e.name)

    def all_actor_profiles(self, *, exclude_campaign: str | None = None) -> list[Profile]:
        return [self.actor(a, exclude_campaign=exclude_campaign) for a in self._typed(ThreatActor)]

    def all_campaign_profiles(self) -> list[Profile]:
        return [self.campaign(c) for c in self._typed(Campaign)]


def entity_label(entity: Entity | None) -> str:
    return entity.name if entity else "unknown"
