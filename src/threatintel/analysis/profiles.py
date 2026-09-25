"""Builds correlation profiles for campaigns, actors and new intelligence from the repository."""

from __future__ import annotations

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


class ProfileBuilder:
    def __init__(self, repo: Repository, kb: AttackKnowledgeBase) -> None:
        self.repo = repo
        self.kb = kb
        self._stix_to_tid = {t.stix_id: t.technique_id for t in kb.techniques.values()}

    # ---------------------------------------------------------------- helpers
    def is_nameserver(self, obs_id: str) -> bool:
        """A domain other domains delegate to: weak shared-hosting signal, not a distinctive IOC."""
        return bool(self.repo.list_relationships(target_ref=obs_id, relationship_type="uses-nameserver"))

    def add_observable(self, profile: Profile, obs_id: str, obs_type: ObservableType, value: str) -> None:
        if obs_type == ObservableType.DOMAIN and self.is_nameserver(obs_id):
            profile.nameservers.add(value)
        else:
            profile.add_observable(obs_type, value)

    def add_observable_with_context(self, profile: Profile, obs_id: str) -> None:
        obs = self.repo.get_observable_by_id(obs_id)
        if obs is None or not obs.actionable:
            return
        self.add_observable(profile, obs.id, obs.type, obs.value)
        for p in obs.provenance:
            if p.source_type not in NON_REPORTING_SOURCES:
                profile.sources.add(p.origin)
        self.add_infrastructure_context(profile, obs.id, obs.type, obs.value)

    def add_infrastructure_context(
        self, profile: Profile, obs_id: str, obs_type: ObservableType, value: str
    ) -> None:
        """Pivot one hop through enrichment: resolved IPs, name servers, ASN, certificates."""
        for rel in self.repo.list_relationships(source_ref=obs_id):
            target = self.repo.get_observable_by_id(rel.target_ref)
            if target is None:
                continue
            if rel.relationship_type == "uses-nameserver":
                profile.nameservers.add(target.value)
            elif rel.relationship_type == "resolves-to":
                profile.ips.add(target.value)
                for sub in self.repo.list_relationships(source_ref=target.id, relationship_type="belongs-to"):
                    asn = self.repo.get_observable_by_id(sub.target_ref)
                    if asn:
                        profile.asns.add(asn.value)
            elif rel.relationship_type == "belongs-to":
                profile.asns.add(target.value)
        for enr in self.repo.enrichments_for(obs_type, value):
            cert = enr.result.get("certificate_sha256")
            if cert:
                profile.certificates.add(str(cert))

    def _add_related_entities(self, profile: Profile, subject_id: str) -> None:
        for rel in self.repo.list_relationships(source_ref=subject_id):
            if rel.relationship_type in {"uses", "exploits"}:
                if rel.target_ref.startswith("attack-pattern--"):
                    tid = self._stix_to_tid.get(rel.target_ref)
                    if tid:
                        profile.techniques.add(tid)
                    continue
                ent = self.repo.get_entity(rel.target_ref)
                if isinstance(ent, Malware | Tool):
                    profile.malware.add(ent.name)
                    if getattr(ent, "commodity", False):
                        profile.commodity_malware.add(ent.name)
                elif ent is not None and ent.entity_type == "vulnerability":
                    profile.cves.add(ent.name)
        for rel in self.repo.list_relationships(target_ref=subject_id):
            if rel.relationship_type in INDICATOR_RELS:
                self.add_observable_with_context(profile, rel.source_ref)

    # --------------------------------------------------------------- profiles
    def campaign(self, campaign: Campaign) -> Profile:
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
            c = self.repo.get_entity(campaign_id)
            if isinstance(c, Campaign):
                cp = self.campaign(c)
                cp.names = set()  # a campaign's name is not evidence about a different subject
                p.merge(cp)
        return p

    def campaigns_of(self, actor_id: str) -> list[str]:
        return sorted(
            {
                r.source_ref
                for r in self.repo.list_relationships(target_ref=actor_id)
                if r.relationship_type in ATTRIBUTION_RELS and r.confidence >= 50
            }
        )

    def all_actor_profiles(self, *, exclude_campaign: str | None = None) -> list[Profile]:
        return [
            self.actor(a, exclude_campaign=exclude_campaign)  # type: ignore[arg-type]
            for a in self.repo.list_entities("threat-actor")
        ]

    def all_campaign_profiles(self) -> list[Profile]:
        return [self.campaign(c) for c in self.repo.list_entities("campaign")]  # type: ignore[arg-type]


def entity_label(entity: Entity | None) -> str:
    return entity.name if entity else "unknown"
