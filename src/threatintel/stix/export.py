"""STIX 2.1 export using the official ``stix2`` library.

Modelling decisions (see docs/decisions/ADR-006-stix-modelling.md):
  * tracked groups -> ``intrusion-set``; individual personas -> ``threat-actor``
  * each actionable observable -> SCO + ``indicator`` (``based-on`` the SCO)
  * a SOURCE's attribution claim -> ``attributed-to`` created_by_ref that source's Identity;
    our own assessment -> ``attributed-to`` created_by_ref THREATINTEL-X, plus an ``opinion``
  * ATT&CK techniques keep MITRE's STIX ids so they merge with ATT&CK in MISP/OpenCTI
  * each collected item -> ``report`` whose object_refs are the objects derived from it
  * synthetic objects carry ``labels: ["synthetic"]`` and ``x_threatintel_synthetic: true``
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import stix2
from stix2 import v21

from threatintel import __version__
from threatintel.attack.knowledge_base import AttackKnowledgeBase
from threatintel.config import Settings, get_settings
from threatintel.models.common import TIX_NAMESPACE, ObservableType, utcnow
from threatintel.models.entities import Campaign, Entity, Malware, ThreatActor, Tool, Vulnerability
from threatintel.models.intel import Observable
from threatintel.storage.repository import Repository

MITRE_IDENTITY_ID = "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
TLP_MAP = {"clear": stix2.TLP_WHITE, "green": stix2.TLP_GREEN, "amber": stix2.TLP_AMBER, "red": stix2.TLP_RED}
MOTIVATION_MAP = {
    "financial-gain": "organizational-gain",
    "espionage": "organizational-gain",
    "ideology": "ideology",
    "notoriety": "notoriety",
    "revenge": "revenge",
}
MALWARE_TYPE_MAP = {
    "rat": "remote-access-trojan",
    "infostealer": "spyware",
    "loader": "downloader",
    "botnet": "bot",
    "ransomware": "ransomware",
    "backdoor": "backdoor",
    "wiper": "wiper",
}
REGION_MAP = {
    "south-asia": "southern-asia",
    "north-america": "northern-america",
    "europe": "europe",
    "east-asia": "eastern-asia",
    "middle-east": "western-asia",
}
REL_EXPORT = {
    "indicates": "indicates",
    "uses": "uses",
    "exploits": "targets",
    "related-to": "related-to",
    "resolves-to": "resolves-to",
    "belongs-to": "belongs-to",
    "uses-nameserver": "related-to",
}
HASH_KEYS = {ObservableType.MD5: "MD5", ObservableType.SHA1: "SHA-1", ObservableType.SHA256: "SHA-256"}


def stix_id(stix_type: str, internal_id: str) -> str:
    return f"{stix_type}--{uuid.uuid5(TIX_NAMESPACE, f'stix|{stix_type}|{internal_id}')}"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def pattern_for(obs: Observable) -> str | None:
    v = _escape(obs.value)
    match obs.type:
        case ObservableType.IPV4:
            return f"[ipv4-addr:value = '{v}']"
        case ObservableType.IPV6:
            return f"[ipv6-addr:value = '{v}']"
        case ObservableType.DOMAIN:
            return f"[domain-name:value = '{v}']"
        case ObservableType.URL:
            return f"[url:value = '{v}']"
        case ObservableType.EMAIL:
            return f"[email-addr:value = '{v}']"
        case ObservableType.MD5 | ObservableType.SHA1 | ObservableType.SHA256:
            return f"[file:hashes.'{HASH_KEYS[obs.type]}' = '{v}']"
        case _:
            return None


def sco_for(obs: Observable) -> Any:
    kwargs: dict[str, Any] = {"allow_custom": True}
    if obs.synthetic:
        kwargs["x_threatintel_synthetic"] = True
    match obs.type:
        case ObservableType.IPV4:
            return v21.IPv4Address(value=obs.value, **kwargs)
        case ObservableType.IPV6:
            return v21.IPv6Address(value=obs.value, **kwargs)
        case ObservableType.DOMAIN:
            return v21.DomainName(value=obs.value, **kwargs)
        case ObservableType.URL:
            return v21.URL(value=obs.value, **kwargs)
        case ObservableType.EMAIL:
            return v21.EmailAddress(value=obs.value, **kwargs)
        case ObservableType.MD5 | ObservableType.SHA1 | ObservableType.SHA256:
            return v21.File(hashes={HASH_KEYS[obs.type]: obs.value}, **kwargs)
        case ObservableType.ASN:
            return v21.AutonomousSystem(number=int(obs.value.removeprefix("AS")), **kwargs)
        case _:
            return None


class StixExporter:
    def __init__(self, repo: Repository, kb: AttackKnowledgeBase, settings: Settings | None = None) -> None:
        self.repo = repo
        self.kb = kb
        self.settings = settings or get_settings()
        self.objects: dict[str, Any] = {}
        self.internal_to_stix: dict[str, str] = {}
        self._tech_by_stix = {t.stix_id: t for t in kb.techniques.values()}
        self.producer = v21.Identity(
            id=stix_id("identity", "producer"),
            name=self.settings.producer_name,
            identity_class="system",
            description=f"THREATINTEL-X {__version__} automated CTI pipeline",
            created="2026-01-01T00:00:00Z",
            modified="2026-01-01T00:00:00Z",
        )

    # ------------------------------------------------------------------ utils
    def _add(self, obj: Any) -> Any:
        self.objects[obj.id] = obj
        return obj

    def _common(self, ent: Entity) -> dict[str, Any]:
        refs = [
            v21.ExternalReference(
                **{k: v for k, v in r.items() if k in ("source_name", "url", "external_id", "description")}
            )
            for r in ent.external_references
            if r.get("source_name")
        ]
        common: dict[str, Any] = {
            "created": ent.created_at,
            "modified": max(ent.modified_at, ent.created_at),
            "created_by_ref": self.producer.id,
            "confidence": ent.confidence,
            "object_marking_refs": [TLP_MAP[ent.tlp.value]],
            "allow_custom": True,
            "x_threatintel_provenance": sorted({p.source_name for p in ent.provenance}),
        }
        if refs:
            common["external_references"] = refs
        labels = list(ent.labels)
        if ent.synthetic:
            common["x_threatintel_synthetic"] = True
            labels = sorted({*labels, "synthetic"})
        if labels:
            common["labels"] = labels
        return common

    def _source_identity(self, source_id: str, source_name: str) -> str:
        sid = stix_id("identity", f"source|{source_id}")
        if sid not in self.objects:
            self._add(
                v21.Identity(
                    id=sid,
                    name=source_name,
                    identity_class="organization",
                    created="2026-01-01T00:00:00Z",
                    modified="2026-01-01T00:00:00Z",
                )
            )
        return sid

    def _sector_identity(self, sector: str) -> str:
        sid = stix_id("identity", f"sector|{sector}")
        if sid not in self.objects:
            self._add(
                v21.Identity(
                    id=sid,
                    name=sector.replace("-", " ").title(),
                    identity_class="class",
                    sectors=[sector],
                    created="2026-01-01T00:00:00Z",
                    modified="2026-01-01T00:00:00Z",
                )
            )
        return sid

    def _location(self, region: str) -> str:
        lid = stix_id("location", region)
        if lid not in self.objects:
            self._add(
                v21.Location(
                    id=lid,
                    name=region.replace("-", " ").title(),
                    region=REGION_MAP.get(region, region),
                    created="2026-01-01T00:00:00Z",
                    modified="2026-01-01T00:00:00Z",
                )
            )
        return lid

    def _rel(
        self,
        rtype: str,
        src: str,
        dst: str,
        *,
        confidence: int = 50,
        description: str = "",
        created_by: str | None = None,
        synthetic: bool = False,
        key: str = "",
    ) -> Any:
        kwargs: dict[str, Any] = {"allow_custom": True}
        if synthetic:
            kwargs.update(labels=["synthetic"], x_threatintel_synthetic=True)
        if description:
            kwargs["description"] = description[:2000]
        return self._add(
            v21.Relationship(
                id=stix_id("relationship", f"{rtype}|{src}|{dst}|{key}"),
                relationship_type=rtype,
                source_ref=src,
                target_ref=dst,
                confidence=confidence,
                created_by_ref=created_by or self.producer.id,
                object_marking_refs=[stix2.TLP_AMBER],
                created="2026-01-01T00:00:00Z",
                modified=utcnow(),
                **kwargs,
            )
        )

    # --------------------------------------------------------------- entities
    def _entity(self, ent: Entity) -> Any:
        c = self._common(ent)
        seen = (
            {"first_seen": ent.first_seen, "last_seen": ent.last_seen}
            if ent.first_seen and ent.last_seen and ent.last_seen >= ent.first_seen
            else {}
        )
        if isinstance(ent, ThreatActor):
            if ent.motivation in MOTIVATION_MAP:
                c["primary_motivation"] = MOTIVATION_MAP[ent.motivation]
            c["x_threatintel_motivation"] = ent.motivation
            if ent.actor_kind == "threat-actor":
                obj = v21.ThreatActor(
                    id=stix_id("threat-actor", ent.id),
                    name=ent.name,
                    aliases=ent.aliases or None,
                    description=ent.description or None,
                    threat_actor_types=["crime-syndicate"],
                    **seen,
                    **c,
                )
            else:
                obj = v21.IntrusionSet(
                    id=stix_id("intrusion-set", ent.id),
                    name=ent.name,
                    aliases=ent.aliases or None,
                    description=ent.description or None,
                    **seen,
                    **c,
                )
            obj = self._add(obj)
            for sector in ent.target_sectors:
                self._rel("targets", obj.id, self._sector_identity(sector), synthetic=ent.synthetic)
            for region in ent.target_regions:
                self._rel("targets", obj.id, self._location(region), synthetic=ent.synthetic)
            return obj
        if isinstance(ent, Campaign):
            obj = self._add(
                v21.Campaign(
                    id=stix_id("campaign", ent.id),
                    name=ent.name,
                    aliases=ent.aliases or None,
                    description=ent.description or None,
                    objective=ent.objective or None,
                    **seen,
                    **c,
                )
            )
            for sector in ent.target_sectors:
                self._rel("targets", obj.id, self._sector_identity(sector), synthetic=ent.synthetic)
            for region in ent.target_regions:
                self._rel("targets", obj.id, self._location(region), synthetic=ent.synthetic)
            return obj
        if isinstance(ent, Malware):
            return self._add(
                v21.Malware(
                    id=stix_id("malware", ent.id),
                    name=ent.name,
                    is_family=ent.is_family,
                    aliases=ent.aliases or None,
                    description=ent.description or None,
                    malware_types=[MALWARE_TYPE_MAP.get(t, t) for t in ent.malware_types] or None,
                    **({"first_seen": ent.first_seen} if ent.first_seen else {}),
                    **c,
                )
            )
        if isinstance(ent, Tool):
            return self._add(
                v21.Tool(
                    id=stix_id("tool", ent.id),
                    name=ent.name,
                    aliases=ent.aliases or None,
                    description=ent.description or None,
                    tool_types=ent.tool_types or None,
                    **c,
                )
            )
        if isinstance(ent, Vulnerability):
            if "external_references" not in c:
                c["external_references"] = [v21.ExternalReference(source_name="cve", external_id=ent.name)]
            c["x_threatintel_known_exploited"] = ent.known_exploited
            if ent.cvss is not None:
                c["x_threatintel_cvss"] = ent.cvss
            return self._add(
                v21.Vulnerability(
                    id=stix_id("vulnerability", ent.id),
                    name=ent.name,
                    description=ent.description or ent.affected_product or None,
                    **c,
                )
            )
        return None

    def _attack_pattern(self, stix_ap_id: str) -> str | None:
        if stix_ap_id in self.objects:
            return stix_ap_id
        tech = self._tech_by_stix.get(stix_ap_id)
        if tech is None:
            return None
        if MITRE_IDENTITY_ID not in self.objects:
            self._add(
                v21.Identity(
                    id=MITRE_IDENTITY_ID,
                    name="The MITRE Corporation",
                    identity_class="organization",
                    created="2017-06-01T00:00:00Z",
                    modified="2017-06-01T00:00:00Z",
                )
            )
        self._add(
            v21.AttackPattern(
                id=tech.stix_id,
                name=tech.name,
                created=tech.created or "2017-05-31T21:30:00Z",
                modified=tech.modified or tech.created or "2017-05-31T21:30:00Z",
                created_by_ref=MITRE_IDENTITY_ID,
                description=tech.description or None,
                external_references=[
                    v21.ExternalReference(
                        source_name="mitre-attack", external_id=tech.technique_id, url=tech.url or None
                    )
                ],
                kill_chain_phases=[
                    v21.KillChainPhase(kill_chain_name="mitre-attack", phase_name=p) for p in tech.tactics
                ]
                or None,
                allow_custom=True,
                x_mitre_attack_version=self.kb.version,
            )
        )
        return stix_ap_id

    # ---------------------------------------------------------- observables
    def _observable(self, obs: Observable) -> str | None:
        sco = sco_for(obs)
        if sco is None:
            return None
        self._add(sco)
        self.internal_to_stix[obs.id] = sco.id
        pattern = pattern_for(obs)
        if pattern is None or not obs.actionable:
            return sco.id
        conf = self.repo.latest_assessment(obs.id, "confidence")
        kwargs: dict[str, Any] = {"allow_custom": True}
        if obs.synthetic:
            kwargs.update(labels=["synthetic"], x_threatintel_synthetic=True)
        ind = self._add(
            v21.Indicator(
                id=stix_id("indicator", obs.id),
                name=f"{obs.type.value}: {obs.value}"[:250],
                pattern=pattern,
                pattern_type="stix",
                valid_from=obs.first_seen,
                indicator_types=["malicious-activity"],
                confidence=int(conf.score) if conf else 50,
                created_by_ref=self.producer.id,
                description=conf.statement[:1000] if conf else None,
                object_marking_refs=[stix2.TLP_AMBER],
                created=obs.first_seen,
                modified=max(obs.last_seen, obs.first_seen),
                x_threatintel_sources=sorted({p.source_name for p in obs.provenance}),
                **kwargs,
            )
        )
        self._rel("based-on", ind.id, sco.id, confidence=100, synthetic=obs.synthetic)
        self.internal_to_stix[obs.id + "#indicator"] = ind.id
        return sco.id

    # ------------------------------------------------------------------- main
    def build(self, *, include_synthetic: bool = True) -> dict[str, Any]:
        self._add(self.producer)
        for ent in self.repo.list_entities():
            if ent.synthetic and not include_synthetic:
                continue
            obj = self._entity(ent)
            if obj is not None:
                self.internal_to_stix[ent.id] = obj.id
        for obs in self.repo.list_observables(limit=100_000):
            if obs.synthetic and not include_synthetic:
                continue
            self._observable(obs)

        for ent_id in list(self.internal_to_stix):
            for rel in self.repo.list_relationships(source_ref=ent_id):
                self._export_relationship(rel)
        self._export_reports(include_synthetic)
        self._export_assessments()
        return self.bundle()

    def _export_relationship(self, rel: Any) -> None:
        src_ind = self.internal_to_stix.get(rel.source_ref + "#indicator")
        src = (
            src_ind
            if rel.relationship_type == "indicates" and src_ind
            else self.internal_to_stix.get(rel.source_ref)
        )
        if rel.target_ref.startswith("attack-pattern--"):
            dst = self._attack_pattern(rel.target_ref)
        else:
            dst = self.internal_to_stix.get(rel.target_ref)
        if not src or not dst:
            return
        if rel.relationship_type == "reported-attribution":
            for p in self.repo.provenance_for(rel.id)[:3]:
                self._rel(
                    "attributed-to",
                    src,
                    dst,
                    confidence=rel.confidence,
                    synthetic=rel.synthetic,
                    created_by=self._source_identity(p.source_id, p.source_name),
                    key=p.source_id,
                    description=f"Attribution as REPORTED by {p.source_name} (a source claim, not our "
                    f"assessment)",
                )
            return
        if rel.relationship_type == "attributed-to":
            r = self._rel(
                "attributed-to",
                src,
                dst,
                confidence=rel.confidence,
                synthetic=rel.synthetic,
                description=rel.description,
                key="assessed",
            )
            level = self.repo.latest_assessment(rel.source_ref, "attribution")
            opinion = {"HIGH": "strongly-agree", "MEDIUM": "agree"}.get(
                level.level if level else "", "neutral"
            )
            self._add(
                v21.Opinion(
                    id=stix_id("opinion", r.id),
                    opinion=opinion,
                    object_refs=[r.id],
                    explanation=(level.statement if level else rel.description)[:2000],
                    created_by_ref=self.producer.id,
                    allow_custom=True,
                    **({"labels": ["synthetic"]} if rel.synthetic else {}),
                )
            )
            return
        rtype = REL_EXPORT.get(rel.relationship_type)
        if rtype:
            self._rel(
                rtype,
                src,
                dst,
                confidence=rel.confidence,
                description=rel.description,
                synthetic=rel.synthetic,
            )

    def _export_assessments(self) -> None:
        for a in self.repo.list_assessments("attribution"):
            subject = self.internal_to_stix.get(a.subject_id)
            if not subject:
                continue
            refs = [subject] + [
                self.internal_to_stix[str(alt["actor_id"])]
                for alt in a.alternatives[:3]
                if str(alt["actor_id"]) in self.internal_to_stix
            ]
            content = [a.statement, "", "Evidence:"] + [
                f"- [{e.type}] {e.description}" for e in a.evidence[:12]
            ]
            content += ["", "Caveats:"] + [f"- {c}" for c in a.caveats]
            self._add(
                v21.Note(
                    id=stix_id("note", a.id),
                    abstract=f"Attribution assessment: {a.level}",
                    content="\n".join(content)[:10000],
                    object_refs=refs,
                    created_by_ref=self.producer.id,
                    allow_custom=True,
                    x_threatintel_method=a.method,
                )
            )

    def _export_reports(self, include_synthetic: bool) -> None:
        for item in self.repo.list_collected_items(limit=100_000):
            if item.synthetic and not include_synthetic:
                continue
            refs = []
            for subj in self.repo.subjects_for_item(item.id):
                sid = self.internal_to_stix.get(subj + "#indicator") or self.internal_to_stix.get(subj)
                if sid:
                    refs.append(sid)
            for rel in self.repo.list_relationships(
                source_ref=item.id, relationship_type="exhibits-technique"
            ):
                ap = self._attack_pattern(rel.target_ref)
                if ap:
                    refs.append(ap)
            if not refs:
                continue
            kwargs: dict[str, Any] = {"allow_custom": True}
            if item.synthetic:
                kwargs.update(labels=["synthetic"], x_threatintel_synthetic=True)
            if item.url:
                kwargs["external_references"] = [
                    v21.ExternalReference(source_name=item.source_name, url=item.url)
                ]
            self.internal_to_stix[item.id] = stix_id("report", item.id)
            self._add(
                v21.Report(
                    id=stix_id("report", item.id),
                    name=item.title[:250],
                    report_types=["threat-report"],
                    published=item.published_at or item.collection_timestamp,
                    object_refs=sorted(set(refs)),
                    description=item.content[:4000],
                    created_by_ref=self._source_identity(item.source_id, item.source_name),
                    x_threatintel_reliability=item.source_reliability.value,
                    x_threatintel_credibility=item.information_credibility.value,
                    **kwargs,
                )
            )

    def bundle(self) -> dict[str, Any]:
        objs = [self.objects[k] for k in sorted(self.objects)]
        needs_markings = {m for o in objs for m in (o.get("object_marking_refs") or [])}
        for tlp in TLP_MAP.values():
            if tlp.id in needs_markings and tlp.id not in self.objects:
                objs.append(tlp)
        b = v21.Bundle(objects=objs, allow_custom=True)
        return dict(json.loads(b.serialize()))


def export_stix_bundle(
    repo: Repository,
    kb: AttackKnowledgeBase,
    settings: Settings | None = None,
    *,
    include_synthetic: bool = True,
) -> dict[str, Any]:
    return StixExporter(repo, kb, settings).build(include_synthetic=include_synthetic)
