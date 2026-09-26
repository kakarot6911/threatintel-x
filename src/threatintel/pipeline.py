"""Processing pipeline for one collected item.

    redact -> store raw -> extract -> validate/normalise -> store observables (+provenance)
    -> link to named entities -> map ATT&CK -> enrich -> correlate -> attribute
    -> confidence -> priority -> lifecycle

Each stage is deterministic. LLMs are not involved anywhere in this path.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from threatintel.analysis.confidence import score_confidence
from threatintel.analysis.correlation import Profile
from threatintel.analysis.lifecycle import PIPELINE_PATH
from threatintel.analysis.priority import PriorityInput, score_priority
from threatintel.enrichment.engine import technical_evidence
from threatintel.extraction.benign import host_of, is_benign, load_benign, registrable
from threatintel.extraction.redaction import redact
from threatintel.extraction.validate import validate
from threatintel.models.common import LifecycleStatus, ObservableType, Provenance, SourceType, utcnow
from threatintel.models.entities import (
    Campaign,
    CredentialExposure,
    Entity,
    Malware,
    Relationship,
    ThreatActor,
    Tool,
    Vulnerability,
)
from threatintel.models.intel import Assessment, CollectedItem, EnrichmentResult, Observable
from threatintel.platform import Platform

log = logging.getLogger(__name__)

# Observable types that can "indicate" a campaign / actor / malware.
INDICATOR_TYPES = {
    ObservableType.IPV4,
    ObservableType.IPV6,
    ObservableType.DOMAIN,
    ObservableType.URL,
    ObservableType.EMAIL,
    ObservableType.MD5,
    ObservableType.SHA1,
    ObservableType.SHA256,
    ObservableType.BTC_ADDRESS,
    ObservableType.ETH_ADDRESS,
    ObservableType.TELEGRAM_REF,
}
HASH_TYPES = {ObservableType.MD5, ObservableType.SHA1, ObservableType.SHA256}
NETWORK_TYPES = {
    ObservableType.IPV4,
    ObservableType.IPV6,
    ObservableType.DOMAIN,
    ObservableType.URL,
    ObservableType.EMAIL,
}
ENRICHABLE = {
    ObservableType.IPV4,
    ObservableType.IPV6,
    ObservableType.DOMAIN,
    ObservableType.URL,
    *HASH_TYPES,
}
SYNTHETIC_TOLERATED_FLAGS = {"documentation", "special-use"}
C2_TECHNIQUES = {"T1071", "T1071.001", "T1071.004", "T1573", "T1102", "T1105", "T1568.002", "T1090"}
PHISHING_TECHNIQUES = {"T1566", "T1566.001", "T1566.002"}
RANSOM_TECHNIQUES = {"T1486", "T1490"}
SOURCE_CONFIDENCE = {"A": 85, "B": 75, "C": 60, "D": 40, "E": 25, "F": 35}


@dataclass
class ProcessResult:
    item_id: str
    duplicate: bool = False
    redactions: int = 0
    observables: list[str] = field(default_factory=list)
    rejected: int = 0
    entities: dict[str, list[str]] = field(default_factory=dict)
    techniques: list[dict[str, Any]] = field(default_factory=list)
    enrichments: int = 0
    correlations: list[dict[str, Any]] = field(default_factory=list)
    attribution: dict[str, Any] | None = None
    confidence: dict[str, Any] | None = None
    priority: dict[str, Any] | None = None
    status: str | None = None
    credential_exposures: int = 0

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class Pipeline:
    def __init__(self, platform: Platform, *, enrich: bool = True) -> None:
        self.p = platform
        self.repo = platform.repo
        self.enrich_enabled = enrich

    # ================================================================== entry
    def process(self, item: CollectedItem, *, now: datetime | None = None) -> ProcessResult:
        now = now or utcnow()
        key = self.p.settings.redaction_key.get_secret_value().encode()
        red = redact(item.content, key)
        red_title = redact(item.title, key)
        item = item.model_copy(
            update={
                "content": red.text,
                "title": red_title.text,
                "redactions": red.redactions + red_title.redactions,
                "id": "",
            }
        )
        item.finalise()
        result = ProcessResult(item_id=item.id, redactions=item.redactions)
        if not self.repo.add_collected_item(item):
            result.duplicate = True
            result.status = (self.repo.get_status(item.id) or LifecycleStatus.NEW).value
            return result
        self.p.lifecycle.advance(item.id, [LifecycleStatus.NEW], by="pipeline", note="collected")
        if item.metadata.get("reference_data"):
            return result
        prov = item.provenance()

        # --- credential exposure (after redaction: only accounts + fingerprints survive)
        for acct in red.accounts:
            domain = acct.account.rpartition("@")[2]
            org = domain in self.p.settings.org_domains
            exposure = CredentialExposure(
                organization=self.p.settings.org_name if org else "",
                domain=domain,
                account=acct.account,
                secret_fingerprint=acct.fingerprint,
                source_id=item.source_id,
                discovered_at=item.collection_timestamp,
                confidence=SOURCE_CONFIDENCE[item.source_reliability.value],
                potential_access="corporate SSO / email" if org else "unknown",
                business_impact="account takeover risk" if org else "third-party exposure",
                synthetic=item.synthetic,
            )
            self.repo.put_record(
                "credential_exposure",
                exposure.id,
                {**exposure.model_dump(mode="json"), "collected_item_id": item.id},
                synthetic=item.synthetic,
            )
            result.credential_exposures += 1

        # --- extraction
        telegram = item.source_type == SourceType.TELEGRAM or "channel_reference" in item.metadata
        extraction = self.p.extractor().extract(f"{item.title}\n{item.content}", telegram_context=telegram)
        result.rejected = len(extraction.rejected)
        self.p.lifecycle.advance(
            item.id,
            [LifecycleStatus.NEW, LifecycleStatus.TRIAGED],
            by="pipeline",
            note=f"{len(extraction.observables)} observable(s) extracted",
        )

        observables: list[Observable] = []
        benign = load_benign(str(self.p.settings.config_dir / "benign_domains.txt"))
        feed_host = host_of(ObservableType.URL, item.url or "") if item.url else None
        if feed_host:
            benign = benign | {registrable(feed_host)}
        source = self.repo.get_source(item.source_id)
        references_only = bool(source and not source.plain_indicators and not item.synthetic)
        for ex in extraction.observables:
            check = validate(ex.type, ex.value, known_techniques=self.p.kb.technique_ids)
            actionable = check.actionable
            flags = list(check.flags)
            if item.synthetic and not actionable and set(check.flags) <= SYNTHETIC_TOLERATED_FLAGS:
                actionable = True  # the synthetic world deliberately lives in documentation space
            if (
                actionable
                and is_benign(ex.type, ex.value, benign)
                and (not ex.defanged or ex.type == ObservableType.DOMAIN)
            ):
                # A citation, or the host of an abused legitimate service: the specific (defanged) URL may be
                # an indicator, but blocking e.g. gateway.icloud.com itself never is.
                actionable = False
                flags.append("known-benign")
            elif actionable and references_only and not ex.defanged and ex.type in NETWORK_TYPES:
                actionable = False  # this publisher defangs its IOCs; a plain link is a reference
                flags.append("reference-link")
            obs = self.repo.upsert_observable(
                Observable(
                    type=ex.type,
                    value=ex.value,
                    first_seen=item.published_at or item.collection_timestamp,
                    last_seen=item.published_at or item.collection_timestamp,
                    actionable=actionable,
                    flags=flags,
                    synthetic=item.synthetic,
                ),
                prov,
            )
            observables.append(obs)
            result.observables.append(f"{obs.type.value}:{obs.value}")

        # --- named entities
        named: dict[str, list[Entity]] = {}
        for etype, names in extraction.entities.items():
            for name in sorted(names):
                ent = self.repo.find_entity(etype, name)
                if ent is not None:
                    named.setdefault(etype, []).append(ent)
        cves = [o for o in observables if o.type == ObservableType.CVE]
        for cve in cves:
            vuln = self.repo.find_entity("vulnerability", cve.value) or self.repo.upsert_entity(
                Vulnerability(
                    name=cve.value,
                    synthetic=False,
                    external_references=[{"source_name": "cve", "external_id": cve.value}],
                )
            )
            named.setdefault("vulnerability", [])
            if vuln.id not in {v.id for v in named["vulnerability"]}:
                named["vulnerability"].append(vuln)
        result.entities = {k: [e.name for e in v] for k, v in named.items()}

        # --- ATT&CK mapping
        explicit = {
            o.value for o in observables if o.type == ObservableType.ATTACK_TECHNIQUE and o.actionable
        }
        mappings = self.p.mapper.map_text(item.content, explicit)
        result.techniques = [
            {
                "id": m.technique.technique_id,
                "name": m.technique.name,
                "method": m.method,
                "matched": m.matched,
                "confidence": m.confidence,
            }
            for m in mappings
        ]
        for m in mappings:
            self.repo.upsert_relationship(
                Relationship(
                    source_ref=item.id,
                    target_ref=m.technique.stix_id,
                    relationship_type="exhibits-technique",
                    confidence=m.confidence,
                    synthetic=item.synthetic,
                    provenance=[prov],
                    description=(
                        "explicit technique id in source"
                        if m.method == "explicit-id"
                        else "keyword-rule suggestion - requires analyst review"
                    ),
                    evidence=[f"{m.method}: '{m.matched}'"],
                )
            )

        self._link_entities(item, prov, observables, named, mappings)

        # --- enrichment
        self.p.lifecycle.advance(item.id, [LifecycleStatus.TRIAGED, LifecycleStatus.ENRICHING], by="pipeline")
        enrichments: dict[str, list[EnrichmentResult]] = {}
        if self.enrich_enabled:
            for obs in observables:
                if obs.actionable and obs.type in ENRICHABLE:
                    enrichments[obs.id] = self.p.enrichment.enrich(obs)
                    result.enrichments += len(enrichments[obs.id])

        # --- correlation + attribution
        subject = self._item_profile(item, observables, named, mappings)
        campaign_matches = self.p.correlation.rank(
            subject, self.p.profiles.all_campaign_profiles(), min_score=0.2
        )
        result.correlations = [
            {
                "campaign_id": c.candidate_id,
                "campaign": c.candidate_label,
                "score": c.score,
                "signals": [s.explanation for s in c.signals],
            }
            for c in campaign_matches[:5]
        ]
        if campaign_matches:
            self.repo.save_assessment(
                Assessment(
                    subject_id=item.id,
                    kind="correlation",
                    score=campaign_matches[0].score,
                    level="MATCH" if campaign_matches[0].score >= 0.5 else "WEAK",
                    statement=campaign_matches[0].explain(),
                    alternatives=[
                        {
                            "campaign_id": c.candidate_id,
                            "campaign": c.candidate_label,
                            "score": c.score,
                            "categories": sorted(c.categories),
                        }
                        for c in campaign_matches[:5]
                    ],
                )
            )
        self.p.lifecycle.advance(
            item.id, [LifecycleStatus.ENRICHING, LifecycleStatus.CORRELATED], by="pipeline"
        )

        has_technical = any(o.actionable and o.type in INDICATOR_TYPES for o in observables)
        if has_technical:
            attribution = self.p.attribution.assess(subject, self.p.profiles.all_actor_profiles())
            self.repo.save_assessment(attribution)
            result.attribution = {
                "level": attribution.level,
                "score": attribution.score,
                "statement": attribution.statement,
                "alternatives": attribution.alternatives,
            }

        # --- confidence (per observable, and for the item as a whole)
        tech_values: list[float] = []
        for obs in observables:
            if not obs.actionable or obs.type not in INDICATOR_TYPES:
                continue
            fresh = self.repo.get_observable_by_id(obs.id) or obs
            enr = enrichments.get(obs.id) or self.repo.enrichments_for(obs.type, obs.value)
            tech, tech_x = technical_evidence(enr, now)
            tech_values.append(tech)
            spec = None
            if obs.type == ObservableType.DOMAIN and self.p.profiles.is_nameserver(obs.id):
                spec = 0.2  # a name server is shared hosting, not a distinctive indicator
            conf = score_confidence(
                fresh.provenance,
                observable_type=obs.type,
                last_seen=fresh.last_seen,
                technical_evidence=tech,
                technical_explanation=tech_x,
                now=now,
                specificity_override=spec,
            )
            self.repo.save_assessment(
                Assessment(
                    subject_id=obs.id,
                    kind="confidence",
                    score=conf.score,
                    level=conf.level.value,
                    statement=conf.explanation,
                    factors=conf.factors,
                )
            )
        item_conf = score_confidence(
            [prov],
            last_seen=item.published_at or item.collection_timestamp,
            technical_evidence=max(tech_values, default=0.0),
            technical_explanation="strongest technical signal among extracted observables",
            specificity_override=min(1.0, 0.3 + 0.1 * len(observables)),
            now=now,
        )
        self.repo.save_assessment(
            Assessment(
                subject_id=item.id,
                kind="confidence",
                score=item_conf.score,
                level=item_conf.level.value,
                statement=item_conf.explanation,
                factors=item_conf.factors,
            )
        )
        result.confidence = {"score": item_conf.score, "level": item_conf.level.value}

        # --- priority
        pr = self._priority(item, observables, named, mappings, item_conf.score / 100, result, now)
        self.repo.save_assessment(
            Assessment(
                subject_id=item.id,
                kind="priority",
                score=pr.score,
                level=pr.priority.value,
                statement="; ".join(pr.explanation),
            )
        )
        result.priority = {
            "priority": pr.priority.value,
            "label": pr.label,
            "score": pr.score,
            "explanation": pr.explanation,
        }

        # --- lifecycle: P1/P2 or any credential exposure goes to an analyst
        final = self.p.lifecycle.advance(
            item.id,
            PIPELINE_PATH
            if pr.priority.value in ("P1", "P2") or result.credential_exposures
            else PIPELINE_PATH[:-1],
            by="pipeline",
            note=f"auto-triage {pr.priority.value}",
        )
        result.status = final.value if final else None
        for obs in observables:
            self.p.lifecycle.advance(obs.id, [LifecycleStatus.NEW], by="pipeline")
        return result

    # ============================================================ entity links
    def _link_entities(
        self,
        item: CollectedItem,
        prov: Provenance,
        observables: list[Observable],
        named: dict[str, list[Entity]],
        mappings: list[Any],
    ) -> None:
        base_conf = SOURCE_CONFIDENCE[item.source_reliability.value]
        indicators = [o for o in observables if o.actionable and o.type in INDICATOR_TYPES]
        campaigns = [e for e in named.get("campaign", []) if isinstance(e, Campaign)]
        actors = [e for e in named.get("threat-actor", []) if isinstance(e, ThreatActor)]
        malware = [e for e in named.get("malware", []) if isinstance(e, Malware)]
        tools = [e for e in named.get("tool", []) if isinstance(e, Tool)]
        vulns = named.get("vulnerability", [])
        evidence = [
            f"co-reported in '{item.title}' ({item.source_name}, {item.source_reliability.value}"
            f"{item.information_credibility.value})"
        ]

        def rel(src: str, target: str, rtype: str, conf: int, desc: str = "") -> None:
            self.repo.upsert_relationship(
                Relationship(
                    source_ref=src,
                    target_ref=target,
                    relationship_type=rtype,
                    confidence=max(0, min(conf, 100)),
                    description=desc,
                    evidence=evidence,
                    provenance=[prov],
                    synthetic=item.synthetic,
                    first_seen=item.published_at,
                    last_seen=item.published_at,
                )
            )

        # Free text is weak structure. From it we derive only:
        #   * IOC -> named campaign (or, with no campaign, named actor)  "indicates"
        #   * sample hash -> malware family, only when exactly one family/tool is named
        #   * ATT&CK technique -> campaign, only when exactly one campaign is named and one actor at most
        #   * campaign -> actor "reported-attribution", only when exactly one actor is named
        # Every other entity co-mention becomes a weak "related-to" for analyst review; promotion to
        # "uses"/"exploits" requires a structured source (STIX/MISP/feed) or an analyst.
        ambiguous = len(actors) > 1
        targets: list[tuple[Entity, int]] = [(c, base_conf) for c in campaigns]
        if not campaigns:
            targets += [(a, int(base_conf * 0.8)) for a in actors]
        for ent, conf in targets:
            for obs in indicators:
                rel(obs.id, ent.id, "indicates", conf, f"observed in reporting on {ent.name}")
            for other in [*vulns, *malware, *tools]:
                rel(ent.id, other.id, "related-to", min(conf, 30), f"co-mentioned in {item.source_name}")
            if len(campaigns) == 1 and not ambiguous and ent in campaigns:
                for mp in mappings:
                    if mp.method == "explicit-id" or mp.confidence >= 60:
                        rel(
                            ent.id,
                            mp.technique.stix_id,
                            "uses",
                            min(conf, mp.confidence),
                            f"{mp.method}: '{mp.matched}'",
                        )
        families = [*malware, *tools]
        if len(families) == 1:  # only unambiguous: one family named alongside the hashes
            for obs in indicators:
                if obs.type in HASH_TYPES:
                    rel(obs.id, families[0].id, "indicates", base_conf, f"sample of {families[0].name}")
        # A source naming a campaign and exactly ONE actor is a REPORTED attribution claim, kept separate
        # from our own assessed "attributed-to" relationships. Several actors in one text (e.g. "the same IP
        # later used by X") is co-mention, not a claim - recorded as a weak "related-to" only.
        for c in campaigns:
            if len(actors) == 1:
                rel(
                    c.id,
                    actors[0].id,
                    "reported-attribution",
                    base_conf,
                    f"{item.source_name} reports {c.name} -> {actors[0].name}",
                )
            else:
                for a in actors:
                    rel(
                        c.id,
                        a.id,
                        "related-to",
                        min(base_conf, 30),
                        f"co-mentioned with {c.name} in {item.source_name}; not an attribution claim",
                    )

    # ================================================================ profiles
    def _item_profile(
        self,
        item: CollectedItem,
        observables: list[Observable],
        named: dict[str, list[Entity]],
        mappings: list[Any],
    ) -> Profile:
        when = item.published_at or item.collection_timestamp
        profile = Profile(
            subject_id=item.id,
            label=f"'{item.title}'",
            start=when,
            end=when,
            sources={item.provenance().origin},
        )
        for obs in observables:
            if obs.actionable:
                self.p.profiles.add_observable(profile, obs.id, obs.type, obs.value)
                self.p.profiles.add_infrastructure_context(profile, obs.id, obs.type, obs.value)
            if obs.type in HASH_TYPES:  # pivot: known sample -> its malware family
                for r in self.repo.list_relationships(source_ref=obs.id, relationship_type="indicates"):
                    fam = self.repo.get_entity(r.target_ref)
                    if isinstance(fam, Malware):
                        profile.malware.add(fam.name)
        for ent in [*named.get("malware", []), *named.get("tool", [])]:
            profile.malware.add(ent.name)
            if getattr(ent, "commodity", False):
                profile.commodity_malware.add(ent.name)
        for ent in [*named.get("threat-actor", []), *named.get("campaign", [])]:
            profile.names |= ent.all_names()
        for m in mappings:
            if m.method == "explicit-id" or m.confidence >= 60:
                profile.techniques.add(m.technique.technique_id)
        for sector in self.p.settings.org_sectors:
            if sector in item.content.lower():
                profile.target_sectors.add(sector)
        return profile

    # ================================================================ priority
    def _priority(
        self,
        item: CollectedItem,
        observables: list[Observable],
        named: dict[str, list[Entity]],
        mappings: list[Any],
        confidence: float,
        result: ProcessResult,
        now: datetime,
    ) -> Any:
        tids = {m.technique.technique_id for m in mappings}
        factors: list[str] = []
        malware = named.get("malware", [])
        if tids & RANSOM_TECHNIQUES or any("ransomware" in getattr(m, "malware_types", []) for m in malware):
            factors.append("ransomware")
        vulns = [v for v in named.get("vulnerability", []) if isinstance(v, Vulnerability)]
        if any(v.known_exploited for v in vulns):
            factors.append("active_exploitation")
        if any(v.ransomware_use for v in vulns) and "ransomware" not in factors:
            factors.append("ransomware")
        cvss = max((v.cvss for v in vulns if v.cvss is not None), default=None)
        if result.credential_exposures:
            factors.append("exposed_credential")
        if tids & C2_TECHNIQUES:
            factors.append("active_c2")
        if tids & PHISHING_TECHNIQUES:
            factors.append("phishing")
        if any(o.type in HASH_TYPES for o in observables) or malware:
            factors.append("malware_delivery")

        org_domains = {d.lower() for d in self.p.settings.org_domains}
        source = self.repo.get_source(item.source_id)
        internal = bool(source and source.internal)
        org_match = internal or bool(
            result.credential_exposures
            and any(
                r.get("domain") in org_domains
                for r in self.repo.list_records("credential_exposure")
                if r.get("collected_item_id") == item.id
            )
        )
        for obs in observables:
            host = obs.value.rpartition("@")[2] if obs.type == ObservableType.EMAIL else obs.value
            if obs.type in (ObservableType.DOMAIN, ObservableType.EMAIL, ObservableType.URL) and any(
                d in host for d in org_domains | {d.split(".")[0] for d in org_domains}
            ):
                org_match = True
        sectors = {s.lower() for s in self.p.settings.org_sectors}
        regions = {r.lower() for r in self.p.settings.org_regions}
        ent_sectors: set[str] = set()
        ent_regions: set[str] = set()
        for ent in [*named.get("campaign", []), *named.get("threat-actor", [])]:
            ent_sectors |= set(getattr(ent, "target_sectors", []))
            ent_regions |= set(getattr(ent, "target_regions", []))
        text = item.content.lower()
        sector_match = bool(ent_sectors & sectors) or any(s in text for s in sectors)
        region_match = bool(ent_regions & regions)
        age_days = max((now - (item.published_at or item.collection_timestamp)).total_seconds() / 86400, 0)
        recency = 0.5 ** (age_days / 14.0)
        return score_priority(
            PriorityInput(
                impact_factors=factors,
                confidence=confidence,
                recency=recency,
                sector_match=sector_match,
                region_match=region_match,
                org_asset_match=org_match,
                cvss=cvss,
            )
        )
