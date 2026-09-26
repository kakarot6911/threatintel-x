"""Domain entities (knowledge layer). Mirrors STIX 2.1 SDOs closely so export is lossless."""

from __future__ import annotations

from datetime import datetime
from typing import Any, ClassVar

from pydantic import Field

from threatintel.models.common import (
    TLP,
    InformationCredibility,
    LifecycleStatus,
    Provenance,
    SourceReliability,
    StatementType,
    TixModel,
    stable_id,
    utcnow,
)


class Entity(TixModel):
    entity_type: ClassVar[str] = "entity"

    id: str = ""
    name: str
    aliases: list[str] = []
    description: str = ""
    confidence: int = Field(default=50, ge=0, le=100)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    provenance: list[Provenance] = []
    synthetic: bool = False
    tlp: TLP = TLP.AMBER
    labels: list[str] = []
    external_references: list[dict[str, str]] = []
    created_at: datetime = Field(default_factory=utcnow)
    modified_at: datetime = Field(default_factory=utcnow)

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = stable_id(self.entity_type, self.name)

    def all_names(self) -> set[str]:
        return {n.lower() for n in [self.name, *self.aliases]}


class ThreatActor(Entity):
    entity_type: ClassVar[str] = "threat-actor"

    actor_kind: str = "intrusion-set"  # intrusion-set (group) | threat-actor (persona)
    motivation: str = "unknown"
    sophistication: str = "unknown"
    target_sectors: list[str] = []
    target_regions: list[str] = []
    suspected_origin: str | None = None  # an assessment, never a fact


class Campaign(Entity):
    entity_type: ClassVar[str] = "campaign"

    campaign_status: str = "active"  # active | dormant | concluded
    start_date: datetime | None = None
    end_date: datetime | None = None
    target_sectors: list[str] = []
    target_regions: list[str] = []
    objective: str = ""


class Malware(Entity):
    entity_type: ClassVar[str] = "malware"

    malware_types: list[str] = []  # rat, infostealer, ransomware, loader, botnet, backdoor, wiper
    platforms: list[str] = []
    is_family: bool = True
    commodity: bool = False  # widely available -> weak attribution signal


class Tool(Entity):
    entity_type: ClassVar[str] = "tool"

    tool_types: list[str] = []
    commodity: bool = True


class Vulnerability(Entity):
    entity_type: ClassVar[str] = "vulnerability"

    cvss: float | None = None
    known_exploited: bool = False
    ransomware_use: bool = False  # CISA KEV "knownRansomwareCampaignUse" == "Known"
    affected_product: str = ""
    kev_date_added: datetime | None = None
    kev_due_date: datetime | None = None


class Infrastructure(Entity):
    entity_type: ClassVar[str] = "infrastructure"

    infrastructure_types: list[str] = []  # command-and-control, phishing, staging, exfiltration


class Relationship(TixModel):
    id: str = ""
    source_ref: str
    target_ref: str
    relationship_type: str
    confidence: int = Field(default=50, ge=0, le=100)
    description: str = ""
    evidence: list[str] = []  # human-readable rationale
    provenance: list[Provenance] = []
    synthetic: bool = False
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = stable_id("relationship", self.source_ref, self.relationship_type, self.target_ref)


class IntelligenceRequirement(TixModel):
    id: str  # IR-001
    question: str
    priority: str = "P3"
    stakeholders: list[str] = []
    rationale: str = ""
    active: bool = True


class HumintReport(TixModel):
    """HUMINT-style analyst intake. Raw report, assessment and confirmation are distinct fields."""

    id: str = ""
    source_type: str = "human-source"
    source_identifier: str  # pseudonymised before storage
    source_reliability: SourceReliability
    information_credibility: InformationCredibility
    collection_method: str
    date_observed: datetime
    raw_note: str
    analyst_assessment: str = ""
    corroborating_sources: list[str] = []
    statement_type: StatementType = StatementType.RAW_SOURCE_REPORT
    synthetic: bool = False

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = stable_id(
                "humint", self.source_identifier, self.date_observed.isoformat(), self.raw_note
            )


class CredentialExposure(TixModel):
    """Exposure record. Holds NO secret material - only the fact a credential was present."""

    id: str = ""
    organization: str = ""
    domain: str
    account: str  # email / username (synthetic in demo data)
    credential_present: bool = True
    secret_fingerprint: str | None = None  # keyed HMAC, only when TIX_REDACTION_KEY set
    source_id: str
    discovered_at: datetime = Field(default_factory=utcnow)
    confidence: int = Field(default=50, ge=0, le=100)
    potential_access: str = "unknown"
    business_impact: str = "unknown"
    synthetic: bool = False

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = stable_id("credential-exposure", self.account, self.source_id)


class RansomwareClaim(TixModel):
    id: str = ""
    group: str
    victim_label: str  # synthetic / anonymised victim label, never a real org name
    victim_sector: str
    victim_region: str
    claimed_date: datetime
    leak_site_reference: str  # opaque synthetic reference - we never visit leak sites
    ttps: list[str] = []
    malware: list[str] = []
    infrastructure: list[str] = []
    confidence: int = Field(default=40, ge=0, le=100)
    synthetic: bool = True

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = stable_id(
                "ransomware-claim", self.group, self.victim_label, self.claimed_date.isoformat()
            )


class StatusChange(TixModel):
    subject_id: str
    from_status: LifecycleStatus | None
    to_status: LifecycleStatus
    at: datetime = Field(default_factory=utcnow)
    by: str = "system"
    note: str = ""


class IntelProduct(TixModel):
    id: str = ""
    kind: str  # technical-report | actor-profile | campaign-report | ciso-brief | ioc-bulletin
    title: str
    subject_id: str | None = None
    tlp: TLP = TLP.AMBER
    requirements: list[str] = []
    body_markdown: str
    generated_at: datetime = Field(default_factory=utcnow)
    contains_synthetic: bool = False

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = stable_id("report", self.kind, self.subject_id or "", self.generated_at.isoformat())


ENTITY_CLASSES: dict[str, type[Entity]] = {
    cls.entity_type: cls for cls in (ThreatActor, Campaign, Malware, Tool, Vulnerability, Infrastructure)
}
