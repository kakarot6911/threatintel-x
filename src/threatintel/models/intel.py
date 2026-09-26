"""Core intelligence objects.

Layering (never collapsed into one another):

    CollectedItem       raw intelligence, as received (after credential redaction)
    Observable          normalised, validated, de-duplicated technical datum
    EnrichmentResult    third-party context about an observable, with its own provenance
    Evidence            a single, weighted reason supporting a correlation / attribution
    Assessment          an analytic judgement (score + level + rationale), never a fact
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field, field_validator

from threatintel.models.common import (
    ConfidenceLevel,
    InformationCredibility,
    ObservableType,
    Provenance,
    SourceReliability,
    SourceType,
    StatementType,
    TixModel,
    sha256_text,
    stable_id,
    utcnow,
)


class Source(TixModel):
    id: str
    name: str
    source_type: SourceType
    reliability: SourceReliability = SourceReliability.F
    url: str | None = None
    description: str = ""
    collection_policy: str = ""  # terms-of-use / legal basis note
    derived_from: str | None = None
    synthetic: bool = False
    internal: bool = False  # first-party telemetry (our SOC/EDR): always organisation-relevant
    # False for publishers that defang their indicators: their plain links/IPs are references, not IOCs.
    plain_indicators: bool = True
    enabled: bool = True


class CollectedItem(TixModel):
    """Common normalised output of every collector (raw intelligence layer)."""

    id: str = ""
    source_id: str
    source_name: str
    source_type: SourceType
    collection_timestamp: datetime = Field(default_factory=utcnow)
    published_at: datetime | None = None
    title: str
    content: str
    url: str | None = None
    language: str = "en"
    source_reliability: SourceReliability = SourceReliability.F
    information_credibility: InformationCredibility = InformationCredibility.CANNOT_BE_JUDGED
    raw_reference: str | None = None
    statement_type: StatementType = StatementType.RAW_SOURCE_REPORT
    derived_from: str | None = None
    tags: list[str] = []
    metadata: dict[str, Any] = {}
    content_hash: str = ""
    redactions: int = 0

    @property
    def synthetic(self) -> bool:
        return self.source_type == SourceType.SYNTHETIC or bool(self.metadata.get("synthetic"))

    def finalise(self) -> CollectedItem:
        """Compute content hash + deterministic id (dedup key = source + content)."""
        self.content_hash = sha256_text(self.content)
        if not self.id:
            self.id = stable_id("collected-item", self.source_id, self.content_hash)
        return self

    def provenance(self) -> Provenance:
        return Provenance(
            source_id=self.source_id,
            source_name=self.source_name,
            source_type=self.source_type,
            collected_at=self.collection_timestamp,
            collected_item_id=self.id,
            reliability=self.source_reliability,
            credibility=self.information_credibility,
            reference=self.url or self.raw_reference,
            derived_from=self.derived_from,
            synthetic=self.synthetic,
        )


class ExtractedObservable(TixModel):
    type: ObservableType
    value: str  # normalised
    raw: str  # as seen in the text
    defanged: bool = False
    context: str = ""


class ValidationResult(TixModel):
    valid: bool
    actionable: bool = True
    reasons: list[str] = []
    flags: list[str] = []  # e.g. private, documentation, reserved, special-use, unverified


class Observable(TixModel):
    id: str = ""
    type: ObservableType
    value: str
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    actionable: bool = True
    flags: list[str] = []
    synthetic: bool = False
    sightings: int = 1
    provenance: list[Provenance] = []

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = stable_id("observable", self.type.value, self.value)


class EnrichmentResult(TixModel):
    provider: str
    observable_type: ObservableType
    observable: str
    timestamp: datetime = Field(default_factory=utcnow)
    result: dict[str, Any] = {}
    confidence: int = Field(default=50, ge=0, le=100)
    source_reference: str = ""
    synthetic: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


class Evidence(TixModel):
    """One weighted reason. ``llm_generated`` evidence is never scored until validated."""

    type: str  # infrastructure, malware, ttp, targeting, temporal, tooling, language, public_reporting,...
    weight: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    source: str
    source_origin: str | None = None
    timestamp: datetime = Field(default_factory=utcnow)
    description: str
    values: list[str] = []
    llm_generated: bool = False
    validated: bool = True

    @field_validator("type")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.strip().lower()


class FactorScore(TixModel):
    name: str
    weight: float
    value: float  # 0..1
    contribution: float  # weight * value * 100
    explanation: str


class Assessment(TixModel):
    id: str = ""
    subject_id: str
    kind: str  # confidence | attribution | priority | correlation
    score: float
    level: str
    statement: str
    factors: list[FactorScore] = []
    evidence: list[Evidence] = []
    alternatives: list[dict[str, Any]] = []
    caveats: list[str] = []
    method: str = "deterministic"
    llm_assisted: bool = False
    analyst: str = "system"
    created_at: datetime = Field(default_factory=utcnow)
    statement_type: StatementType = StatementType.ANALYST_ASSESSMENT

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = stable_id("assessment", self.kind, self.subject_id, self.created_at.isoformat())


class ConfidenceResult(TixModel):
    score: float
    level: ConfidenceLevel
    factors: list[FactorScore]
    explanation: str
