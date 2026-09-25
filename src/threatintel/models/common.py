"""Shared vocabulary for the intelligence data model.

The enums here encode analytic concepts that must never be conflated:
source reliability vs. information credibility, raw report vs. assessment vs. fact,
association vs. attribution.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

# Stable namespace so internal ids are deterministic across runs (idempotent ingest).
TIX_NAMESPACE = uuid.UUID("8f1d6b2e-2a7c-5d3e-9b4a-6c1f0e7d2a91")


def utcnow() -> datetime:
    return datetime.now(UTC)


def stable_id(prefix: str, *parts: str) -> str:
    """Deterministic id in STIX style: ``<prefix>--<uuid5>``."""
    key = "|".join(p.strip().lower() for p in parts)
    return f"{prefix}--{uuid.uuid5(TIX_NAMESPACE, f'{prefix}|{key}')}"


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class SourceType(StrEnum):
    RSS = "rss"
    STIX = "stix"
    TAXII = "taxii"
    MISP = "misp"
    TELEGRAM = "telegram"
    MITRE = "mitre"
    HUMINT = "humint"
    ANALYST = "analyst"
    ENRICHMENT = "enrichment"
    SYNTHETIC = "synthetic"


class SourceReliability(StrEnum):
    """Admiralty / NATO source reliability (judged on the SOURCE's track record)."""

    A = "A"  # Completely reliable
    B = "B"  # Usually reliable
    C = "C"  # Fairly reliable
    D = "D"  # Not usually reliable
    E = "E"  # Unreliable
    F = "F"  # Reliability cannot be judged


RELIABILITY_LABELS = {
    "A": "Completely reliable",
    "B": "Usually reliable",
    "C": "Fairly reliable",
    "D": "Not usually reliable",
    "E": "Unreliable",
    "F": "Reliability cannot be judged",
}


class InformationCredibility(StrEnum):
    """Admiralty information credibility (judged on the INFORMATION itself)."""

    CONFIRMED = "1"
    PROBABLY_TRUE = "2"
    POSSIBLY_TRUE = "3"
    DOUBTFUL = "4"
    IMPROBABLE = "5"
    CANNOT_BE_JUDGED = "6"


CREDIBILITY_LABELS = {
    "1": "Confirmed by other sources",
    "2": "Probably true",
    "3": "Possibly true",
    "4": "Doubtful",
    "5": "Improbable",
    "6": "Truth cannot be judged",
}


class ConfidenceLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    VERY_HIGH = "VERY HIGH"


class AttributionLevel(StrEnum):
    """Attribution vocabulary. NONE/ASSOCIATED are deliberately weaker than LOW-HIGH."""

    INSUFFICIENT = "INSUFFICIENT EVIDENCE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class StatementType(StrEnum):
    """What kind of claim a piece of intelligence is. Never silently upgraded."""

    RAW_SOURCE_REPORT = "raw_source_report"
    ANALYST_ASSESSMENT = "analyst_assessment"
    CONFIRMED_FACT = "confirmed_fact"


class LifecycleStatus(StrEnum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    ENRICHING = "ENRICHING"
    CORRELATED = "CORRELATED"
    UNDER_REVIEW = "UNDER_REVIEW"
    CONFIRMED = "CONFIRMED"
    DISSEMINATED = "DISSEMINATED"
    ARCHIVED = "ARCHIVED"


class TLP(StrEnum):
    CLEAR = "clear"
    GREEN = "green"
    AMBER = "amber"
    RED = "red"


class ObservableType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CVE = "cve"
    ATTACK_TECHNIQUE = "attack-technique"
    BTC_ADDRESS = "btc-address"
    ETH_ADDRESS = "eth-address"
    TELEGRAM_REF = "telegram-ref"
    ASN = "asn"


class Priority(StrEnum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"
    P5 = "P5"


PRIORITY_LABELS = {
    "P1": "Critical",
    "P2": "High",
    "P3": "Medium",
    "P4": "Low",
    "P5": "Informational",
}


class TixModel(BaseModel):
    model_config = ConfigDict(use_enum_values=False, validate_assignment=True, extra="forbid")


class Provenance(TixModel):
    """Where a claim came from. Every intelligence object carries one or more of these."""

    source_id: str
    source_name: str
    source_type: SourceType
    collected_at: datetime
    processed_at: datetime = Field(default_factory=utcnow)
    collected_item_id: str | None = None
    reliability: SourceReliability = SourceReliability.F
    credibility: InformationCredibility = InformationCredibility.CANNOT_BE_JUDGED
    reference: str | None = None  # URL / message id / event uuid
    derived_from: str | None = None  # upstream origin, used for independence checks
    synthetic: bool = False

    @property
    def origin(self) -> str:
        """Identity used to decide whether two sources are independent."""
        return self.derived_from or self.source_id
