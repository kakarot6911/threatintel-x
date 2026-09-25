"""Deterministic correlation engine.

A *profile* is the set of technical and contextual features known about a subject
(a new report, a campaign, an actor). Two profiles are compared signal by signal;
each shared feature contributes a configured weight, combined with a noisy-OR:

    score = 1 - prod(1 - w_i)

so independent weak signals add up, but no pile of weak signals (e.g. 20 common
ATT&CK techniques) can masquerade as a strong one - technique overlap is capped.
Every signal is kept with its explanation: the score is never a black box.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from threatintel.analysis.scoring_config import load_scoring
from threatintel.models.common import ObservableType


@dataclass
class Profile:
    subject_id: str
    label: str
    hashes: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    emails: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    certificates: set[str] = field(default_factory=set)
    crypto: set[str] = field(default_factory=set)
    nameservers: set[str] = field(default_factory=set)
    asns: set[str] = field(default_factory=set)
    malware: set[str] = field(default_factory=set)
    commodity_malware: set[str] = field(default_factory=set)
    cves: set[str] = field(default_factory=set)
    techniques: set[str] = field(default_factory=set)
    target_sectors: set[str] = field(default_factory=set)
    names: set[str] = field(default_factory=set)
    start: datetime | None = None
    end: datetime | None = None
    sources: set[str] = field(default_factory=set)  # independent origins behind this profile

    def add_observable(self, obs_type: ObservableType, value: str) -> None:
        bucket = {
            ObservableType.MD5: self.hashes,
            ObservableType.SHA1: self.hashes,
            ObservableType.SHA256: self.hashes,
            ObservableType.URL: self.urls,
            ObservableType.DOMAIN: self.domains,
            ObservableType.EMAIL: self.emails,
            ObservableType.IPV4: self.ips,
            ObservableType.IPV6: self.ips,
            ObservableType.CVE: self.cves,
            ObservableType.ATTACK_TECHNIQUE: self.techniques,
            ObservableType.BTC_ADDRESS: self.crypto,
            ObservableType.ETH_ADDRESS: self.crypto,
            ObservableType.ASN: self.asns,
        }.get(obs_type)
        if bucket is not None:
            bucket.add(value)

    def merge(self, other: Profile) -> None:
        for name in (
            "hashes",
            "urls",
            "domains",
            "emails",
            "ips",
            "certificates",
            "crypto",
            "nameservers",
            "asns",
            "malware",
            "commodity_malware",
            "cves",
            "techniques",
            "target_sectors",
            "names",
            "sources",
        ):
            getattr(self, name).update(getattr(other, name))
        self.start = min(filter(None, [self.start, other.start]), default=None)
        self.end = max(filter(None, [self.end, other.end]), default=None)

    @property
    def infrastructure(self) -> set[str]:
        return self.domains | self.ips | self.urls


@dataclass
class Signal:
    name: str
    category: str  # infrastructure | malware | ttp | targeting | temporal | tooling | identity
    weight: float
    values: list[str]
    explanation: str


@dataclass
class CorrelationResult:
    subject_id: str
    candidate_id: str
    candidate_label: str
    score: float
    signals: list[Signal]

    @property
    def categories(self) -> set[str]:
        return {s.category for s in self.signals}

    def explain(self) -> str:
        if not self.signals:
            return f"No overlap with {self.candidate_label}."
        parts = [f"{s.explanation} (w={s.weight:.2f})" for s in sorted(self.signals, key=lambda s: -s.weight)]
        return f"Correlation {self.score:.2f} with {self.candidate_label}: " + "; ".join(parts)


def noisy_or(weights: list[float]) -> float:
    prod = 1.0
    for w in weights:
        prod *= 1.0 - max(0.0, min(w, 1.0))
    return 1.0 - prod


def _fmt(values: set[str], limit: int = 5) -> str:
    items = sorted(values)
    more = f" (+{len(items) - limit} more)" if len(items) > limit else ""
    return ", ".join(items[:limit]) + more


class CorrelationEngine:
    def __init__(self, config: dict[str, Any] | None = None) -> None:
        cfg = config or load_scoring()["correlation"]
        self.w: dict[str, float] = dict(cfg["signals"])
        self.technique_cap = float(cfg["max_technique_contribution"])

    def compare(self, a: Profile, b: Profile) -> CorrelationResult:
        signals: list[Signal] = []

        def shared(attr: str, signal: str, category: str, noun: str) -> None:
            common = getattr(a, attr) & getattr(b, attr)
            if common:
                weight = noisy_or([self.w[signal]] * min(len(common), 3))
                signals.append(
                    Signal(
                        signal, category, round(weight, 3), sorted(common), f"shared {noun}: {_fmt(common)}"
                    )
                )

        shared("hashes", "shared_hash", "malware", "file hash")
        shared("urls", "shared_url", "infrastructure", "URL")
        shared("domains", "shared_domain", "infrastructure", "domain")
        shared("emails", "shared_email", "infrastructure", "email address")
        shared("certificates", "shared_certificate", "infrastructure", "TLS certificate")
        shared("crypto", "shared_crypto_address", "infrastructure", "cryptocurrency address")
        shared("ips", "shared_ip", "infrastructure", "IP address")
        # A name server may appear as a plain domain on one side (e.g. quoted in an incident note)
        # and as enrichment-derived NS data on the other.
        ns_common = ((a.nameservers | a.domains) & b.nameservers) | (
            a.nameservers & (b.nameservers | b.domains)
        )
        if ns_common:
            signals.append(
                Signal(
                    "shared_nameserver",
                    "infrastructure",
                    self.w["shared_nameserver"],
                    sorted(ns_common),
                    f"shared name server: {_fmt(ns_common)}",
                )
            )
        shared("asns", "shared_asn", "infrastructure", "ASN")
        shared("cves", "shared_cve", "ttp", "exploited CVE")
        shared("target_sectors", "shared_target_sector", "targeting", "target sector")

        distinctive = (a.malware - a.commodity_malware - b.commodity_malware) & (
            b.malware - b.commodity_malware
        )
        if distinctive:
            signals.append(
                Signal(
                    "shared_malware",
                    "malware",
                    round(noisy_or([self.w["shared_malware"]] * min(len(distinctive), 2)), 3),
                    sorted(distinctive),
                    f"shared non-commodity malware: {_fmt(distinctive)}",
                )
            )
        commodity = (a.malware & b.malware) - distinctive
        if commodity:
            signals.append(
                Signal(
                    "shared_commodity_malware",
                    "tooling",
                    self.w["shared_commodity_malware"],
                    sorted(commodity),
                    f"shared commodity malware/tooling (weak): {_fmt(commodity)}",
                )
            )

        techniques = a.techniques & b.techniques
        if techniques:
            weight = min(self.technique_cap, noisy_or([self.w["shared_technique"]] * len(techniques)))
            signals.append(
                Signal(
                    "shared_technique",
                    "ttp",
                    round(weight, 3),
                    sorted(techniques),
                    f"{len(techniques)} shared ATT&CK technique(s): {_fmt(techniques)} "
                    f"(capped at {self.technique_cap:.2f})",
                )
            )

        names = a.names & b.names
        if names:
            signals.append(
                Signal(
                    "shared_alias",
                    "identity",
                    self.w["shared_alias"],
                    sorted(names),
                    f"explicitly named in source: {_fmt(names)}",
                )
            )

        if a.start and b.start:
            a_end, b_end = a.end or a.start, b.end or b.start
            if a.start <= b_end and b.start <= a_end:
                signals.append(
                    Signal(
                        "temporal_overlap",
                        "temporal",
                        self.w["temporal_overlap"],
                        [],
                        "activity windows overlap",
                    )
                )

        score = round(noisy_or([s.weight for s in signals]), 3)
        return CorrelationResult(a.subject_id, b.subject_id, b.label, score, signals)

    def rank(
        self, subject: Profile, candidates: list[Profile], min_score: float = 0.05
    ) -> list[CorrelationResult]:
        results = [self.compare(subject, c) for c in candidates if c.subject_id != subject.subject_id]
        return sorted(
            (r for r in results if r.score >= min_score), key=lambda r: (-r.score, r.candidate_label)
        )
