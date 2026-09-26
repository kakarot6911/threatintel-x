"""Runs providers for an observable, caches results, and derives infrastructure relationships.

Derived facts (domain resolves-to IP, IP belongs-to ASN, domain uses name server) are
stored with ENRICHMENT provenance: they add context but never count as independent
corroboration of maliciousness.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from threatintel.config import Settings, get_settings
from threatintel.enrichment.base import EnrichmentProvider
from threatintel.enrichment.providers import default_providers
from threatintel.extraction.validate import validate
from threatintel.models.common import ObservableType, Provenance, SourceType, utcnow
from threatintel.models.entities import Relationship
from threatintel.models.intel import EnrichmentResult, Observable
from threatintel.storage.repository import Repository


class EnrichmentEngine:
    def __init__(
        self,
        repo: Repository,
        providers: list[EnrichmentProvider] | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.repo = repo
        self.settings = settings or get_settings()
        self.providers = providers if providers is not None else default_providers(self.settings)

    def status(self) -> list[dict[str, Any]]:
        out = []
        for p in self.providers:
            ok, why = p.available()
            out.append(
                {
                    "provider": p.name,
                    "available": ok,
                    "detail": why,
                    "supports": sorted(t.value for t in p.supported),
                }
            )
        return out

    def enrich(self, obs: Observable, *, use_cache: bool = True) -> list[EnrichmentResult]:
        results: list[EnrichmentResult] = []
        default_ttl = timedelta(hours=self.settings.enrichment_cache_ttl_hours)
        for provider in self.providers:
            if not provider.supports(obs.type):
                continue
            if provider.name == "synthetic" and not obs.synthetic:
                continue
            ok, _ = provider.available()
            if not ok:
                continue
            ttl = provider.cache_ttl or default_ttl
            cached = (
                self.repo.cached_enrichment(provider.name, obs.type, obs.value, ttl) if use_cache else None
            )
            if cached is not None:
                results.append(cached)
                continue
            result = provider.enrich(obs.type, obs.value, synthetic=obs.synthetic)
            self.repo.save_enrichment(result)
            if result.ok:
                results.append(result)
                self._derive(obs, result)
        return results

    # ------------------------------------------------------------------ derived
    def _prov(self, result: EnrichmentResult) -> Provenance:
        return Provenance(
            source_id=f"enrichment:{result.provider}",
            source_name=f"{result.provider} enrichment",
            source_type=SourceType.ENRICHMENT,
            collected_at=result.timestamp,
            reference=result.source_reference,
            synthetic=result.synthetic,
        )

    def _link(
        self,
        src: Observable,
        rel_type: str,
        target_type: ObservableType,
        value: str,
        result: EnrichmentResult,
    ) -> None:
        value = value.strip().rstrip(".").lower() if target_type != ObservableType.ASN else value
        check = validate(target_type, value)
        if not check.valid:
            return
        prov = self._prov(result)
        target = self.repo.upsert_observable(
            Observable(
                type=target_type,
                value=value,
                # Derived infrastructure (name servers, ASNs, resolutions) is context for pivoting, not an
                # indicator in its own right. (The synthetic world keeps it actionable for the demo.)
                actionable=src.synthetic,
                flags=sorted({*check.flags, "infrastructure-context"}),
                synthetic=src.synthetic,
            ),
            prov,
        )
        self.repo.upsert_relationship(
            Relationship(
                source_ref=src.id,
                target_ref=target.id,
                relationship_type=rel_type,
                confidence=result.confidence,
                description=f"derived from {result.provider}",
                evidence=[f"{result.provider} @ {result.timestamp:%Y-%m-%d}"],
                provenance=[prov],
                synthetic=src.synthetic,
            )
        )

    def _derive(self, obs: Observable, result: EnrichmentResult) -> None:
        data = result.result
        if obs.type == ObservableType.DOMAIN:
            for ip in data.get("a", []):
                self._link(obs, "resolves-to", ObservableType.IPV4, ip, result)
            for ns in data.get("nameservers", []):
                self._link(obs, "uses-nameserver", ObservableType.DOMAIN, ns, result)
        if obs.type in (ObservableType.IPV4, ObservableType.IPV6) and data.get("asn"):
            self._link(obs, "belongs-to", ObservableType.ASN, str(data["asn"]), result)


def technical_evidence(results: list[EnrichmentResult], now: datetime | None = None) -> tuple[float, str]:
    """Collapse enrichment into a 0..1 technical-evidence value with an explanation."""
    now = now or utcnow()
    signals: list[tuple[float, str]] = []
    for r in results:
        d = r.result
        tag = " [synthetic]" if r.synthetic else ""
        rep = d.get("reputation") if isinstance(d.get("reputation"), dict) else None
        if r.provider == "virustotal" and d.get("engines"):
            ratio = d.get("malicious", 0) / max(d["engines"], 1)
            signals.append((min(1.0, ratio * 5), f"VirusTotal {d.get('malicious')}/{d['engines']} malicious"))
        if rep and rep.get("engines"):
            ratio = rep.get("malicious_votes", 0) / max(rep["engines"], 1)
            signals.append(
                (min(1.0, ratio * 5), f"reputation {rep.get('malicious_votes')}/{rep['engines']}{tag}")
            )
        if r.provider == "abuseipdb" and d.get("abuse_confidence") is not None:
            signals.append((d["abuse_confidence"] / 100, f"AbuseIPDB confidence {d['abuse_confidence']}%"))
        if d.get("created"):
            try:
                created = datetime.fromisoformat(str(d["created"]).replace("Z", "+00:00"))
                age = (now - created).days
                if age <= 30:
                    signals.append((0.6, f"domain registered {age} day(s) ago{tag}"))
            except ValueError:
                pass
        if r.provider == "shodan" and d.get("vulns"):
            signals.append((0.3, f"Shodan lists {len(d['vulns'])} vulnerable service(s)"))
    if not signals:
        return 0.0, "no corroborating technical evidence from enrichment"
    best = max(signals, key=lambda s: s[0])
    return round(best[0], 3), "; ".join(s[1] for s in sorted(signals, key=lambda s: -s[0]))
