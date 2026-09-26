"""Enrichment providers.

Passive providers (RDAP, DNS, Team Cymru ASN) need only ``TIX_ONLINE=true``.
Reputation providers additionally need their API key in the environment.
The synthetic provider answers ONLY for synthetic observables from fixtures and
labels every result ``synthetic=True``.
"""

from __future__ import annotations

import base64
import ipaddress
import json
from datetime import timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import quote

import dns.exception
import dns.resolver

from threatintel.config import get_settings
from threatintel.enrichment.base import EnrichmentProvider, ProviderUnavailableError
from threatintel.models.common import ObservableType as T
from threatintel.models.common import utcnow
from threatintel.models.intel import EnrichmentResult
from threatintel.net import require_online

IP_TYPES = frozenset({T.IPV4, T.IPV6})
HASH_TYPES = frozenset({T.MD5, T.SHA1, T.SHA256})


# --------------------------------------------------------------------------- RDAP
def _vcard_name(entity: dict[str, Any]) -> str | None:
    for entry in (entity.get("vcardArray") or [None, []])[1]:
        if entry and entry[0] == "fn":
            return str(entry[3])
    return None


def parse_rdap(doc: dict[str, Any]) -> dict[str, Any]:
    events = {e.get("eventAction"): e.get("eventDate") for e in doc.get("events", [])}
    registrar = None
    for ent in doc.get("entities", []):
        if "registrar" in ent.get("roles", []):
            registrar = _vcard_name(ent) or ent.get("handle")
    return {
        "handle": doc.get("handle"),
        "name": doc.get("name") or doc.get("ldhName"),
        "registrar": registrar,
        "created": events.get("registration"),
        "expires": events.get("expiration"),
        "last_changed": events.get("last changed"),
        "nameservers": sorted(
            {ns.get("ldhName", "").lower() for ns in doc.get("nameservers", []) if ns.get("ldhName")}
        ),
        "status": doc.get("status", []),
        "country": doc.get("country"),
        "start_address": doc.get("startAddress"),
        "end_address": doc.get("endAddress"),
    }


class RDAPProvider(EnrichmentProvider):
    name = "rdap"
    supported = frozenset({T.DOMAIN, T.IPV4, T.IPV6})
    rate_per_minute = 20
    cache_ttl = timedelta(days=7)
    base_url = "https://rdap.org"

    def _lookup(self, obs_type: T, value: str) -> tuple[dict[str, Any], int, str]:
        if obs_type != T.DOMAIN:
            return self._query("ip", value)
        # Registries answer for the *registered* domain only (a.b.example.org -> example.org). Without a
        # public-suffix list we walk up one label at a time and stop at the first registry answer.
        labels = value.split(".")
        url = ""
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            result, conf, url = self._query("domain", candidate, missing_ok=True)
            if result.get("found"):
                if candidate != value:
                    result["queried_as"] = candidate
                return result, conf, url
        return {"found": False}, 60, url

    def _query(self, kind: str, value: str, missing_ok: bool = False) -> tuple[dict[str, Any], int, str]:
        url = f"{self.base_url}/{kind}/{quote(value, safe='')}"
        resp = self.http_get(url, headers={"Accept": "application/rdap+json"})
        if resp.status_code == 404 or (missing_ok and resp.status_code == 400):
            return {"found": False}, 60, url
        resp.raise_for_status()
        return {"found": True, **parse_rdap(resp.json())}, 90, url


# ---------------------------------------------------------------------------- DNS
class DNSProvider(EnrichmentProvider):
    name = "dns"
    supported = frozenset({T.DOMAIN})
    rate_per_minute = 120
    cache_ttl = timedelta(hours=6)
    record_types = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")

    def __init__(self, *args: Any, resolver: dns.resolver.Resolver | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.resolver = resolver

    def _lookup(self, obs_type: T, value: str) -> tuple[dict[str, Any], int, str]:
        require_online(self.settings)
        resolver = self.resolver or dns.resolver.Resolver()
        resolver.lifetime = self.settings.http_timeout_seconds
        records: dict[str, list[str]] = {}
        for rtype in self.record_types:
            self.bucket.acquire()
            try:
                answer = resolver.resolve(value, rtype)
                records[rtype.lower()] = sorted(r.to_text().strip('"').rstrip(".").lower() for r in answer)
            except dns.resolver.NXDOMAIN:
                return {"nxdomain": True, "records": {}}, 80, "dns"
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
                continue
        return (
            {
                "nxdomain": False,
                "records": records,
                "a": records.get("a", []),
                "nameservers": records.get("ns", []),
            },
            85,
            "dns:recursive",
        )


# ------------------------------------------------------------------- ASN (Cymru)
def cymru_origin_name(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    nibbles = addr.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def parse_cymru_origin(txt: str) -> dict[str, str]:
    parts = [p.strip() for p in txt.strip('"').split("|")]
    return {
        "asn": f"AS{parts[0].split()[0]}",
        "prefix": parts[1],
        "country": parts[2],
        "registry": parts[3],
        "allocated": parts[4] if len(parts) > 4 else "",
    }


class ASNProvider(EnrichmentProvider):
    """IP -> ASN / prefix / country via Team Cymru's public DNS interface (GeoIP at country level)."""

    name = "asn"
    supported = IP_TYPES
    rate_per_minute = 60
    cache_ttl = timedelta(days=3)

    def __init__(self, *args: Any, resolver: dns.resolver.Resolver | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.resolver = resolver

    def _lookup(self, obs_type: T, value: str) -> tuple[dict[str, Any], int, str]:
        require_online(self.settings)
        resolver = self.resolver or dns.resolver.Resolver()
        resolver.lifetime = self.settings.http_timeout_seconds
        self.bucket.acquire()
        try:
            origin = resolver.resolve(cymru_origin_name(value), "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return {"found": False}, 60, "team-cymru"
        info = parse_cymru_origin(origin[0].to_text())
        try:
            asn_txt = resolver.resolve(f"{info['asn']}.asn.cymru.com", "TXT")[0].to_text().strip('"')
            info["as_name"] = asn_txt.split("|")[-1].strip()
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, IndexError):
            info["as_name"] = ""
        return {"found": True, **info}, 85, "team-cymru:origin"


# ------------------------------------------------------------- reputation APIs
class VirusTotalProvider(EnrichmentProvider):
    name = "virustotal"
    supported = frozenset({T.IPV4, T.IPV6, T.DOMAIN, T.URL, *HASH_TYPES})
    rate_per_minute = 4  # public API quota
    base_url = "https://www.virustotal.com/api/v3"

    def configured(self) -> bool:
        return bool(self.settings.vt_api_key.get_secret_value())

    def _lookup(self, obs_type: T, value: str) -> tuple[dict[str, Any], int, str]:
        if obs_type in IP_TYPES:
            path = f"ip_addresses/{value}"
        elif obs_type == T.DOMAIN:
            path = f"domains/{value}"
        elif obs_type == T.URL:
            path = "urls/" + base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        else:
            path = f"files/{value}"
        url = f"{self.base_url}/{path}"
        resp = self.http_get(url, headers={"x-apikey": self.settings.vt_api_key.get_secret_value()})
        if resp.status_code == 404:
            return {"found": False}, 50, url
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        engines = sum(int(v) for v in stats.values()) or 0
        return (
            {
                "found": True,
                "malicious": int(stats.get("malicious", 0)),
                "suspicious": int(stats.get("suspicious", 0)),
                "engines": engines,
                "reputation": attrs.get("reputation"),
                "tags": attrs.get("tags", []),
                "last_analysis_date": attrs.get("last_analysis_date"),
            },
            80,
            url,
        )


class URLScanProvider(EnrichmentProvider):
    name = "urlscan"
    supported = frozenset({T.DOMAIN, T.IPV4, T.IPV6, T.URL})
    rate_per_minute = 30
    base_url = "https://urlscan.io/api/v1/search/"

    def configured(self) -> bool:
        return bool(self.settings.urlscan_api_key.get_secret_value())

    def _lookup(self, obs_type: T, value: str) -> tuple[dict[str, Any], int, str]:
        field = {T.DOMAIN: "domain", T.URL: "page.url", T.IPV4: "ip", T.IPV6: "ip"}[obs_type]
        query = f'{field}:"{value}"'
        resp = self.http_get(
            self.base_url,
            params={"q": query, "size": "10"},
            headers={"API-Key": self.settings.urlscan_api_key.get_secret_value()},
        )
        resp.raise_for_status()
        body = resp.json()
        results = [
            {
                "time": r.get("task", {}).get("time"),
                "url": r.get("page", {}).get("url"),
                "ip": r.get("page", {}).get("ip"),
                "asn": r.get("page", {}).get("asn"),
                "country": r.get("page", {}).get("country"),
                "result": r.get("result"),
            }
            for r in body.get("results", [])[:5]
        ]
        return {"total": body.get("total", 0), "results": results}, 70, f"{self.base_url}?q={quote(query)}"


class AbuseIPDBProvider(EnrichmentProvider):
    name = "abuseipdb"
    supported = IP_TYPES
    rate_per_minute = 30
    base_url = "https://api.abuseipdb.com/api/v2/check"

    def configured(self) -> bool:
        return bool(self.settings.abuseipdb_api_key.get_secret_value())

    def _lookup(self, obs_type: T, value: str) -> tuple[dict[str, Any], int, str]:
        resp = self.http_get(
            self.base_url,
            params={"ipAddress": value, "maxAgeInDays": "90"},
            headers={"Key": self.settings.abuseipdb_api_key.get_secret_value(), "Accept": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return (
            {
                "abuse_confidence": int(data.get("abuseConfidenceScore", 0)),
                "total_reports": int(data.get("totalReports", 0)),
                "country": data.get("countryCode"),
                "isp": data.get("isp"),
                "usage_type": data.get("usageType"),
                "last_reported": data.get("lastReportedAt"),
            },
            70,
            self.base_url,
        )


class ShodanProvider(EnrichmentProvider):
    name = "shodan"
    supported = IP_TYPES
    rate_per_minute = 30
    base_url = "https://api.shodan.io/shodan/host"

    def configured(self) -> bool:
        return bool(self.settings.shodan_api_key.get_secret_value())

    def _lookup(self, obs_type: T, value: str) -> tuple[dict[str, Any], int, str]:
        url = f"{self.base_url}/{value}"
        resp = self.http_get(
            url, params={"key": self.settings.shodan_api_key.get_secret_value(), "minify": "true"}
        )
        if resp.status_code == 404:
            return {"found": False}, 50, url
        resp.raise_for_status()
        d = resp.json()
        return (
            {
                "found": True,
                "ports": d.get("ports", []),
                "hostnames": d.get("hostnames", []),
                "org": d.get("org"),
                "asn": d.get("asn"),
                "country": d.get("country_code"),
                "vulns": sorted(d.get("vulns", [])),
                "tags": d.get("tags", []),
                "last_update": d.get("last_update"),
            },
            75,
            url,
        )


class CensysProvider(EnrichmentProvider):
    """Censys Search API v2 host lookup (legacy search.censys.io endpoint)."""

    name = "censys"
    supported = IP_TYPES
    rate_per_minute = 10
    base_url = "https://search.censys.io/api/v2/hosts"

    def configured(self) -> bool:
        return bool(
            self.settings.censys_api_id.get_secret_value()
            and self.settings.censys_api_secret.get_secret_value()
        )

    def _lookup(self, obs_type: T, value: str) -> tuple[dict[str, Any], int, str]:
        url = f"{self.base_url}/{value}"
        resp = self.http_get(
            url,
            auth=(
                self.settings.censys_api_id.get_secret_value(),
                self.settings.censys_api_secret.get_secret_value(),
            ),
        )
        if resp.status_code == 404:
            return {"found": False}, 50, url
        resp.raise_for_status()
        r = resp.json().get("result", {})
        asys = r.get("autonomous_system", {})
        return (
            {
                "found": True,
                "services": [
                    {"port": s.get("port"), "service": s.get("service_name")} for s in r.get("services", [])
                ],
                "asn": f"AS{asys['asn']}" if asys.get("asn") else None,
                "as_name": asys.get("name"),
                "country": r.get("location", {}).get("country_code"),
            },
            75,
            url,
        )


# ------------------------------------------------------------------- synthetic
@lru_cache(maxsize=2)
def _synthetic_fixtures(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {}
    return dict(json.loads(p.read_text("utf-8")).get("enrichment", {}))


class SyntheticProvider(EnrichmentProvider):
    """Answers from fixtures for SYNTHETIC observables only; never for real-world data."""

    name = "synthetic"
    supported = frozenset({T.DOMAIN, T.IPV4})
    requires_network = False
    rate_per_minute = 100_000

    def __init__(self, *args: Any, fixtures_path: Path | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.fixtures_path = fixtures_path or get_settings().data_dir / "synthetic" / "world.json"

    def enrich(self, obs_type: T, value: str, *, synthetic: bool = False) -> EnrichmentResult:
        if not synthetic:
            return EnrichmentResult(
                provider=self.name,
                observable_type=obs_type,
                observable=value,
                error="synthetic provider only answers for synthetic observables",
            )
        return super().enrich(obs_type, value, synthetic=True)

    def _lookup(self, obs_type: T, value: str) -> tuple[dict[str, Any], int, str]:
        fixtures = _synthetic_fixtures(str(self.fixtures_path))
        table = fixtures.get("domain" if obs_type == T.DOMAIN else "ip", {})
        if value not in table:
            raise ProviderUnavailableError("no synthetic fixture for this observable")
        data = dict(table[value])
        if "created_days_ago" in data:
            data["created"] = (utcnow() - timedelta(days=int(data.pop("created_days_ago")))).isoformat()
        data["synthetic"] = True
        return data, 100, "synthetic-fixture"


def default_providers(settings: Any = None) -> list[EnrichmentProvider]:
    s = settings or get_settings()
    # Active DNS resolution of suspicious domains sends queries towards attacker-controlled name servers
    # (tipping off operators); it is therefore opt-in via TIX_ACTIVE_DNS. RDAP / Team Cymru only query
    # registries and Cymru.
    dns_provider: list[EnrichmentProvider] = [DNSProvider(s)] if s.active_dns else []
    return [
        SyntheticProvider(s),
        RDAPProvider(s),
        *dns_provider,
        ASNProvider(s),
        VirusTotalProvider(s),
        URLScanProvider(s),
        AbuseIPDBProvider(s),
        ShodanProvider(s),
        CensysProvider(s),
    ]
