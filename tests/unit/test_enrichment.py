import base64
import ipaddress
from datetime import timedelta

import httpx
import pytest
import respx

from threatintel import net
from threatintel.config import Settings
from threatintel.enrichment.base import TokenBucket, TransientProviderError, with_retry
from threatintel.enrichment.engine import EnrichmentEngine, technical_evidence
from threatintel.enrichment.providers import (
    AbuseIPDBProvider,
    CensysProvider,
    RDAPProvider,
    ShodanProvider,
    SyntheticProvider,
    URLScanProvider,
    VirusTotalProvider,
    cymru_origin_name,
    parse_cymru_origin,
    parse_rdap,
)
from threatintel.models.common import ObservableType as T
from threatintel.models.common import utcnow
from threatintel.models.intel import EnrichmentResult, Observable
from threatintel.storage.repository import Repository


@pytest.fixture
def online(monkeypatch: pytest.MonkeyPatch) -> Settings:
    monkeypatch.setattr(net, "_resolve", lambda host: [ipaddress.ip_address("93.184.216.34")])
    return Settings(
        database_url="sqlite://",
        online=True,
        vt_api_key="vt",
        abuseipdb_api_key="ab",
        urlscan_api_key="us",
        shodan_api_key="sh",
        censys_api_id="id",
        censys_api_secret="sec",
    )


def no_sleep(_: float) -> None:
    return None


def test_unconfigured_and_offline_providers_do_not_run() -> None:
    offline = Settings(database_url="sqlite://")
    r = VirusTotalProvider(offline).enrich(T.IPV4, "8.8.8.8")
    assert r.error and "not configured" in r.error and r.result == {}
    r = RDAPProvider(offline).enrich(T.DOMAIN, "google.com")
    assert r.error and "network disabled" in r.error


def test_refuses_reserved_observables(online: Settings) -> None:
    for obs_type, value in [(T.IPV4, "10.0.0.1"), (T.IPV4, "192.0.2.1"), (T.DOMAIN, "evil.example")]:
        r = VirusTotalProvider(online, sleep=no_sleep).enrich(obs_type, value)
        assert r.error and r.error.startswith("refused"), value


@respx.mock
def test_virustotal_parsing(online: Settings) -> None:
    url_id = base64.urlsafe_b64encode(b"https://bad.test.com/x").decode().rstrip("=")
    respx.get(f"https://www.virustotal.com/api/v3/urls/{url_id}").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 7, "harmless": 60, "undetected": 3},
                        "reputation": -20,
                        "tags": ["phishing"],
                    }
                }
            },
        )
    )
    r = VirusTotalProvider(online, sleep=no_sleep).enrich(T.URL, "https://bad.test.com/x")
    assert r.ok and r.result["malicious"] == 7 and r.result["engines"] == 70
    route = respx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").mock(
        return_value=httpx.Response(404)
    )
    assert VirusTotalProvider(online, sleep=no_sleep).enrich(T.IPV4, "8.8.8.8").result == {"found": False}
    assert route.calls[0].request.headers["x-apikey"] == "vt"


@respx.mock
def test_abuseipdb_urlscan_shodan_censys(online: Settings) -> None:
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(
            200, json={"data": {"abuseConfidenceScore": 88, "totalReports": 12, "countryCode": "NL"}}
        )
    )
    assert (
        AbuseIPDBProvider(online, sleep=no_sleep).enrich(T.IPV4, "8.8.4.4").result["abuse_confidence"] == 88
    )
    respx.get("https://urlscan.io/api/v1/search/").mock(
        return_value=httpx.Response(
            200,
            json={"total": 2, "results": [{"task": {"time": "t"}, "page": {"url": "u", "ip": "1.1.1.1"}}]},
        )
    )
    assert URLScanProvider(online, sleep=no_sleep).enrich(T.DOMAIN, "google.com").result["total"] == 2
    respx.get("https://api.shodan.io/shodan/host/8.8.4.4").mock(
        return_value=httpx.Response(200, json={"ports": [53], "vulns": ["CVE-1"], "org": "X"})
    )
    assert ShodanProvider(online, sleep=no_sleep).enrich(T.IPV4, "8.8.4.4").result["ports"] == [53]
    respx.get("https://search.censys.io/api/v2/hosts/8.8.4.4").mock(
        return_value=httpx.Response(
            200,
            json={
                "result": {
                    "services": [{"port": 443, "service_name": "HTTP"}],
                    "autonomous_system": {"asn": 15169, "name": "G"},
                }
            },
        )
    )
    assert CensysProvider(online, sleep=no_sleep).enrich(T.IPV4, "8.8.4.4").result["asn"] == "AS15169"


@respx.mock
def test_rdap_follows_redirect_and_parses(online: Settings) -> None:
    respx.get("https://rdap.org/domain/google.com").mock(
        return_value=httpx.Response(
            302, headers={"location": "https://rdap.verisign.com/com/v1/domain/google.com"}
        )
    )
    respx.get("https://rdap.verisign.com/com/v1/domain/google.com").mock(
        return_value=httpx.Response(
            200,
            json={
                "ldhName": "GOOGLE.COM",
                "events": [{"eventAction": "registration", "eventDate": "1997-09-15T04:00:00Z"}],
                "nameservers": [{"ldhName": "NS1.GOOGLE.COM"}],
                "entities": [
                    {
                        "roles": ["registrar"],
                        "vcardArray": [
                            "vcard",
                            [["version", {}, "text", "4.0"], ["fn", {}, "text", "MarkMonitor Inc."]],
                        ],
                    }
                ],
            },
        )
    )
    r = RDAPProvider(online, sleep=no_sleep).enrich(T.DOMAIN, "google.com")
    assert (
        r.ok and r.result["registrar"] == "MarkMonitor Inc." and r.result["nameservers"] == ["ns1.google.com"]
    )


@respx.mock
def test_retry_then_give_up_without_fabricating(online: Settings) -> None:
    route = respx.get("https://api.shodan.io/shodan/host/8.8.8.8").mock(
        side_effect=[httpx.Response(429), httpx.Response(503), httpx.Response(500)]
    )
    r = ShodanProvider(online, sleep=no_sleep).enrich(T.IPV4, "8.8.8.8")
    assert route.call_count == 3
    assert r.error == "lookup failed: TransientProviderError" and r.result == {}


@respx.mock
def test_retry_recovers(online: Settings) -> None:
    respx.get("https://api.shodan.io/shodan/host/8.8.8.8").mock(
        side_effect=[httpx.ConnectError("boom"), httpx.Response(200, json={"ports": [22]})]
    )
    assert ShodanProvider(online, sleep=no_sleep).enrich(T.IPV4, "8.8.8.8").result["ports"] == [22]


def test_with_retry_backoff() -> None:
    delays: list[float] = []
    with pytest.raises(TransientProviderError):
        with_retry(lambda: httpx.Response(500), attempts=3, base_delay=1.0, sleep=delays.append)
    assert delays == [1.0, 2.0]


def test_token_bucket_waits() -> None:
    t = [0.0]
    slept: list[float] = []

    def sleep(s: float) -> None:
        slept.append(s)
        t[0] += s

    bucket = TokenBucket(60, clock=lambda: t[0], sleep=sleep)  # 1 token / second
    bucket.acquire()
    bucket.acquire()
    assert slept and slept[0] == pytest.approx(1.0)


def test_synthetic_provider_only_for_synthetic() -> None:
    p = SyntheticProvider(Settings(database_url="sqlite://"))
    assert p.enrich(T.DOMAIN, "cdn-lantern.example", synthetic=False).error
    r = p.enrich(T.DOMAIN, "cdn-lantern.example", synthetic=True)
    assert r.ok and r.synthetic and r.result["synthetic"] is True and "created" in r.result
    assert p.enrich(T.DOMAIN, "unknown.example", synthetic=True).error


def test_engine_caches_and_derives(repo: Repository) -> None:
    s = Settings(database_url="sqlite://")
    engine = EnrichmentEngine(repo, [SyntheticProvider(s)], s)
    obs = repo.upsert_observable(Observable(type=T.DOMAIN, value="harbor-sync.example", synthetic=True))
    first = engine.enrich(obs)
    second = engine.enrich(obs)
    assert len(first) == len(second) == 1
    rels = {r.relationship_type for r in repo.list_relationships(source_ref=obs.id)}
    assert rels == {"resolves-to", "uses-nameserver"}
    with repo.Session() as sess:
        from sqlalchemy import func, select

        from threatintel.storage.db import EnrichmentRow

        assert sess.scalar(select(func.count()).select_from(EnrichmentRow)) == 1  # second call was cached


def test_technical_evidence_and_parsers() -> None:
    now = utcnow()
    r = EnrichmentResult(
        provider="virustotal",
        observable_type=T.IPV4,
        observable="8.8.8.8",
        result={"malicious": 10, "engines": 70},
    )
    young = EnrichmentResult(
        provider="rdap",
        observable_type=T.DOMAIN,
        observable="x.com",
        result={"created": (now - timedelta(days=3)).isoformat()},
    )
    value, why = technical_evidence([r, young], now)
    assert value == pytest.approx(0.714, abs=0.01) and "registered 3 day(s) ago" in why
    assert technical_evidence([], now) == (0.0, "no corroborating technical evidence from enrichment")
    assert cymru_origin_name("8.8.4.4") == "4.4.8.8.origin.asn.cymru.com"
    assert cymru_origin_name("2001:db8::1").endswith(".origin6.asn.cymru.com")
    assert parse_cymru_origin('"15169 | 8.8.8.0/24 | US | arin | 1992-12-01"')["asn"] == "AS15169"
    assert parse_rdap({"events": [], "entities": []})["registrar"] is None


class _Rec:
    def __init__(self, text: str) -> None:
        self._t = text

    def to_text(self) -> str:
        return self._t


class FakeResolver:
    lifetime = 0.0

    def __init__(self, answers: dict[tuple[str, str], list[str]]) -> None:
        self.answers = answers

    def resolve(self, name: str, rtype: str) -> list[_Rec]:
        import dns.resolver

        if (name, rtype) not in self.answers:
            raise dns.resolver.NoAnswer()
        if self.answers[(name, rtype)] == ["NXDOMAIN"]:
            raise dns.resolver.NXDOMAIN()
        return [_Rec(t) for t in self.answers[(name, rtype)]]


def test_dns_provider(online: Settings) -> None:
    from threatintel.enrichment.providers import DNSProvider

    resolver = FakeResolver(
        {
            ("google.com", "A"): ["142.250.1.1"],
            ("google.com", "NS"): ["ns1.google.com."],
            ("google.com", "TXT"): ['"v=spf1 -all"'],
        }
    )
    r = DNSProvider(online, sleep=no_sleep, resolver=resolver).enrich(T.DOMAIN, "google.com")
    assert r.ok and r.result["a"] == ["142.250.1.1"] and r.result["nameservers"] == ["ns1.google.com"]
    assert r.result["records"]["txt"] == ["v=spf1 -all"]
    nx = FakeResolver({("nope-nope.com", "A"): ["NXDOMAIN"]})
    assert (
        DNSProvider(online, sleep=no_sleep, resolver=nx).enrich(T.DOMAIN, "nope-nope.com").result["nxdomain"]
    )


def test_asn_provider(online: Settings) -> None:
    from threatintel.enrichment.providers import ASNProvider

    resolver = FakeResolver(
        {
            ("4.4.8.8.origin.asn.cymru.com", "TXT"): ['"15169 | 8.8.4.0/24 | US | arin | 1992-12-01"'],
            ("AS15169.asn.cymru.com", "TXT"): ['"15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"'],
        }
    )
    r = ASNProvider(online, sleep=no_sleep, resolver=resolver).enrich(T.IPV4, "8.8.4.4")
    assert r.ok and r.result["asn"] == "AS15169" and r.result["as_name"] == "GOOGLE - Google LLC, US"
    empty = ASNProvider(online, sleep=no_sleep, resolver=FakeResolver({})).enrich(T.IPV4, "8.8.4.4")
    assert empty.result == {"found": False}


@respx.mock
def test_rdap_walks_up_to_registered_domain(online: Settings) -> None:
    respx.get("https://rdap.org/domain/savannah.nongnu.org").mock(return_value=httpx.Response(400))
    respx.get("https://rdap.org/domain/nongnu.org").mock(
        return_value=httpx.Response(
            200,
            json={
                "ldhName": "NONGNU.ORG",
                "events": [{"eventAction": "registration", "eventDate": "2003-01-01T00:00:00Z"}],
            },
        )
    )
    r = RDAPProvider(online, sleep=no_sleep).enrich(T.DOMAIN, "savannah.nongnu.org")
    assert r.ok and r.result["queried_as"] == "nongnu.org" and r.result["created"].startswith("2003")


def test_unexpected_provider_crash_is_contained(online: Settings) -> None:
    import dns.resolver

    from threatintel.enrichment.providers import ASNProvider

    class Broken:
        lifetime = 0.0

        def resolve(self, *_: object) -> None:
            raise dns.resolver.NoResolverConfiguration("no nameservers")

    r = ASNProvider(online, sleep=no_sleep, resolver=Broken()).enrich(T.IPV4, "8.8.8.8")
    assert r.error == "provider error: NoResolverConfiguration" and r.result == {}
