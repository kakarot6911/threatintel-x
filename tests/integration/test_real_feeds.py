"""Structured real-feed importers, exercised with small fixtures in the real formats (no network)."""

from threatintel.collectors.feeds import (
    attack_knowledge_subset,
    import_attack_knowledge,
    import_feodo,
    import_kev,
    import_urlhaus,
    parse_urlhaus_csv,
)
from threatintel.extraction.benign import is_benign
from threatintel.models.common import ObservableType
from threatintel.models.entities import Vulnerability
from threatintel.platform import Platform
from threatintel.storage.repository import Repository
from threatintel.workflows import ingest_text

KEV = {
    "catalogVersion": "2026.09.25",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-3400",
            "vendorProject": "Palo Alto Networks",
            "product": "PAN-OS",
            "vulnerabilityName": "PAN-OS Command Injection",
            "shortDescription": "OS command injection.",
            "dateAdded": "2024-04-12",
            "dueDate": "2024-04-19",
            "knownRansomwareCampaignUse": "Known",
        },
        {"cveID": "not-a-cve", "dateAdded": "2024-01-01"},
    ],
}
FEODO = [
    {
        "ip_address": "50.16.16.211",
        "port": 443,
        "status": "online",
        "as_number": 14618,
        "as_name": "AMAZON-AES",
        "first_seen": "2025-12-30 13:56:31",
        "last_online": "2026-03-12",
        "malware": "QakBot",
    },
    {
        "ip_address": "10.0.0.1",
        "port": 443,
        "status": "online",
        "first_seen": "2025-01-01 00:00:00",
        "malware": "Emotet",
    },
]
URLHAUS = """################################################################
# abuse.ch URLhaus Database Dump (CSV - recent URLs only)      #
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"1","2026-09-25 17:59:16","http://185.9.139.117:35729/bin.sh","online","2026-09-25 17:59:16","malware_download","32-bit,arm,elf,Mozi","https://urlhaus.abuse.ch/url/1/","r"
"2","2026-09-25 17:47:19","http://124.235.239.197:35644/i","offline","","malware_download","mirai","https://urlhaus.abuse.ch/url/2/","r"
"""
ATTACK = {
    "type": "bundle",
    "id": "bundle--1",
    "objects": [
        {
            "type": "intrusion-set",
            "spec_version": "2.1",
            "id": "intrusion-set--11111111-1111-4111-8111-111111111111",
            "created": "2020-01-01T00:00:00Z",
            "modified": "2020-01-01T00:00:00Z",
            "name": "Example Group",
            "aliases": ["Example Group", "EG-1"],
        },
        {
            "type": "malware",
            "spec_version": "2.1",
            "id": "malware--22222222-2222-4222-8222-222222222222",
            "created": "2020-01-01T00:00:00Z",
            "modified": "2020-01-01T00:00:00Z",
            "name": "Mozi",
            "is_family": True,
        },
        {
            "type": "malware",
            "spec_version": "2.1",
            "id": "malware--33333333-3333-4333-8333-333333333333",
            "created": "2020-01-01T00:00:00Z",
            "modified": "2020-01-01T00:00:00Z",
            "name": "OldThing",
            "is_family": True,
            "revoked": True,
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--44444444-4444-4444-8444-444444444444",
            "created": "2020-01-01T00:00:00Z",
            "modified": "2020-01-01T00:00:00Z",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--11111111-1111-4111-8111-111111111111",
            "target_ref": "malware--22222222-2222-4222-8222-222222222222",
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--55555555-5555-4555-8555-555555555555",
            "created": "2020-01-01T00:00:00Z",
            "modified": "2020-01-01T00:00:00Z",
            "relationship_type": "mitigates",
            "source_ref": "intrusion-set--11111111-1111-4111-8111-111111111111",
            "target_ref": "malware--22222222-2222-4222-8222-222222222222",
        },
        {"type": "x-mitre-analytic", "id": "x-mitre-analytic--1"},
    ],
}


def test_kev_import(repo: Repository) -> None:
    res = import_kev(repo, KEV)
    assert (res.imported, res.skipped) == (1, 1)
    v = repo.find_entity("vulnerability", "CVE-2024-3400")
    assert isinstance(v, Vulnerability) and v.known_exploited and v.ransomware_use
    assert v.affected_product == "Palo Alto Networks PAN-OS"
    assert any(i.metadata.get("feed_snapshot") for i in repo.list_collected_items())


def test_feodo_import(repo: Repository) -> None:
    res = import_feodo(repo, FEODO)
    assert (res.imported, res.skipped) == (1, 1)  # private IP refused
    obs = repo.get_observable(ObservableType.IPV4, "50.16.16.211")
    assert obs and "botnet-c2" in obs.flags and not obs.synthetic
    rels = {r.relationship_type for r in repo.list_relationships(source_ref=obs.id)}
    assert rels == {"indicates", "belongs-to"}
    assert repo.find_entity("malware", "QakBot") is not None
    assert repo.latest_assessment(obs.id, "confidence") is not None


def test_urlhaus_import_links_only_known_families(repo: Repository) -> None:
    import_attack_knowledge(repo, ATTACK)
    rows = parse_urlhaus_csv(URLHAUS)
    assert len(rows) == 2
    res = import_urlhaus(repo, rows, family_aliases=repo.alias_dictionary()["malware"])
    assert res.imported == 1  # offline row filtered
    url = repo.get_observable(ObservableType.URL, "http://185.9.139.117:35729/bin.sh")
    targets = {repo.get_entity(r.target_ref).name for r in repo.list_relationships(source_ref=url.id)}
    assert targets == {"Mozi"}  # 'elf', 'arm', '32-bit' tags are not families


def test_attack_subset_filters_revoked_and_irrelevant() -> None:
    sub = attack_knowledge_subset(ATTACK)
    ids = {o["id"] for o in sub["objects"]}
    assert "malware--33333333-3333-4333-8333-333333333333" not in ids
    assert "relationship--55555555-5555-4555-8555-555555555555" not in ids
    assert not any(o["type"].startswith("x-mitre") for o in sub["objects"])


def test_attack_knowledge_import(repo: Repository) -> None:
    res = import_attack_knowledge(repo, ATTACK)
    assert res.entities == 2 and res.imported == 1
    grp = repo.find_entity("threat-actor", "EG-1")
    assert grp and grp.name == "Example Group"
    prov = repo.provenance_for(grp.id)
    assert prov[0].source_name == "MITRE ATT&CK"


def test_citations_are_not_indicators(platform: Platform) -> None:
    res = ingest_text(
        platform,
        "Vendor blog",
        "See https://github.com/org/repo and microsoft.com docs. "
        "C2: hxxps://github[.]com/badactor/payload.exe and evil-cdn[.]com",
    )
    benign = platform.repo.get_observable(ObservableType.DOMAIN, "microsoft.com")
    assert benign and not benign.actionable and "known-benign" in benign.flags
    defanged = platform.repo.get_observable(ObservableType.URL, "https://github.com/badactor/payload.exe")
    assert defanged and defanged.actionable  # the author defanged it: it IS an indicator
    assert "domain:evil-cdn.com" in res.observables
    assert is_benign(ObservableType.EMAIL, "a@mail.google.com", frozenset({"google.com"}))
    assert not is_benign(ObservableType.DOMAIN, "notgoogle.com", frozenset({"google.com"}))


def test_defanging_publisher_plain_links_are_references(platform: Platform) -> None:
    from threatintel.models.common import SourceReliability, SourceType
    from threatintel.models.intel import Source

    src = Source(
        id="src-rss-vendor",
        name="Vendor blog",
        source_type=SourceType.RSS,
        reliability=SourceReliability.B,
        plain_indicators=False,
    )
    ingest_text(
        platform,
        "Post",
        "C2 evil-c2[.]com; read more at https://newsletter.example-vendor.com/ and com.abc.nexus",
        source=src,
    )
    assert platform.repo.get_observable(ObservableType.DOMAIN, "evil-c2.com").actionable
    ref = platform.repo.get_observable(ObservableType.URL, "https://newsletter.example-vendor.com/")
    assert ref and not ref.actionable and "reference-link" in ref.flags
    pkg = platform.repo.get_observable(ObservableType.DOMAIN, "com.abc.nexus")
    assert pkg is None or not pkg.actionable


def test_rss_source_config_is_applied(platform: Platform) -> None:
    from threatintel.workflows import load_rss_sources

    sources = {s.id: s for s in load_rss_sources(platform)}
    assert len(sources) >= 8
    assert sources["src-rss-cisa-advisories"].plain_indicators is False
    assert sources["src-rss-microsoft-ti"].plain_indicators is True
    assert all(s.url and s.url.startswith("https://") for s in sources.values())


def test_abused_service_url_kept_but_domain_not(platform: Platform) -> None:
    ingest_text(platform, "C2 via iCloud", "Beacon hxxps://gateway.icloud[.]com/caldav/abc123 observed")
    assert platform.repo.get_observable(
        ObservableType.URL, "https://gateway.icloud.com/caldav/abc123"
    ).actionable
    assert not platform.repo.get_observable(ObservableType.DOMAIN, "gateway.icloud.com").actionable
