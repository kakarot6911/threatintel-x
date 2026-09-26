from threatintel.extraction.extractor import IOCExtractor, extract_all
from threatintel.models.common import ObservableType as T

SAMPLE = """APT-Red used hxxps://login-portal[.]example/verify?utm_source=x&id=3 and 203.0.113.45 (also 10.0.0.1).
Mail from ops@evil-mail.example. Payload invoice.zip; SHA256 9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08
MD5 9e107d9d372bb6826bd81d3542a419d6 exploits cve-2024-3400 via T1566.001 and T1071.
Version 1.2.3.4.5 is not an IP. ETH 0x52908400098527886E0F7030069857D2E4169EE7 BTC 1BoatSLRHtKNngkdXEeobR76b53LETtpyT
Chat t.me/fake_channel_x at 12:30:45 via 2001:db8::1. Defanged update[.]zip is intentional."""


def test_extracts_expected_types() -> None:
    r = IOCExtractor(entity_aliases={"threat-actor": {"apt-red": "APT-Red"}}).extract(SAMPLE)
    assert r.values(T.URL) == {"https://login-portal.example/verify?id=3"}
    assert "login-portal.example" in r.values(T.DOMAIN)
    assert r.values(T.EMAIL) == {"ops@evil-mail.example"}
    assert "evil-mail.example" in r.values(T.DOMAIN)
    assert r.values(T.IPV4) == {"203.0.113.45", "10.0.0.1"}
    assert r.values(T.IPV6) == {"2001:db8::1"}
    assert r.values(T.SHA256) == {"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}
    assert r.values(T.MD5) == {"9e107d9d372bb6826bd81d3542a419d6"}
    assert r.values(T.CVE) == {"CVE-2024-3400"}
    assert r.values(T.ATTACK_TECHNIQUE) == {"T1566.001", "T1071"}
    assert r.values(T.ETH_ADDRESS) == {"0x52908400098527886e0f7030069857d2e4169ee7"}
    assert r.values(T.SHA1) == set()  # the ETH address must not be mistaken for a SHA-1
    assert r.values(T.BTC_ADDRESS) == {"1BoatSLRHtKNngkdXEeobR76b53LETtpyT"}
    assert r.values(T.TELEGRAM_REF) == {"fake_channel_x"}
    assert r.entities == {"threat-actor": {"APT-Red"}}


def test_file_names_are_not_domains_unless_defanged() -> None:
    r = IOCExtractor().extract(SAMPLE)
    assert "invoice.zip" not in r.values(T.DOMAIN)
    assert ("domain", "invoice.zip", "ambiguous file-extension TLD") in r.rejected
    assert "update.zip" in r.values(T.DOMAIN)  # defanged -> deliberate indicator


def test_defanged_flag() -> None:
    r = IOCExtractor().extract("C2 at evil[.]example and clean.example")
    flags = {o.value: o.defanged for o in r.of_type(T.DOMAIN)}
    assert flags == {"evil.example": True, "clean.example": False}


def test_telegram_handles_need_context() -> None:
    text = "contact @seller_handle today"
    assert IOCExtractor().extract(text).values(T.TELEGRAM_REF) == set()
    assert IOCExtractor().extract(text, telegram_context=True).values(T.TELEGRAM_REF) == {"seller_handle"}


def test_alias_word_boundaries() -> None:
    ex = IOCExtractor(entity_aliases={"threat-actor": {"moth_access": "VANTA MOTH"}})
    assert ex.extract("see moth_access_syn channel").entities == {}
    assert ex.extract("seller moth_access posted").entities == {"threat-actor": {"VANTA MOTH"}}


def test_dedup_and_merge() -> None:
    r = extract_all(["a 198.51.100.1 b 198.51.100.1", "198.51.100.1"])
    assert [o.value for o in r.observables] == ["198.51.100.1"]


def test_hostile_input_does_not_crash() -> None:
    nasty = "\x00" * 10 + "http://[::1" + "a" * 5000 + "@" * 300 + "[.]" * 200 + "‮" + "T" * 100
    IOCExtractor().extract(nasty)


def test_ambiguous_aliases_need_qualifier_or_caps() -> None:
    aliases = {
        "malware": {"play": "Play", "emotet": "Emotet"},
        "threat-actor": {"hafnium": "HAFNIUM", "silence": "Silence"},
    }
    ex = IOCExtractor(
        entity_aliases=aliases,
        ambiguous=frozenset({"play", "silence", "hafnium"}),
        uppercase=frozenset({"hafnium"}),
    )
    assert ex.extract("Users play games in silence; the hafnium isotope").entities == {}
    hits = ex.extract("Play ransomware and the Silence group; HAFNIUM exploited it; Emotet spread").entities
    assert hits == {"malware": {"Play", "Emotet"}, "threat-actor": {"HAFNIUM", "Silence"}}
    assert IOCExtractor(entity_aliases={"tool": {"cmd": "cmd"}}).extract("run cmd now").entities == {}


def test_titlecase_identifiers_are_not_domains() -> None:
    r = IOCExtractor().extract("The app requested Mail.Read and Files.ReadWrite.All; C2 at bad-host.com")
    assert r.values(T.DOMAIN) == {"bad-host.com"}
