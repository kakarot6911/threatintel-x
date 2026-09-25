from datetime import timedelta

from threatintel.extraction.validate import is_stale, validate, validate_btc
from threatintel.models.common import ObservableType as T
from threatintel.models.common import utcnow


def test_domain_rules() -> None:
    assert validate(T.DOMAIN, "google.com").actionable
    bad_tld = validate(T.DOMAIN, "invoice.exe")
    assert not bad_tld.valid and "unknown TLD" in bad_tld.reasons[0]
    doc = validate(T.DOMAIN, "evil.example")
    assert doc.valid and not doc.actionable and "documentation" in doc.flags
    assert validate(T.DOMAIN, "hidden.onion").actionable  # special-use but real-world meaningful
    assert not validate(T.DOMAIN, "-bad-.com").valid
    assert not validate(T.DOMAIN, "localhost").valid


def test_ip_flags() -> None:
    assert validate(T.IPV4, "8.8.8.8").actionable
    for ip, flag in [
        ("10.1.2.3", "private"),
        ("127.0.0.1", "loopback"),
        ("192.0.2.5", "documentation"),
        ("169.254.169.254", "link-local"),
        ("224.0.0.1", "multicast"),
    ]:
        r = validate(T.IPV4, ip)
        assert r.valid and not r.actionable and flag in r.flags, ip
    assert "documentation" in validate(T.IPV6, "2001:db8::1").flags


def test_hashes() -> None:
    assert validate(T.SHA256, "a" * 63 + "b").valid
    assert not validate(T.SHA256, "a" * 64).valid  # degenerate
    assert not validate(T.MD5, "z" * 32).valid
    empty = validate(T.SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856")
    assert empty.valid and not empty.actionable and "empty-file" in empty.flags


def test_cve_and_attack() -> None:
    assert validate(T.CVE, "CVE-2024-3400").valid
    assert not validate(T.CVE, "CVE-24-1").valid
    known = frozenset({"T1566"})
    assert validate(T.ATTACK_TECHNIQUE, "T1566", known_techniques=known).actionable
    unverified = validate(T.ATTACK_TECHNIQUE, "T9999", known_techniques=known)
    assert unverified.valid and not unverified.actionable and "unverified" in unverified.flags


def test_crypto() -> None:
    assert validate_btc("1BoatSLRHtKNngkdXEeobR76b53LETtpyT")
    assert not validate_btc("1BoatSLRHtKNngkdXEeobR76b53LETtpyX")  # checksum broken
    assert validate_btc("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")  # BIP-173 test vector
    assert not validate_btc("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5")
    assert validate(T.ETH_ADDRESS, "0x52908400098527886e0f7030069857d2e4169ee7").valid
    assert not validate(T.ETH_ADDRESS, "0x123").valid


def test_telegram_and_staleness() -> None:
    assert validate(T.TELEGRAM_REF, "valid_name").valid
    assert not validate(T.TELEGRAM_REF, "abc").valid
    now = utcnow()
    assert is_stale(T.IPV4, now - timedelta(days=31), now)
    assert not is_stale(T.SHA256, now - timedelta(days=31), now)
    assert not is_stale(T.CVE, now - timedelta(days=3000), now)
