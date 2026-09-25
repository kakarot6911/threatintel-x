import pytest

from threatintel.extraction.normalize import normalize, refang
from threatintel.models.common import ObservableType as T


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("hxxp://evil[.]example/a", "http://evil.example/a"),
        ("hxxps[:]//evil[.]example", "https://evil.example"),
        ("evil(.)example", "evil.example"),
        ("evil [dot] example", "evil.example"),
        ("user[@]evil[.]example", "user@evil.example"),
        ("meows://x[.]example", "https://x.example"),
    ],
)
def test_refang(raw: str, expected: str) -> None:
    out, changed = refang(raw)
    assert out == expected
    assert changed


def test_refang_leaves_clean_text() -> None:
    assert refang("plain text example.com") == ("plain text example.com", False)


@pytest.mark.parametrize("raw", ["Example.COM", "example.com.", "EXAMPLE.com", " example.com "])
def test_domain_canonical(raw: str) -> None:
    assert normalize(T.DOMAIN, raw) == "example.com"


def test_domain_idna() -> None:
    assert normalize(T.DOMAIN, "bücher.example") == "xn--bcher-kva.example"


def test_url_removes_tracking_and_default_port() -> None:
    url = "HTTPS://Evil.Example:443/login?utm_source=mail&id=3&fbclid=x#frag"
    assert normalize(T.URL, url) == "https://evil.example/login?id=3"


def test_url_keeps_nondefault_port_and_userinfo() -> None:
    assert normalize(T.URL, "http://user@evil.example:8080/x") == "http://user@evil.example:8080/x"


def test_ip_canonical() -> None:
    assert normalize(T.IPV6, "2001:0DB8:0000:0000:0000:0000:0000:0042") == "2001:db8::42"
    assert normalize(T.IPV4, " 192.0.2.1 ") == "192.0.2.1"
    with pytest.raises(ValueError):
        normalize(T.IPV4, "999.1.1.1")


def test_misc_types() -> None:
    assert normalize(T.SHA256, "ABCDEF") == "abcdef"
    assert normalize(T.CVE, "cve_2024_3400") == "CVE-2024-3400"
    assert normalize(T.EMAIL, "Alice@Corp.EXAMPLE") == "alice@corp.example"
    assert normalize(T.ASN, "64500") == "AS64500"
    assert normalize(T.TELEGRAM_REF, "@Some_Channel") == "some_channel"
