import ipaddress

import httpx
import pytest
import respx

from threatintel import net
from threatintel.config import Settings


@pytest.fixture
def online() -> Settings:
    return Settings(database_url="sqlite://", online=True)


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.0.0.5",
        "169.254.169.254",
        "192.168.1.1",
        "::1",
        "::ffff:127.0.0.1",
        "0.0.0.0",
        "100.64.0.1",
    ],
)
def test_blocks_non_public(monkeypatch: pytest.MonkeyPatch, online: Settings, ip: str) -> None:
    monkeypatch.setattr(net, "_resolve", lambda host: [ipaddress.ip_address(ip)])
    with pytest.raises(net.UnsafeDestinationError):
        net.assert_safe_destination("http://feed.example/rss", online)


@pytest.mark.parametrize(
    "url", ["file:///etc/passwd", "gopher://x.example", "ftp://x.example/", "http:///nohost"]
)
def test_blocks_bad_schemes(online: Settings, url: str) -> None:
    with pytest.raises(net.UnsafeDestinationError):
        net.assert_safe_destination(url, online)


def test_offline_by_default() -> None:
    with pytest.raises(net.NetworkDisabledError):
        net.safe_get("https://example.com", settings=Settings(database_url="sqlite://"))


@respx.mock
def test_redirect_to_private_is_blocked(monkeypatch: pytest.MonkeyPatch, online: Settings) -> None:
    def resolve(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        return [ipaddress.ip_address("10.0.0.1" if host == "internal.example" else "93.184.216.34")]

    monkeypatch.setattr(net, "_resolve", resolve)
    respx.get("https://public.example/feed").mock(
        return_value=httpx.Response(302, headers={"location": "http://internal.example/admin"})
    )
    with pytest.raises(net.UnsafeDestinationError, match="non-public"):
        net.safe_get("https://public.example/feed", settings=online)


@respx.mock
def test_follows_safe_redirect(monkeypatch: pytest.MonkeyPatch, online: Settings) -> None:
    monkeypatch.setattr(net, "_resolve", lambda host: [ipaddress.ip_address("93.184.216.34")])
    respx.get("https://a.example/x").mock(return_value=httpx.Response(301, headers={"location": "/y"}))
    respx.get("https://a.example/y").mock(return_value=httpx.Response(200, text="ok"))
    assert net.safe_get("https://a.example/x", settings=online).text == "ok"
