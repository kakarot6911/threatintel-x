"""Outbound HTTP with safety rails.

* Disabled entirely unless ``TIX_ONLINE=true``.
* SSRF guard: every hop (including redirects) must resolve only to public unicast
  addresses unless ``TIX_ALLOW_PRIVATE_DESTINATIONS=true`` (e.g. a lab MISP).
* Bounded response size and timeouts.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

import httpx

from threatintel.config import Settings, get_settings

MAX_RESPONSE_BYTES = 20 * 1024 * 1024
MAX_REDIRECTS = 3
# Names the real HTTP client: some CDN bot managers reject a custom agent whose TLS fingerprint is
# httpx's, and we would rather be accurate than spoof a browser.
USER_AGENT = (
    f"THREATINTEL-X/0.1 python-httpx/{httpx.__version__} (+https://github.com/kakarot6911/threatintel-x)"
)


class NetworkDisabledError(RuntimeError):
    pass


class UnsafeDestinationError(RuntimeError):
    pass


def _resolve(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnsafeDestinationError(f"cannot resolve {host!r}") from exc
    return [ipaddress.ip_address(info[4][0]) for info in infos]


def assert_safe_destination(url: str, settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise UnsafeDestinationError(f"scheme {parts.scheme!r} not allowed")
    if not parts.hostname:
        raise UnsafeDestinationError("URL has no host")
    if settings.allow_private_destinations:
        return
    for ip in _resolve(parts.hostname):
        mapped = getattr(ip, "ipv4_mapped", None)
        candidate = mapped or ip
        if not candidate.is_global or candidate.is_multicast:
            raise UnsafeDestinationError(f"{parts.hostname} resolves to non-public address {candidate}")


def require_online(settings: Settings | None = None) -> Settings:
    settings = settings or get_settings()
    if not settings.online:
        raise NetworkDisabledError("network access disabled (set TIX_ONLINE=true to enable)")
    return settings


def safe_get(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
    settings: Settings | None = None,
    client: httpx.Client | None = None,
) -> httpx.Response:
    settings = require_online(settings)
    own = client is None
    http = client or httpx.Client(timeout=settings.http_timeout_seconds, follow_redirects=False)
    try:
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            assert_safe_destination(current, settings)
            resp = http.get(current, headers={"User-Agent": USER_AGENT, **(headers or {})}, params=params)
            if resp.is_redirect and resp.headers.get("location"):
                current = urljoin(current, resp.headers["location"])
                params = None
                continue
            if len(resp.content) > MAX_RESPONSE_BYTES:
                raise UnsafeDestinationError("response exceeds size limit")
            return resp
        raise UnsafeDestinationError("too many redirects")
    finally:
        if own:
            http.close()
