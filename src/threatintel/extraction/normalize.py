"""Canonicalisation of observables. Pure functions, no I/O."""

from __future__ import annotations

import contextlib
import ipaddress
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from threatintel.models.common import ObservableType

_DEFANG_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bhxxp(s?)://", re.I), r"http\1://"),
    (re.compile(r"\bhxxp(s?)\[:\]//", re.I), r"http\1://"),
    (re.compile(r"\bmeow(s?)://", re.I), r"http\1://"),
    (re.compile(r"\[:\]//"), "://"),
    (re.compile(r"\s*\[dot\]\s*|\s*\(dot\)\s*", re.I), "."),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}"), "."),
    (re.compile(r"\[@\]|\(@\)|\[at\]|\(at\)", re.I), "@"),
    (re.compile(r"\[/\]"), "/"),
]

TRACKING_PARAMS = frozenset(
    {
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_term",
        "utm_content",
        "utm_id",
        "gclid",
        "fbclid",
        "mc_cid",
        "mc_eid",
        "msclkid",
        "_hsenc",
        "_hsmi",
        "igshid",
        "ref_src",
    }
)


def refang(text: str) -> tuple[str, bool]:
    """Undo common defanging. Returns (refanged_text, was_defanged)."""
    out = text
    for pattern, repl in _DEFANG_RULES:
        out = pattern.sub(repl, out)
    return out, out != text


def normalize_domain(value: str) -> str:
    d = value.strip().strip(".").lower()
    with contextlib.suppress(UnicodeError):  # leave un-encodable labels for the validator to reject
        d = d.encode("idna").decode("ascii")
    return d


def normalize_ip(value: str) -> str:
    return str(ipaddress.ip_address(value.strip().strip("[]")))


def normalize_url(value: str) -> str:
    parts = urlsplit(value.strip())
    scheme = parts.scheme.lower()
    host = normalize_domain(parts.hostname or "")
    if parts.hostname and ":" in parts.hostname:  # IPv6 literal
        host = f"[{normalize_ip(parts.hostname)}]"
    port = parts.port
    default = {"http": 80, "https": 443}.get(scheme)
    netloc = host if port in (None, default) else f"{host}:{port}"
    if parts.username:
        netloc = f"{parts.username}@{netloc}"
    query = urlencode(
        [
            (k, v)
            for k, v in parse_qsl(parts.query, keep_blank_values=True)
            if k.lower() not in TRACKING_PARAMS
        ]
    )
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, query, ""))


def normalize_email(value: str) -> str:
    local, _, domain = value.strip().rpartition("@")
    return f"{local.lower()}@{normalize_domain(domain)}"


def normalize_cve(value: str) -> str:
    return value.strip().upper().replace("_", "-")


def normalize(obs_type: ObservableType, value: str) -> str:
    match obs_type:
        case ObservableType.DOMAIN:
            return normalize_domain(value)
        case ObservableType.IPV4 | ObservableType.IPV6:
            return normalize_ip(value)
        case ObservableType.URL:
            return normalize_url(value)
        case ObservableType.EMAIL:
            return normalize_email(value)
        case ObservableType.MD5 | ObservableType.SHA1 | ObservableType.SHA256 | ObservableType.ETH_ADDRESS:
            return value.strip().lower()
        case ObservableType.CVE:
            return normalize_cve(value)
        case ObservableType.ATTACK_TECHNIQUE:
            return value.strip().upper()
        case ObservableType.TELEGRAM_REF:
            return value.strip().lstrip("@").lower()
        case ObservableType.ASN:
            return "AS" + value.strip().upper().removeprefix("AS")
        case _:
            return value.strip()
