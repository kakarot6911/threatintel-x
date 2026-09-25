"""Passive validation of observables. Nothing here touches the network."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timedelta
from functools import lru_cache
from urllib.parse import urlsplit

from threatintel.config import get_settings
from threatintel.models.common import ObservableType, utcnow
from threatintel.models.intel import ValidationResult

# RFC 2606 / RFC 6761 / RFC 7686 special-use names.
SPECIAL_USE_TLDS = frozenset({"example", "test", "invalid", "localhost", "local", "onion"})
DOCUMENTATION_TLDS = frozenset({"example", "test", "invalid"})
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_HASH_LEN = {ObservableType.MD5: 32, ObservableType.SHA1: 40, ObservableType.SHA256: 64}
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_CVE_RE = re.compile(r"^CVE-(19[89]\d|2\d{3})-\d{4,7}$")
_ATTACK_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_ETH_RE = re.compile(r"^0x[0-9a-f]{40}$")
_TG_RE = re.compile(r"^[a-z][a-z0-9_]{4,31}$")
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# Hashes of the empty file: frequently pasted into reports, never a meaningful IOC.
EMPTY_FILE_HASHES = frozenset(
    {
        "d41d8cd98f00b204e9800998ecf8427e",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856",
    }
)

# Staleness horizons: after this long without a sighting an IOC is considered stale.
STALENESS = {
    ObservableType.IPV4: timedelta(days=30),
    ObservableType.IPV6: timedelta(days=30),
    ObservableType.URL: timedelta(days=30),
    ObservableType.DOMAIN: timedelta(days=180),
    ObservableType.EMAIL: timedelta(days=365),
    ObservableType.MD5: timedelta(days=730),
    ObservableType.SHA1: timedelta(days=730),
    ObservableType.SHA256: timedelta(days=730),
}


@lru_cache(maxsize=1)
def known_tlds() -> frozenset[str]:
    path = get_settings().data_dir / "reference" / "iana_tlds.txt"
    tlds: set[str] = set(SPECIAL_USE_TLDS)
    if path.exists():
        tlds.update(line.strip().lower() for line in path.read_text().splitlines() if line.strip())
    return frozenset(tlds)


def domain_tld(domain: str) -> str:
    return domain.rsplit(".", 1)[-1]


def is_documentation_domain(domain: str) -> bool:
    tld = domain_tld(domain)
    return (
        tld in DOCUMENTATION_TLDS
        or domain in {"example.com", "example.net", "example.org"}
        or any(domain.endswith(f".{d}") for d in ("example.com", "example.net", "example.org"))
    )


def validate_domain(domain: str) -> ValidationResult:
    reasons: list[str] = []
    flags: list[str] = []
    if len(domain) > 253 or "." not in domain:
        return ValidationResult(valid=False, actionable=False, reasons=["not a fully-qualified domain"])
    labels = domain.split(".")
    if not all(_LABEL_RE.match(label) for label in labels):
        return ValidationResult(valid=False, actionable=False, reasons=["invalid DNS label"])
    tld = labels[-1]
    if tld not in known_tlds():
        return ValidationResult(valid=False, actionable=False, reasons=[f"unknown TLD '.{tld}'"])
    actionable = True
    if tld in SPECIAL_USE_TLDS:
        flags.append("special-use")
        if tld != "onion":
            actionable = False
            reasons.append("special-use / reserved name (RFC 2606/6761)")
    if is_documentation_domain(domain):
        flags.append("documentation")
        actionable = False
    return ValidationResult(valid=True, actionable=actionable, reasons=reasons, flags=sorted(set(flags)))


# RFC 5737 / RFC 3849 documentation ranges - what our synthetic world lives in.
_DOC_NETS = [
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
]


def validate_ip(value: str) -> ValidationResult:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return ValidationResult(valid=False, actionable=False, reasons=["not an IP address"])
    flags: list[str] = []
    if any(ip in net for net in _DOC_NETS):
        flags.append("documentation")
    elif ip.is_private:
        flags.append("private")
    if ip.is_loopback:
        flags.append("loopback")
    if ip.is_multicast:
        flags.append("multicast")
    if ip.is_link_local:
        flags.append("link-local")
    if ip.is_unspecified:
        flags.append("unspecified")
    if ip.is_reserved:
        flags.append("reserved")
    actionable = not flags
    reasons = [] if actionable else [f"non-routable address ({', '.join(sorted(set(flags)))})"]
    return ValidationResult(valid=True, actionable=actionable, reasons=reasons, flags=sorted(set(flags)))


def _b58decode_check(addr: str) -> bool:
    num = 0
    for ch in addr:
        idx = _B58.find(ch)
        if idx < 0:
            return False
        num = num * 58 + idx
    raw = num.to_bytes(25, "big") if num.bit_length() <= 200 else b""
    if len(raw) != 25:
        return False
    return hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:]


def _bech32_polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_valid(addr: str) -> bool:
    addr = addr.lower()
    hrp, _, data = addr.rpartition("1")
    if hrp != "bc" or len(data) < 6 or any(c not in _BECH32 for c in data):
        return False
    values = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + [_BECH32.find(c) for c in data]
    return _bech32_polymod(values) in (1, 0x2BC830A3)  # bech32 / bech32m constants


def validate_btc(addr: str) -> bool:
    if addr.lower().startswith("bc1"):
        return _bech32_valid(addr)
    return addr[:1] in "13" and 26 <= len(addr) <= 35 and _b58decode_check(addr)


def validate(
    obs_type: ObservableType, value: str, *, known_techniques: frozenset[str] | None = None
) -> ValidationResult:
    match obs_type:
        case ObservableType.DOMAIN:
            return validate_domain(value)
        case ObservableType.IPV4 | ObservableType.IPV6:
            return validate_ip(value)
        case ObservableType.URL:
            try:
                parts = urlsplit(value)
                parts.port  # noqa: B018 - raises ValueError on a malformed port
            except ValueError:
                return ValidationResult(valid=False, actionable=False, reasons=["malformed URL"])
            if parts.scheme not in ("http", "https", "ftp") or not parts.hostname:
                return ValidationResult(valid=False, actionable=False, reasons=["unsupported URL"])
            host = parts.hostname
            try:
                ipaddress.ip_address(host)
                host_result = validate_ip(host)
            except ValueError:
                host_result = validate_domain(host)
            return ValidationResult(
                valid=host_result.valid,
                actionable=host_result.actionable,
                reasons=host_result.reasons,
                flags=host_result.flags,
            )
        case ObservableType.EMAIL:
            local, _, domain = value.rpartition("@")
            if not local or len(local) > 64:
                return ValidationResult(valid=False, actionable=False, reasons=["invalid local part"])
            return validate_domain(domain)
        case ObservableType.MD5 | ObservableType.SHA1 | ObservableType.SHA256:
            ok = len(value) == _HASH_LEN[obs_type] and bool(_HEX_RE.match(value))
            if not ok or len(set(value)) == 1:
                return ValidationResult(
                    valid=False, actionable=False, reasons=["malformed or degenerate hash"]
                )
            if value in EMPTY_FILE_HASHES:
                return ValidationResult(
                    valid=True, actionable=False, flags=["empty-file"], reasons=["hash of the empty file"]
                )
            return ValidationResult(valid=True)
        case ObservableType.CVE:
            ok = bool(_CVE_RE.match(value))
            return ValidationResult(valid=ok, actionable=ok, reasons=[] if ok else ["malformed CVE id"])
        case ObservableType.ATTACK_TECHNIQUE:
            if not _ATTACK_RE.match(value):
                return ValidationResult(valid=False, actionable=False, reasons=["malformed ATT&CK id"])
            if known_techniques is not None and value not in known_techniques:
                return ValidationResult(
                    valid=True,
                    actionable=False,
                    flags=["unverified"],
                    reasons=["technique id not present in loaded ATT&CK release"],
                )
            return ValidationResult(valid=True)
        case ObservableType.BTC_ADDRESS:
            ok = validate_btc(value)
            return ValidationResult(valid=ok, actionable=ok, reasons=[] if ok else ["checksum failed"])
        case ObservableType.ETH_ADDRESS:
            ok = bool(_ETH_RE.match(value))
            return ValidationResult(valid=ok, actionable=ok, reasons=[] if ok else ["malformed address"])
        case ObservableType.TELEGRAM_REF:
            ok = bool(_TG_RE.match(value))
            return ValidationResult(
                valid=ok, actionable=ok, reasons=[] if ok else ["invalid Telegram handle"]
            )
        case _:
            return ValidationResult(valid=True)


def is_stale(obs_type: ObservableType, last_seen: datetime, now: datetime | None = None) -> bool:
    horizon = STALENESS.get(obs_type)
    return horizon is not None and (now or utcnow()) - last_seen > horizon
