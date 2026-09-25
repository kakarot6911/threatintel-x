"""Deterministic IOC / entity extraction from free text.

Order matters: URLs and emails are extracted (and masked) first so their host
parts are not double-counted as bare domains, then hashes, IPs, domains, etc.
Named entities (actors, malware, campaigns) are matched against the knowledge
base's alias dictionary - no model guesses names.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urlsplit

from threatintel.extraction.normalize import normalize, refang
from threatintel.extraction.validate import validate
from threatintel.models.common import ObservableType
from threatintel.models.intel import ExtractedObservable

_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`)\]}]+", re.I)
_EMAIL_RE = re.compile(r"(?<![\w.%+\-])[A-Za-z0-9._%+\-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}\b")
_SHA256_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
_SHA1_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])")
_MD5_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])")
_IPV4_RE = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.]*\d)"
)
_IPV6_RE = re.compile(r"(?<![0-9A-Fa-f:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Fa-f:])")
_DOMAIN_RE = re.compile(
    r"(?<![\w@.\-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{1,23}\b(?![\w-]*@)"
)
_CVE_RE = re.compile(r"\bCVE[-_]\d{4}[-_]\d{4,7}\b", re.I)
_ATTACK_RE = re.compile(r"(?<![\w.])T\d{4}(?:\.\d{3})?\b")
_BTC_RE = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_ETH_RE = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
_TME_RE = re.compile(r"\bt(?:elegram)?\.me/(?:s/)?([A-Za-z][A-Za-z0-9_]{4,31})\b", re.I)
_TG_HANDLE_RE = re.compile(r"(?<![\w@])@([A-Za-z][A-Za-z0-9_]{4,31})\b")

# TLDs that are also common file extensions: a bare "invoice.zip" is a filename, not an IOC,
# unless it was defanged or appeared inside a URL/email.
AMBIGUOUS_TLDS = frozenset(
    {"zip", "mov", "py", "sh", "md", "rs", "pl", "ps", "exe", "dll", "doc", "pdf", "js"}
)


@dataclass
class ExtractionResult:
    observables: list[ExtractedObservable] = field(default_factory=list)
    entities: dict[str, set[str]] = field(default_factory=dict)  # entity_type -> canonical names
    rejected: list[tuple[str, str, str]] = field(default_factory=list)  # (type, raw, reason)

    def of_type(self, obs_type: ObservableType) -> list[ExtractedObservable]:
        return [o for o in self.observables if o.type == obs_type]

    def values(self, obs_type: ObservableType) -> set[str]:
        return {o.value for o in self.of_type(obs_type)}


def _safe_host(url: str) -> str:
    try:
        return urlsplit(url).hostname or ""
    except ValueError:  # e.g. unbalanced IPv6 brackets in hostile input
        return ""


def _context(text: str, start: int, end: int, width: int = 60) -> str:
    return text[max(0, start - width) : min(len(text), end + width)].replace("\n", " ").strip()


class IOCExtractor:
    def __init__(
        self,
        entity_aliases: dict[str, dict[str, str]] | None = None,
        known_techniques: frozenset[str] | None = None,
    ) -> None:
        """``entity_aliases``: {entity_type: {alias_lower: canonical_name}}."""
        self.entity_aliases = entity_aliases or {}
        self.known_techniques = known_techniques
        self._alias_patterns: dict[str, re.Pattern[str]] = {}
        for etype, aliases in self.entity_aliases.items():
            if aliases:
                alts = sorted((re.escape(a) for a in aliases), key=len, reverse=True)
                self._alias_patterns[etype] = re.compile(
                    r"(?<![\w-])(" + "|".join(alts) + r")(?![\w-])", re.I
                )

    def extract(self, text: str, *, telegram_context: bool = False) -> ExtractionResult:
        refanged, _ = refang(text)
        original_lower = text.lower()
        result = ExtractionResult()
        seen: set[tuple[ObservableType, str]] = set()
        masked = list(refanged)

        def mask(start: int, end: int) -> None:
            for i in range(start, end):
                masked[i] = " "

        def add(
            obs_type: ObservableType, raw: str, start: int, end: int, *, from_container: bool = False
        ) -> None:
            try:
                value = normalize(obs_type, raw)
            except ValueError as exc:
                result.rejected.append((obs_type.value, raw, f"normalisation failed: {exc}"))
                return
            if obs_type == ObservableType.DOMAIN and not from_container:
                tld = value.rsplit(".", 1)[-1]
                if tld in AMBIGUOUS_TLDS and not self._was_defanged(original_lower, obs_type, value):
                    result.rejected.append((obs_type.value, raw, "ambiguous file-extension TLD"))
                    return
            check = validate(obs_type, value, known_techniques=self.known_techniques)
            if not check.valid:
                result.rejected.append((obs_type.value, raw, "; ".join(check.reasons)))
                return
            if (obs_type, value) in seen:
                return
            seen.add((obs_type, value))
            result.observables.append(
                ExtractedObservable(
                    type=obs_type,
                    value=value,
                    raw=raw,
                    defanged=self._was_defanged(original_lower, obs_type, value),
                    context=_context(refanged, start, end),
                )
            )

        for m in _URL_RE.finditer(refanged):
            raw = m.group(0).rstrip(".,;:!?")
            add(ObservableType.URL, raw, m.start(), m.start() + len(raw))
            host = _safe_host(raw)
            if host:
                self._add_host(host, add, m.start(), m.end())
            mask(m.start(), m.start() + len(raw))

        for m in _EMAIL_RE.finditer("".join(masked)):
            add(ObservableType.EMAIL, m.group(0), m.start(), m.end())
            domain = m.group(0).rpartition("@")[2]
            add(ObservableType.DOMAIN, domain, m.start(), m.end(), from_container=True)
            mask(m.start(), m.end())

        current = "".join(masked)
        for m in _ETH_RE.finditer(current):
            add(ObservableType.ETH_ADDRESS, m.group(0), m.start(), m.end())
            mask(m.start(), m.end())
        current = "".join(masked)
        for regex, obs_type in (
            (_SHA256_RE, ObservableType.SHA256),
            (_SHA1_RE, ObservableType.SHA1),
            (_MD5_RE, ObservableType.MD5),
        ):
            for m in regex.finditer(current):
                add(obs_type, m.group(0), m.start(), m.end())
                mask(m.start(), m.end())
            current = "".join(masked)

        for m in _BTC_RE.finditer(current):
            add(ObservableType.BTC_ADDRESS, m.group(0), m.start(), m.end())

        for m in _IPV4_RE.finditer(current):
            add(ObservableType.IPV4, m.group(0), m.start(), m.end())
            mask(m.start(), m.end())
        for m in _IPV6_RE.finditer(current):
            raw = m.group(0)
            if len(raw) < 3 or not any(c.isalnum() for c in raw):
                continue
            try:
                ipaddress.IPv6Address(raw)
            except ValueError:
                continue  # clock times, MAC fragments, etc. - not worth reporting as rejections
            add(ObservableType.IPV6, raw, m.start(), m.end())
            mask(m.start(), m.end())
        current = "".join(masked)

        for m in _TME_RE.finditer(current):
            add(ObservableType.TELEGRAM_REF, m.group(1), m.start(), m.end())
            mask(m.start(), m.end())
        current = "".join(masked)
        if telegram_context:
            for m in _TG_HANDLE_RE.finditer(current):
                add(ObservableType.TELEGRAM_REF, m.group(1), m.start(), m.end())
                mask(m.start(), m.end())
            current = "".join(masked)

        for m in _DOMAIN_RE.finditer(current):
            add(ObservableType.DOMAIN, m.group(0), m.start(), m.end())

        for m in _CVE_RE.finditer(refanged):
            add(ObservableType.CVE, m.group(0), m.start(), m.end())
        for m in _ATTACK_RE.finditer(refanged):
            add(ObservableType.ATTACK_TECHNIQUE, m.group(0), m.start(), m.end())

        for etype, pattern in self._alias_patterns.items():
            for m in pattern.finditer(refanged):
                canonical = self.entity_aliases[etype].get(m.group(1).lower())
                if canonical:
                    result.entities.setdefault(etype, set()).add(canonical)
        return result

    def _add_host(self, host: str, add: _AddFn, start: int, end: int) -> None:
        try:
            normalize(ObservableType.IPV4, host)
        except ValueError:
            add(ObservableType.DOMAIN, host, start, end, from_container=True)
            return
        add(ObservableType.IPV6 if ":" in host else ObservableType.IPV4, host, start, end)

    @staticmethod
    def _was_defanged(original_lower: str, obs_type: ObservableType, value: str) -> bool:
        """True when the value only exists in the text after refanging."""
        probe = (_safe_host(value) or value) if obs_type == ObservableType.URL else value
        return probe.lower() not in original_lower


class _AddFn(Protocol):
    def __call__(
        self, obs_type: ObservableType, raw: str, start: int, end: int, *, from_container: bool = False
    ) -> None: ...


def extract_all(texts: Iterable[str], extractor: IOCExtractor | None = None) -> ExtractionResult:
    ex = extractor or IOCExtractor()
    merged = ExtractionResult()
    keys: set[tuple[ObservableType, str]] = set()
    for text in texts:
        r = ex.extract(text)
        for o in r.observables:
            if (o.type, o.value) not in keys:
                keys.add((o.type, o.value))
                merged.observables.append(o)
        for k, v in r.entities.items():
            merged.entities.setdefault(k, set()).update(v)
        merged.rejected.extend(r.rejected)
    return merged
