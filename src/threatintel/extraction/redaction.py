"""Credential and secret redaction.

Runs BEFORE anything is persisted. The platform records *that* a credential was
exposed (``credential_present``) and, optionally, a keyed fingerprint so two
synthetic leaks of the same secret can be correlated - it never stores the secret.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field

REDACTED = "[REDACTED]"

# account:secret combo lines, e.g. "alice@corp.example:Summer2024!" or "user=bob pass=hunter2"
_COMBO_RE = re.compile(
    r"(?<![/\w.%+\-])(?P<account>[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24})[:|;](?P<secret>[^\s:|;]{3,128})"
)
_KV_RE = re.compile(
    r"(?i)\b(?P<key>pass(?:word|wd)?|pwd|passphrase|secret|api[_-]?key|access[_-]?token|auth[_-]?token|"
    r"session(?:id)?|cookie)\b(?P<sep>\s*[:=]\s*)(?P<secret>[\"']?[^\s\"',;]{3,256}[\"']?)"
)
_TOKEN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    (
        "private-key",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    ),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b")),
    ("bearer-token", re.compile(r"(?i)(?<=bearer )[A-Za-z0-9._~+/-]{20,}=*")),
    ("telegram-bot-token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")),
]


@dataclass
class ExposedAccount:
    account: str
    fingerprint: str | None


@dataclass
class RedactionResult:
    text: str
    redactions: int = 0
    accounts: list[ExposedAccount] = field(default_factory=list)
    secret_kinds: list[str] = field(default_factory=list)

    @property
    def credential_present(self) -> bool:
        return self.redactions > 0


def fingerprint(secret: str, key: bytes) -> str | None:
    if not key:
        return None
    return hmac.new(key, secret.encode("utf-8"), hashlib.sha256).hexdigest()[:24]


def redact(text: str, key: bytes = b"") -> RedactionResult:
    result = RedactionResult(text=text)

    def _combo(m: re.Match[str]) -> str:
        result.redactions += 1
        result.accounts.append(
            ExposedAccount(m.group("account").lower(), fingerprint(m.group("secret"), key))
        )
        result.secret_kinds.append("password")
        return f"{m.group('account')}:{REDACTED}"

    out = _COMBO_RE.sub(_combo, text)

    for kind, pattern in _TOKEN_PATTERNS:
        out, n = pattern.subn(f"{REDACTED}", out)
        if n:
            result.redactions += n
            result.secret_kinds.extend([kind] * n)

    def _kv(m: re.Match[str]) -> str:
        if m.group("secret").strip("\"'") == REDACTED:
            return m.group(0)
        result.redactions += 1
        result.secret_kinds.append(m.group("key").lower())
        return f"{m.group('key')}{m.group('sep')}{REDACTED}"

    out = _KV_RE.sub(_kv, out)
    result.text = out
    return result
