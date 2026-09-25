"""Telegram collection through permitted mechanisms ONLY.

Supported:
  * messages delivered to OUR authorised bot (Bot API ``getUpdates``) from chats on an explicit allow-list
  * analyst-submitted message references
  * synthetic messages (demo)

Not supported by design: user-account (MTProto) scraping of arbitrary public channels
or private groups. Author identities are pseudonymised (salted hash) before storage.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from typing import Any

import httpx

from threatintel.collectors.base import Collector
from threatintel.config import Settings, get_settings
from threatintel.models.common import sha256_text
from threatintel.models.intel import CollectedItem, Source
from threatintel.net import require_online

BOT_API = "https://api.telegram.org"


def pseudonymise(identifier: str, salt: str = "tix-telegram") -> str:
    return "tg-author-" + hashlib.sha256(f"{salt}:{identifier}".encode()).hexdigest()[:16]


class TelegramPermittedCollector(Collector):
    name = "telegram"

    def __init__(
        self,
        source: Source,
        messages: Iterable[dict[str, Any]] | None = None,
        settings: Settings | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        super().__init__(source)
        self.messages = messages
        self.settings = settings or get_settings()
        self.client = client

    def _fetch_updates(self) -> list[dict[str, Any]]:
        settings = require_online(self.settings)
        token = settings.telegram_bot_token.get_secret_value()
        if not token:
            raise RuntimeError("TIX_TELEGRAM_BOT_TOKEN is not configured")
        http = self.client or httpx.Client(timeout=settings.http_timeout_seconds)
        try:
            resp = http.get(f"{BOT_API}/bot{token}/getUpdates", params={"timeout": "0"})
            resp.raise_for_status()
            body = resp.json()
        finally:
            if self.client is None:
                http.close()
        if not body.get("ok"):
            raise RuntimeError("Telegram Bot API returned an error")
        allowed = set(settings.telegram_allowed_chats)
        out = []
        for update in body.get("result", []):
            msg = update.get("message") or update.get("channel_post")
            if not msg or "text" not in msg:
                continue
            chat = msg.get("chat", {})
            if chat.get("id") not in allowed:
                continue  # never process chats that were not explicitly authorised
            out.append(
                {
                    "channel_reference": chat.get("username") or f"chat-{chat.get('id')}",
                    "message_id": msg.get("message_id"),
                    "timestamp": datetime.fromtimestamp(msg.get("date", 0), tz=UTC).isoformat(),
                    "author_reference": str((msg.get("from") or {}).get("id", "unknown")),
                    "text": msg["text"],
                    "synthetic": False,
                }
            )
        return out

    def collect(self) -> Iterator[CollectedItem]:
        messages = list(self.messages) if self.messages is not None else self._fetch_updates()
        for m in messages:
            text = m["text"]
            author = m.get("author_reference", "unknown")
            if not str(author).startswith("tg-author-"):
                author = pseudonymise(str(author))
            ts = datetime.fromisoformat(str(m["timestamp"]).replace("Z", "+00:00"))
            yield self._item(
                title=f"Telegram {m['channel_reference']} #{m['message_id']}",
                content=text,
                published_at=ts,
                raw_reference=f"telegram:{m['channel_reference']}/{m['message_id']}",
                metadata={
                    "channel_reference": m["channel_reference"],
                    "message_id": m["message_id"],
                    "author_reference": author,
                    "content_hash": sha256_text(text),
                    "synthetic": bool(m.get("synthetic")),
                },
            )
