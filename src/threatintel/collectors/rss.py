"""RSS 2.0 / Atom collector for public threat-report feeds (e.g. CISA advisories, vendor blogs).

Parsing uses defusedxml (no entity expansion / XXE). Fetching goes through the
SSRF-guarded client and only happens when TIX_ONLINE=true; ``from_bytes`` allows
offline processing of a saved feed.
"""

from __future__ import annotations

import html
import logging
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

from defusedxml import ElementTree

from threatintel.collectors.base import Collector
from threatintel.models.intel import CollectedItem, Source
from threatintel.net import safe_get

log = logging.getLogger(__name__)
_TAG_RE = re.compile(r"<[^>]+>")
_ATOM = "{http://www.w3.org/2005/Atom}"


def _text(el: Any, tag: str) -> str:
    child = el.find(tag)
    return (child.text or "").strip() if child is not None and child.text else ""


def _strip_html(value: str) -> str:
    return html.unescape(_TAG_RE.sub(" ", value)).strip()


def _parse_date(value: str) -> datetime | None:
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


class RSSCollector(Collector):
    name = "rss"

    def __init__(self, source: Source, payload: bytes | None = None) -> None:
        super().__init__(source)
        self.payload = payload

    def collect(self) -> Iterator[CollectedItem]:
        payload = self.payload
        if payload is None:
            if not self.source.url:
                raise ValueError(f"source {self.source.id} has no feed URL")
            payload = safe_get(self.source.url).content
        yield from self.parse(payload)

    def parse(self, payload: bytes) -> Iterator[CollectedItem]:
        root = ElementTree.fromstring(payload)
        entries = root.findall("./channel/item") or root.findall(f"{_ATOM}entry")
        for entry in entries:
            try:
                if entry.tag == f"{_ATOM}entry":
                    title = _text(entry, f"{_ATOM}title")
                    link_el = entry.find(f"{_ATOM}link")
                    link = link_el.get("href") if link_el is not None else None
                    body = _text(entry, f"{_ATOM}content") or _text(entry, f"{_ATOM}summary")
                    published = _parse_date(
                        _text(entry, f"{_ATOM}updated") or _text(entry, f"{_ATOM}published")
                    )
                    guid = _text(entry, f"{_ATOM}id") or link
                else:
                    title = _text(entry, "title")
                    link = _text(entry, "link") or None
                    body = _text(entry, "description")
                    published = _parse_date(_text(entry, "pubDate"))
                    guid = _text(entry, "guid") or link
                content = _strip_html(body)
                if not title and not content:
                    continue
                yield self._item(
                    title=title or "(untitled)",
                    content=f"{title}\n\n{content}".strip(),
                    url=link,
                    published_at=published,
                    raw_reference=guid,
                )
            except Exception:  # one malformed entry must not stop the feed
                log.exception("skipping malformed feed entry from %s", self.source.id)
