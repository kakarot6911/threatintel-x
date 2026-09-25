"""TAXII 2.1 collector (taxii2-client). Endpoints come only from configuration."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from typing import Any

from taxii2client.v21 import Collection, Server, as_pages

from threatintel.collectors.base import Collector
from threatintel.collectors.stix_collector import bundle_to_items
from threatintel.config import Settings, get_settings
from threatintel.models.intel import CollectedItem, Source
from threatintel.net import assert_safe_destination, require_online


class TAXIICollector(Collector):
    name = "taxii"

    def __init__(
        self,
        source: Source,
        collection_url: str,
        *,
        added_after: datetime | None = None,
        settings: Settings | None = None,
        page_size: int = 100,
    ) -> None:
        super().__init__(source)
        self.collection_url = collection_url
        self.added_after = added_after
        self.settings = settings or get_settings()
        self.page_size = page_size

    def _auth(self) -> dict[str, Any]:
        s = self.settings
        return {"user": s.taxii_username or None, "password": s.taxii_password.get_secret_value() or None}

    def collect(self) -> Iterator[CollectedItem]:
        require_online(self.settings)
        assert_safe_destination(self.collection_url, self.settings)
        collection = Collection(self.collection_url, **self._auth())
        kwargs: dict[str, Any] = {}
        if self.added_after:
            kwargs["added_after"] = self.added_after.isoformat()
        for envelope in as_pages(collection.get_objects, per_request=self.page_size, **kwargs):
            yield from bundle_to_items(self, {"type": "bundle", "objects": envelope.get("objects", [])})


def discover(server_url: str, settings: Settings | None = None) -> dict[str, Any]:
    """Return api roots and collections of a TAXII server (discovery + collection metadata)."""
    settings = require_online(settings)
    assert_safe_destination(server_url, settings)
    server = Server(
        server_url,
        user=settings.taxii_username or None,
        password=settings.taxii_password.get_secret_value() or None,
    )
    out: dict[str, Any] = {"title": server.title, "api_roots": []}
    for root in server.api_roots:
        out["api_roots"].append(
            {
                "url": root.url,
                "title": root.title,
                "collections": [
                    {
                        "id": c.id,
                        "title": c.title,
                        "can_read": c.can_read,
                        "can_write": c.can_write,
                        "url": c.url,
                    }
                    for c in root.collections
                ],
            }
        )
    return out
