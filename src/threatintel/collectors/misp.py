"""MISP collector: pulls events (PyMISP) or reads exported MISP JSON offline."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

from threatintel.collectors.base import Collector
from threatintel.models.intel import CollectedItem, Source


def event_to_text(event: dict[str, Any]) -> str:
    ev = event.get("Event", event)
    lines = [ev.get("info", "")]
    for attr in ev.get("Attribute", []):
        comment = f" ({attr['comment']})" if attr.get("comment") else ""
        lines.append(f"{attr.get('type')}: {attr.get('value')}{comment}")
    for obj in ev.get("Object", []):
        for attr in obj.get("Attribute", []):
            lines.append(f"{obj.get('name')}/{attr.get('object_relation')}: {attr.get('value')}")
    tags = [t.get("name", "") for t in ev.get("Tag", [])]
    if tags:
        lines.append("tags: " + ", ".join(tags))
    return "\n".join(line for line in lines if line)


class MISPCollector(Collector):
    name = "misp"

    def __init__(
        self,
        source: Source,
        events: Iterable[dict[str, Any]] | None = None,
        search: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(source)
        self.events = events
        self.search = search or {"last": "7d"}

    def collect(self) -> Iterator[CollectedItem]:
        events = self.events
        if events is None:
            from threatintel.integrations.misp import MISPAdapter

            events = MISPAdapter.from_settings().search_events(**self.search)
        for event in events:
            ev = event.get("Event", event)
            tags = [t.get("name", "") for t in ev.get("Tag", [])]
            yield self._item(
                title=ev.get("info", "MISP event"),
                content=event_to_text(event),
                raw_reference=ev.get("uuid"),
                tags=tags,
                metadata={
                    "misp_event_uuid": ev.get("uuid"),
                    "synthetic": any("synthetic" in t for t in tags),
                },
            )
