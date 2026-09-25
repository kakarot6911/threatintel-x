"""STIX 2.1 bundle collector: turns text-bearing STIX objects into raw items.

Structured import of the same bundle (objects -> knowledge base) lives in
``threatintel.stix.importer``; this collector feeds the *text* through the same
extraction pipeline as every other source so provenance is uniform.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from threatintel.collectors.base import Collector
from threatintel.models.intel import CollectedItem, Source

TEXT_TYPES = {
    "report",
    "indicator",
    "note",
    "campaign",
    "intrusion-set",
    "threat-actor",
    "malware",
    "opinion",
}


def bundle_to_items(collector: Collector, bundle: dict[str, Any]) -> Iterator[CollectedItem]:
    for obj in bundle.get("objects", []):
        if obj.get("type") not in TEXT_TYPES:
            continue
        parts = [
            obj.get("name", ""),
            obj.get("description", ""),
            obj.get("pattern", ""),
            obj.get("content", ""),
            obj.get("explanation", ""),
        ]
        content = "\n".join(p for p in parts if p).strip()
        if not content:
            continue
        synthetic = bool(obj.get("x_threatintel_synthetic")) or "synthetic" in obj.get("labels", [])
        yield collector._item(
            title=obj.get("name") or f"{obj['type']} {obj['id']}",
            content=content,
            raw_reference=obj["id"],
            tags=list(obj.get("labels", [])),
            metadata={"stix_type": obj["type"], "stix_id": obj["id"], "synthetic": synthetic},
        )


class STIXCollector(Collector):
    name = "stix"

    def __init__(
        self, source: Source, bundle: dict[str, Any] | None = None, path: Path | None = None
    ) -> None:
        super().__init__(source)
        if bundle is None and path is None:
            raise ValueError("STIXCollector needs a bundle or a path")
        self.bundle = bundle
        self.path = path

    def collect(self) -> Iterator[CollectedItem]:
        bundle = self.bundle if self.bundle is not None else json.loads(Path(self.path).read_text("utf-8"))  # type: ignore[arg-type]
        if bundle.get("type") != "bundle":
            raise ValueError("not a STIX bundle")
        yield from bundle_to_items(self, bundle)
