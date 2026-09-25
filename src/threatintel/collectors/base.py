"""Collector contract: every collector yields ``CollectedItem`` objects and nothing else.

Collectors do not extract, enrich or store - they are decoupled from downstream
processing so any source can be added without touching the pipeline.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator

from threatintel.models.intel import CollectedItem, Source


class Collector(ABC):
    name: str = "collector"

    def __init__(self, source: Source) -> None:
        self.source = source

    @abstractmethod
    def collect(self) -> Iterator[CollectedItem]:
        """Yield normalised raw items. Must not raise for a single malformed record."""

    def _item(self, **kwargs: object) -> CollectedItem:
        base: dict[str, object] = {
            "source_id": self.source.id,
            "source_name": self.source.name,
            "source_type": self.source.source_type,
            "source_reliability": self.source.reliability,
            "derived_from": self.source.derived_from,
        }
        base.update(kwargs)
        return CollectedItem.model_validate(base).finalise()
