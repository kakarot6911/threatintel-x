"""HUMINT-style analyst intake (no covert collection - analysts record what they were told)."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Iterator

from threatintel.collectors.base import Collector
from threatintel.models.common import StatementType
from threatintel.models.entities import HumintReport
from threatintel.models.intel import CollectedItem, Source


def pseudonymise_source(identifier: str) -> str:
    if identifier.startswith("HS-"):
        return identifier
    return "HS-" + hashlib.sha256(identifier.encode("utf-8")).hexdigest()[:12].upper()


class HumintCollector(Collector):
    name = "humint"

    def __init__(self, source: Source, reports: Iterable[HumintReport]) -> None:
        super().__init__(source)
        self.reports = list(reports)

    def collect(self) -> Iterator[CollectedItem]:
        for r in self.reports:
            r.source_identifier = pseudonymise_source(r.source_identifier)
            # The raw note is the collected item; the analyst assessment is kept separately and
            # is never merged into the raw text.
            yield self._item(
                title=f"HUMINT report {r.source_identifier} {r.date_observed.date().isoformat()}",
                content=r.raw_note,
                published_at=r.date_observed,
                source_reliability=r.source_reliability,
                information_credibility=r.information_credibility,
                statement_type=StatementType.RAW_SOURCE_REPORT,
                raw_reference=r.id,
                metadata={
                    "humint_report_id": r.id,
                    "collection_method": r.collection_method,
                    "source_identifier": r.source_identifier,
                    "analyst_assessment": r.analyst_assessment,
                    "corroborating_sources": r.corroborating_sources,
                    "synthetic": r.synthetic,
                },
            )
