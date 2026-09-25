"""MITRE ATT&CK reference-data collector (downloads the official STIX release when online)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from threatintel.attack.knowledge_base import AttackKnowledgeBase
from threatintel.collectors.base import Collector
from threatintel.config import Settings, get_settings
from threatintel.models.intel import CollectedItem, Source
from threatintel.net import safe_get


class MITRECollector(Collector):
    name = "mitre"

    def __init__(
        self, source: Source, settings: Settings | None = None, bundle_path: Path | None = None
    ) -> None:
        super().__init__(source)
        self.settings = settings or get_settings()
        self.bundle_path = bundle_path

    def sync(self) -> Path:
        """Download the full Enterprise ATT&CK bundle to data/attack/enterprise-attack.json."""
        resp = safe_get(self.settings.attack_url, settings=self.settings)
        resp.raise_for_status()
        bundle = resp.json()
        if bundle.get("type") != "bundle":
            raise ValueError("downloaded document is not a STIX bundle")
        target = self.settings.data_dir / "attack" / "enterprise-attack.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(bundle), encoding="utf-8")
        return target

    def collect(self) -> Iterator[CollectedItem]:
        path = self.bundle_path or self.settings.attack_bundle_path
        kb = AttackKnowledgeBase.load(path)
        yield self._item(
            title=f"{kb.domain} v{kb.version}",
            content=f"Reference data: {kb.domain} release {kb.version} with {len(kb.techniques)} techniques "
            f"and {len(kb.tactics)} tactics.",
            raw_reference=str(path.name),
            metadata={"attack_version": kb.version, "reference_data": True},
        )
