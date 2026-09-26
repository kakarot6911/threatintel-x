"""Composition root: wires settings, repository and engines together once."""

from __future__ import annotations

from functools import cached_property, lru_cache
from pathlib import Path

from threatintel.analysis.attribution import AttributionEngine
from threatintel.analysis.correlation import CorrelationEngine
from threatintel.analysis.lifecycle import LifecycleManager
from threatintel.analysis.profiles import ProfileBuilder
from threatintel.attack.knowledge_base import AttackKnowledgeBase, TechniqueMapper, load_default_kb
from threatintel.config import Settings, get_settings
from threatintel.enrichment.base import EnrichmentProvider
from threatintel.enrichment.engine import EnrichmentEngine
from threatintel.extraction.extractor import IOCExtractor
from threatintel.storage.repository import Repository


class Platform:
    def __init__(
        self,
        settings: Settings | None = None,
        repo: Repository | None = None,
        kb: AttackKnowledgeBase | None = None,
        providers: list[EnrichmentProvider] | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.repo = repo or Repository.from_url(self.settings.database_url)
        self._kb = kb
        self._providers = providers

    @cached_property
    def kb(self) -> AttackKnowledgeBase:
        return self._kb or load_default_kb(str(self.settings.attack_bundle_path))

    @cached_property
    def mapper(self) -> TechniqueMapper:
        return TechniqueMapper(self.kb, self.settings.config_dir / "mitre_mapping.yaml")

    @cached_property
    def enrichment(self) -> EnrichmentEngine:
        return EnrichmentEngine(self.repo, self._providers, self.settings)

    @cached_property
    def correlation(self) -> CorrelationEngine:
        return CorrelationEngine()

    @cached_property
    def attribution(self) -> AttributionEngine:
        return AttributionEngine(self.correlation)

    @cached_property
    def lifecycle(self) -> LifecycleManager:
        return LifecycleManager(self.repo)

    @cached_property
    def profiles(self) -> ProfileBuilder:
        return ProfileBuilder(self.repo, self.kb)

    def extractor(self) -> IOCExtractor:
        """Built per use: the alias dictionary grows as entities are added."""
        return IOCExtractor(
            entity_aliases=self.repo.alias_dictionary(),
            known_techniques=self.kb.technique_ids,
            ambiguous=load_ambiguous_aliases(str(self.settings.config_dir / "ambiguous_aliases.txt")),
            uppercase=self.repo.uppercase_aliases(),
        )


@lru_cache(maxsize=4)
def load_ambiguous_aliases(path: str) -> frozenset[str]:
    p = Path(path)
    if not p.exists():
        return frozenset()
    lines = (line.strip().lower() for line in p.read_text(encoding="utf-8").splitlines())
    return frozenset(line for line in lines if line and not line.startswith("#"))
