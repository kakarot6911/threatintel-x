"""MITRE ATT&CK knowledge base loaded from an official STIX 2.1 bundle.

The version is read from the bundle's ``x-mitre-collection`` object - it is never
hard-coded. The repository ships a field-trimmed copy of Enterprise ATT&CK
(``data/attack/enterprise-attack-lite.json``); ``threatintel attack-sync``
downloads the full current release when online.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from threatintel.config import get_settings


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    stix_id: str
    tactics: tuple[str, ...]
    is_subtechnique: bool
    url: str
    description: str = ""
    platforms: tuple[str, ...] = ()
    created: str = ""
    modified: str = ""
    created_by_ref: str = ""

    @property
    def parent_id(self) -> str:
        return self.technique_id.split(".")[0]


@dataclass(frozen=True)
class Tactic:
    tactic_id: str
    name: str
    shortname: str


@dataclass(frozen=True)
class TechniqueMapping:
    technique: Technique
    method: str  # explicit-id | keyword-rule
    matched: str
    confidence: int


@dataclass
class AttackKnowledgeBase:
    version: str
    domain: str
    techniques: dict[str, Technique] = field(default_factory=dict)
    tactics: dict[str, Tactic] = field(default_factory=dict)  # by shortname
    source: str = ""

    @classmethod
    def from_bundle(cls, bundle: dict[str, Any], source: str = "") -> AttackKnowledgeBase:
        version, domain = "unknown", "enterprise-attack"
        techniques: dict[str, Technique] = {}
        tactics: dict[str, Tactic] = {}
        for obj in bundle.get("objects", []):
            otype = obj.get("type")
            if otype == "x-mitre-collection":
                version = str(obj.get("x_mitre_version", version))
                domain = obj.get("name", domain)
            elif otype == "x-mitre-tactic":
                ext = _mitre_ref(obj)
                if ext:
                    tactics[obj["x_mitre_shortname"]] = Tactic(
                        ext["external_id"], obj["name"], obj["x_mitre_shortname"]
                    )
            elif otype == "attack-pattern" and not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
                ext = _mitre_ref(obj)
                if not ext:
                    continue
                techniques[ext["external_id"]] = Technique(
                    technique_id=ext["external_id"],
                    name=obj["name"],
                    stix_id=obj["id"],
                    tactics=tuple(
                        p["phase_name"]
                        for p in obj.get("kill_chain_phases", [])
                        if p.get("kill_chain_name") == "mitre-attack"
                    ),
                    is_subtechnique=bool(obj.get("x_mitre_is_subtechnique")),
                    url=ext.get("url", ""),
                    description=(obj.get("description") or "").split("\n")[0][:400],
                    platforms=tuple(obj.get("x_mitre_platforms", [])),
                    created=obj.get("created", ""),
                    modified=obj.get("modified", ""),
                    created_by_ref=obj.get("created_by_ref", ""),
                )
        return cls(version=version, domain=domain, techniques=techniques, tactics=tactics, source=source)

    @classmethod
    def load(cls, path: Path) -> AttackKnowledgeBase:
        return cls.from_bundle(json.loads(path.read_text(encoding="utf-8")), source=str(path.name))

    @property
    def technique_ids(self) -> frozenset[str]:
        return frozenset(self.techniques)

    def get(self, technique_id: str) -> Technique | None:
        return self.techniques.get(technique_id.upper())

    def tactic_name(self, shortname: str) -> str:
        t = self.tactics.get(shortname)
        return t.name if t else shortname.replace("-", " ").title()

    def tactic_order(self) -> list[str]:
        order = [
            "reconnaissance",
            "resource-development",
            "initial-access",
            "execution",
            "persistence",
            "privilege-escalation",
            "defense-evasion",
            "stealth",
            "defense-impairment",
            "credential-access",
            "discovery",
            "lateral-movement",
            "collection",
            "command-and-control",
            "exfiltration",
            "impact",
        ]
        return [t for t in order if t in self.tactics] + sorted(t for t in self.tactics if t not in order)


def _mitre_ref(obj: dict[str, Any]) -> dict[str, str] | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref
    return None


@dataclass(frozen=True)
class KeywordRule:
    technique_id: str
    pattern: re.Pattern[str]
    confidence: int


class TechniqueMapper:
    """Maps text to techniques: explicit IDs (validated against the KB) + curated keyword rules."""

    def __init__(self, kb: AttackKnowledgeBase, rules_path: Path | None = None) -> None:
        self.kb = kb
        self.rules: list[KeywordRule] = []
        path = rules_path or get_settings().config_dir / "mitre_mapping.yaml"
        if path.exists():
            spec = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for rule in spec.get("rules", []):
                tid = str(rule["technique"]).upper()
                if tid in kb.techniques:  # never map to an id the loaded release does not contain
                    words = "|".join(re.escape(k) for k in rule["keywords"])
                    self.rules.append(
                        KeywordRule(
                            tid, re.compile(rf"\b(?:{words})\b", re.I), int(rule.get("confidence", 50))
                        )
                    )

    def map_text(self, text: str, explicit_ids: set[str] | None = None) -> list[TechniqueMapping]:
        found: dict[str, TechniqueMapping] = {}
        for tid in sorted(explicit_ids or set()):
            tech = self.kb.get(tid)
            if tech:
                found[tid] = TechniqueMapping(tech, "explicit-id", tid, 85)
        for rule in self.rules:
            m = rule.pattern.search(text)
            if m and rule.technique_id not in found:
                found[rule.technique_id] = TechniqueMapping(
                    self.kb.techniques[rule.technique_id], "keyword-rule", m.group(0), rule.confidence
                )
        return sorted(found.values(), key=lambda x: x.technique.technique_id)


@lru_cache(maxsize=4)
def load_default_kb(path: str | None = None) -> AttackKnowledgeBase:
    return AttackKnowledgeBase.load(Path(path) if path else get_settings().attack_bundle_path)
