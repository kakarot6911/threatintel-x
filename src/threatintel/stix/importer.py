"""STIX 2.1 import: structured objects -> knowledge base, with provenance to the bundle's producer.

Imported ``attributed-to`` relationships are stored as ``reported-attribution`` - a third
party's claim - never as our own assessment. Indicator patterns are parsed only for the
simple ``[type:prop = 'value']`` comparisons (joined by OR); anything else is kept as the
indicator's text for analyst review rather than guessed at.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import stix2

from threatintel.extraction.normalize import normalize
from threatintel.extraction.validate import validate
from threatintel.models.common import (
    InformationCredibility,
    ObservableType,
    Provenance,
    SourceReliability,
    SourceType,
    utcnow,
)
from threatintel.models.entities import (
    Campaign,
    Entity,
    Malware,
    Relationship,
    ThreatActor,
    Tool,
    Vulnerability,
)
from threatintel.models.intel import Observable
from threatintel.storage.repository import Repository

_CMP_RE = re.compile(r"(?P<path>[a-z0-9-]+:[a-z0-9_.'\-]+)\s*=\s*'(?P<value>(?:[^'\\]|\\.)*)'", re.I)
PATH_TYPES = {
    "ipv4-addr:value": ObservableType.IPV4,
    "ipv6-addr:value": ObservableType.IPV6,
    "domain-name:value": ObservableType.DOMAIN,
    "url:value": ObservableType.URL,
    "email-addr:value": ObservableType.EMAIL,
    "file:hashes.'md5'": ObservableType.MD5,
    "file:hashes.md5": ObservableType.MD5,
    "file:hashes.'sha-1'": ObservableType.SHA1,
    "file:hashes.'sha-256'": ObservableType.SHA256,
    "file:hashes.sha256": ObservableType.SHA256,
    "file:hashes.'sha256'": ObservableType.SHA256,
    "file:hashes.'sha1'": ObservableType.SHA1,
}
REL_IMPORT = {
    "indicates": "indicates",
    "uses": "uses",
    "targets": "exploits",
    "related-to": "related-to",
    "attributed-to": "reported-attribution",
    "resolves-to": "resolves-to",
    "belongs-to": "belongs-to",
}


@dataclass
class ImportResult:
    entities: int = 0
    observables: int = 0
    relationships: int = 0
    skipped: list[str] = field(default_factory=list)
    id_map: dict[str, str] = field(default_factory=dict)


def parse_pattern(pattern: str) -> list[tuple[ObservableType, str]]:
    out: list[tuple[ObservableType, str]] = []
    if " AND " in pattern.upper() or "FOLLOWEDBY" in pattern.upper():
        return out  # compound behavioural patterns are not single observables
    for m in _CMP_RE.finditer(pattern):
        obs_type = PATH_TYPES.get(m.group("path").lower())
        if obs_type:
            out.append((obs_type, m.group("value").replace("\\'", "'").replace("\\\\", "\\")))
    return out


def _dt(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


class StixImporter:
    def __init__(
        self,
        repo: Repository,
        *,
        source_id: str,
        source_name: str,
        reliability: SourceReliability = SourceReliability.F,
    ) -> None:
        self.repo = repo
        self.prov = Provenance(
            source_id=source_id,
            source_name=source_name,
            source_type=SourceType.STIX,
            collected_at=utcnow(),
            reliability=reliability,
            credibility=InformationCredibility.CANNOT_BE_JUDGED,
        )

    def import_bundle(self, bundle: dict[str, Any]) -> ImportResult:
        if bundle.get("type") != "bundle":
            raise ValueError("not a STIX bundle")
        result = ImportResult()
        objects = bundle.get("objects", [])
        for obj in objects:
            try:
                stix2.parse(obj, allow_custom=True)
            except Exception as exc:  # invalid objects are reported, not imported
                result.skipped.append(f"{obj.get('id')}: {exc}")
                continue
            self._import_object(obj, result)
        for obj in objects:
            if obj.get("type") == "relationship":
                self._import_relationship(obj, result)
        return result

    def _synthetic(self, obj: dict[str, Any]) -> bool:
        return bool(obj.get("x_threatintel_synthetic")) or "synthetic" in (obj.get("labels") or [])

    def _entity(self, obj: dict[str, Any], ent: Entity, result: ImportResult) -> None:
        stored = self.repo.upsert_entity(ent, self.prov)
        result.id_map[obj["id"]] = stored.id
        result.entities += 1

    def _import_object(self, obj: dict[str, Any], result: ImportResult) -> None:
        t = obj["type"]
        common: dict[str, Any] = {
            "name": obj.get("name", ""),
            "aliases": obj.get("aliases") or [],
            "description": obj.get("description", ""),
            "synthetic": self._synthetic(obj),
            "confidence": int(obj.get("confidence", 50)),
            "labels": [x for x in obj.get("labels") or [] if isinstance(x, str)],
        }
        if t in ("intrusion-set", "threat-actor"):
            self._entity(
                obj,
                ThreatActor(
                    **common,
                    actor_kind=t,
                    motivation=obj.get("x_threatintel_motivation", obj.get("primary_motivation", "unknown")),
                    first_seen=_dt(obj.get("first_seen")),
                    last_seen=_dt(obj.get("last_seen")),
                ),
                result,
            )
        elif t == "campaign":
            self._entity(
                obj,
                Campaign(
                    **common,
                    objective=obj.get("objective", ""),
                    first_seen=_dt(obj.get("first_seen")),
                    last_seen=_dt(obj.get("last_seen")),
                ),
                result,
            )
        elif t == "malware":
            if not common["name"]:
                result.skipped.append(f"{obj['id']}: unnamed malware instance")
                return
            self._entity(
                obj,
                Malware(
                    **common,
                    malware_types=obj.get("malware_types") or [],
                    is_family=bool(obj.get("is_family", True)),
                ),
                result,
            )
        elif t == "tool":
            self._entity(obj, Tool(**common, tool_types=obj.get("tool_types") or []), result)
        elif t == "vulnerability":
            self._entity(
                obj,
                Vulnerability(
                    **common,
                    known_exploited=bool(obj.get("x_threatintel_known_exploited")),
                    cvss=obj.get("x_threatintel_cvss"),
                ),
                result,
            )
        elif t == "attack-pattern":
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    result.id_map[obj["id"]] = obj["id"]  # ATT&CK ids are kept as-is
        elif t == "indicator":
            for obs_type, value in parse_pattern(obj.get("pattern", "")):
                obs = self._observable(obs_type, value, obj)
                if obs:
                    result.id_map[obj["id"]] = obs.id
                    result.observables += 1
        elif t in ("ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr"):
            obs_type = {
                "ipv4-addr": ObservableType.IPV4,
                "ipv6-addr": ObservableType.IPV6,
                "domain-name": ObservableType.DOMAIN,
                "url": ObservableType.URL,
                "email-addr": ObservableType.EMAIL,
            }[t]
            obs = self._observable(obs_type, obj.get("value", ""), obj)
            if obs:
                result.id_map[obj["id"]] = obs.id
                result.observables += 1
        elif t == "autonomous-system" and obj.get("number") is not None:
            obs = self._observable(ObservableType.ASN, f"AS{obj['number']}", obj)
            if obs:
                result.id_map[obj["id"]] = obs.id
                result.observables += 1
        elif t == "file":
            for key, value in (obj.get("hashes") or {}).items():
                hash_type = {
                    "MD5": ObservableType.MD5,
                    "SHA-1": ObservableType.SHA1,
                    "SHA-256": ObservableType.SHA256,
                }.get(key.upper())
                if hash_type:
                    obs = self._observable(hash_type, value, obj)
                    if obs:
                        result.id_map[obj["id"]] = obs.id
                        result.observables += 1

    def _observable(self, obs_type: ObservableType, value: str, obj: dict[str, Any]) -> Observable | None:
        try:
            norm = normalize(obs_type, value)
        except ValueError:
            return None
        check = validate(obs_type, norm)
        if not check.valid:
            return None
        synthetic = self._synthetic(obj)
        when = _dt(obj.get("valid_from") or obj.get("created")) or utcnow()
        return self.repo.upsert_observable(
            Observable(
                type=obs_type,
                value=norm,
                actionable=check.actionable or synthetic,
                flags=check.flags,
                synthetic=synthetic,
                first_seen=when,
                last_seen=_dt(obj.get("modified")) or when,
            ),
            self.prov,
        )

    def _import_relationship(self, obj: dict[str, Any], result: ImportResult) -> None:
        rtype = REL_IMPORT.get(obj.get("relationship_type", ""))
        src = result.id_map.get(obj.get("source_ref", ""))
        dst = result.id_map.get(obj.get("target_ref", ""))
        if not rtype or not src or not dst:
            return
        self.repo.upsert_relationship(
            Relationship(
                source_ref=src,
                target_ref=dst,
                relationship_type=rtype,
                confidence=int(obj.get("confidence", 50)),
                description=obj.get("description", ""),
                provenance=[self.prov],
                synthetic=self._synthetic(obj),
                evidence=[f"imported from STIX ({self.prov.source_name})"],
            )
        )
        result.relationships += 1


def import_stix_bundle(
    repo: Repository,
    bundle: dict[str, Any],
    *,
    source_id: str = "src-stix-import",
    source_name: str = "STIX import",
    reliability: SourceReliability = SourceReliability.F,
) -> ImportResult:
    return StixImporter(
        repo, source_id=source_id, source_name=source_name, reliability=reliability
    ).import_bundle(bundle)
