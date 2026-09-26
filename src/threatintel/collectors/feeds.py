"""Structured public feeds: CISA KEV, abuse.ch Feodo Tracker & URLhaus, MITRE ATT&CK knowledge.

These are *structured* sources, so records map straight to observables/entities with provenance
instead of going through free-text extraction. Each pull is also recorded as one raw collected
item (the audit trail of what was fetched, when, from where). Nothing is fabricated: a record
that fails validation is counted and skipped.

Terms: CISA KEV is public-domain US-government data; abuse.ch data is free for commercial and
non-commercial use (see https://abuse.ch/terms); MITRE ATT&CK under its terms of use (see NOTICE).
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from threatintel.analysis.confidence import score_confidence
from threatintel.extraction.normalize import normalize
from threatintel.extraction.validate import validate
from threatintel.models.common import (
    TLP,
    InformationCredibility,
    ObservableType,
    Provenance,
    SourceReliability,
    SourceType,
    utcnow,
)
from threatintel.models.entities import Malware, Relationship, Vulnerability
from threatintel.models.intel import Assessment, CollectedItem, Observable, Source
from threatintel.storage.repository import Repository

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

FEED_SOURCES = {
    "kev": Source(
        id="src-cisa-kev",
        name="CISA Known Exploited Vulnerabilities",
        source_type=SourceType.RSS,
        reliability=SourceReliability.A,
        url=KEV_URL,
        collection_policy="Public US-government catalogue (public domain).",
    ),
    "feodo": Source(
        id="src-abusech-feodo",
        name="abuse.ch Feodo Tracker",
        source_type=SourceType.RSS,
        reliability=SourceReliability.B,
        url=FEODO_URL,
        collection_policy="abuse.ch terms: free for commercial and non-commercial use.",
    ),
    "urlhaus": Source(
        id="src-abusech-urlhaus",
        name="abuse.ch URLhaus",
        source_type=SourceType.RSS,
        reliability=SourceReliability.B,
        url=URLHAUS_URL,
        collection_policy="abuse.ch terms: free for commercial and non-commercial use.",
    ),
}


@dataclass
class FeedResult:
    feed: str
    records: int = 0
    imported: int = 0
    skipped: int = 0
    entities: int = 0
    notes: list[str] = field(default_factory=list)


def _dt(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.fromisoformat(text) if fmt is None else datetime.strptime(text, fmt)
        except ValueError:
            continue
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    return None


def _snapshot(
    repo: Repository, source: Source, summary: str, when: datetime, extra: dict[str, Any]
) -> Provenance:
    """Record the pull itself as a raw item and return provenance pointing at it."""
    repo.upsert_source(source)
    item = CollectedItem(
        source_id=source.id,
        source_name=source.name,
        source_type=source.source_type,
        source_reliability=source.reliability,
        information_credibility=InformationCredibility.PROBABLY_TRUE,
        title=f"{source.name} snapshot {when:%Y-%m-%d %H:%M} UTC",
        content=summary,
        url=source.url,
        raw_reference=source.url,
        collection_timestamp=when,
        metadata={"reference_data": True, "feed_snapshot": True, **extra},
    ).finalise()
    repo.add_collected_item(item)
    return item.provenance()


def _confidence(repo: Repository, obs: Observable) -> None:
    conf = score_confidence(obs.provenance, observable_type=obs.type, last_seen=obs.last_seen)
    repo.save_assessment(
        Assessment(
            subject_id=obs.id,
            kind="confidence",
            score=conf.score,
            level=conf.level.value,
            statement=conf.explanation,
            factors=conf.factors,
        )
    )


def _family(repo: Repository, name: str, prov: Provenance, types: list[str] | None = None) -> Malware | None:
    if not name or name.lower() in {"unknown", "none", "n/a"}:
        return None
    existing = repo.find_entity("malware", name) or repo.find_entity("tool", name)
    if isinstance(existing, Malware):
        return existing
    if existing is not None:
        return None  # a tool of that name exists; do not invent a malware family
    return repo.upsert_entity(Malware(name=name, malware_types=types or [], tlp=TLP.CLEAR), prov)


# --------------------------------------------------------------------------- KEV
def import_kev(repo: Repository, catalog: dict[str, Any], now: datetime | None = None) -> FeedResult:
    now = now or utcnow()
    res = FeedResult("cisa-kev", records=len(catalog.get("vulnerabilities", [])))
    prov = _snapshot(
        repo,
        FEED_SOURCES["kev"],
        f"CISA KEV catalogue v{catalog.get('catalogVersion')} with {res.records} vulnerabilities",
        now,
        {"catalog_version": catalog.get("catalogVersion")},
    )
    for v in catalog.get("vulnerabilities", []):
        cve = str(v.get("cveID", "")).upper()
        if not validate(ObservableType.CVE, cve).valid:
            res.skipped += 1
            continue
        repo.upsert_entity(
            Vulnerability(
                name=cve,
                known_exploited=True,
                ransomware_use=v.get("knownRansomwareCampaignUse") == "Known",
                affected_product=f"{v.get('vendorProject', '')} {v.get('product', '')}".strip(),
                description=f"{v.get('vulnerabilityName', '')}. {v.get('shortDescription', '')}".strip()[
                    :2000
                ],
                kev_date_added=_dt(v.get("dateAdded")),
                kev_due_date=_dt(v.get("dueDate")),
                first_seen=_dt(v.get("dateAdded")),
                tlp=TLP.CLEAR,
                confidence=95,
                external_references=[
                    {
                        "source_name": "cve",
                        "external_id": cve,
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
                    }
                ],
            ),
            prov,
        )
        res.imported += 1
    return res


# ------------------------------------------------------------------------- Feodo
def import_feodo(repo: Repository, records: list[dict[str, Any]], now: datetime | None = None) -> FeedResult:
    now = now or utcnow()
    res = FeedResult("feodo-tracker", records=len(records))
    prov = _snapshot(
        repo,
        FEED_SOURCES["feodo"],
        f"Feodo Tracker botnet C2 blocklist, {len(records)} entries",
        now,
        {"entries": len(records)},
    )
    for r in records:
        try:
            ip = normalize(ObservableType.IPV4, str(r.get("ip_address", "")))
        except ValueError:
            res.skipped += 1
            continue
        check = validate(ObservableType.IPV4, ip)
        if not check.actionable:
            res.skipped += 1
            continue
        online = r.get("status") == "online"
        first = _dt(r.get("first_seen")) or now
        last = _dt(r.get("last_online")) or first
        obs = repo.upsert_observable(
            Observable(
                type=ObservableType.IPV4,
                value=ip,
                first_seen=first,
                last_seen=max(last, first),
                flags=["botnet-c2", "online" if online else "offline"],
            ),
            prov,
        )
        if r.get("as_number"):
            asn = repo.upsert_observable(
                Observable(
                    type=ObservableType.ASN,
                    value=f"AS{r['as_number']}",
                    first_seen=first,
                    last_seen=last,
                    actionable=False,
                    flags=["context"],
                ),
                prov,
            )
            repo.upsert_relationship(
                Relationship(
                    source_ref=obs.id,
                    target_ref=asn.id,
                    relationship_type="belongs-to",
                    confidence=90,
                    provenance=[prov],
                    description=str(r.get("as_name") or ""),
                )
            )
        fam = _family(repo, str(r.get("malware") or ""), prov, ["botnet"])
        if fam:
            repo.upsert_relationship(
                Relationship(
                    source_ref=obs.id,
                    target_ref=fam.id,
                    relationship_type="indicates",
                    confidence=80 if online else 55,
                    provenance=[prov],
                    description=f"Feodo Tracker: {fam.name} C2 on port {r.get('port')}",
                    evidence=[f"Feodo Tracker status {r.get('status')}, last online {r.get('last_online')}"],
                )
            )
        _confidence(repo, repo.get_observable_by_id(obs.id) or obs)
        res.imported += 1
    return res


# ----------------------------------------------------------------------- URLhaus
def parse_urlhaus_csv(text: str) -> list[dict[str, str]]:
    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    cols = [
        "id",
        "dateadded",
        "url",
        "url_status",
        "last_online",
        "threat",
        "tags",
        "urlhaus_link",
        "reporter",
    ]
    return [dict(zip(cols, row, strict=False)) for row in csv.reader(io.StringIO("\n".join(lines)))]


def import_urlhaus(
    repo: Repository,
    rows: list[dict[str, str]],
    *,
    limit: int = 300,
    online_only: bool = True,
    family_aliases: dict[str, str] | None = None,
    now: datetime | None = None,
) -> FeedResult:
    now = now or utcnow()
    selected = [r for r in rows if not online_only or r.get("url_status") == "online"][:limit]
    res = FeedResult("urlhaus", records=len(selected))
    prov = _snapshot(
        repo,
        FEED_SOURCES["urlhaus"],
        f"URLhaus recent malware URLs, {len(selected)} of {len(rows)} (online_only={online_only})",
        now,
        {"selected": len(selected), "total": len(rows)},
    )
    aliases = family_aliases or {}
    for r in selected:
        try:
            url = normalize(ObservableType.URL, r.get("url", ""))
        except ValueError:
            res.skipped += 1
            continue
        if not validate(ObservableType.URL, url).actionable:
            res.skipped += 1
            continue
        added = _dt(r.get("dateadded")) or now
        last = _dt(r.get("last_online")) or added
        tags = [t.strip() for t in (r.get("tags") or "").split(",") if t.strip()]
        obs = repo.upsert_observable(
            Observable(
                type=ObservableType.URL,
                value=url,
                first_seen=added,
                last_seen=max(last, added),
                flags=["malware-download", r.get("url_status", "unknown")],
            ),
            prov,
        )
        # Tags are free-form: only link a family when a tag exactly names a known malware alias.
        for tag in tags:
            canonical = aliases.get(tag.lower())
            fam = repo.find_entity("malware", canonical) if canonical else None
            if fam:
                repo.upsert_relationship(
                    Relationship(
                        source_ref=obs.id,
                        target_ref=fam.id,
                        relationship_type="indicates",
                        confidence=70,
                        provenance=[prov],
                        description=f"URLhaus tag '{tag}'",
                        evidence=[f"URLhaus {r.get('urlhaus_link', '')}"],
                    )
                )
        _confidence(repo, repo.get_observable_by_id(obs.id) or obs)
        res.imported += 1
    return res


# ---------------------------------------------------------------- ATT&CK knowledge
ATTACK_TYPES = {
    "intrusion-set",
    "malware",
    "tool",
    "campaign",
    "attack-pattern",
    "identity",
    "marking-definition",
}
ATTACK_RELS = {"uses", "attributed-to"}


def attack_knowledge_subset(bundle: dict[str, Any]) -> dict[str, Any]:
    """Groups, software, campaigns and their uses/attributed-to relationships (current objects only)."""
    objs = [o for o in bundle.get("objects", []) if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    keep = {o["id"] for o in objs if o["type"] in ATTACK_TYPES}
    rels = [
        o
        for o in objs
        if o["type"] == "relationship"
        and o.get("relationship_type") in ATTACK_RELS
        and o["source_ref"] in keep
        and o["target_ref"] in keep
    ]
    return {
        "type": "bundle",
        "id": bundle.get("id", "bundle--attack"),
        "objects": [o for o in objs if o["id"] in keep] + rels,
    }


def import_attack_knowledge(repo: Repository, bundle: dict[str, Any]) -> FeedResult:
    from threatintel.stix.importer import StixImporter

    subset = attack_knowledge_subset(bundle)
    res = FeedResult("mitre-attack", records=len(subset["objects"]))
    importer = StixImporter(
        repo,
        source_id="src-mitre-attack",
        source_name="MITRE ATT&CK",
        reliability=SourceReliability.B,
        credibility=InformationCredibility.PROBABLY_TRUE,
        source_type=SourceType.MITRE,
    )
    repo.upsert_source(
        Source(
            id="src-mitre-attack",
            name="MITRE ATT&CK",
            source_type=SourceType.MITRE,
            reliability=SourceReliability.B,
            description="Curated public-reporting knowledge base (groups, software, campaigns).",
            collection_policy="ATT&CK Terms of Use",
        )
    )
    out = importer.import_bundle(subset)
    res.imported, res.entities = out.relationships, out.entities
    res.skipped = len(out.skipped)
    res.notes = out.skipped[:5]
    return res
