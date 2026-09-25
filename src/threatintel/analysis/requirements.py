"""Answers the Intelligence Requirements (IR-001..IR-008) from the knowledge base.

Each answer is a structured, reproducible query - not free text - so a product that
cites an IR can show exactly which data answered it.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from threatintel.models.common import LifecycleStatus
from threatintel.models.entities import Campaign, IntelligenceRequirement, Malware, ThreatActor
from threatintel.platform import Platform


def _actors_targeting_sector(p: Platform) -> dict[str, Any]:
    sectors = set(p.settings.org_sectors)
    rows = []
    for a in p.repo.list_typed(ThreatActor):
        hits = sorted(set(a.target_sectors) & sectors)
        if hits:
            rows.append(
                {
                    "actor": a.name,
                    "sectors": hits,
                    "last_seen": a.last_seen.isoformat() if a.last_seen else None,
                    "motivation": a.motivation,
                    "synthetic": a.synthetic,
                }
            )
    rows.sort(key=lambda r: r["last_seen"] or "", reverse=True)
    return {"summary": f"{len(rows)} tracked actor(s) target {', '.join(sorted(sectors))}.", "rows": rows}


def _ransomware_new_infra(p: Platform) -> dict[str, Any]:
    rows = []
    for c in p.repo.list_typed(Campaign):
        uses_ransomware = any(
            isinstance(m := p.repo.get_entity(r.target_ref), Malware) and "ransomware" in m.malware_types
            for r in p.repo.list_relationships(source_ref=c.id, relationship_type="uses")
        )
        if not uses_ransomware:
            continue
        infra = []
        for r in p.repo.list_relationships(target_ref=c.id, relationship_type="indicates"):
            o = p.repo.get_observable_by_id(r.source_ref)
            if o and o.type.value in ("ipv4", "ipv6", "domain", "url"):
                infra.append({"value": o.value, "type": o.type.value, "first_seen": o.first_seen.isoformat()})
        infra.sort(key=lambda x: x["first_seen"], reverse=True)
        rows.append({"campaign": c.name, "status": c.campaign_status, "infrastructure": infra[:10]})
    return {"summary": f"{len(rows)} ransomware campaign(s) with linked infrastructure.", "rows": rows}


def _credential_exposure(p: Platform) -> dict[str, Any]:
    org = {d.lower() for d in p.settings.org_domains}
    rows = [r for r in p.repo.list_records("credential_exposure") if r.get("domain") in org]
    return {
        "summary": f"{len(rows)} exposed organisational account(s); no secrets are stored.",
        "rows": [
            {
                k: r.get(k)
                for k in (
                    "account",
                    "domain",
                    "source_id",
                    "discovered_at",
                    "confidence",
                    "potential_access",
                    "synthetic",
                )
            }
            for r in rows
        ],
    }


def _malware_for_iocs(p: Platform) -> dict[str, Any]:
    rows = []
    for m in p.repo.list_entities("malware"):
        samples = [
            p.repo.get_observable_by_id(r.source_ref)
            for r in p.repo.list_relationships(target_ref=m.id, relationship_type="indicates")
        ]
        vals = [s.value for s in samples if s]
        if vals:
            rows.append({"malware": m.name, "iocs": vals})
    return {"summary": f"{len(rows)} malware famil(ies) linked to observed IOCs.", "rows": rows}


def _actors_using_infra(p: Platform) -> dict[str, Any]:
    rows = []
    for a in p.repo.list_entities("threat-actor"):
        prof = p.profiles.actor(a)  # type: ignore[arg-type]
        infra = sorted(prof.infrastructure)
        if infra:
            rows.append({"actor": a.name, "infrastructure": infra[:15], "count": len(infra)})
    return {
        "summary": "Infrastructure associated with each actor via SOURCE-REPORTED campaigns "
        "(association, not ownership).",
        "rows": rows,
    }


def _attack_for_campaigns(p: Platform) -> dict[str, Any]:
    stix_to_tech = {t.stix_id: t for t in p.kb.techniques.values()}
    rows = []
    for c in p.repo.list_entities("campaign"):
        techs = sorted(
            {
                f"{stix_to_tech[r.target_ref].technique_id} {stix_to_tech[r.target_ref].name}"
                for r in p.repo.list_relationships(source_ref=c.id, relationship_type="uses")
                if r.target_ref in stix_to_tech
            }
        )
        rows.append({"campaign": c.name, "techniques": techs})
    return {
        "summary": f"ATT&CK {p.kb.domain} v{p.kb.version} mapping for {len(rows)} campaign(s).",
        "rows": rows,
    }


def _infra_overlap(p: Platform) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for a in p.repo.list_assessments("correlation"):
        item = p.repo.get_collected_item(a.subject_id)
        if item and a.score >= 0.5:
            rows.append(
                {
                    "item": item.title,
                    "best_match": a.alternatives[0]["campaign"] if a.alternatives else None,
                    "score": a.score,
                    "explanation": a.statement[:400],
                }
            )
    rows.sort(key=lambda r: -r["score"])
    return {"summary": f"{len(rows)} new item(s) overlap known campaigns (score >= 0.5).", "rows": rows}


def _review_queue(p: Platform) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for sid in p.repo.subjects_with_status([LifecycleStatus.UNDER_REVIEW]):
        item = p.repo.get_collected_item(sid)
        pr = p.repo.latest_assessment(sid, "priority")
        if item:
            rows.append(
                {
                    "id": sid,
                    "title": item.title,
                    "priority": pr.level if pr else "P5",
                    "source": item.source_name,
                    "synthetic": item.synthetic,
                }
            )
    rows.sort(key=lambda r: r["priority"])
    return {"summary": f"{len(rows)} item(s) await analyst review.", "rows": rows}


ANSWERERS: dict[str, Callable[[Platform], dict[str, Any]]] = {
    "IR-001": _actors_targeting_sector,
    "IR-002": _ransomware_new_infra,
    "IR-003": _credential_exposure,
    "IR-004": _malware_for_iocs,
    "IR-005": _actors_using_infra,
    "IR-006": _attack_for_campaigns,
    "IR-007": _infra_overlap,
    "IR-008": _review_queue,
}


def list_requirements(p: Platform) -> list[IntelligenceRequirement]:
    return sorted(
        (IntelligenceRequirement.model_validate(r) for r in p.repo.list_records("intelligence_requirement")),
        key=lambda r: r.id,
    )


def answer(p: Platform, ir_id: str) -> dict[str, Any]:
    fn = ANSWERERS.get(ir_id.upper())
    if fn is None:
        raise KeyError(ir_id)
    return {"requirement": ir_id.upper(), **fn(p)}
