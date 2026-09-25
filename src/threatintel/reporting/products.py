"""Intelligence products: technical report, actor profile, campaign report, CISO brief, IOC bulletin.

All products are rendered from structured data with Jinja2 templates (Markdown). Every
product states its TLP, whether it contains synthetic data, its analytic standards and
that no LLM determined any judgement in it.
"""

from __future__ import annotations

import csv
import io
from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined

from threatintel.analysis.requirements import answer, list_requirements
from threatintel.models.common import PRIORITY_LABELS, LifecycleStatus, ObservableType, utcnow
from threatintel.models.entities import Campaign, IntelProduct, Malware, ThreatActor, Tool, Vulnerability
from threatintel.platform import Platform


def _md_safe(value: Any) -> Any:
    """Neutralise HTML in interpolated values: products are Markdown, which some consumers render
    to HTML - attacker-controlled CTI text (titles, IOCs, notes) must not become markup there."""
    if isinstance(value, str):
        return value.replace("<", "&lt;").replace(">", "&gt;")
    return value


# Markdown output: HTML autoescaping would corrupt it; _md_safe neutralises markup instead.
_env = Environment(  # nosec B701
    loader=PackageLoader("threatintel.reporting", "templates"),
    autoescape=False,  # noqa: S701
    finalize=_md_safe,
    trim_blocks=True,
    lstrip_blocks=True,
    undefined=StrictUndefined,
    keep_trailing_newline=True,
)

DETECTION_HINTS = {
    "T1566.001": "Detonate/inspect inbound Office & archive attachments; alert on Office spawning "
    "script hosts.",
    "T1566.002": "Rewrite/inspect URLs in mail; alert on first-seen domains in clicked links.",
    "T1566": "Mail gateway phishing detections; user reporting button telemetry.",
    "T1059.001": "PowerShell script-block logging (4104) and AMSI; alert on encoded commands.",
    "T1547.001": "Monitor Run/RunOnce registry keys and Startup folder writes.",
    "T1071.001": "Beacon detection on proxy logs (periodicity, rare user-agents, first-seen destinations).",
    "T1041": "Egress volume anomalies to C2 destinations.",
    "T1190": "WAF/IPS signatures for the exploited CVE; patch verification; anomalous child processes of "
    "edge services.",
    "T1105": "Alert on script hosts or edge devices downloading executables.",
    "T1555.003": "Monitor non-browser processes reading browser credential stores.",
    "T1539": "Detect session reuse from new ASN/geo; bind sessions to device where possible.",
    "T1102": "Flag non-browser processes contacting api.telegram.org or paste sites.",
    "T1583.001": "Monitor new registrations of look-alike domains of our brand.",
    "T1567.002": "Detect rclone/MEGA and bulk uploads to cloud storage.",
    "T1021.001": "Alert on RDP between workstations and from VPN pools to servers.",
    "T1486": "Canary files and mass-rename/entropy detections on file servers.",
    "T1490": "Alert on vssadmin/wbadmin/bcdedit recovery-inhibiting commands.",
    "T1133": "MFA on all remote access; alert on VPN logins from new ASNs/geo.",
    "T1078": "Impossible-travel and first-seen-device analytics for privileged accounts.",
    "T1003.001": "LSASS access auditing (Sysmon EID 10); enable Credential Guard / RunAsPPL.",
    "T1219": "Inventory and alert on unapproved remote-access tools.",
    "T1485": "Detect mass deletion; protect backups offline.",
    "T1561.002": "Alert on raw disk / MBR write attempts.",
    "T1657": "Finance process controls for extortion / payment fraud.",
}
IOC_HINTS = {
    "domain": "Block at DNS resolver / proxy; hunt DNS logs for historic resolutions.",
    "ipv4": "Block at egress firewall; hunt NetFlow/proxy logs (IPs churn - apply expiry).",
    "url": "Block at proxy; hunt proxy logs for exact URL and host.",
    "sha256": "Add to EDR block list; retro-hunt file telemetry.",
    "md5": "Retro-hunt only (MD5 is weak for blocking).",
    "email": "Block sender in mail gateway; hunt for delivered messages.",
}


class ProductBuilder:
    def __init__(self, platform: Platform) -> None:
        self.p = platform
        self.repo = platform.repo
        self._stix_to_tech = {t.stix_id: t for t in platform.kb.techniques.values()}

    # ------------------------------------------------------------------ data
    def _header(
        self, title: str, synthetic: bool, requirements: list[str], tlp: str = "amber"
    ) -> dict[str, Any]:
        return {
            "title": title,
            "tlp": tlp.upper(),
            "synthetic": synthetic,
            "generated": utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            "requirements": requirements,
            "producer": self.p.settings.producer_name,
            "attack_version": f"{self.p.kb.domain} v{self.p.kb.version}",
        }

    def _iocs_for(self, subject_id: str) -> list[dict[str, Any]]:
        rows = []
        for rel in self.repo.list_relationships(target_ref=subject_id, relationship_type="indicates"):
            obs = self.repo.get_observable_by_id(rel.source_ref)
            if obs is None:
                continue
            conf = self.repo.latest_assessment(obs.id, "confidence")
            rows.append(
                {
                    "type": obs.type.value,
                    "value": obs.value,
                    "confidence": conf.level if conf else "n/a",
                    "score": conf.score if conf else None,
                    "first_seen": obs.first_seen.date().isoformat(),
                    "last_seen": obs.last_seen.date().isoformat(),
                    "actionable": obs.actionable,
                    "sources": len({p.origin for p in obs.provenance}),
                    "synthetic": obs.synthetic,
                }
            )
        return sorted(rows, key=lambda r: (r["type"], r["value"]))

    def _techniques_for(self, subject_id: str) -> list[dict[str, Any]]:
        rows = []
        for rel in self.repo.list_relationships(source_ref=subject_id, relationship_type="uses"):
            t = self._stix_to_tech.get(rel.target_ref)
            if t:
                rows.append(
                    {
                        "id": t.technique_id,
                        "name": t.name,
                        "tactics": ", ".join(self.p.kb.tactic_name(x) for x in t.tactics),
                        "detection": DETECTION_HINTS.get(
                            t.technique_id, DETECTION_HINTS.get(t.parent_id, "See ATT&CK page.")
                        ),
                        "url": t.url,
                    }
                )
        return sorted(rows, key=lambda r: r["id"])

    def _entities_used(self, subject_id: str) -> dict[str, list[Any]]:
        out: dict[str, list[Any]] = {"malware": [], "tool": [], "vulnerability": []}
        for rel in self.repo.list_relationships(source_ref=subject_id):
            if rel.relationship_type not in ("uses", "exploits"):
                continue
            ent = self.repo.get_entity(rel.target_ref)
            if isinstance(ent, Malware):
                out["malware"].append(ent)
            elif isinstance(ent, Tool):
                out["tool"].append(ent)
            elif isinstance(ent, Vulnerability):
                out["vulnerability"].append(ent)
        return out

    def _sources_for(self, subject_ids: list[str]) -> list[dict[str, Any]]:
        seen: dict[str, dict[str, Any]] = {}
        for sid in subject_ids:
            for rel in self.repo.list_relationships(involving=sid):
                for p in self.repo.provenance_for(rel.id):
                    seen.setdefault(
                        p.source_id,
                        {
                            "name": p.source_name,
                            "reliability": p.reliability.value,
                            "credibility": p.credibility.value,
                            "independent_of": p.derived_from or "-",
                            "synthetic": p.synthetic,
                        },
                    )
        return sorted(seen.values(), key=lambda s: (s["reliability"], s["name"]))

    def _campaign_ctx(self, camp: Campaign) -> dict[str, Any]:
        attribution = self.repo.latest_assessment(camp.id, "attribution")
        used = self._entities_used(camp.id)
        reported = []
        for rel in self.repo.list_relationships(source_ref=camp.id, relationship_type="reported-attribution"):
            actor = self.repo.get_entity(rel.target_ref)
            for p in self.repo.provenance_for(rel.id):
                reported.append(
                    {
                        "actor": actor.name if actor else rel.target_ref,
                        "source": p.source_name,
                        "reliability": p.reliability.value,
                        "confidence": rel.confidence,
                    }
                )
        iocs = self._iocs_for(camp.id)
        techniques = self._techniques_for(camp.id)
        return {
            "campaign": camp,
            "attribution": attribution,
            "reported": reported,
            "iocs": iocs,
            "techniques": techniques,
            "malware": used["malware"],
            "tools": used["tool"],
            "vulnerabilities": used["vulnerability"],
            "sources": self._sources_for([camp.id]),
            "ioc_hints": sorted({(r["type"], IOC_HINTS[r["type"]]) for r in iocs if r["type"] in IOC_HINTS}),
            "infrastructure": [r for r in iocs if r["type"] in ("ipv4", "ipv6", "domain", "url")],
            "hashes": [r for r in iocs if r["type"] in ("md5", "sha1", "sha256")],
        }

    # -------------------------------------------------------------- products
    def technical_report(self, campaign_id: str) -> IntelProduct:
        camp = self._get(campaign_id, Campaign)
        ctx = {
            **self._header(
                f"Technical Intelligence Report - {camp.name}",
                camp.synthetic,
                ["IR-004", "IR-006", "IR-007"],
                camp.tlp.value,
            ),
            **self._campaign_ctx(camp),
        }
        return self._product("technical-report", ctx, "technical_report.md.j2", camp.id)

    def campaign_report(self, campaign_id: str) -> IntelProduct:
        camp = self._get(campaign_id, Campaign)
        ctx = {
            **self._header(
                f"Campaign Report - {camp.name}",
                camp.synthetic,
                ["IR-002", "IR-005", "IR-007"],
                camp.tlp.value,
            ),
            **self._campaign_ctx(camp),
        }
        timeline = []
        if camp.start_date:
            timeline.append((camp.start_date.date().isoformat(), "Campaign activity begins (reported)"))
        for rel in self.repo.list_relationships(target_ref=camp.id, relationship_type="indicates"):
            for p in self.repo.provenance_for(rel.id):
                if p.collected_item_id:
                    item = self.repo.get_collected_item(p.collected_item_id)
                    if item:
                        when = (item.published_at or item.collection_timestamp).date().isoformat()
                        timeline.append((when, f"Reported: {item.title} ({item.source_name})"))
        if camp.end_date:
            timeline.append((camp.end_date.date().isoformat(), "Last reported activity"))
        ctx["timeline"] = sorted(set(timeline))
        related = []
        subject = self.p.profiles.campaign(camp)
        subject.names = set()
        others = [pr for pr in self.p.profiles.all_campaign_profiles() if pr.subject_id != camp.id]
        for r in self.p.correlation.rank(subject, others, min_score=0.2)[:5]:
            related.append(
                {
                    "campaign": r.candidate_label,
                    "score": r.score,
                    "why": "; ".join(s.explanation for s in r.signals[:4]),
                }
            )
        ctx["related"] = related
        return self._product("campaign-report", ctx, "campaign_report.md.j2", camp.id)

    def actor_profile(self, actor_id: str) -> IntelProduct:
        actor = self._get(actor_id, ThreatActor)
        campaigns = []
        for cid in self.p.profiles.campaigns_of(actor.id):
            c = self.repo.get_entity(cid)
            if isinstance(c, Campaign):
                a = self.repo.latest_assessment(c.id, "attribution")
                campaigns.append(
                    {
                        "name": c.name,
                        "status": c.campaign_status,
                        "start": c.start_date.date().isoformat() if c.start_date else "?",
                        "assessment": a.level if a else "not assessed",
                        "assessed_actor": a.alternatives[0]["actor"] if a and a.alternatives else "-",
                    }
                )
        profile = self.p.profiles.actor(actor)
        techniques = sorted(profile.techniques)
        tech_rows = [
            {"id": t, "name": self.p.kb.techniques[t].name} for t in techniques if t in self.p.kb.techniques
        ]
        humint = [
            h for h in self.repo.list_records("humint_report") if actor.name.lower() in h["raw_note"].lower()
        ]
        ctx = {
            **self._header(
                f"Threat Actor Profile - {actor.name}", actor.synthetic, ["IR-001", "IR-005"], actor.tlp.value
            ),
            "actor": actor,
            "campaigns": campaigns,
            "techniques": tech_rows,
            "malware": sorted(profile.malware),
            "commodity": sorted(profile.commodity_malware),
            "infrastructure": sorted(profile.infrastructure)[:25],
            "infrastructure_total": len(profile.infrastructure),
            "humint": humint,
            "sources": self._sources_for([actor.id, *self.p.profiles.campaigns_of(actor.id)]),
        }
        return self._product("actor-profile", ctx, "actor_profile.md.j2", actor.id)

    def ciso_brief(self) -> IntelProduct:
        queue = answer(self.p, "IR-008")["rows"]
        top = [r for r in queue if r["priority"] in ("P1", "P2")]
        creds = answer(self.p, "IR-003")
        actors = answer(self.p, "IR-001")
        ransomware = self.repo.list_records("ransomware_claim")
        sector_claims = [r for r in ransomware if r["victim_sector"] in self.p.settings.org_sectors]
        synthetic = (
            any(r["synthetic"] for r in top)
            or bool(ransomware)
            or any(a["synthetic"] for a in actors["rows"])
        )
        ctx = {
            **self._header(
                "CISO Threat Brief", synthetic, [r.id for r in list_requirements(self.p)], "amber"
            ),
            "org": self.p.settings.org_name,
            "top": top,
            "queue_total": len(queue),
            "creds": creds,
            "actors": actors["rows"][:5],
            "ransomware_total": len(ransomware),
            "sector_claims": sector_claims,
            "priority_labels": PRIORITY_LABELS,
        }
        return self._product("ciso-brief", ctx, "ciso_brief.md.j2", None)

    def ioc_bulletin(self, min_score: float = 40.0) -> tuple[IntelProduct, str]:
        rows: list[dict[str, Any]] = []
        for obs in self.repo.list_observables(limit=100_000, actionable_only=True):
            if obs.type in (ObservableType.CVE, ObservableType.ATTACK_TECHNIQUE, ObservableType.ASN):
                continue
            conf = self.repo.latest_assessment(obs.id, "confidence")
            if conf is None or conf.score < min_score:
                continue
            status = self.repo.get_status(obs.id) or LifecycleStatus.NEW
            rows.append(
                {
                    "type": obs.type.value,
                    "value": obs.value,
                    "confidence": conf.level,
                    "score": conf.score,
                    "first_seen": obs.first_seen.date().isoformat(),
                    "last_seen": obs.last_seen.date().isoformat(),
                    "status": status.value,
                    "synthetic": obs.synthetic,
                }
            )
        rows.sort(key=lambda r: (-r["score"], r["type"], r["value"]))
        synthetic = any(r["synthetic"] for r in rows)
        ctx = {
            **self._header("IOC Bulletin", synthetic, ["IR-004", "IR-007"], "amber"),
            "rows": rows,
            "min_score": min_score,
        }
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf,
            fieldnames=[
                "type",
                "value",
                "confidence",
                "score",
                "first_seen",
                "last_seen",
                "status",
                "synthetic",
            ],
        )
        writer.writeheader()
        for r in rows:
            writer.writerow({k: _csv_safe(v) for k, v in r.items()})
        return self._product("ioc-bulletin", ctx, "ioc_bulletin.md.j2", None), buf.getvalue()

    # ----------------------------------------------------------------- utils
    def _get(self, entity_id: str, cls: type[Any]) -> Any:
        ent = self.repo.get_entity(entity_id) or self.repo.find_entity(cls.entity_type, entity_id)
        if not isinstance(ent, cls):
            raise KeyError(f"{cls.__name__} {entity_id!r} not found")
        return ent

    def _product(self, kind: str, ctx: dict[str, Any], template: str, subject_id: str | None) -> IntelProduct:
        body = _env.get_template(template).render(**ctx)
        product = IntelProduct(
            kind=kind,
            title=ctx["title"],
            subject_id=subject_id,
            body_markdown=body,
            requirements=ctx["requirements"],
            contains_synthetic=ctx["synthetic"],
        )
        self.repo.put_record(
            "product", product.id, product.model_dump(mode="json"), synthetic=ctx["synthetic"]
        )
        return product


def _csv_safe(value: Any) -> Any:
    """Neutralise spreadsheet formula injection (CSV injection) from attacker-controlled IOC values."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value
