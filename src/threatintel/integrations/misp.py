"""MISP integration (PyMISP) using MISP's own data model and taxonomies.

Mapping:
  campaign              -> MISP event
  observables           -> MISP attributes (typed, categorised, to_ids by confidence)
  actor / ATT&CK        -> galaxy cluster tags (misp-galaxy:threat-actor, misp-galaxy:mitre-attack-pattern)
  confidence / sources  -> admiralty-scale + estimative-language taxonomy tags
  TLP / workflow        -> tlp: and workflow: taxonomy tags
"""

from __future__ import annotations

from typing import Any

from pymisp import MISPEvent

from threatintel.attack.knowledge_base import AttackKnowledgeBase
from threatintel.config import Settings, get_settings
from threatintel.models.common import ObservableType
from threatintel.models.entities import Campaign
from threatintel.net import assert_safe_destination, require_online
from threatintel.storage.repository import Repository

ATTRIBUTE_MAP: dict[ObservableType, tuple[str, str]] = {
    ObservableType.IPV4: ("ip-dst", "Network activity"),
    ObservableType.IPV6: ("ip-dst", "Network activity"),
    ObservableType.DOMAIN: ("domain", "Network activity"),
    ObservableType.URL: ("url", "Network activity"),
    ObservableType.EMAIL: ("email-src", "Payload delivery"),
    ObservableType.MD5: ("md5", "Payload delivery"),
    ObservableType.SHA1: ("sha1", "Payload delivery"),
    ObservableType.SHA256: ("sha256", "Payload delivery"),
    ObservableType.BTC_ADDRESS: ("btc", "Financial fraud"),
    ObservableType.CVE: ("vulnerability", "External analysis"),
}
LIKELIHOOD = {"HIGH": "very-likely", "MEDIUM": "likely", "LOW": "roughly-even-chance"}
TLP_TAG = {"clear": "tlp:clear", "green": "tlp:green", "amber": "tlp:amber", "red": "tlp:red"}


def campaign_to_event(repo: Repository, kb: AttackKnowledgeBase, campaign: Campaign) -> MISPEvent:
    ev = MISPEvent()
    ev.info = f"{campaign.name}{' [SYNTHETIC]' if campaign.synthetic else ''}"
    ev.distribution = 0  # this organisation only - widening distribution is an analyst decision
    ev.threat_level_id = 2
    ev.analysis = 2 if campaign.campaign_status == "concluded" else 1
    ev.add_tag(TLP_TAG[campaign.tlp.value])
    ev.add_tag('workflow:state="incomplete"')
    if campaign.synthetic:
        ev.add_tag("threatintel-x:synthetic")

    best_rel = None
    for rel in repo.list_relationships(target_ref=campaign.id, relationship_type="indicates"):
        obs = repo.get_observable_by_id(rel.source_ref)
        if obs is None or obs.type not in ATTRIBUTE_MAP:
            continue
        mtype, category = ATTRIBUTE_MAP[obs.type]
        conf = repo.latest_assessment(obs.id, "confidence")
        score = conf.score if conf else rel.confidence
        attr = ev.add_attribute(
            mtype,
            obs.value,
            category=category,
            to_ids=bool(obs.actionable and score >= 40),
            comment=f"confidence {score:.0f}/100; sources: "
            f"{', '.join(sorted({p.source_name for p in obs.provenance}))[:200]}",
        )
        for p in obs.provenance:
            if best_rel is None or p.reliability.value < best_rel.reliability.value:
                best_rel = p
        if obs.synthetic:
            for a in attr if isinstance(attr, list) else [attr]:
                a.add_tag("threatintel-x:synthetic")
    for rel in repo.list_relationships(source_ref=campaign.id, relationship_type="exploits"):
        vuln = repo.get_entity(rel.target_ref)
        if vuln:
            ev.add_attribute("vulnerability", vuln.name, category="External analysis", to_ids=False)
    if best_rel is not None:
        ev.add_tag(f'admiralty-scale:source-reliability="{best_rel.reliability.value.lower()}"')
        ev.add_tag(f'admiralty-scale:information-credibility="{best_rel.credibility.value}"')

    attribution = repo.latest_assessment(campaign.id, "attribution")
    if attribution and attribution.level in LIKELIHOOD and attribution.alternatives:
        ev.add_tag(f'misp-galaxy:threat-actor="{attribution.alternatives[0]["actor"]}"')
        ev.add_tag(f'estimative-language:likelihood-probability="{LIKELIHOOD[attribution.level]}"')
    stix_to_tech = {t.stix_id: t for t in kb.techniques.values()}
    for rel in repo.list_relationships(source_ref=campaign.id, relationship_type="uses"):
        tech = stix_to_tech.get(rel.target_ref)
        if tech:
            ev.add_tag(f'misp-galaxy:mitre-attack-pattern="{tech.name} - {tech.technique_id}"')
    return ev


class MISPAdapter:
    def __init__(
        self,
        url: str,
        key: str,
        verify_tls: bool = True,
        settings: Settings | None = None,
        client: Any = None,
    ) -> None:
        self.url = url
        self.key = key
        self.verify_tls = verify_tls
        self.settings = settings or get_settings()
        self._client = client

    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> MISPAdapter:
        s = settings or get_settings()
        if not s.misp_url or not s.misp_key.get_secret_value():
            raise RuntimeError("MISP not configured (TIX_MISP_URL / TIX_MISP_KEY)")
        return cls(s.misp_url, s.misp_key.get_secret_value(), s.misp_verify_tls, s)

    @property
    def client(self) -> Any:
        if self._client is None:
            require_online(self.settings)
            assert_safe_destination(self.url, self.settings)
            from pymisp import PyMISP

            self._client = PyMISP(
                self.url,
                self.key,
                ssl=self.verify_tls,
                timeout=self.settings.http_timeout_seconds,
                tool="THREATINTEL-X",
            )
        return self._client

    def push_event(self, event: MISPEvent) -> dict[str, Any]:
        result = self.client.add_event(event, pythonify=False)
        if isinstance(result, dict) and result.get("errors"):
            raise RuntimeError(f"MISP rejected event: {result['errors']}")
        return dict(result)

    def search_events(self, **kwargs: Any) -> list[dict[str, Any]]:
        result = self.client.search(controller="events", pythonify=False, **kwargs)
        if isinstance(result, dict) and result.get("errors"):
            raise RuntimeError(f"MISP search failed: {result['errors']}")
        return list(result)

    def tag_event(self, event_uuid: str, tag: str) -> None:
        self.client.tag(event_uuid, tag)
