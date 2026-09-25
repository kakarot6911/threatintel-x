import json
from typing import Any

import pytest

from threatintel.integrations.misp import MISPAdapter, campaign_to_event
from threatintel.integrations.opencti import OpenCTIAdapter
from threatintel.platform import Platform
from threatintel.stix.export import export_stix_bundle


def test_misp_event_mapping(demo_platform: Platform) -> None:
    camp = demo_platform.repo.find_entity("campaign", "Stolen Keys")
    ev = json.loads(campaign_to_event(demo_platform.repo, demo_platform.kb, camp).to_json())
    tags = {t["name"] for t in ev["Tag"]}
    assert ev["info"].endswith("[SYNTHETIC]") and ev["distribution"] == "0"
    assert {"tlp:amber", "threatintel-x:synthetic", 'misp-galaxy:threat-actor="GLASS MANTIS"'} <= tags
    assert any(t.startswith("admiralty-scale:source-reliability=") for t in tags)
    assert any(
        t.startswith('misp-galaxy:mitre-attack-pattern="Spearphishing Link - T1566.002"') for t in tags
    )
    types = {a["type"] for a in ev["Attribute"]}
    assert {"domain", "url", "sha256"} <= types


def test_unattributed_campaign_gets_no_actor_galaxy(demo_platform: Platform) -> None:
    camp = demo_platform.repo.find_entity("campaign", "HollowBot Spray")
    ev = json.loads(campaign_to_event(demo_platform.repo, demo_platform.kb, camp).to_json())
    assert not any(t["name"].startswith("misp-galaxy:threat-actor") for t in ev["Tag"])


class FakeMISP:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def add_event(self, event: Any, pythonify: bool = False) -> dict[str, Any]:
        self.events.append(event)
        return {"Event": {"id": "1"}}

    def search(self, **kwargs: Any) -> list[dict[str, Any]]:
        return [{"Event": {"info": "x"}}]


def test_misp_adapter_with_fake_client(demo_platform: Platform) -> None:
    fake = FakeMISP()
    adapter = MISPAdapter("https://misp.example", "key", client=fake)
    camp = demo_platform.repo.find_entity("campaign", "Cookie Jar")
    assert (
        adapter.push_event(campaign_to_event(demo_platform.repo, demo_platform.kb, camp))["Event"]["id"]
        == "1"
    )
    assert adapter.search_events(value="x")[0]["Event"]["info"] == "x"
    with pytest.raises(RuntimeError, match="not configured"):
        MISPAdapter.from_settings(demo_platform.settings)


class FakeOpenCTI:
    class stix2:
        pushed: list[str] = []

        @classmethod
        def import_bundle_from_json(cls, data: str, update: bool = False) -> list[dict[str, Any]]:
            cls.pushed.append(data)
            return [{"id": "x"}]

    def health_check(self) -> bool:
        return True


def test_opencti_adapter(demo_platform: Platform) -> None:
    adapter = OpenCTIAdapter("https://octi.example", "t", client=FakeOpenCTI())
    assert adapter.health()
    bundle = export_stix_bundle(demo_platform.repo, demo_platform.kb, demo_platform.settings)
    assert adapter.push_bundle(bundle)["pushed_objects"] == len(bundle["objects"])
    with pytest.raises(ValueError, match="invalid bundle"):
        adapter.push_bundle(
            {"type": "bundle", "objects": [{"type": "relationship", "id": "relationship--1"}]}
        )
