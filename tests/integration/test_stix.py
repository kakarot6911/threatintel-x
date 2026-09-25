import json

from threatintel.platform import Platform
from threatintel.stix.export import export_stix_bundle, pattern_for
from threatintel.stix.importer import import_stix_bundle
from threatintel.stix.validate import validate_bundle
from threatintel.storage.repository import Repository


def test_bundle_is_valid_and_complete(demo_platform: Platform) -> None:
    b = export_stix_bundle(demo_platform.repo, demo_platform.kb, demo_platform.settings)
    assert validate_bundle(b) == []
    types = {o["type"] for o in b["objects"]}
    assert {
        "intrusion-set",
        "threat-actor",
        "campaign",
        "malware",
        "tool",
        "vulnerability",
        "indicator",
        "attack-pattern",
        "relationship",
        "report",
        "note",
        "opinion",
        "identity",
        "location",
        "marking-definition",
    } <= types
    for o in b["objects"]:
        assert o.get("spec_version", "2.1") == "2.1"


def test_synthetic_objects_are_labelled_and_filterable(demo_platform: Platform) -> None:
    b = export_stix_bundle(demo_platform.repo, demo_platform.kb, demo_platform.settings)
    actors = [o for o in b["objects"] if o["type"] in ("intrusion-set", "threat-actor")]
    assert actors and all("synthetic" in o["labels"] and o["x_threatintel_synthetic"] for o in actors)
    real = export_stix_bundle(
        demo_platform.repo, demo_platform.kb, demo_platform.settings, include_synthetic=False
    )
    assert validate_bundle(real) == []
    assert not any(o.get("x_threatintel_synthetic") for o in real["objects"])


def test_attribution_claims_vs_assessments(demo_platform: Platform) -> None:
    b = export_stix_bundle(demo_platform.repo, demo_platform.kb, demo_platform.settings)
    rels = [
        o for o in b["objects"] if o["type"] == "relationship" and o["relationship_type"] == "attributed-to"
    ]
    producer = next(o["id"] for o in b["objects"] if o["type"] == "identity" and o["name"] == "THREATINTEL-X")
    claimed = [r for r in rels if r["created_by_ref"] != producer]
    assessed = [r for r in rels if r["created_by_ref"] == producer]
    assert claimed and assessed
    assert all("REPORTED" in r["description"] for r in claimed)


def test_attack_patterns_keep_mitre_ids(demo_platform: Platform) -> None:
    b = export_stix_bundle(demo_platform.repo, demo_platform.kb, demo_platform.settings)
    aps = [o for o in b["objects"] if o["type"] == "attack-pattern"]
    ids = {t.stix_id for t in demo_platform.kb.techniques.values()}
    assert aps and all(o["id"] in ids for o in aps)


def test_pattern_escaping() -> None:
    from threatintel.models.common import ObservableType
    from threatintel.models.intel import Observable

    o = Observable(type=ObservableType.URL, value="http://x.example/a'b\\c")
    assert pattern_for(o) == "[url:value = 'http://x.example/a\\'b\\\\c']"


def test_roundtrip_and_claims_stay_claims(demo_platform: Platform) -> None:
    b = export_stix_bundle(demo_platform.repo, demo_platform.kb, demo_platform.settings)
    fresh = Repository.from_url("sqlite://")
    res = import_stix_bundle(fresh, json.loads(json.dumps(b)))
    assert res.skipped == []
    assert res.entities == len(demo_platform.repo.list_entities())
    types = {r.relationship_type for r in fresh.list_relationships()}
    assert "attributed-to" not in types and "reported-attribution" in types


def test_invalid_objects_are_skipped_not_imported(repo: Repository) -> None:
    bundle = {
        "type": "bundle",
        "id": "bundle--0",
        "objects": [
            {"type": "indicator", "spec_version": "2.1", "id": "indicator--not-a-uuid", "pattern": "[x]"},
            {
                "type": "malware",
                "spec_version": "2.1",
                "id": "malware--2f8b2d25-9a4f-4a3a-9a47-5c0f1cfb1f0e",
                "created": "2024-01-01T00:00:00Z",
                "modified": "2024-01-01T00:00:00Z",
                "name": "OK",
                "is_family": True,
            },
        ],
    }
    res = import_stix_bundle(repo, bundle)
    assert res.entities == 1 and len(res.skipped) == 1
    assert validate_bundle(
        {
            "type": "bundle",
            "objects": [{"type": "relationship", "id": "relationship--x", "source_ref": "a--b"}],
        }
    )
