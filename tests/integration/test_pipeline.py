"""End-to-end vertical slice on the synthetic world: collection -> ... -> assessment."""

from sqlalchemy import text

from tests.conftest import NOW
from threatintel.models.common import LifecycleStatus, ObservableType
from threatintel.platform import Platform
from threatintel.workflows import ingest_text, run_demo


def _item(p: Platform, title_prefix: str):  # type: ignore[no-untyped-def]
    return next(i for i in p.repo.list_collected_items(limit=500) if i.title.startswith(title_prefix))


def test_soc_ransomware_incident_is_p1_with_medium_association(demo_platform: Platform) -> None:
    p = demo_platform
    item = _item(p, "SOC incident INC-SYN-0042")
    assert p.repo.latest_assessment(item.id, "priority").level == "P1"
    attribution = p.repo.latest_assessment(item.id, "attribution")
    assert attribution.level == "MEDIUM"
    assert attribution.alternatives[0]["actor"] == "HOLLOW KESTREL"
    assert attribution.alternatives[1]["actor"] == "VANTA MOTH"  # competing hypothesis is reported
    assert p.repo.get_status(item.id) == LifecycleStatus.UNDER_REVIEW
    corr = p.repo.latest_assessment(item.id, "correlation")
    assert corr.alternatives[0]["campaign"] == "KestrelLock Wave Two"


def test_ambiguous_campaign_stays_unresolved(demo_platform: Platform) -> None:
    camp = demo_platform.repo.find_entity("campaign", "Midnight Relay")
    a = demo_platform.repo.latest_assessment(camp.id, "attribution")
    assert a.level in ("INSUFFICIENT EVIDENCE", "LOW")
    assert not demo_platform.repo.list_relationships(source_ref=camp.id, relationship_type="attributed-to")


def test_well_evidenced_campaign_is_high(demo_platform: Platform) -> None:
    camp = demo_platform.repo.find_entity("campaign", "Operation Paper Lantern")
    a = demo_platform.repo.latest_assessment(camp.id, "attribution")
    assert a.level == "HIGH" and a.alternatives[0]["actor"] == "CRIMSON TAPIR"
    assert demo_platform.repo.list_relationships(source_ref=camp.id, relationship_type="attributed-to")


def test_unattributed_cluster_is_not_forced(demo_platform: Platform) -> None:
    camp = demo_platform.repo.find_entity("campaign", "HollowBot Spray")
    assert demo_platform.repo.latest_assessment(camp.id, "attribution").level == "INSUFFICIENT EVIDENCE"


def test_no_plaintext_secret_is_persisted(demo_platform: Platform) -> None:
    with demo_platform.repo.engine.connect() as conn:
        dump = " ".join(
            str(row)
            for table in (
                "collected_items",
                "records",
                "observables",
                "provenance",
                "entities",
                "assessments",
                "relationships",
            )
            for row in conn.execute(text(f"SELECT * FROM {table}"))  # noqa: S608 - fixed table names
        )
    for secret in ("Summer2024!", "Qwerty!234", "P@ssw0rd99", "letmein1", "Winter2025!"):
        assert secret not in dump
    exposures = demo_platform.repo.list_records("credential_exposure")
    assert {e["account"] for e in exposures} >= {"j.doe@examplecorp.example", "a.khan@examplecorp.example"}
    assert all(e["credential_present"] for e in exposures)


def test_republished_source_is_not_independent(demo_platform: Platform) -> None:
    obs = demo_platform.repo.get_observable(ObservableType.DOMAIN, "cdn-lantern.example")
    origins = {p.origin for p in obs.provenance if p.source_type.value != "enrichment"}
    assert origins == {"src-syn-vendor-alpha"}  # the mirror derives from Vendor Alpha


def test_synthetic_marking_everywhere(demo_platform: Platform) -> None:
    for obs in demo_platform.repo.list_observables(limit=10_000):
        if obs.type in (ObservableType.CVE, ObservableType.ATTACK_TECHNIQUE):
            continue
        assert obs.synthetic, obs.value
    for item in demo_platform.repo.list_collected_items(limit=10_000):
        assert item.synthetic


def test_demo_is_idempotent(platform: Platform) -> None:
    first = run_demo(platform, now=NOW)
    second = run_demo(platform, now=NOW)
    assert second.duplicates == second.items == first.items
    assert second.observables == first.observables


def test_real_world_text_flows_without_synthetic_leakage(platform: Platform) -> None:
    res = ingest_text(
        platform,
        "Analyst note",
        "Beacon to hxxp://198.51.100.200/gate.php and "
        "evil-update[.]com, sample 44d88ab8e2a5e5a4b8f1c6f2d3e4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c",
        reliability="C",
        credibility="3",
    )
    assert not res.duplicate and res.priority and res.confidence
    obs = platform.repo.get_observable(ObservableType.DOMAIN, "evil-update.com")
    assert obs and not obs.synthetic and obs.actionable
    doc_ip = platform.repo.get_observable(ObservableType.IPV4, "198.51.100.200")
    assert doc_ip and not doc_ip.actionable  # documentation IP in REAL text is not an IOC
    assert ingest_text(
        platform,
        "Analyst note",
        "Beacon to hxxp://198.51.100.200/gate.php and "
        "evil-update[.]com, sample 44d88ab8e2a5e5a4b8f1c6f2d3e4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c",
    ).duplicate
