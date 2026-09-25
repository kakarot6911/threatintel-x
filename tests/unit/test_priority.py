from threatintel.analysis.priority import PriorityInput, score_priority
from threatintel.models.common import Priority


def test_product_and_bands() -> None:
    low = score_priority(PriorityInput(impact_factors=[], confidence=0.3, recency=0.2))
    assert low.priority in (Priority.P4, Priority.P5)
    high = score_priority(
        PriorityInput(impact_factors=["ransomware"], confidence=0.9, recency=1.0, org_asset_match=True)
    )
    assert high.priority == Priority.P1
    assert any("product" in e for e in high.explanation)


def test_credential_escalation_requires_fresh_org_match() -> None:
    base = {
        "impact_factors": ["exposed_credential"],
        "confidence": 0.5,
        "recency": 0.3,
        "org_asset_match": True,
    }
    r = score_priority(PriorityInput(**base))
    assert r.priority in (Priority.P1, Priority.P2)
    stale = score_priority(PriorityInput(**{**base, "recency": 0.01}))
    assert not any("escalated" in e for e in stale.explanation)


def test_old_exploitation_report_not_escalated() -> None:
    r = score_priority(
        PriorityInput(
            impact_factors=["active_exploitation"], confidence=0.7, recency=0.004, sector_match=True
        )
    )
    assert r.priority == Priority.P5


def test_critical_cvss_raises_impact() -> None:
    r = score_priority(PriorityInput(impact_factors=[], confidence=0.8, recency=1.0, cvss=10.0))
    assert r.components["impact"] >= 0.75
