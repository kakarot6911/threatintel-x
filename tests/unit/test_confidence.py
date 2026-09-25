from datetime import timedelta

import pytest

from threatintel.analysis.confidence import band, independent_origins, score_confidence
from threatintel.analysis.scoring_config import load_scoring
from threatintel.models.common import (
    ConfidenceLevel,
    InformationCredibility,
    ObservableType,
    Provenance,
    SourceReliability,
    SourceType,
    utcnow,
)

NOW = utcnow()


def prov(
    sid: str, rel: str = "B", cred: str = "2", derived: str | None = None, stype: SourceType = SourceType.RSS
) -> Provenance:
    return Provenance(
        source_id=sid,
        source_name=sid,
        source_type=stype,
        collected_at=NOW,
        reliability=SourceReliability(rel),
        credibility=InformationCredibility(cred),
        derived_from=derived,
    )


def test_weights_sum_to_one() -> None:
    assert sum(load_scoring()["confidence"]["weights"].values()) == pytest.approx(1.0)


def test_strong_corroborated_hash_is_high() -> None:
    r = score_confidence(
        [prov("a", "A", "1"), prov("b", "B", "2"), prov("c", "B", "2")],
        observable_type=ObservableType.SHA256,
        last_seen=NOW,
        technical_evidence=0.9,
        now=NOW,
    )
    assert r.level in (ConfidenceLevel.HIGH, ConfidenceLevel.VERY_HIGH)
    assert len(r.factors) == 6
    assert sum(f.contribution for f in r.factors) == pytest.approx(r.score, abs=0.1)
    assert all(f.explanation for f in r.factors)


def test_weak_single_stale_ip_is_low() -> None:
    r = score_confidence(
        [prov("x", "F", "6")],
        observable_type=ObservableType.IPV4,
        last_seen=NOW - timedelta(days=200),
        now=NOW,
    )
    assert r.level == ConfidenceLevel.LOW
    assert "Weakest" in r.explanation


def test_republished_source_is_not_corroboration() -> None:
    origins = independent_origins([prov("vendor"), prov("mirror", derived="vendor")])
    assert origins == {"vendor"}
    single = score_confidence([prov("vendor")], now=NOW)
    mirrored = score_confidence([prov("vendor"), prov("mirror", derived="vendor")], now=NOW)
    corr = {f.name: f.value for f in mirrored.factors}["corroboration"]
    assert corr == 0.0
    assert mirrored.score == pytest.approx(single.score)


def test_enrichment_is_not_reporting() -> None:
    r = score_confidence([prov("v"), prov("enrichment:rdap", stype=SourceType.ENRICHMENT)], now=NOW)
    assert {f.name: f.value for f in r.factors}["corroboration"] == 0.0


def test_bands() -> None:
    assert band(95) == ConfidenceLevel.VERY_HIGH
    assert band(70) == ConfidenceLevel.HIGH
    assert band(40) == ConfidenceLevel.MEDIUM
    assert band(39.9) == ConfidenceLevel.LOW
