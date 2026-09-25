from threatintel.analysis.attribution import AttributionEngine
from threatintel.analysis.correlation import Profile
from threatintel.models.common import AttributionLevel
from threatintel.models.intel import Evidence


def test_infrastructure_only_never_exceeds_low() -> None:
    subject = Profile(
        "s", "incident", ips={"a", "b", "c"}, domains={"d1", "d2"}, urls={"u"}, sources={"src1", "src2"}
    )
    actor = Profile("x", "ACTOR X", ips={"a", "b", "c"}, domains={"d1", "d2"}, urls={"u"})
    a = AttributionEngine().assess(subject, [actor])
    assert a.level in (AttributionLevel.LOW.value, AttributionLevel.INSUFFICIENT.value)
    assert a.score > 0.5  # strong overlap...
    assert any("infrastructure overlap only" in c for c in a.caveats)  # ...but explicitly not attribution


def test_high_requires_diverse_evidence_and_sources() -> None:
    subject = Profile(
        "s",
        "incident",
        hashes={"h"},
        domains={"d"},
        certificates={"c"},
        techniques={"T1", "T2", "T3", "T4"},
        malware={"FamilyX"},
        sources={"soc", "vendor"},
    )
    actor = Profile(
        "x",
        "ACTOR X",
        hashes={"h"},
        domains={"d"},
        certificates={"c"},
        techniques={"T1", "T2", "T3", "T4"},
        malware={"FamilyX"},
    )
    a = AttributionEngine().assess(subject, [actor])
    assert a.level == AttributionLevel.HIGH.value
    assert a.statement.startswith("We assess with HIGH confidence")

    single_source = Profile(**{**subject.__dict__, "sources": {"soc"}})
    b = AttributionEngine().assess(single_source, [actor])
    assert b.level != AttributionLevel.HIGH.value
    assert any("independent source" in c for c in b.caveats)


def test_competing_hypotheses_downgrade() -> None:
    subject = Profile("s", "incident", hashes={"h"}, malware={"F"}, domains={"d"}, sources={"a", "b"})
    x = Profile("x", "ACTOR X", hashes={"h"}, malware={"F"}, domains={"d"})
    y = Profile("y", "ACTOR Y", hashes={"h"}, malware={"F"}, domains={"d"})
    a = AttributionEngine().assess(subject, [x, y])
    assert any("Competing hypothesis" in c for c in a.caveats)
    assert {alt["actor"] for alt in a.alternatives} == {"ACTOR X", "ACTOR Y"}


def test_llm_evidence_is_not_scored() -> None:
    subject = Profile("s", "incident", sources={"a"})
    actor = Profile("x", "ACTOR X")
    llm = Evidence(
        type="public_reporting",
        weight=0.9,
        confidence=1.0,
        source="llm:any",
        description="model says ACTOR X",
        llm_generated=True,
        validated=False,
    )
    a = AttributionEngine().assess(subject, [actor], {"x": [llm]})
    assert a.level == AttributionLevel.INSUFFICIENT.value
    assert a.score == 0.0
    assert any("LLM-generated" in c for c in a.caveats)


def test_timing_alone_is_not_a_hypothesis() -> None:
    from threatintel.models.common import utcnow

    now = utcnow()
    subject = Profile("s", "incident", target_sectors={"technology"}, start=now, end=now, sources={"a"})
    actor = Profile("x", "ACTOR X", target_sectors={"technology"}, start=now, end=now)
    a = AttributionEngine().assess(subject, [actor])
    assert a.alternatives == []
    assert a.level == AttributionLevel.INSUFFICIENT.value
