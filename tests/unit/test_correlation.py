from datetime import timedelta

import pytest

from threatintel.analysis.correlation import CorrelationEngine, Profile, noisy_or
from threatintel.models.common import utcnow


def test_noisy_or() -> None:
    assert noisy_or([]) == 0.0
    assert noisy_or([0.5, 0.5]) == pytest.approx(0.75)
    assert noisy_or([1.2]) == 1.0


def test_shared_hash_is_strong_and_explained() -> None:
    a = Profile("a", "A", hashes={"h1"})
    b = Profile("b", "B", hashes={"h1"})
    r = CorrelationEngine().compare(a, b)
    assert r.score >= 0.9
    assert "shared file hash" in r.explain()


def test_many_common_techniques_are_capped() -> None:
    techs = {f"T{1000 + i}" for i in range(40)}
    r = CorrelationEngine().compare(Profile("a", "A", techniques=techs), Profile("b", "B", techniques=techs))
    assert r.score <= 0.45 + 1e-9


def test_commodity_malware_is_weak() -> None:
    a = Profile("a", "A", malware={"Cobalt Strike"}, commodity_malware={"Cobalt Strike"})
    b = Profile("b", "B", malware={"Cobalt Strike"}, commodity_malware={"Cobalt Strike"})
    r = CorrelationEngine().compare(a, b)
    assert [s.name for s in r.signals] == ["shared_commodity_malware"]
    assert r.score < 0.2


def test_nameserver_matches_across_buckets() -> None:
    a = Profile("a", "A", domains={"ns1.host.example"})
    b = Profile("b", "B", nameservers={"ns1.host.example"})
    r = CorrelationEngine().compare(a, b)
    assert [s.name for s in r.signals] == ["shared_nameserver"]


def test_temporal_overlap_and_rank() -> None:
    now = utcnow()
    a = Profile("a", "A", ips={"1"}, start=now - timedelta(days=5), end=now)
    b = Profile("b", "B", ips={"1"}, start=now - timedelta(days=3), end=now)
    c = Profile("c", "C", start=now - timedelta(days=90), end=now - timedelta(days=80))
    eng = CorrelationEngine()
    assert "temporal_overlap" in {s.name for s in eng.compare(a, b).signals}
    ranked = eng.rank(a, [b, c, a])
    assert [r.candidate_id for r in ranked] == ["b"]
