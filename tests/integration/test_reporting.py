import pytest

from threatintel.analysis.requirements import ANSWERERS, answer
from threatintel.platform import Platform
from threatintel.reporting.products import ProductBuilder


def test_all_products_render(demo_platform: Platform) -> None:
    b = ProductBuilder(demo_platform)
    camp = demo_platform.repo.find_entity("campaign", "KestrelLock Wave Two")
    actor = demo_platform.repo.find_entity("threat-actor", "VANTA MOTH")
    products = [
        b.technical_report(camp.id),
        b.campaign_report(camp.name),
        b.actor_profile(actor.id),
        b.ciso_brief(),
        b.ioc_bulletin()[0],
    ]
    for prod in products:
        md = prod.body_markdown
        assert md.startswith("# ")
        assert "TLP:AMBER" in md
        assert "SYNTHETIC DATA NOTICE" in md and prod.contains_synthetic
        assert "No LLM determined any judgement" in md
        assert prod.requirements
    tech = products[0].body_markdown
    for section in (
        "Executive summary",
        "Indicators of compromise",
        "TTPs (MITRE ATT&CK)",
        "Evidence",
        "Confidence",
        "Detection opportunities",
        "Recommended actions",
        "Sources",
    ):
        assert f"## {section}" in tech
    assert "Alternative hypotheses considered" in tech
    ciso = products[3].body_markdown
    assert "Summer2024!" not in ciso and "redacted at collection" in ciso
    assert "Mimikatz" not in products[0].body_markdown or "commodity" in products[0].body_markdown


def test_products_are_stored(demo_platform: Platform) -> None:
    ProductBuilder(demo_platform).ciso_brief()
    assert demo_platform.repo.list_records("product")


def test_unknown_subject_raises(demo_platform: Platform) -> None:
    with pytest.raises(KeyError):
        ProductBuilder(demo_platform).technical_report("campaign--missing")


@pytest.mark.parametrize("ir", sorted(ANSWERERS))
def test_every_requirement_answers(demo_platform: Platform, ir: str) -> None:
    a = answer(demo_platform, ir)
    assert a["requirement"] == ir and a["summary"]
    assert isinstance(a["rows"], list)


def test_requirement_content(demo_platform: Platform) -> None:
    assert {r["actor"] for r in answer(demo_platform, "IR-001")["rows"]} >= {"CRIMSON TAPIR", "GLASS MANTIS"}
    assert all(r["domain"] == "examplecorp.example" for r in answer(demo_platform, "IR-003")["rows"])
    assert answer(demo_platform, "IR-008")["rows"][0]["priority"] == "P1"


def test_markdown_products_neutralise_html() -> None:
    from threatintel.reporting.products import _env

    out = _env.from_string("{{ v }} {{ n }}").render(v="<img src=x onerror=alert(1)>", n=5)
    assert out == "&lt;img src=x onerror=alert(1)&gt; 5"
