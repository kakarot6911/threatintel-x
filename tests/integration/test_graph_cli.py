import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from threatintel.graph.graph import build_graph, neighborhood, pivot, render_svg
from threatintel.models.common import ObservableType
from threatintel.platform import Platform


def test_graph_pivot_and_svg(demo_platform: Platform) -> None:
    g = build_graph(demo_platform.repo, demo_platform.kb)
    obs = demo_platform.repo.get_observable(ObservableType.DOMAIN, "sso-examplecorp.example")
    paths = pivot(g, obs.id)
    assert paths and paths[0][0]["id"] == obs.id
    ends = {p[-1]["label"] for p in paths if p[-1]["kind"] == "threat-actor"}
    assert "GLASS MANTIS" in ends
    assert len({tuple(n["id"] for n in p) for p in paths}) == len(paths)
    actor = demo_platform.repo.find_entity("threat-actor", "GLASS MANTIS")
    svg = render_svg(neighborhood(g, actor.id), actor.id)
    assert svg.startswith("<svg") and "GLASS MANTIS" in svg
    assert pivot(g, "missing") == [] and render_svg(g, "missing") == ""


def test_svg_escapes_labels() -> None:
    import networkx as nx

    g = nx.MultiDiGraph()
    g.add_node("a", kind="threat-actor", label="<script>x</script>", synthetic=False)
    g.add_node("b", kind="campaign", label="b&c", synthetic=False)
    g.add_edge("a", "b", key="uses", rel="uses", label="USES", confidence=50)
    svg = render_svg(g, "a")
    assert "<script>" not in svg and "&lt;script&gt;" in svg and "b&amp;c" in svg


@pytest.fixture
def cli_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from threatintel.config import get_settings

    monkeypatch.setenv("TIX_DATABASE_URL", f"sqlite:///{tmp_path / 'cli.db'}")
    monkeypatch.setenv("TIX_LOG_JSON", "false")
    monkeypatch.setenv("TIX_LOG_LEVEL", "WARNING")
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


def test_cli_end_to_end(cli_env: Path) -> None:
    from threatintel.cli import app

    runner = CliRunner()
    r = runner.invoke(app, ["demo"])
    assert r.exit_code == 0, r.output
    assert json.loads(r.output)["items"] >= 20
    out = cli_env / "bundle.json"
    r = runner.invoke(app, ["export-stix", "--out", str(out)])
    assert r.exit_code == 0 and "validation errors: 0" in r.output
    r = runner.invoke(app, ["report", "ciso-brief"])
    assert r.exit_code == 0 and "CISO Threat Brief" in r.output
    r = runner.invoke(app, ["report", "technical-report", "--subject", "Stolen Keys"])
    assert r.exit_code == 0 and "Stolen Keys" in r.output
    r = runner.invoke(app, ["investigate", "192.0.2.52"])
    assert r.exit_code == 0 and json.loads(r.output)["found"]
    r = runner.invoke(app, ["requirement", "IR-003"])
    assert r.exit_code == 0
    r = runner.invoke(app, ["misp-push", "Stolen Keys", "--dry-run"])
    assert r.exit_code == 0 and "misp-galaxy" in r.output
    r = runner.invoke(app, ["opencti-push", "--dry-run"])
    assert r.exit_code == 0 and "would push" in r.output
    text = cli_env / "note.txt"
    text.write_text("Beacon to evil-update[.]com and 8.8.4.4")
    r = runner.invoke(app, ["ingest", str(text), "--reliability", "C", "--credibility", "3"])
    assert r.exit_code == 0 and "domain:evil-update.com" in r.output
    r = runner.invoke(app, ["import-stix", str(out)])
    assert r.exit_code == 0 and json.loads(r.output)["validation_errors"] == []
    feed = cli_env / "feed.xml"
    feed.write_text(
        '<?xml version="1.0"?><rss><channel><item><title>A</title><description>evil[.]com</description>'
        "</item></channel></rss>"
    )
    r = runner.invoke(app, ["collect-rss", "Vendor", "--file", str(feed)])
    assert r.exit_code == 0 and "processed 1" in r.output
