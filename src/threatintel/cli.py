"""THREATINTEL-X command line."""

from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Annotated

import typer

from threatintel.config import get_settings
from threatintel.logging_setup import configure_logging
from threatintel.models.common import LifecycleStatus, SourceReliability, SourceType
from threatintel.models.intel import Source

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="THREATINTEL-X - evidence-first cyber threat intelligence platform.",
)


def _platform():  # type: ignore[no-untyped-def]
    from threatintel.platform import Platform

    s = get_settings()
    configure_logging(s.log_level, s.log_json)
    return Platform(s)


def _echo_json(data: object) -> None:
    typer.echo(json.dumps(data, indent=2, default=str))


@app.command("init-db")
def init_db() -> None:
    """Create database tables and load the intelligence requirements."""
    from threatintel.collectors.synthetic import load_requirements

    p = _platform()
    load_requirements(p.repo)
    typer.echo(f"database ready: {p.settings.database_url}")


@app.command()
def demo() -> None:
    """Seed the SYNTHETIC world and run every item through the full pipeline."""
    from threatintel.workflows import run_demo

    summary = run_demo(_platform())
    _echo_json(summary.__dict__)


@app.command()
def ingest(
    path: Path,
    title: Annotated[str | None, typer.Option()] = None,
    reliability: Annotated[str, typer.Option(help="Admiralty A-F")] = "F",
    credibility: Annotated[str, typer.Option(help="Admiralty 1-6")] = "6",
) -> None:
    """Process a text file (report, alert, paste) as analyst-submitted intelligence."""
    from threatintel.workflows import ingest_text

    text = path.read_text(encoding="utf-8", errors="replace")
    res = ingest_text(_platform(), title or path.name, text, reliability=reliability, credibility=credibility)
    _echo_json(res.as_dict())


@app.command("collect-rss")
def collect_rss(
    name: str,
    url: Annotated[str | None, typer.Option(help="feed URL (needs TIX_ONLINE)")] = None,
    file: Annotated[Path | None, typer.Option(help="saved feed file (offline)")] = None,
    reliability: Annotated[str, typer.Option()] = "C",
) -> None:
    """Collect a public RSS/Atom feed (e.g. a vendor or CISA advisory feed) and process every entry."""
    from threatintel.collectors.rss import RSSCollector
    from threatintel.pipeline import Pipeline

    if not url and not file:
        raise typer.BadParameter("give --url or --file")
    p = _platform()
    src = Source(
        id=f"src-rss-{name.lower().replace(' ', '-')}",
        name=name,
        source_type=SourceType.RSS,
        reliability=SourceReliability(reliability),
        url=url,
    )
    p.repo.upsert_source(src)
    collector = RSSCollector(src, payload=file.read_bytes() if file else None)
    results = [Pipeline(p).process(item) for item in collector.collect()]
    typer.echo(f"processed {len(results)} entries ({sum(r.duplicate for r in results)} duplicates)")


@app.command("import-stix")
def import_stix(
    path: Path,
    source_name: Annotated[str, typer.Option()] = "STIX file import",
    reliability: Annotated[str, typer.Option()] = "F",
) -> None:
    """Import a STIX 2.1 bundle (attributions are stored as REPORTED claims)."""
    from threatintel.stix.importer import import_stix_bundle
    from threatintel.stix.validate import validate_bundle

    bundle = json.loads(path.read_text(encoding="utf-8"))
    errors = validate_bundle(bundle)
    res = import_stix_bundle(
        _platform().repo,
        bundle,
        source_id=f"src-stix-{path.stem}",
        source_name=source_name,
        reliability=SourceReliability(reliability),
    )
    _echo_json(
        {
            "entities": res.entities,
            "observables": res.observables,
            "relationships": res.relationships,
            "skipped": res.skipped,
            "validation_errors": errors[:20],
        }
    )


@app.command("export-stix")
def export_stix(
    out: Annotated[Path, typer.Option()] = Path("data/exports/threatintel-x.stix.json"),
    synthetic: Annotated[bool, typer.Option("--synthetic/--no-synthetic")] = True,
) -> None:
    """Export the knowledge base as a validated STIX 2.1 bundle."""
    from threatintel.stix.export import export_stix_bundle
    from threatintel.stix.validate import validate_bundle

    p = _platform()
    bundle = export_stix_bundle(p.repo, p.kb, p.settings, include_synthetic=synthetic)
    errors = validate_bundle(bundle)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    typer.echo(f"wrote {len(bundle['objects'])} objects to {out}; validation errors: {len(errors)}")
    if errors:
        raise typer.Exit(1)


@app.command("collect-real")
def collect_real(
    rss_per_feed: Annotated[int, typer.Option(help="newest entries per RSS feed")] = 10,
    urlhaus_limit: Annotated[int, typer.Option(help="max online URLhaus URLs")] = 300,
    attack: Annotated[bool, typer.Option("--attack/--no-attack")] = True,
    kev: Annotated[bool, typer.Option("--kev/--no-kev")] = True,
    abusech: Annotated[bool, typer.Option("--abusech/--no-abusech")] = True,
    rss: Annotated[bool, typer.Option("--rss/--no-rss")] = True,
) -> None:
    """Collect REAL intelligence: ATT&CK, CISA KEV, abuse.ch, public RSS feeds (needs TIX_ONLINE)."""
    from threatintel.workflows import run_real

    summary = run_real(
        _platform(),
        attack=attack,
        kev=kev,
        abusech=abusech,
        rss=rss,
        rss_per_feed=rss_per_feed,
        urlhaus_limit=urlhaus_limit,
        progress=lambda m: typer.echo(m, err=True),
    )
    _echo_json(summary.__dict__)
    if summary.errors:
        typer.echo(f"{len(summary.errors)} source(s) failed - see 'errors'", err=True)


@app.command()
def investigate(value: str) -> None:
    """Everything known about an IOC, and why it matters."""
    from threatintel.workflows import investigate as inv

    _echo_json(inv(_platform(), value))


@app.command()
def report(
    kind: Annotated[
        str,
        typer.Argument(help="technical-report | campaign-report | actor-profile | ciso-brief | ioc-bulletin"),
    ],
    subject: Annotated[str | None, typer.Option(help="campaign/actor id or name")] = None,
    out: Annotated[Path | None, typer.Option()] = None,
) -> None:
    """Generate an intelligence product (Markdown)."""
    from threatintel.reporting.products import ProductBuilder

    b = ProductBuilder(_platform())
    builders = {
        "technical-report": lambda: b.technical_report(subject or ""),
        "campaign-report": lambda: b.campaign_report(subject or ""),
        "actor-profile": lambda: b.actor_profile(subject or ""),
        "ciso-brief": b.ciso_brief,
        "ioc-bulletin": lambda: b.ioc_bulletin()[0],
    }
    if kind not in builders:
        raise typer.BadParameter(f"unknown kind {kind}")
    body = builders[kind]().body_markdown
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(body, encoding="utf-8")
        typer.echo(f"wrote {out}")
    else:
        typer.echo(body)


@app.command()
def requirement(ir_id: str) -> None:
    """Answer an intelligence requirement (IR-001 .. IR-008)."""
    from threatintel.analysis.requirements import answer

    _echo_json(answer(_platform(), ir_id))


@app.command()
def transition(
    subject_id: str,
    to: LifecycleStatus,
    by: Annotated[str, typer.Option()],
    note: Annotated[str, typer.Option()] = "",
) -> None:
    """Move an item through the intelligence lifecycle (CONFIRMED requires a named analyst)."""
    change = _platform().lifecycle.transition(subject_id, to, by=by, note=note)
    _echo_json(change.model_dump(mode="json"))


@app.command()
def enrich(value: str) -> None:
    """Enrich a known observable with every available provider (needs TIX_ONLINE for real providers)."""
    p = _platform()
    found = p.repo.find_observables(value)
    if not found:
        raise typer.BadParameter("observable not in the knowledge base; ingest it first")
    _echo_json([r.model_dump(mode="json") for r in p.enrichment.enrich(found[0], use_cache=False)])


@app.command("attack-sync")
def attack_sync() -> None:
    """Download the current Enterprise ATT&CK STIX release (needs TIX_ONLINE=true)."""
    from threatintel.collectors.mitre import MITRECollector

    p = _platform()
    src = Source(
        id="src-mitre-attack",
        name="MITRE ATT&CK",
        source_type=SourceType.MITRE,
        reliability=SourceReliability.A,
    )
    path = MITRECollector(src, p.settings).sync()
    typer.echo(f"saved {path}")


@app.command("misp-push")
def misp_push(campaign: str, dry_run: Annotated[bool, typer.Option("--dry-run")] = False) -> None:
    """Push a campaign to MISP as an event (use --dry-run to print the MISP JSON)."""
    from threatintel.integrations.misp import MISPAdapter, campaign_to_event
    from threatintel.models.entities import Campaign

    p = _platform()
    ent = p.repo.get_entity(campaign) or p.repo.find_entity("campaign", campaign)
    if not isinstance(ent, Campaign):
        raise typer.BadParameter("campaign not found")
    event = campaign_to_event(p.repo, p.kb, ent)
    if dry_run:
        typer.echo(event.to_json(indent=2))
        return
    _echo_json(MISPAdapter.from_settings(p.settings).push_event(event))


@app.command("opencti-push")
def opencti_push(
    synthetic: Annotated[bool, typer.Option("--synthetic/--no-synthetic")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Push the STIX 2.1 knowledge base into OpenCTI (synthetic excluded unless --synthetic)."""
    from threatintel.integrations.opencti import OpenCTIAdapter
    from threatintel.stix.export import export_stix_bundle

    p = _platform()
    bundle = export_stix_bundle(p.repo, p.kb, p.settings, include_synthetic=synthetic)
    if dry_run:
        typer.echo(f"would push {len(bundle['objects'])} objects")
        return
    _echo_json(OpenCTIAdapter.from_settings(p.settings).push_bundle(bundle))


@app.command("taxii-pull")
def taxii_pull(
    collection_url: str,
    name: Annotated[str, typer.Option()] = "TAXII feed",
    reliability: Annotated[str, typer.Option()] = "C",
) -> None:
    """Pull a TAXII 2.1 collection and process its text-bearing objects."""
    from threatintel.collectors.taxii import TAXIICollector
    from threatintel.pipeline import Pipeline

    p = _platform()
    src = Source(
        id=f"src-taxii-{abs(hash(collection_url)) % 10**8}",
        name=name,
        source_type=SourceType.TAXII,
        reliability=SourceReliability(reliability),
        url=collection_url,
    )
    p.repo.upsert_source(src)
    results = [
        Pipeline(p).process(i) for i in TAXIICollector(src, collection_url, settings=p.settings).collect()
    ]
    typer.echo(f"processed {len(results)} objects")


@app.command("telegram-poll")
def telegram_poll() -> None:
    """Process messages delivered to the authorised bot from allow-listed chats only."""
    from threatintel.collectors.telegram import TelegramPermittedCollector
    from threatintel.pipeline import Pipeline

    p = _platform()
    src = Source(
        id="src-telegram-bot",
        name="Telegram bot (authorised)",
        source_type=SourceType.TELEGRAM,
        reliability=SourceReliability.D,
    )
    p.repo.upsert_source(src)
    results = [Pipeline(p).process(i) for i in TelegramPermittedCollector(src, settings=p.settings).collect()]
    typer.echo(f"processed {len(results)} messages")


@app.command()
def serve(
    host: Annotated[str, typer.Option()] = "127.0.0.1", port: Annotated[int, typer.Option()] = 8000
) -> None:
    """Run the API, TAXII server and analyst workbench."""
    import uvicorn
    from pydantic import SecretStr

    from threatintel.api.app import create_app

    settings = get_settings()
    if not settings.api_key.get_secret_value() and not settings.allow_anonymous:
        key = secrets.token_urlsafe(24)
        settings = settings.model_copy(update={"api_key": SecretStr(key)})
        typer.echo(
            f"No TIX_API_KEY set - generated an ephemeral key for this session:\n\n    {key}\n\n"
            f"Browser: any username + this key as password. API: header 'X-API-Key: {key}'.\n"
        )
    configure_logging(settings.log_level, settings.log_json)
    uvicorn.run(create_app(settings), host=host, port=port, proxy_headers=True, log_level="info")


if __name__ == "__main__":  # pragma: no cover
    app()
