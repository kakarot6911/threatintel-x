"""FastAPI application: REST API (/api/v1), TAXII 2.1 (/taxii2) and the analyst workbench (/)."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from threatintel import __version__
from threatintel.analysis.lifecycle import LifecycleError
from threatintel.analysis.requirements import answer, list_requirements
from threatintel.api.security import SecurityMiddleware
from threatintel.api.taxii import build_router
from threatintel.collectors.humint import HumintCollector
from threatintel.config import PACKAGE_DIR, Settings, get_settings
from threatintel.graph.graph import build_graph, pivot
from threatintel.models.common import (
    InformationCredibility,
    LifecycleStatus,
    ObservableType,
    SourceReliability,
    SourceType,
)
from threatintel.models.entities import HumintReport
from threatintel.models.intel import Source
from threatintel.pipeline import Pipeline
from threatintel.platform import Platform
from threatintel.reporting.products import ProductBuilder
from threatintel.stix.export import export_stix_bundle
from threatintel.stix.importer import import_stix_bundle
from threatintel.stix.validate import validate_bundle
from threatintel.workflows import ingest_text, investigate, run_demo

log = logging.getLogger(__name__)


# ----------------------------------------------------------------- schemas
class TextIn(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    content: str = Field(min_length=1, max_length=200_000)
    reliability: SourceReliability = SourceReliability.F
    credibility: InformationCredibility = InformationCredibility.CANNOT_BE_JUDGED
    url: str | None = Field(default=None, max_length=2048)


class HumintIn(BaseModel):
    source_identifier: str = Field(min_length=1, max_length=120)
    source_reliability: SourceReliability
    information_credibility: InformationCredibility
    collection_method: str = Field(min_length=1, max_length=200)
    date_observed: datetime
    raw_note: str = Field(min_length=1, max_length=20_000)
    analyst_assessment: str = Field(default="", max_length=20_000)
    corroborating_sources: list[str] = Field(default=[], max_length=20)


class TransitionIn(BaseModel):
    to: LifecycleStatus
    by: str = Field(min_length=1, max_length=120)
    note: str = Field(default="", max_length=2000)


def platform_of(request: Request) -> Platform:
    return request.app.state.platform


def create_app(settings: Settings | None = None, platform: Platform | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(
        title="THREATINTEL-X",
        version=__version__,
        description="Evidence-first Cyber Threat Intelligence platform",
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.platform = platform or Platform(settings)
    app.add_middleware(SecurityMiddleware, settings=settings)
    app.mount("/static", StaticFiles(directory=PACKAGE_DIR / "web" / "static"), name="static")
    app.include_router(build_router(platform_of))

    from threatintel.web.views import build_web_router

    app.include_router(build_web_router())

    @app.get("/health", tags=["meta"])
    def health() -> dict[str, Any]:
        return {"status": "ok", "version": __version__}

    # ------------------------------------------------------------- ingest
    @app.post("/api/v1/ingest/text", tags=["ingest"])
    def api_ingest_text(body: TextIn, request: Request) -> dict[str, Any]:
        return ingest_text(
            platform_of(request),
            body.title,
            body.content,
            reliability=body.reliability.value,
            credibility=body.credibility.value,
            url=body.url,
        ).as_dict()

    @app.post("/api/v1/ingest/humint", tags=["ingest"])
    def api_ingest_humint(body: HumintIn, request: Request) -> dict[str, Any]:
        p = platform_of(request)
        src = Source(
            id="src-humint-desk",
            name="HUMINT desk",
            source_type=SourceType.HUMINT,
            reliability=body.source_reliability,
        )
        p.repo.upsert_source(src)
        report = HumintReport(**body.model_dump())
        items = list(HumintCollector(src, [report]).collect())
        p.repo.put_record("humint_report", report.id, report.model_dump(mode="json"))
        return Pipeline(p).process(items[0]).as_dict()

    @app.post("/api/v1/ingest/stix", tags=["ingest"])
    async def api_ingest_stix(request: Request) -> dict[str, Any]:
        bundle = await request.json()
        if not isinstance(bundle, dict):
            raise HTTPException(400, "expected a STIX bundle object")
        errors = validate_bundle(bundle)
        res = import_stix_bundle(platform_of(request).repo, bundle, source_name="API STIX upload")
        return {
            "entities": res.entities,
            "observables": res.observables,
            "relationships": res.relationships,
            "skipped": res.skipped[:50],
            "validation_errors": errors[:50],
        }

    @app.post("/api/v1/demo/seed", tags=["ingest"])
    def api_demo(request: Request) -> dict[str, Any]:
        return run_demo(platform_of(request)).__dict__

    # ------------------------------------------------------------- query
    @app.get("/api/v1/stats", tags=["query"])
    def stats(request: Request) -> dict[str, Any]:
        p = platform_of(request)
        return {
            "observables": p.repo.count_observables(),
            "entities": {
                t: len(p.repo.list_entities(t))
                for t in ("threat-actor", "campaign", "malware", "tool", "vulnerability")
            },
            "items": len(p.repo.list_collected_items(limit=100_000)),
            "under_review": len(p.repo.subjects_with_status([LifecycleStatus.UNDER_REVIEW])),
            "attack_version": p.kb.version,
        }

    @app.get("/api/v1/observables", tags=["query"])
    def observables(
        request: Request,
        type: ObservableType | None = None,
        q: str | None = Query(None, max_length=200),
        limit: int = Query(200, ge=1, le=5000),
    ) -> list[dict[str, Any]]:
        return [
            o.model_dump(mode="json", exclude={"provenance"})
            for o in platform_of(request).repo.list_observables(type, q, limit)
        ]

    @app.get("/api/v1/investigate", tags=["query"])
    def api_investigate(
        request: Request, value: str = Query(min_length=1, max_length=2048)
    ) -> dict[str, Any]:
        return investigate(platform_of(request), value)

    @app.get("/api/v1/entities/{entity_type}", tags=["query"])
    def entities(entity_type: str, request: Request) -> list[dict[str, Any]]:
        if entity_type not in (
            "threat-actor",
            "campaign",
            "malware",
            "tool",
            "vulnerability",
            "infrastructure",
        ):
            raise HTTPException(404, "unknown entity type")
        return [e.model_dump(mode="json") for e in platform_of(request).repo.list_entities(entity_type)]

    @app.get("/api/v1/entity/{entity_id}", tags=["query"])
    def entity(entity_id: str, request: Request) -> dict[str, Any]:
        p = platform_of(request)
        ent = p.repo.get_entity(entity_id)
        if ent is None:
            raise HTTPException(404, "not found")
        return {
            "entity": ent.model_dump(mode="json"),
            "relationships": [
                r.model_dump(mode="json") for r in p.repo.list_relationships(involving=entity_id)
            ],
            "assessments": {
                k: (a.model_dump(mode="json") if (a := p.repo.latest_assessment(entity_id, k)) else None)
                for k in ("attribution", "confidence")
            },
        }

    @app.get("/api/v1/items", tags=["query"])
    def items(request: Request, limit: int = Query(100, ge=1, le=5000)) -> list[dict[str, Any]]:
        p = platform_of(request)
        out = []
        for it in p.repo.list_collected_items(limit=limit):
            pr = p.repo.latest_assessment(it.id, "priority")
            out.append(
                {
                    "id": it.id,
                    "title": it.title,
                    "source": it.source_name,
                    "synthetic": it.synthetic,
                    "priority": pr.level if pr else None,
                    "status": (p.repo.get_status(it.id) or LifecycleStatus.NEW).value,
                }
            )
        return out

    @app.get("/api/v1/assessments/{subject_id}", tags=["query"])
    def assessments(subject_id: str, request: Request) -> dict[str, Any]:
        p = platform_of(request)
        return {
            k: (a.model_dump(mode="json") if (a := p.repo.latest_assessment(subject_id, k)) else None)
            for k in ("confidence", "priority", "correlation", "attribution")
        }

    @app.get("/api/v1/requirements", tags=["requirements"])
    def requirements(request: Request) -> list[dict[str, Any]]:
        return [r.model_dump(mode="json") for r in list_requirements(platform_of(request))]

    @app.get("/api/v1/requirements/{ir_id}", tags=["requirements"])
    def requirement(ir_id: str, request: Request) -> dict[str, Any]:
        try:
            return answer(platform_of(request), ir_id)
        except KeyError as exc:
            raise HTTPException(404, "unknown requirement") from exc

    @app.post("/api/v1/lifecycle/{subject_id}", tags=["lifecycle"])
    def transition(subject_id: str, body: TransitionIn, request: Request) -> dict[str, Any]:
        try:
            change = platform_of(request).lifecycle.transition(
                subject_id, body.to, by=body.by, note=body.note
            )
        except LifecycleError as exc:
            raise HTTPException(409, str(exc)) from exc
        return change.model_dump(mode="json")

    @app.get("/api/v1/graph/pivot", tags=["query"])
    def api_pivot(request: Request, value: str = Query(min_length=1, max_length=2048)) -> dict[str, Any]:
        p = platform_of(request)
        obs = p.repo.find_observables(value.strip())
        if not obs:
            raise HTTPException(404, "observable not found")
        return {"paths": pivot(build_graph(p.repo, p.kb), obs[0].id)}

    # ------------------------------------------------------ dissemination
    @app.get("/api/v1/stix/bundle", tags=["dissemination"])
    def stix_bundle(request: Request, include_synthetic: bool = True) -> dict[str, Any]:
        p = platform_of(request)
        return export_stix_bundle(p.repo, p.kb, p.settings, include_synthetic=include_synthetic)

    @app.get("/api/v1/reports/{kind}", tags=["dissemination"], response_class=PlainTextResponse)
    def report(
        kind: str,
        request: Request,
        subject: str | None = Query(None, max_length=300),
        format: str = Query("md", pattern="^(md|csv)$"),
    ) -> PlainTextResponse:
        b = ProductBuilder(platform_of(request))
        try:
            if kind == "technical-report" and subject:
                return PlainTextResponse(
                    b.technical_report(subject).body_markdown, media_type="text/markdown"
                )
            if kind == "campaign-report" and subject:
                return PlainTextResponse(b.campaign_report(subject).body_markdown, media_type="text/markdown")
            if kind == "actor-profile" and subject:
                return PlainTextResponse(b.actor_profile(subject).body_markdown, media_type="text/markdown")
            if kind == "ciso-brief":
                return PlainTextResponse(b.ciso_brief().body_markdown, media_type="text/markdown")
            if kind == "ioc-bulletin":
                prod, csv_text = b.ioc_bulletin()
                if format == "csv":
                    return PlainTextResponse(
                        csv_text,
                        media_type="text/csv",
                        headers={"Content-Disposition": 'attachment; filename="ioc-bulletin.csv"'},
                    )
                return PlainTextResponse(prod.body_markdown, media_type="text/markdown")
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        raise HTTPException(400, "unknown report kind or missing subject")

    @app.get("/api/v1/enrichment/status", tags=["integrations"])
    def enrichment_status(request: Request) -> list[dict[str, Any]]:
        return platform_of(request).enrichment.status()

    @app.get("/api/v1/integrations/status", tags=["integrations"])
    def integrations_status(request: Request) -> dict[str, Any]:
        s = platform_of(request).settings
        return {
            "online": s.online,
            "misp": bool(s.misp_url and s.misp_key.get_secret_value()),
            "opencti": bool(s.opencti_url and s.opencti_token.get_secret_value()),
            "taxii_client": bool(s.taxii_server),
            "taxii_server": "/taxii2/",
            "telegram_bot": bool(s.telegram_bot_token.get_secret_value()),
        }

    return app
