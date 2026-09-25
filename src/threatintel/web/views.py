"""Analyst workbench: server-rendered pages (Jinja2, autoescaped, no inline script - strict CSP)."""

from __future__ import annotations

from collections import Counter
from typing import Any

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from threatintel import __version__
from threatintel.analysis.lifecycle import ALLOWED, LifecycleError
from threatintel.analysis.requirements import answer, list_requirements
from threatintel.config import PACKAGE_DIR
from threatintel.graph.graph import build_graph, neighborhood, pivot, render_svg
from threatintel.models.common import (
    CREDIBILITY_LABELS,
    PRIORITY_LABELS,
    RELIABILITY_LABELS,
    LifecycleStatus,
    ObservableType,
)
from threatintel.models.entities import Campaign, ThreatActor
from threatintel.platform import Platform
from threatintel.reporting.products import ProductBuilder
from threatintel.workflows import ingest_text, investigate, run_demo

templates = Jinja2Templates(directory=str(PACKAGE_DIR / "web" / "templates"))
templates.env.globals.update(
    version=__version__,
    priority_labels=PRIORITY_LABELS,
    reliability_labels=RELIABILITY_LABELS,
    credibility_labels=CREDIBILITY_LABELS,
)


def _p(request: Request) -> Platform:
    return request.app.state.platform


def _render(request: Request, name: str, **ctx: Any) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        name,
        {"active": name.split(".")[0], "instance_synthetic": _p(request).repo.has_synthetic(), **ctx},
    )


def _items_with_scores(p: Platform, limit: int = 500) -> list[dict[str, Any]]:
    rows = []
    for it in p.repo.list_collected_items(limit=limit):
        pr = p.repo.latest_assessment(it.id, "priority")
        at = p.repo.latest_assessment(it.id, "attribution")
        conf = p.repo.latest_assessment(it.id, "confidence")
        rows.append(
            {
                "item": it,
                "priority": pr.level if pr else "P5",
                "attribution": at,
                "confidence": conf,
                "status": (p.repo.get_status(it.id) or LifecycleStatus.NEW).value,
            }
        )
    return rows


def build_web_router() -> APIRouter:
    r = APIRouter(include_in_schema=False)

    @r.get("/", response_class=HTMLResponse)
    def dashboard(request: Request) -> HTMLResponse:
        p = _p(request)
        rows = _items_with_scores(p)
        queue = sorted([x for x in rows if x["status"] == "UNDER_REVIEW"], key=lambda x: x["priority"])
        counts = p.repo.count_observables()
        creds = answer(p, "IR-003")
        return _render(
            request,
            "dashboard.html",
            queue=queue,
            counts=counts,
            total_obs=sum(counts.values()),
            priorities=Counter(x["priority"] for x in rows),
            items=len(rows),
            actors=p.repo.list_entities("threat-actor"),
            campaigns=p.repo.list_entities("campaign"),
            creds=creds,
            synthetic=any(x["item"].synthetic for x in rows),
            attack=f"{p.kb.domain} v{p.kb.version}",
            empty=not rows,
        )

    @r.get("/intel", response_class=HTMLResponse)
    def intel(request: Request) -> HTMLResponse:
        rows = sorted(_items_with_scores(_p(request)), key=lambda x: (x["priority"], x["item"].title))
        return _render(request, "intel.html", rows=rows)

    @r.get("/intel/{item_id}", response_class=HTMLResponse)
    def intel_item(item_id: str, request: Request) -> HTMLResponse:
        p = _p(request)
        item = p.repo.get_collected_item(item_id)
        if item is None:
            raise HTTPException(404)
        obs = [o for o in (p.repo.get_observable_by_id(s) for s in p.repo.subjects_for_item(item_id)) if o]
        status = p.repo.get_status(item_id)
        techniques = []
        stix_to_tech = {t.stix_id: t for t in p.kb.techniques.values()}
        for rel in p.repo.list_relationships(source_ref=item_id, relationship_type="exhibits-technique"):
            t = stix_to_tech.get(rel.target_ref)
            if t:
                techniques.append({"t": t, "rel": rel})
        return _render(
            request,
            "intel_item.html",
            item=item,
            observables=obs,
            techniques=techniques,
            a={
                k: p.repo.latest_assessment(item_id, k)
                for k in ("confidence", "priority", "correlation", "attribution")
            },
            status=status.value if status else "NEW",
            history=p.repo.status_history(item_id),
            allowed=[s.value for s in LifecycleStatus if s in ALLOWED[status]],
            error=request.query_params.get("error"),
        )

    @r.post("/intel/{item_id}/transition")
    def intel_transition(
        item_id: str, request: Request, to: str = Form(...), by: str = Form(...), note: str = Form("")
    ) -> RedirectResponse:
        try:
            _p(request).lifecycle.transition(item_id, LifecycleStatus(to), by=by[:120], note=note[:2000])
        except (LifecycleError, ValueError) as exc:
            from urllib.parse import quote

            return RedirectResponse(f"/intel/{item_id}?error={quote(str(exc))}", status_code=303)
        return RedirectResponse(f"/intel/{item_id}", status_code=303)

    @r.get("/actors", response_class=HTMLResponse)
    def actors(request: Request) -> HTMLResponse:
        p = _p(request)
        rows = []
        for a in p.repo.list_entities("threat-actor"):
            rows.append({"a": a, "campaigns": len(p.profiles.campaigns_of(a.id))})
        return _render(request, "actors.html", rows=rows)

    @r.get("/actors/{actor_id}", response_class=HTMLResponse)
    def actor(actor_id: str, request: Request) -> HTMLResponse:
        p = _p(request)
        a = p.repo.get_entity(actor_id)
        if not isinstance(a, ThreatActor):
            raise HTTPException(404)
        g = build_graph(p.repo, p.kb)
        prof = p.profiles.actor(a)
        campaigns = [c for c in (p.repo.get_entity(cid) for cid in p.profiles.campaigns_of(a.id)) if c]
        return _render(
            request,
            "actor.html",
            a=a,
            svg=render_svg(neighborhood(g, a.id), a.id),
            prof=prof,
            campaigns=[(c, p.repo.latest_assessment(c.id, "attribution")) for c in campaigns],
            techniques=[p.kb.techniques[t] for t in sorted(prof.techniques) if t in p.kb.techniques],
        )

    @r.get("/campaigns", response_class=HTMLResponse)
    def campaigns(request: Request) -> HTMLResponse:
        p = _p(request)
        rows = [
            {"c": c, "a": p.repo.latest_assessment(c.id, "attribution")}
            for c in p.repo.list_entities("campaign")
        ]
        return _render(request, "campaigns.html", rows=rows)

    @r.get("/campaigns/{campaign_id}", response_class=HTMLResponse)
    def campaign(campaign_id: str, request: Request) -> HTMLResponse:
        p = _p(request)
        c = p.repo.get_entity(campaign_id)
        if not isinstance(c, Campaign):
            raise HTTPException(404)
        product = ProductBuilder(p).campaign_report(c.id)
        g = build_graph(p.repo, p.kb)
        return _render(
            request,
            "campaign.html",
            c=c,
            a=p.repo.latest_assessment(c.id, "attribution"),
            svg=render_svg(neighborhood(g, c.id), c.id),
            report=product.body_markdown,
        )

    @r.get("/iocs", response_class=HTMLResponse)
    def iocs(request: Request, q: str = "", type: str = "") -> HTMLResponse:
        p = _p(request)
        obs_type = ObservableType(type) if type in {t.value for t in ObservableType} else None
        rows = []
        for o in p.repo.list_observables(obs_type, q[:200] or None, limit=500):
            conf = p.repo.latest_assessment(o.id, "confidence")
            rows.append({"o": o, "conf": conf})
        return _render(
            request, "iocs.html", rows=rows, q=q, type=type, types=[t.value for t in ObservableType]
        )

    @r.get("/investigate", response_class=HTMLResponse)
    def investigate_page(request: Request, q: str = "") -> HTMLResponse:
        p = _p(request)
        result = investigate(p, q[:2048]) if q.strip() else None
        paths = []
        if result and result.get("found"):
            paths = pivot(build_graph(p.repo, p.kb), result["observable"]["id"], limit=12)
        return _render(request, "investigate.html", q=q, r=result, paths=paths)

    @r.get("/attack", response_class=HTMLResponse)
    def attack(request: Request) -> HTMLResponse:
        p = _p(request)
        used: dict[str, list[str]] = {}
        stix_to_tech = {t.stix_id: t for t in p.kb.techniques.values()}
        for c in p.repo.list_entities("campaign"):
            for rel in p.repo.list_relationships(source_ref=c.id, relationship_type="uses"):
                t = stix_to_tech.get(rel.target_ref)
                if t:
                    used.setdefault(t.technique_id, []).append(c.name)
        matrix = []
        for tactic in p.kb.tactic_order():
            techs = sorted(
                (t for t in p.kb.techniques.values() if tactic in t.tactics and t.technique_id in used),
                key=lambda t: t.technique_id,
            )
            matrix.append(
                {"tactic": p.kb.tactic_name(tactic), "techniques": [(t, used[t.technique_id]) for t in techs]}
            )
        return _render(request, "attack.html", matrix=matrix, kb=p.kb, used=len(used))

    @r.get("/reports", response_class=HTMLResponse)
    def reports(request: Request) -> HTMLResponse:
        p = _p(request)
        return _render(
            request,
            "reports.html",
            campaigns=p.repo.list_entities("campaign"),
            actors=p.repo.list_entities("threat-actor"),
        )

    @r.get("/reports/view", response_class=HTMLResponse)
    def report_view(request: Request, kind: str, subject: str = "") -> HTMLResponse:
        b = ProductBuilder(_p(request))
        try:
            if kind == "technical-report":
                prod = b.technical_report(subject)
            elif kind == "campaign-report":
                prod = b.campaign_report(subject)
            elif kind == "actor-profile":
                prod = b.actor_profile(subject)
            elif kind == "ciso-brief":
                prod = b.ciso_brief()
            elif kind == "ioc-bulletin":
                prod = b.ioc_bulletin()[0]
            else:
                raise HTTPException(400, "unknown report kind")
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        return _render(request, "report_view.html", prod=prod, kind=kind, subject=subject)

    @r.get("/sources", response_class=HTMLResponse)
    def sources(request: Request) -> HTMLResponse:
        return _render(request, "sources.html", sources=_p(request).repo.list_sources())

    @r.get("/requirements", response_class=HTMLResponse)
    def requirements(request: Request) -> HTMLResponse:
        p = _p(request)
        return _render(
            request, "requirements.html", reqs=[(ir, answer(p, ir.id)) for ir in list_requirements(p)]
        )

    @r.get("/integrations", response_class=HTMLResponse)
    def integrations(request: Request) -> HTMLResponse:
        p = _p(request)
        s = p.settings
        return _render(
            request,
            "integrations.html",
            providers=p.enrichment.status(),
            online=s.online,
            misp=bool(s.misp_url),
            opencti=bool(s.opencti_url),
            taxii=bool(s.taxii_server),
            telegram=bool(s.telegram_bot_token.get_secret_value()),
            base=str(request.base_url).rstrip("/"),
        )

    @r.get("/collect", response_class=HTMLResponse)
    def collect(request: Request) -> HTMLResponse:
        return _render(request, "collect.html", result=None)

    @r.post("/collect/demo", response_class=HTMLResponse)
    def collect_demo(request: Request) -> HTMLResponse:
        summary = run_demo(_p(request))
        return _render(request, "collect.html", result={"demo": summary.__dict__})

    @r.post("/collect/text", response_class=HTMLResponse)
    def collect_text(
        request: Request,
        title: str = Form(...),
        content: str = Form(...),
        reliability: str = Form("F"),
        credibility: str = Form("6"),
    ) -> HTMLResponse:
        if reliability not in RELIABILITY_LABELS or credibility not in CREDIBILITY_LABELS:
            raise HTTPException(400, "invalid rating")
        res = ingest_text(
            _p(request), title[:300], content[:200_000], reliability=reliability, credibility=credibility
        )
        return _render(request, "collect.html", result={"ingest": res.as_dict()})

    return r
