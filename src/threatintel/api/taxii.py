"""Read-only TAXII 2.1 server exposing THREATINTEL-X intelligence as STIX 2.1.

Endpoints (spec section 4-5): discovery, API root, collections, collection, objects,
object-by-id and manifest, with ``added_after``, ``match[type]``, ``match[id]``,
``limit`` and ``next`` pagination.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from threatintel.models.common import TIX_NAMESPACE
from threatintel.platform import Platform
from threatintel.stix.export import export_stix_bundle

TAXII_MEDIA = "application/taxii+json;version=2.1"
STIX_MEDIA = "application/stix+json;version=2.1"
MAX_PAGE = 500
COLLECTIONS = {
    str(uuid.uuid5(TIX_NAMESPACE, "taxii|all")): {
        "title": "THREATINTEL-X - all intelligence (includes SYNTHETIC demo data)",
        "include_synthetic": True,
    },
    str(uuid.uuid5(TIX_NAMESPACE, "taxii|real")): {
        "title": "THREATINTEL-X - real-world intelligence only (synthetic excluded)",
        "include_synthetic": False,
    },
}


def _resp(body: dict[str, Any], headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(body, media_type=TAXII_MEDIA, headers=headers or {})


def _added(obj: dict[str, Any]) -> str:
    return str(obj.get("modified") or obj.get("created") or "1970-01-01T00:00:00.000Z")


def _parse_ts(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(400, f"invalid timestamp: {value}") from exc


def build_router(platform_getter: Any) -> APIRouter:
    router = APIRouter(prefix="/taxii2", tags=["taxii"])

    def collection_meta(cid: str) -> dict[str, Any]:
        c = COLLECTIONS[cid]
        return {
            "id": cid,
            "title": c["title"],
            "can_read": True,
            "can_write": False,
            "media_types": [STIX_MEDIA],
        }

    cache: dict[tuple[str, int], list[dict[str, Any]]] = {}

    def objects_for(cid: str, request: Request) -> list[dict[str, Any]]:
        if cid not in COLLECTIONS:
            raise HTTPException(404, "collection not found")
        platform: Platform = platform_getter(request)
        key = (cid, platform.repo.revision)
        if key in cache:  # pagination re-requests the same collection: export once per data revision
            return cache[key]
        bundle = export_stix_bundle(
            platform.repo,
            platform.kb,
            platform.settings,
            include_synthetic=bool(COLLECTIONS[cid]["include_synthetic"]),
        )
        objs = sorted(bundle["objects"], key=lambda o: (_added(o), o["id"]))
        for stale in [k for k in cache if k[1] != key[1]]:
            del cache[stale]
        cache[key] = objs
        return objs

    def filtered(
        objs: list[dict[str, Any]], added_after: str | None, types: str | None, ids: str | None
    ) -> list[dict[str, Any]]:
        if added_after:
            cutoff = _parse_ts(added_after)
            objs = [o for o in objs if _parse_ts(_added(o)) > cutoff]
        if types:
            wanted = set(types.split(","))
            objs = [o for o in objs if o["type"] in wanted]
        if ids:
            wanted_ids = set(ids.split(","))
            objs = [o for o in objs if o["id"] in wanted_ids]
        return objs

    def page(
        objs: list[dict[str, Any]], limit: int, next_: str | None
    ) -> tuple[list[dict[str, Any]], str | None]:
        start = int(next_) if next_ and next_.isdigit() else 0
        chunk = objs[start : start + limit]
        more = start + limit < len(objs)
        return chunk, str(start + limit) if more else None

    @router.get("/")
    def discovery(request: Request) -> JSONResponse:
        base = str(request.base_url).rstrip("/")
        return _resp(
            {
                "title": "THREATINTEL-X TAXII 2.1",
                "description": "Read-only CTI sharing",
                "default": f"{base}/taxii2/api1/",
                "api_roots": [f"{base}/taxii2/api1/"],
            }
        )

    @router.get("/api1/")
    def api_root() -> JSONResponse:
        return _resp(
            {"title": "THREATINTEL-X API root", "versions": [TAXII_MEDIA], "max_content_length": 10_485_760}
        )

    @router.get("/api1/collections/")
    def collections() -> JSONResponse:
        return _resp({"collections": [collection_meta(cid) for cid in COLLECTIONS]})

    @router.get("/api1/collections/{cid}/")
    def collection(cid: str) -> JSONResponse:
        if cid not in COLLECTIONS:
            raise HTTPException(404, "collection not found")
        return _resp(collection_meta(cid))

    @router.get("/api1/collections/{cid}/objects/")
    def get_objects(
        cid: str,
        request: Request,
        added_after: str | None = None,
        match_type: str | None = Query(None, alias="match[type]"),
        match_id: str | None = Query(None, alias="match[id]"),
        limit: int = Query(100, ge=1, le=MAX_PAGE),
        next: str | None = None,
    ) -> JSONResponse:
        objs = filtered(objects_for(cid, request), added_after, match_type, match_id)
        chunk, nxt = page(objs, limit, next)
        body: dict[str, Any] = {"more": nxt is not None, "objects": chunk}
        if nxt:
            body["next"] = nxt
        headers = {}
        if chunk:
            headers = {
                "X-TAXII-Date-Added-First": _added(chunk[0]),
                "X-TAXII-Date-Added-Last": _added(chunk[-1]),
            }
        return _resp(body, headers)

    @router.get("/api1/collections/{cid}/objects/{object_id}/")
    def get_object(cid: str, object_id: str, request: Request) -> JSONResponse:
        objs = [o for o in objects_for(cid, request) if o["id"] == object_id]
        if not objs:
            raise HTTPException(404, "object not found")
        return _resp({"more": False, "objects": objs})

    @router.get("/api1/collections/{cid}/manifest/")
    def manifest(
        cid: str,
        request: Request,
        added_after: str | None = None,
        match_type: str | None = Query(None, alias="match[type]"),
        limit: int = Query(100, ge=1, le=MAX_PAGE),
        next: str | None = None,
    ) -> JSONResponse:
        objs = filtered(objects_for(cid, request), added_after, match_type, None)
        chunk, nxt = page(objs, limit, next)
        body: dict[str, Any] = {
            "more": nxt is not None,
            "objects": [
                {
                    "id": o["id"],
                    "date_added": _added(o),
                    "version": str(o.get("modified", _added(o))),
                    "media_type": STIX_MEDIA,
                }
                for o in chunk
            ],
        }
        if nxt:
            body["next"] = nxt
        return _resp(body)

    return router
