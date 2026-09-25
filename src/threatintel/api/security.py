"""API security: key auth (header or HTTP Basic), security headers, body-size limit."""

from __future__ import annotations

import base64
import binascii
import hmac
from urllib.parse import urlsplit

from fastapi import Request
from fastapi.responses import JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import ASGIApp

from threatintel.config import Settings

PUBLIC_PATHS = {"/health", "/favicon.ico"}
PUBLIC_PREFIXES = ("/static/",)
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    ),
    "Cache-Control": "no-store",
}
DOCS_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; "
    "object-src 'none'; frame-ancestors 'none'"
)


UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def same_origin(request: Request) -> bool:
    origin = request.headers.get("origin") or request.headers.get("referer") or ""
    if not origin:
        return False
    parts = urlsplit(origin)
    return f"{parts.scheme}://{parts.netloc}" == f"{request.url.scheme}://{request.url.netloc}"


def key_matches(presented: str, expected: str) -> bool:
    return bool(presented) and bool(expected) and hmac.compare_digest(presented.encode(), expected.encode())


def presented_key(request: Request) -> str:
    header = request.headers.get("x-api-key", "")
    if header:
        return header
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(auth[6:], validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return ""
        return decoded.partition(":")[2]
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        super().__init__(app)
        self.settings = settings

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > self.settings.max_body_bytes:
            return self._secure(JSONResponse({"detail": "request body too large"}, status_code=413))
        path = request.url.path
        expected = self.settings.api_key.get_secret_value()
        anonymous_ok = self.settings.allow_anonymous and not expected
        if not (path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES) or anonymous_ok):
            if not expected:
                return self._secure(
                    JSONResponse(
                        {"detail": "server has no API key configured (set TIX_API_KEY)"}, status_code=503
                    )
                )
            if not key_matches(presented_key(request), expected):
                resp = JSONResponse({"detail": "authentication required"}, status_code=401)
                resp.headers["WWW-Authenticate"] = 'Basic realm="THREATINTEL-X"'
                return self._secure(resp)
            if (
                request.method in UNSAFE_METHODS
                and not request.headers.get("x-api-key")
                and not same_origin(request)
            ):
                # Browsers replay Basic credentials on cross-site form posts: require same-origin.
                return self._secure(
                    JSONResponse({"detail": "cross-origin request rejected"}, status_code=403)
                )
        return self._secure(await call_next(request), docs=path == "/api/docs")

    @staticmethod
    def _secure(resp: Response, docs: bool = False) -> Response:
        for k, v in SECURITY_HEADERS.items():
            resp.headers.setdefault(k, v)
        if docs:  # Swagger UI loads its assets from jsDelivr and bootstraps with an inline script
            resp.headers["Content-Security-Policy"] = DOCS_CSP
        return resp
