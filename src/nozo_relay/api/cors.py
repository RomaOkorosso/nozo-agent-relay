"""CORS for the static GitHub Pages gateway (Bearer, no cookies)."""

from __future__ import annotations

from collections.abc import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from nozo_relay.config import Settings

_ALLOW_HEADERS = "Authorization, Content-Type, Idempotency-Key, X-CSRF-Token"
_ALLOW_METHODS = "GET, POST, PATCH, PUT, DELETE, OPTIONS"


class GatewayCorsMiddleware(BaseHTTPMiddleware):
    """Reflect permitted Origins only; credentials stay off (gateway uses Bearer)."""

    def __init__(self, app, settings: Settings) -> None:  # noqa: ANN001
        super().__init__(app)
        self.settings = settings

    def _headers(self, origin: str) -> dict[str, str]:
        return {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Methods": _ALLOW_METHODS,
            "Access-Control-Allow-Headers": _ALLOW_HEADERS,
            "Access-Control-Max-Age": "600",
            "Vary": "Origin",
        }

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        origin = request.headers.get("origin")
        allowed = bool(origin and self.settings.origin_permitted(origin))

        if request.method == "OPTIONS":
            # Always answer preflight locally so unknown Origins get 204 *without* ACAO
            # (avoids falling through to a 405 from the route table).
            if allowed:
                return Response(status_code=204, headers=self._headers(origin))  # type: ignore[arg-type]
            return Response(status_code=204)

        response = await call_next(request)
        if allowed:
            for key, value in self._headers(origin).items():  # type: ignore[arg-type]
                response.headers.setdefault(key, value)
        return response
