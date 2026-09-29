"""FastAPI application: webhook receiver, HTML UI and a small JSON API."""

from __future__ import annotations

import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.concurrency import run_in_threadpool

from . import __version__
from .config import Config
from .export import default_url, to_curl, to_pytest_fixture
from .replay import replay_and_record
from .signatures import UNSIGNED, Verification, verify
from .storage import Store, StoredRequest
from .views import as_dict, body_view, headers_view, query_view

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
TEMPLATES = Path(__file__).parent / "templates"


def create_app(config: Config | None = None, db_path: str | None = None) -> FastAPI:
    config = config or Config()
    store = Store(db_path or config.db, retention=config.retention)
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=select_autoescape(["html"]))
    app = FastAPI(title="webhook-inspector", version=__version__,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.config = config
    app.state.store = store

    def render(name: str, status_code: int = 200, **ctx: object) -> HTMLResponse:
        html = env.get_template(name).render(version=__version__, **ctx)
        return HTMLResponse(html, status_code=status_code)

    def load(request_id: int) -> StoredRequest:
        rec = store.get(request_id)
        if rec is None:
            raise HTTPException(404, f"request {request_id} not found")
        return rec

    @app.middleware("http")
    async def ui_host_guard(request: Request, call_next):  # type: ignore[no-untyped-def]
        # The UI has no login; refuse it under unexpected Host names (DNS rebinding).
        # Webhook endpoints stay open so tunnels with their own hostnames work.
        if not request.url.path.startswith("/hooks/") and "*" not in config.ui_hosts:
            host = urlsplit("//" + request.headers.get("host", "")).hostname or ""
            if host not in config.ui_hosts:
                return PlainTextResponse(f"Host {host!r} not allowed for the UI (see ui_hosts)", 403)
        return await call_next(request)

    def same_origin(request: Request) -> None:
        # Block cross-site form posts (CSRF) to replay endpoints.
        if request.headers.get("sec-fetch-site") in ("cross-site", "same-site"):
            raise HTTPException(403, "cross-site request refused")
        origin = request.headers.get("origin")
        if origin is not None and urlsplit(origin).netloc != request.headers.get("host"):
            raise HTTPException(403, "cross-origin request refused")

    # -- receiver ------------------------------------------------------------

    @app.api_route("/hooks/{name}", methods=METHODS)
    async def receive(name: str, request: Request) -> Response:
        hook = config.hooks.get(name)
        if hook is None and not config.allow_unknown_hooks:
            return JSONResponse({"ok": False, "error": f"unknown hook {name!r}"}, 404)
        body = await request.body()
        if len(body) > config.max_body_bytes:
            return JSONResponse({"ok": False, "error": "body too large"}, 413)
        headers = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in request.scope["headers"]]
        lookup: dict[str, str] = {}
        for k, v in headers:
            lookup.setdefault(k.lower(), v)
        if hook is None:
            result = Verification(UNSIGNED, "hook not in config")
        else:
            result = verify(hook.provider, hook.secret, lookup, body, tolerance=hook.tolerance)
        request_id = await run_in_threadpool(
            store.add, hook=name, method=request.method, path=request.url.path, query=request.url.query,
            headers=headers, body=body, client_ip=request.client.host if request.client else None,
            received_at=time.time(), status=result.status, reason=result.reason,
        )
        return JSONResponse({"ok": True, "id": request_id, "hook": name,
                             "verification": result.status, "reason": result.reason})

    # -- HTML UI -------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    def index(hook: str | None = None, limit: int = 200) -> HTMLResponse:
        rows = store.list(limit=max(1, min(limit, 1000)), hook=hook or None)
        return render("list.html", rows=rows, hook=hook, total=store.count(), config=config)

    @app.get("/requests/{request_id}", response_class=HTMLResponse)
    def detail(request_id: int, request: Request, reveal: int = 0) -> HTMLResponse:
        rec = load(request_id)
        redact = not reveal
        hook = config.hooks.get(rec.hook)
        return render(
            "detail.html", rec=rec, reveal=bool(reveal),
            headers=headers_view(rec, redact), query=query_view(rec, redact),
            body=body_view(rec, redact), replays=store.replays(rec.id), hook=hook,
            replay_to=hook.replay_to if hook else "",
            can_resign=bool(hook and hook.provider == "stripe" and hook.secret),
            error=request.query_params.get("error", ""),
        )

    @app.post("/requests/{request_id}/replay")
    async def replay_form(request_id: int, request: Request) -> Response:
        same_origin(request)
        rec = load(request_id)
        form = parse_qs((await request.body()).decode("utf-8", "replace"))
        target = form.get("to", [""])[0]
        resign = form.get("resign", [""])[0] in ("1", "on", "true")
        try:
            await run_in_threadpool(replay_and_record, store, config, rec, target, resign=resign)
        except ValueError as exc:
            return render("detail.html", status_code=400, rec=rec, reveal=False,
                          headers=headers_view(rec, True), query=query_view(rec, True),
                          body=body_view(rec, True), replays=store.replays(rec.id),
                          hook=config.hooks.get(rec.hook), replay_to=target,
                          can_resign=False, error=str(exc))
        return RedirectResponse(f"/requests/{rec.id}#replays", status_code=303)

    @app.get("/requests/{request_id}/curl", response_class=PlainTextResponse)
    def export_curl(request_id: int, request: Request, reveal: int = 0, to: str = "") -> str:
        rec = load(request_id)
        base = str(request.base_url).rstrip("/")
        return to_curl(rec, to or default_url(rec, base), redact=not reveal) + "\n"

    @app.get("/requests/{request_id}/fixture", response_class=PlainTextResponse)
    def export_fixture(request_id: int, reveal: int = 0) -> str:
        return to_pytest_fixture(load(request_id), redact=not reveal)

    # -- JSON API ------------------------------------------------------------

    @app.get("/api/requests")
    def api_list(hook: str | None = None, limit: int = 100) -> list[dict]:
        return [
            {"id": r.id, "hook": r.hook, "method": r.method, "received": r.received_iso,
             "size": r.size, "status": r.status, "reason": r.reason}
            for r in store.list(limit=max(1, min(limit, 1000)), hook=hook or None)
        ]

    @app.get("/api/requests/{request_id}")
    def api_detail(request_id: int, reveal: int = 0) -> dict:
        return as_dict(load(request_id), redact=not reveal)

    @app.post("/api/requests/{request_id}/replay")
    async def api_replay(request_id: int, request: Request) -> dict:
        same_origin(request)
        rec = load(request_id)
        try:
            payload = await request.json()
        except ValueError:
            raise HTTPException(400, "expected a JSON body") from None
        if not isinstance(payload, dict) or not isinstance(payload.get("to"), str):
            raise HTTPException(400, 'expected {"to": "http://...", "resign_stripe": false}')
        try:
            result = await run_in_threadpool(replay_and_record, store, config, rec, payload["to"],
                                             resign=bool(payload.get("resign_stripe")))
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        return {"target": result.target, "resigned": result.resigned, "status_code": result.status_code,
                "error": result.error, "elapsed_ms": result.elapsed_ms, "response_body": result.response_body}

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True, "stored": store.count()}

    return app
