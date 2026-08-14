"""FastAPI application factory."""
from __future__ import annotations

import base64
import contextvars
import logging
import re
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.gzip import GZipMiddleware

from hub import __version__
from hub.auth import COOKIE_NAME, require_auth
from hub.config import cfg
from hub.errors import error_payload
from hub.macos_admin import use_admin_password
from hub.paths import LEGACY_INDEX, STATIC_DIR
from hub.routers import router
from hub.routers.auth_api import router as auth_router
from hub.terminal_pty import terminal_websocket
from hub.vm_console import console_websocket

#: Bound per request so ``serverhub.*`` log lines can carry a correlation id
#: without every call site threading the Request through.
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "serverhub_request_id", default="-"
)

_REQUEST_ID_RE = re.compile(r"\A[A-Za-z0-9._-]{1,128}\Z")


#: Handlers are attached to the "serverhub" parent, not to the root logger.
#: Nothing in this project configured logging at all, so every
#: ``logging.getLogger("serverhub.…").info(…)`` in the codebase was discarded:
#: with no handler anywhere, Python's lastResort handler takes over and it starts
#: at WARNING.  That is why the only pre-existing logger (hub/macos_admin.py) logs
#: exclusively at warning level.  Configuring "serverhub" rather than the root
#: keeps uvicorn's own loggers untouched -- they carry their own handlers and
#: propagate=False, so duplicating records there would double every access line.
_LOG_ROOT = "serverhub"


def _configure_logging() -> None:
    """Send serverhub.* records to stderr, which launchd captures to the log file.

    Idempotent: create_app() runs once per process in production but many times
    across the test suite, and adding a handler per call would multiply every
    line by the number of apps built so far.
    """
    logger = logging.getLogger(_LOG_ROOT)
    if any(getattr(h, "_serverhub", False) for h in logger.handlers):
        return
    handler = logging.StreamHandler()

    class _RequestIdFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            record.request_id = request_id_var.get("-")
            return True

    handler.addFilter(_RequestIdFilter())
    handler.setFormatter(
        logging.Formatter("%(levelname)s:    %(name)s: [%(request_id)s] %(message)s")
    )
    handler._serverhub = True  # type: ignore[attr-defined]
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    # Without this the records also reach the root logger, and uvicorn's
    # configuration of it would print them a second time.
    logger.propagate = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    from hub import alerts, metrics, network_svc, tools_svc

    s = cfg().get("settings") or {}
    # SSD-friendly defaults: 90s metrics / 90s alerts (was 30/30)
    metrics.start_sampler(int(s.get("metrics_interval") or 90))
    alerts.start_alerter(int(s.get("alert_interval") or 90))
    # `brew outdated` + `softwareupdate -l` is ~11.5s. Warm it in the background
    # so the first visitor to the Tools page reads a cache instead of waiting.
    log = logging.getLogger("serverhub.lifespan")
    try:
        tools_svc.start_updates_warmer()
    except Exception:
        log.exception("updates warmer failed to start")
    # Keep managed IP aliases on the highest-priority active NIC
    try:
        network_svc.start_alias_autobind()
    except Exception:
        log.exception("alias autobind failed to start")
    try:
        yield
    finally:
        # Explicit shutdown keeps reloads/tests from leaving duplicate workers.
        metrics.stop_sampler()
        alerts.stop_alerter()
        network_svc.stop_alias_autobind()
        tools_svc.stop_updates_warmer()


async def admin_password_scope(request: Request):
    """Scope a web-entered macOS administrator password to this one request.

    Privileged endpoints answer "admin.password_required" unless this header is
    present; the SPA then shows its own password dialog and retries with it.
    The value is base64-encoded UTF-8 so passwords containing non-latin
    characters survive the HTTP header round trip.  It is decoded once, held in
    a request-scoped contextvar, and never logged or persisted.
    """
    raw = (request.headers.get("x-admin-password") or "").strip()
    password = ""
    if raw:
        try:
            password = base64.b64decode(raw.encode("ascii"), validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            password = ""
    if password:
        with use_admin_password(password):
            yield
    else:
        yield


def create_app() -> FastAPI:
    _configure_logging()
    # This is a host-control API, not a public developer service.  FastAPI's
    # defaults expose /docs, /redoc and /openapi.json without authentication;
    # the schema enumerates privileged operations such as container exec, file
    # deletion/upload and nginx/cloudflared control even though those operations
    # themselves correctly return 401.  Keep schema generation available through
    # app.openapi() for internal tests, but do not register unauthenticated HTTP
    # routes that publish the blueprint to every LAN client.
    app = FastAPI(
        title="ServerHub",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # Compress large JSON/text payloads (status/network/logs) to cut LAN transfer.
    app.add_middleware(GZipMiddleware, minimum_size=1024)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        incoming = (request.headers.get("x-request-id") or "").strip()
        rid = incoming if _REQUEST_ID_RE.match(incoming) else uuid.uuid4().hex
        request_id_token = request_id_var.set(rid)
        try:
            # Browsers send Origin/Sec-Fetch-Site on cross-site mutations.  Reject
            # those requests while keeping curl, the menu-bar client and same-origin
            # SPA calls compatible.  This matters even when optional auth is off.
            if request.method not in {"GET", "HEAD", "OPTIONS", "TRACE"}:
                def reject(code: str) -> JSONResponse:
                    # Middleware cannot raise HTTPException, so build the same
                    # {"detail": {"code", "message"}} body the SPA translates.
                    status, body = error_payload(code)
                    return JSONResponse(body, status_code=status)

                site = request.headers.get("sec-fetch-site", "").lower()
                if site == "cross-site":
                    resp = reject("auth.cross_site_denied")
                else:
                    origin = request.headers.get("origin")
                    host = request.headers.get("host")
                    resp = None
                    if origin and host:
                        from urllib.parse import urlsplit

                        try:
                            if urlsplit(origin).netloc.lower() != host.lower():
                                resp = reject("auth.cross_site_denied")
                        except ValueError:
                            resp = reject("auth.bad_origin")
                    # Cookie sessions are the CSRF-prone path.  Menu-bar / curl
                    # callers use the local-token header (or no cookie) and stay
                    # compatible when Origin/Sec-Fetch-Site are absent.  A browser
                    # with a session cookie must present matching Origin or a
                    # non-cross-site Sec-Fetch-Site value.
                    if resp is None and request.cookies.get(COOKIE_NAME):
                        if origin and host:
                            pass  # already verified equal above
                        elif site in {"same-origin", "same-site", "none"}:
                            pass
                        else:
                            resp = reject("auth.cross_site_denied")
                    if resp is None:
                        resp = await call_next(request)
            else:
                resp = await call_next(request)
            resp.headers.setdefault("X-Request-ID", rid)
            # Defensive headers — cheap and non-breaking for a local SPA panel.
            resp.headers.setdefault("X-Content-Type-Options", "nosniff")
            resp.headers.setdefault("X-Frame-Options", "DENY")
            resp.headers.setdefault("Referrer-Policy", "same-origin")
            resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
            resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
            resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
            resp.headers.setdefault(
                "Content-Security-Policy",
                "default-src 'self'; base-uri 'none'; object-src 'none'; "
                "frame-ancestors 'none'; form-action 'self'; img-src 'self' data:; "
                "style-src 'self' 'unsafe-inline'; script-src 'self'; "
                "connect-src 'self';",
            )
            if request.url.scheme == "https" or (
                request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
                == "https"
            ):
                resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            if request.url.path.startswith("/assets/"):
                # Vite filenames are content-hashed, so they are safe to cache hard.
                resp.headers.setdefault("Cache-Control", "public, max-age=31536000, immutable")
            elif request.url.path == "/" or not request.url.path.startswith("/api/"):
                # SPA shell/routes must revalidate so a new build is picked up.
                resp.headers.setdefault("Cache-Control", "no-cache")
            elif request.method == "GET" and request.url.path.startswith("/api/"):
                # Do not consume body_iterator here.  File downloads, SSE, and other
                # streaming API responses must retain their incremental delivery and
                # backpressure characteristics.
                resp.headers.setdefault("Cache-Control", "private, max-age=3")
            return resp
        finally:
            request_id_var.reset(request_id_token)

    app.include_router(auth_router)
    app.include_router(
        router,
        dependencies=[Depends(require_auth), Depends(admin_password_scope)],
    )
    # WebSocket routes do not run HTTP dependency injection. Both handlers below
    # apply their own stricter session + same-origin checks before accepting.
    app.add_api_websocket_route("/api/terminal/ws", terminal_websocket)
    # The console bridge additionally requires a single-use ticket bound to the
    # requesting browser session, so a long-lived cookie alone cannot open it.
    app.add_api_websocket_route(
        "/api/vms/{console_id}/console/ws", console_websocket
    )

    if STATIC_DIR.is_dir() and (STATIC_DIR / "index.html").exists():
        assets = STATIC_DIR / "assets"
        if assets.is_dir():
            app.mount("/assets", StaticFiles(directory=assets), name="assets")

        @app.get("/")
        def index_spa():
            return FileResponse(STATIC_DIR / "index.html")

        static_root = STATIC_DIR.resolve()
        index_file = static_root / "index.html"

        @app.get("/{full_path:path}")
        def spa_fallback(full_path: str):
            if full_path == "api" or full_path.startswith("api/"):
                return HTMLResponse("Not Found", status_code=404)
            try:
                candidate = (static_root / full_path).resolve()
            except (OSError, ValueError):
                # A path the filesystem cannot even represent is, by definition,
                # not a static file, so the SPA shell is the right answer. This
                # used to raise and return 500: a request path of a few thousand
                # characters gives OSError "File name too long", and %00 decodes to
                # an embedded null which Path rejects with ValueError. Any scanner
                # or stale link hitting the panel produced a 500 and a traceback in
                # the log, which reads like a broken server rather than a bad URL.
                return FileResponse(index_file)
            # Never serve files outside the static dir (path-traversal guard).
            if candidate == static_root or static_root in candidate.parents:
                try:
                    if candidate.is_file():
                        return FileResponse(candidate)
                except OSError:
                    # Same class of unrepresentable path, reached via stat().
                    pass
            return FileResponse(index_file)
    else:

        @app.get("/", response_class=HTMLResponse)
        def index_legacy():
            return LEGACY_INDEX.read_text()

    return app
