"""FastAPI application: JSON API under /v1, server-rendered pages elsewhere."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.exc import DataError, IntegrityError, StatementError
from starlette.exceptions import HTTPException as StarletteHTTPException

from xe.client import XeError

from . import __version__
from .api import legal, members, public
from .config import lint_public_copy, public_template_prose
from .context import get_context
from .db import session
from .mirror import MarkdownMirror
from .settings import get_settings
from .ui import router as ui_router

log = logging.getLogger("dao.app")
NODE_REFRESH_S = 300
NODE_RETRY_S = 15   # while the network is not confirmed, every signed request is refused: ask again soon
HERE = Path(__file__).parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.basicConfig(level=get_settings().logging_level, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    ctx = get_context()
    await ctx.refresh_node()
    violations = lint_public_copy(ctx.config, public_template_prose())   # the pages too, as `dao copy-lint` reads them (XE-5986)
    app.state.copy_violations = violations
    if violations:
        log.warning("public copy lint: %d violation(s): %s", len(violations), violations[:5])
    try:
        async with session() as db:
            await ctx.events.append(db, "api.started", "harness", {
                "version": __version__, "network_id": ctx.node.network_id, "git_commit": ctx.settings.git_commit,
                "config_hashes": ctx.config.hashes, "copy_lint_violations": len(violations),
            }, public=True)
            await db.commit()
    except Exception as e:
        log.warning("could not write api.started (database not ready?): %s", e)

    async def keep_identity():
        # What the pages, the manifest and every signed request's addressee take from `ctx.node` is asked
        # again on a timer, as the worker does with each health check: read once at start, an API process
        # that came up while the node was down served no network id until it was restarted (XE-2475).
        while True:
            await asyncio.sleep(NODE_REFRESH_S if ctx.node.network_id else NODE_RETRY_S)
            try:
                await ctx.refresh_node()
            except Exception as e:   # refresh_node keeps what it has on any failure; nothing here ends the task
                log.warning("node identity refresh: %s", e)
    refresher = asyncio.create_task(keep_identity())
    yield
    refresher.cancel()
    await ctx.aclose()


app = FastAPI(title="XE DAO", version=__version__, lifespan=lifespan, docs_url="/v1/docs", openapi_url="/v1/openapi.json")

app.include_router(public.router)
app.include_router(legal.router)
app.include_router(members.router)
app.include_router(ui_router)
app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")
# every page as markdown: /x.md, /index.md, or Accept: text/markdown
app.add_middleware(MarkdownMirror, base_url=lambda: get_context().settings.public_base_url)

# The largest legitimate write is a resolution (50k chars of body plus ops of up to 64 KiB each); anything
# past a megabyte is not a request we have a route for, and is refused before it is parsed.
MAX_BODY_BYTES = 1 << 20
# A declared length is a number of few enough digits to be one. `int()` of a long enough run of digits
# raises, and nothing a client puts in a header is allowed to raise out of a middleware (XE-11273).
_LENGTH = re.compile(rb"[0-9]{1,18}")


class BodyLimit:
    def __init__(self, app, limit: int = MAX_BODY_BYTES):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") not in ("POST", "PUT", "PATCH"):
            return await self.app(scope, receive, send)
        declared = next((v for k, v in scope.get("headers", []) if k == b"content-length"), None)
        if declared is not None and not _LENGTH.fullmatch(declared):
            return await self._refuse(send, 400, "content-length is not a length")
        if declared is not None and int(declared) > self.limit:
            return await self._refuse(send)
        seen = 0
        tripped = False
        answered = False

        async def counted():
            nonlocal seen, tripped
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > self.limit:
                    tripped = True
                    raise _TooLarge()
            return msg

        async def guarded(msg):
            # Once the stream is cut, whatever the app answers (FastAPI turns an error in its body reader
            # into its own 400) is replaced by the one 413 in the common shape (XE-0650).
            nonlocal answered
            if not tripped:
                return await send(msg)
            if not answered:
                answered = True
                await self._refuse(send)

        try:
            await self.app(scope, counted, guarded)
        except _TooLarge:
            pass
        if tripped and not answered:
            await self._refuse(send)

    @staticmethod
    async def _refuse(send, status: int = 413, error: str = "request body too large"):
        body = json.dumps({"error": error, "status": status}, separators=(",", ":")).encode()
        await send({"type": "http.response.start", "status": status, "headers": [
            (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})


class _TooLarge(Exception):
    pass


app.add_middleware(BodyLimit)


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    headers = dict(exc.headers or {})
    if request.url.path.startswith("/v1"):
        return JSONResponse({"error": exc.detail, "status": exc.status_code}, status_code=exc.status_code, headers=headers)
    from .ui import render
    resp = render(request, "error.html", {"status": exc.status_code, "detail": exc.detail}, status_code=exc.status_code)
    resp.headers.update(headers)
    return resp


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    """Same shape as every other error: one line naming the field, no echo of the input (XE-0080)."""
    first = (exc.errors() or [{}])[0]
    where = ".".join(str(x) for x in first.get("loc", []) if x not in ("body", "query", "path"))
    detail = f"{where}: {first.get('msg', 'invalid')}" if where else str(first.get("msg", "invalid request"))
    if request.url.path.startswith("/v1"):
        return JSONResponse({"error": detail, "status": 422}, status_code=422)
    from .ui import render
    return render(request, "error.html", {"status": 422, "detail": detail}, status_code=422)


@app.exception_handler(StatementError)
async def statement_error(request: Request, exc: StatementError):
    """A parameter the database cannot hold (U+0000 in text, an integer past int64) is the caller's error,
    whichever read or write path carried it (XE-0967). Anything else from the driver is still ours."""
    if callers_data(exc):
        log.info("unrepresentable parameter on %s %s: %s", request.method, request.url.path,
                 type(exc.orig).__name__)
        return await http_error(request, StarletteHTTPException(400, "a parameter is not representable"))
    return await unhandled_error(request, exc)


def callers_data(exc: StatementError) -> bool:
    """Whether a statement failed on the value it was given rather than on anything of ours. The first
    version asked for SQLAlchemy's DataError or a bare ValueError as the cause, and the asyncpg dialect
    raises neither for the cases the handler was written for: a NUL in a text parameter comes back from
    Postgres as SQLSTATE 22021 wrapped as a plain DBAPIError, and a value the driver cannot encode is its
    own error with the ValueError one link further down. So the handler never fired and a NUL in a path
    still answered 500 (XE-2775). What is read here is what the driver reports: class 22 (data exception)
    anywhere in the chain of causes, or an encode failure anywhere in it."""
    if isinstance(exc, DataError):
        return True
    e, links = exc.orig, 0
    while e is not None and links < 6:
        code = getattr(e, "sqlstate", None) or getattr(e, "pgcode", None)
        if isinstance(e, (OverflowError, ValueError)) or (isinstance(code, str) and code.startswith("22")):
            return True
        e, links = e.__cause__ or e.__context__, links + 1
    return False


@app.exception_handler(IntegrityError)
async def integrity_error(request: Request, exc: IntegrityError):
    """Two requests wrote the same unique key and the database kept one: a fee block reused by two submits,
    a pause started twice. The loser's request conflicts with a write that has since landed; it is a 409 to
    retry or re-read, never a 500, on every table with a unique key (XE-1290, XE-1435). The transaction is
    already rolled back by the session's exit."""
    log.info("conflicting write on %s %s: %s", request.method, request.url.path, str(exc.orig)[:200])
    return await http_error(request, StarletteHTTPException(409, "conflicts with a write that has just landed; re-read and retry"))


@app.exception_handler(XeError)
async def node_error(request: Request, exc: XeError):
    """The node refused or failed a read the request needed: a 502 that says so, not a 500 that says nothing."""
    log.warning("node error on %s %s: %s", request.method, request.url.path, exc)
    return await http_error(request, StarletteHTTPException(502, "node error"))


@app.exception_handler(OverflowError)
async def overflow_error(request: Request, exc: OverflowError):
    """The driver raises this bare when an integer parameter does not fit int64; it is the caller's number."""
    return await http_error(request, StarletteHTTPException(400, "a parameter is not representable"))


@app.exception_handler(RecursionError)
async def recursion_error(request: Request, exc: RecursionError):
    """A body nested deeper than the parser or a walk of it will go is the caller's body: a 400, on every
    route and whichever step reached the bottom first (the body parser, an op value's text, a digest),
    not a 500 that reads as a fault of ours (XE-4124, XE-5877). Logged, since a walk of our own data that
    ended here would be ours to fix."""
    log.warning("recursion limit on %s %s", request.method, request.url.path)
    return await http_error(request, StarletteHTTPException(400, "the request is nested too deeply"))


@app.exception_handler(Exception)
async def unhandled_error(request: Request, exc: Exception):
    """Anything we did not expect: log it in full here, say nothing specific to the client (XE-0080)."""
    log.exception("unhandled error on %s %s", request.method, request.url.path)
    if request.url.path.startswith("/v1"):
        return JSONResponse({"error": "internal error", "status": 500}, status_code=500)
    from .ui import render
    return render(request, "error.html", {"status": 500, "detail": "internal error"}, status_code=500)


class HeadAsGet:
    """Pure ASGI, outermost. A HEAD is answered as the GET of the same path with the body left off: the
    status and the headers a GET would get, its content-length included. Every route here is declared
    for GET, and a router refuses a method a route does not name, so HEAD was a 405 on every page and
    every `/v1` read that exists (XE-14722). Answered here, once, a route is covered by being a GET
    route, the markdown twins and the static files with the rest, and one added later is too.

    The answer is complete when the headers are out, whatever the route goes on to write: the empty body
    that ends it is sent with them, and from then on the app is told the client has gone. A response
    that never ends by itself (the event stream) ends on that, as it does when a reader of the GET
    leaves; a HEAD that waited for the route to finish would wait on that one for as long as the
    connection lasted, and the connection's next request with it."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") != "HEAD":
            return await self.app(scope, receive, send)
        answered = False

        async def headers_only(message):
            nonlocal answered
            if message["type"] == "http.response.start" and not answered:
                answered = True
                await send(message)
                await send({"type": "http.response.body", "body": b""})
            # the body, every part of it, goes nowhere

        async def left():
            if answered:
                return {"type": "http.disconnect"}
            return await receive()

        await self.app({**scope, "method": "GET"}, left, headers_only)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    # Pages carry seat keys in the signer; everything they load is first-party except the fonts, and they
    # talk only to this origin. Inline scripts remain (the page scripts), so this bounds exfiltration and
    # injection surface rather than script execution (XE-0702).
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'",
    )
    if request.url.path.startswith("/v1"):
        resp.headers.setdefault("Access-Control-Allow-Origin", "*")
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp


# added last, so it is the first to see a request: everything below it sees a GET
app.add_middleware(HeadAsGet)
