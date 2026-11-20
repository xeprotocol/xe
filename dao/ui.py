"""Server-rendered pages. Public pages speak the public register; /records and /members speak the
legal register. Writes happen from the browser via the signed JSON API, never through forms."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import yaml
from fastapi import APIRouter, Query, Request
from fastapi import Path as PathParam
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from markdown_it import MarkdownIt
from markupsafe import Markup

from xe.amounts import from_micro

from . import __version__
from .chainops import snapshot_time
from .context import get_context
from .db import session
from .log import EventLog, event_to_dict
from .mirror import build_llms_txt, md_path
from .ratelimit import NODE_READ, enforce_ip
from .services import inbox as inbox_svc
from .services import pause as pause_svc
from .services import portal, records, resolutions, sessions

router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _fmt_ns(ns: int | None) -> str:
    if not ns:
        return ""
    return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _short(h: str | None, n: int = 10) -> str:
    return (h[:n] + "…") if h and len(h) > n else (h or "")


templates.env.filters["ns"] = _fmt_ns
templates.env.filters["short"] = _short
templates.env.filters["xe"] = lambda v: from_micro(int(v or 0))
templates.env.filters["md_path"] = md_path

# Config-authored markdown only (prompts, charter), never user input; and HTML off regardless, so the
# renderer is safe by configuration and not only by what reaches it (XE-0702).
_md = MarkdownIt("commonmark", {"html": False, "linkify": False})


def _render_md(text: str | None) -> Markup:
    return Markup(_md.render(text or ""))


templates.env.filters["md"] = _render_md


def render(request: Request, name: str, ctx: dict, status_code: int = 200) -> HTMLResponse:
    c = get_context()
    base = {
        "request": request, "copy": c.config.copy_public, "legal": c.config.copy_legal, "badge": c.node.badge,
        "network_id": c.node.network_id, "dao_account": c.config.accounts.get("dao", ""),
        "version": __version__, "base_url": c.settings.public_base_url,
        "node_url": c.settings.xe_node_url, "mode": c.config.mode,
    }
    return templates.TemplateResponse(request, name, {**base, **ctx}, status_code=status_code)


async def _common(db):
    head = await EventLog.head(db)
    return {"paused": await pause_svc.active(db), "head": head}


@router.get("/llms.txt", response_class=PlainTextResponse)
async def llms_txt():
    """The reading list for agents (llmstxt.org). Built from config, so it moves with the seats."""
    c = get_context()
    text = build_llms_txt(c.config, c.settings.public_base_url, c.node.network_id, c.config.mode)
    return PlainTextResponse(text, media_type="text/plain; charset=utf-8")


@router.get("/", response_class=HTMLResponse)
async def home(request: Request):
    c = get_context()
    async with session() as db:
        common = await _common(db)
        open_props = await portal.list_proposals(db, "open", 0, 6)
        recent = await EventLog.page(db, 0, 12)
        counts = await portal.counts(db)
    return render(request, "home.html", {
        **common, "proposals": open_props, "events": recent, "counts": counts, "rules": c.config.pinned_rules(),
        "dao_account": inbox_svc.dao_account(c), "fee_account": portal.fee_account(c), "seats": c.config,
    })


@router.get("/proposals", response_class=HTMLResponse)
async def proposals_page(request: Request, status: str | None = None, offset: int = Query(0, ge=0)):
    async with session() as db:
        common = await _common(db)
        rows = await portal.list_proposals(db, status, offset, 50)
        counts = await portal.counts(db)
    return render(request, "proposals.html", {**common, "proposals": rows, "status": status, "counts": counts, "offset": offset})


@router.get("/proposals/new", response_class=HTMLResponse)
async def proposal_new(request: Request):
    c = get_context()
    async with session() as db:
        common = await _common(db)
    return render(request, "proposal_new.html", {**common, "rules": c.config.pinned_rules(), "fee_account": portal.fee_account(c)})


@router.get("/proposals/{h}", response_class=HTMLResponse)
async def proposal_page(request: Request, h: str):
    async with session() as db:
        common = await _common(db)
        pr = await portal.get(db, h)
        votes = await portal.votes_for(db, pr.hash)
        events = await EventLog.page(db, 0, 50, ref=f"proposal:{pr.hash}")
    return render(request, "proposal.html", {**common, "p": pr, "votes": votes, "tally": portal.shown_tally(pr, votes, get_context()), "events": events,
                                             "snapshot_at": snapshot_time(pr.opened_at)})


@router.get("/seats", response_class=HTMLResponse)
async def seats_page(request: Request):
    c = get_context()
    async with session() as db:
        common = await _common(db)
    return render(request, "seats.html", {**common, "cfg": c.config})


@router.get("/seats/{slug}", response_class=HTMLResponse)
async def seat_page(request: Request, slug: str):
    c = get_context()
    async with session() as db:
        common = await _common(db)
    hit = c.config.seat_page(slug)
    if hit is None:
        return render(request, "error.html", {**common, "status": 404, "detail": "no such seat"}, status_code=404)
    kind, seat = hit
    ctx: dict = {**common, "cfg": c.config, "kind": kind, "seat": seat, "glossary": c.config.tool_scope_glossary}
    if kind == "agent":
        body = c.config.prompts.get(seat.id, "")
        # drop the "# Seat: ..." title line; the page supplies its own heading
        lines = body.split("\n")
        if lines and lines[0].startswith("# "):
            body = "\n".join(lines[1:]).lstrip("\n")
        ctx.update({
            "prompt_md": body, "preamble_md": c.config.prompts.get("_preamble", ""),
            "prompt_hash": c.config.prompt_hash(seat.id),
            "preamble_hash": c.config.hashes.get("prompts/_preamble.md", ""),
            "seat_prompt_hash": c.config.hashes.get(f"prompts/{seat.id}.md", ""),
        })
    return render(request, "seat.html", ctx)


@router.get("/charter", response_class=HTMLResponse)
async def charter_page(request: Request):
    c = get_context()
    async with session() as db:
        common = await _common(db)
    body = c.config.charter_md
    lines = body.split("\n")
    if lines and lines[0].startswith("# "):
        body = "\n".join(lines[1:]).lstrip("\n")
    return render(request, "charter.html", {**common, "charter_md": body, "charter_hash": c.config.charter_hash})


@router.get("/how-it-works", response_class=HTMLResponse)
async def how_page(request: Request):
    c = get_context()
    async with session() as db:
        common = await _common(db)
    return render(request, "how.html", {**common, "cfg": c.config})


@router.get("/decisions", response_class=HTMLResponse)
async def decisions_page(request: Request):
    async with session() as db:
        common = await _common(db)
        decided = await portal.list_proposals(db, "decided", 0, 100)
        closed = await portal.awaiting_decision(db, 100)
        closed_total = await portal.count_awaiting_decision(db)
    return render(request, "decisions.html", {**common, "decided": decided, "closed": closed, "closed_total": closed_total})


@router.get("/decisions/example", response_class=HTMLResponse)
async def decision_record_example(request: Request):
    """The worked example in config/examples; the shape every real record will have once seats are on."""
    c = get_context()
    async with session() as db:
        common = await _common(db)
    with (c.config.dir / "examples" / "decision_record.yaml").open("r", encoding="utf-8") as f:
        record = yaml.safe_load(f)
    return render(request, "decision_record.html", {**common, "r": record})


@router.get("/log", response_class=HTMLResponse)
async def log_page(request: Request, offset: int = Query(0, ge=0), kind: str | None = None, ref: str | None = None):
    async with session() as db:
        common = await _common(db)
        rows = await EventLog.page(db, offset, 100, kind, ref)
    return render(request, "log.html", {**common, "events": rows, "offset": offset, "kind": kind, "ref": ref})


@router.get("/live", response_class=HTMLResponse)
async def live_page(request: Request):
    async with session() as db:
        common = await _common(db)
        head = await EventLog.head(db)   # read before the page, so the stream starts no later than the page ends
        rows = await EventLog.page(db, 0, 25)
    return render(request, "live.html", {**common, "events": rows, "head_index": head.index})


@router.get("/log/{index}", response_class=HTMLResponse)
async def log_entry(request: Request, index: int = PathParam(ge=0, le=2**63 - 1)):
    async with session() as db:
        common = await _common(db)
        ev = await EventLog.get(db, index)
    if ev is None or not ev.public:
        return render(request, "error.html", {**common, "status": 404, "detail": "no such entry"}, status_code=404)
    return render(request, "log_entry.html", {**common, "e": ev, "d": event_to_dict(ev)})


@router.get("/inbox", response_class=HTMLResponse)
async def inbox_page(request: Request):
    c = get_context()
    async with session() as db:
        common = await _common(db)
        rows = await inbox_svc.list_public(db, 100)
    return render(request, "inbox.html", {**common, "messages": rows, "dao_account": inbox_svc.dao_account(c),
                                          "pow_difficulty": f"0x{c.node.chat_pow_difficulty:016x}"})


@router.get("/records", response_class=HTMLResponse)
async def records_page(request: Request):
    enforce_ip(request, NODE_READ)
    c = get_context()
    async with session() as db:
        common = await _common(db)
        res = await resolutions.list_resolutions(db)
        anchors = await records.anchors(db, 10)
        hist = await pause_svc.history(db)
    ks = await records.public_keyset(c)
    onchain = await records.onchain_registry(c)
    treasury = await records.treasury(c)
    return render(request, "records.html", {
        **common, "cfg": c.config, "keyset": ks, "registry_intended": records.registry_value(c), "registry_onchain": onchain,
        "resolutions": res, "anchors": anchors, "pause_history": hist, "treasury": treasury, "reserved": sorted(resolutions.RESERVED_MATTERS),
        "res_dict": lambda r: resolutions.to_dict(r, c.config), "git_commit": c.settings.git_commit,
    })


@router.get("/members", response_class=HTMLResponse)
async def members_page(request: Request):
    enforce_ip(request, NODE_READ)
    c = get_context()
    async with session() as db:
        common = await _common(db)
        # what is waiting on a member first and whole (open resolutions, oldest first), then the recent rest
        res = [*await resolutions.open_resolutions(db),
               *[r for r in await resolutions.list_resolutions(db) if r.status != "open"]]
        # the same for sessions: every one a member can still act on, then the recent rest. A page of the
        # newest hundred hid an open session behind the weekly anchors that had come and gone since.
        sess = [*await sessions.open_sessions(db),
                *[s for s in await sessions.list_sessions(db) if s.status not in sessions.OPEN]]
        msgs = await inbox_svc.list_public(db, 100)
        closed = await portal.awaiting_decision(db, 50)
        closed_total = await portal.count_awaiting_decision(db)
    ks = await records.public_keyset(c)
    return render(request, "members.html", {
        **common, "cfg": c.config, "resolutions": res, "sessions": sess, "messages": msgs,
        "closed": closed, "closed_total": closed_total, "keyset": ks, "reserved": sorted(resolutions.RESERVED_MATTERS),
        "ordinary": sorted(resolutions.ORDINARY_MATTERS),
        "res_dict": lambda r: resolutions.to_dict(r, c.config), "sess_dict": lambda s: sessions.to_dict(s, ks),
    })
