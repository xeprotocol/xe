"""/v1: the public surface. Public vocabulary (copy/public.yaml); nothing here uses company terms."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time

from fastapi import APIRouter, HTTPException, Path, Query, Request
from fastapi.responses import RedirectResponse
from sse_starlette.sse import EventSourceResponse

from .. import __version__
from ..auth import POW_RULE, SignedRequest, accept, addressee, member_action, require_pow, verify_signed
from ..canonical import DOMAIN_INBOX_HTTP, DOMAIN_MEMBER_ACTION, DOMAIN_PROPOSAL, DOMAIN_VOTE
from ..db import release, session
from ..log import EventLog, event_to_dict, log_key
from ..ratelimit import INBOX, NODE_READ, PROPOSAL, SNAPSHOT, STREAMS, VOTE, enforce_ip
from ..services import inbox as inbox_svc
from ..services import pause as pause_svc
from ..services import portal, records
from ..text import field_text
from ..worker_schedule import next_runs
from .deps import Ctx, Db

router = APIRouter(prefix="/v1", tags=["public"])
log = logging.getLogger("dao.api")


@router.get("")
async def manifest(ctx: Ctx, db: Db):
    head = await EventLog.head(db)
    base = ctx.settings.public_base_url
    return {
        "name": "XE DAO",
        "network": ctx.node.badge,
        "network_id": ctx.node.network_id,
        "version": __version__,
        "git_commit": ctx.settings.git_commit,
        "mode": ctx.config.mode,
        "paused": await pause_svc.is_paused(db),
        "accounts": {
            "dao": inbox_svc.dao_account(ctx),
            "fee": portal.fee_account(ctx),
        },
        "log_head": {"index": head.index, "hash": head.hash},
        "endpoints": {
            "legal": f"{base}/v1/legal/identifier",
            "charter": f"{base}/v1/charter",
            "seats": f"{base}/v1/seats",
            "proposals": f"{base}/v1/proposals",
            "log": f"{base}/v1/log",
            "events": f"{base}/v1/events",
            "inbox": f"{base}/v1/inbox",
            "health": f"{base}/v1/health",
            "schedule": f"{base}/v1/schedule/next",
        },
        "signing": {
            "method": "ed25519 over sha256(domain || canonical_json({dao, network, payload, timestamp}))",
            "to": addressee(ctx),
            "domains": {
                "proposal": DOMAIN_PROPOSAL.decode().rstrip("\x00"),
                "vote": DOMAIN_VOTE.decode().rstrip("\x00"),
                "inbox": DOMAIN_INBOX_HTTP.decode().rstrip("\x00"),
                "member_action": DOMAIN_MEMBER_ACTION.decode().rstrip("\x00"),
            },
            "note": "domain bytes are the string followed by a single 0x00 byte; dao and network are the values "
                    "in `to`, so a signature is for this deployment and no other; a member-action payload "
                    "names its `action`",
        },
        "rules": ctx.config.pinned_rules(),
    }


@router.get("/charter")
async def charter(ctx: Ctx):
    return {"sha256": ctx.config.charter_hash, "markdown": ctx.config.charter_md}


@router.get("/seats")
async def seats(ctx: Ctx):
    return {
        "mode": ctx.config.mode,
        "people": [{"id": s.id, "name": s.name, "role": s.role, "public_key": s.public_key or None,
                    "account": s.account or None,
                    "page": f"{ctx.settings.public_base_url}/seats/{s.slug}"} for s in ctx.config.human_seats],
        "agents": [{"id": a.id, "role": a.role, "summary": a.summary, "class": a.cls, "status": a.status,
                    "model": a.model or None, "account": a.account or None, "tool_scopes": list(a.tool_scopes),
                    "prompt_hash": ctx.config.prompt_hash(a.id) or None,
                    "prompt": f"{ctx.settings.public_base_url}/v1/seats/{a.id}/prompt",
                    "page": f"{ctx.settings.public_base_url}/seats/{a.slug}"} for a in ctx.config.agent_seats],
        "tool_scopes": ctx.config.tool_scope_glossary,
        "preamble_hash": ctx.config.hashes.get("prompts/_preamble.md"),
        "note": "prompt_hash = sha256(preamble + seat prompt); recorded on every analysis a seat produces",
    }


@router.get("/seats/{seat_id}/prompt")
async def seat_prompt(seat_id: str, ctx: Ctx):
    """The exact text a seat is given: the shared preamble, then the seat prompt. Public, versioned, hashed."""
    body = ctx.config.prompts.get(seat_id)
    if body is None or seat_id.startswith("_"):
        raise HTTPException(404, "no prompt for this seat")
    return {"seat": seat_id, "hash": ctx.config.prompt_hash(seat_id),
            "preamble_hash": ctx.config.hashes.get("prompts/_preamble.md"),
            "seat_prompt_hash": ctx.config.hashes.get(f"prompts/{seat_id}.md"),
            "preamble": ctx.config.prompts.get("_preamble", ""), "prompt": body}


# ---- proposals and votes ----------------------------------------------------------------------

@router.get("/proposals")
async def list_proposals(db: Db, status: str | None = None, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200)):
    rows = await portal.list_proposals(db, status, offset, limit)
    return {"proposals": [portal.to_dict(p, include_body=False) for p in rows], "counts": await portal.counts(db)}


@router.post("/proposals", status_code=201)
async def submit_proposal(request: Request, req: SignedRequest, ctx: Ctx, db: Db):
    enforce_ip(request, PROPOSAL)
    v = verify_signed(ctx, req, DOMAIN_PROPOSAL)
    await accept(db, v, PROPOSAL)
    pr = await portal.submit(ctx, db, v)
    await db.commit()
    return portal.to_dict(pr)


@router.get("/proposals/{h}")
async def get_proposal(h: str, db: Db, ctx: Ctx):
    pr = await portal.get(db, h)
    return portal.to_dict(pr, await portal.votes_for(db, pr.hash), ctx=ctx)


@router.get("/proposals/{h}/votes")
async def proposal_votes(h: str, db: Db, ctx: Ctx):
    pr = await portal.get(db, h)
    votes = await portal.votes_for(db, pr.hash)
    return {"proposal": pr.hash, "tally": portal.shown_tally(pr, votes, ctx),
            "votes": [{"account": v.account, "choice": v.choice, "weight": v.weight, "participating": v.participating,
                       "is_agent": v.is_agent, "timestamp": v.timestamp, "reason": v.reason, "signature": v.signature,
                       "pub_key": v.pub_key} for v in votes]}


@router.post("/proposals/{h}/votes", status_code=201)
async def cast_vote(request: Request, h: str, req: SignedRequest, ctx: Ctx, db: Db):
    enforce_ip(request, VOTE)
    v = verify_signed(ctx, req, DOMAIN_VOTE)
    await accept(db, v, VOTE)
    pr = await portal.get(db, h)
    row = await portal.vote(ctx, db, pr, v)
    await db.commit()
    return {"account": row.account, "choice": row.choice, "weight": row.weight, "participating": row.participating,
            "eligibility": row.eligibility}


@router.post("/votes", status_code=201)
async def cast_vote_flat(request: Request, req: SignedRequest, ctx: Ctx, db: Db):
    """Same as POST /proposals/{hash}/votes; the proposal hash comes from the signed payload."""
    enforce_ip(request, VOTE)
    v = verify_signed(ctx, req, DOMAIN_VOTE)
    await accept(db, v, VOTE)
    pr = await portal.get(db, field_text(v.payload, "proposal"))
    row = await portal.vote(ctx, db, pr, v)
    await db.commit()
    return {"account": row.account, "choice": row.choice, "weight": row.weight, "participating": row.participating,
            "eligibility": row.eligibility}


@router.get("/decisions")
async def decisions(db: Db, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0, le=2**31 - 1)):
    """Decided proposals newest first; those awaiting a decision oldest first, with how many there are in
    all (`awaiting_total`). `offset` pages both lists."""
    rows = await portal.list_proposals(db, "decided", offset, limit)
    closed = await portal.awaiting_decision(db, limit, offset)
    return {"decided": [portal.to_dict(p, include_body=False) for p in rows],
            "awaiting_decision": [portal.to_dict(p, include_body=False) for p in closed],
            "awaiting_total": await portal.count_awaiting_decision(db), "offset": offset, "limit": limit}


@router.get("/snapshot/{account}")
async def snapshot(request: Request, account: str, ctx: Ctx, db: Db, proposal: str | None = Query(None, max_length=64)):
    """What a wallet's vote is worth. With `proposal` (a proposal hash): on that proposal, under the rules
    and the snapshot time pinned to it when it opened. Without: on a proposal opened now, under the rules
    it would pin. Either way it is the vote's own derivation (`portal.eligibility`), given what the vote
    is given, so the preview and the vote cannot answer different questions (XE-2210). The earlier form
    took a time and applied today's rules to it, which is the question of no vote: a proposal keeps the
    rules it opened under, and a preview of it under later ones would promise a weight the vote does not
    give. Reads the wallet's whole chain from the node, so it is metered like a vote."""
    account = account.lower()
    if not portal.HEX64.fullmatch(account):
        raise HTTPException(400, "account must be 64 hex characters")
    enforce_ip(request, SNAPSHOT)
    is_agent = account in ctx.config.agent_accounts
    if proposal is None:
        snap, reasons, participating, weight = await portal.eligibility_at(
            ctx, ctx.config.pinned_rules(), portal.snapshot_time(time.time_ns()), account, is_agent)
    else:
        pr = await portal.get(db, proposal)
        # On a proposal that has closed, a wallet that voted is told what its vote was recorded with: that is
        # what the result counted, and a second derivation from the chain as it reads today is not (XE-4460).
        row = None if pr.status == "open" else await portal.vote_of(db, pr.hash, account)
        if row is not None:
            kept = row.eligibility or {}
            snap, reasons = kept.get("snapshot") or {}, kept.get("not_participating_because") or []
            participating, weight = row.participating, row.weight
        else:
            await release(db)   # the rows are read; the node is not waited on with a pooled connection in hand (XE-4318)
            snap, reasons, participating, weight = await portal.eligibility(ctx, pr, account, is_agent)
    return {"account": account, **snap, "weight": weight, "participating": participating,
            "not_participating_because": reasons}


# ---- inbox ------------------------------------------------------------------------------------

@router.get("/inbox")
async def inbox_info(ctx: Ctx, db: Db, limit: int = Query(50, ge=1, le=200)):
    rows = await inbox_svc.list_public(db, limit)
    return {
        "account": inbox_svc.dao_account(ctx),
        "how": "send an XE chat envelope to the account above, or POST a signed message here with a proof of work",
        "pow": {
            "difficulty": f"0x{ctx.node.chat_pow_difficulty:016x}",
            "rule": POW_RULE + "; signing_digest = sha256(domain || 0x00 || canonical_json({dao, network, payload, timestamp})), "
                    "dao and network as published at GET /v1 under signing.to",
            "domain": DOMAIN_INBOX_HTTP.rstrip(b"\x00").decode(),
        },
        "logging": "messages sent here are kept in the hash chain on receipt and appear here and on the public log once a member has read them",
        "recent": [inbox_svc.to_dict(m) for m in rows],
    }


@router.post("/inbox", status_code=201)
async def inbox_post(request: Request, req: SignedRequest, ctx: Ctx, db: Db):
    """Signed message plus a chat-level proof of work over the signing digest (see GET /v1/inbox for the rule)."""
    enforce_ip(request, INBOX)
    v = verify_signed(ctx, req, DOMAIN_INBOX_HTTP)
    require_pow(v, ctx.node.chat_pow_difficulty)   # the work is paid before anything touches the database (XE-0699)
    await accept(db, v, INBOX)
    m = await inbox_svc.http_submit(ctx, db, v)
    await db.commit()
    return inbox_svc.to_dict(m)


@router.get("/inbox/{mid}")
async def inbox_get(mid: str, db: Db):
    """One message with its replies; an untriaged HTTP message is not here until a member has read it."""
    m = await inbox_svc.get_public(db, mid)
    return inbox_svc.to_dict(m, await inbox_svc.replies_for(db, mid))


# ---- log --------------------------------------------------------------------------------------

@router.get("/log")
async def log_page(db: Db, offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=1000), kind: str | None = None, ref: str | None = None):
    rows = await EventLog.page(db, offset, limit, kind, ref)
    head = await EventLog.head(db)
    return {"head": {"index": head.index, "hash": head.hash}, "events": [event_to_dict(e) for e in rows]}


@router.get("/log/head")
async def log_head(ctx: Ctx, db: Db):
    head = await EventLog.head(db)
    return {"index": head.index, "hash": head.hash,
            "signer": ctx.signer.public_key("harness") if ctx.signer.has("harness") else None,
            "anchors": await records.anchors(db, 5)}


@router.get("/log/verify")
async def log_verify(ctx: Ctx, db: Db):
    """Replays the chain and checks every event is signed by the harness key published at /v1/log/head, and
    that the events written before the v2 envelope are as the `log.v1_sealed` entry recorded them (`legacy`
    in the answer says how many there are and whether they are sealed; unsealed, the log does not verify)."""
    return await EventLog.verify_cached(db, log_key(ctx.signer))


@router.get("/log/{index}")
async def log_get(db: Db, index: int = Path(ge=0, le=2**63 - 1)):
    ev = await EventLog.get(db, index)
    if ev is None or not ev.public:
        raise HTTPException(404, "no such event")
    return event_to_dict(ev)


STREAM_BATCH = 200   # log entries read per pass of the event stream
RESUME_RE = re.compile(r"-?[0-9]{1,18}")   # ASCII digits only: `\d` would take any script's digits


@router.get("/events")
async def events_stream(request: Request, ctx: Ctx, after: int | None = Query(None, ge=0, le=2**63 - 1)):
    """Server-sent events. Each public log entry is sent as `event: entry` (kind inside the data) as it
    lands in the database, whichever process wrote it; `event: ping` every 15 s. Resumes from
    `Last-Event-ID` or `?after=<index>`. Browsers navigating here directly are sent to /live.

    The one long-lived response: it takes no request-scoped session (that would pin a pooled connection
    for as long as the stream is open, and twenty streams would hold the whole pool, XE-1237). Every read,
    including the first, is its own short session; between polls the stream holds no connection. Opening
    a stream spends a node-read token, and an address holds a few at most (`STREAMS`), so streams cannot
    be opened or accumulated without bound."""
    accept = request.headers.get("accept", "")
    if "text/html" in accept and "text/event-stream" not in accept:
        return RedirectResponse("/live", status_code=302)
    enforce_ip(request, NODE_READ)
    # Everything that can refuse the request happens before the slot is taken, and the slot is held only
    # by a generator whose `finally` releases it; nothing between take and the response can raise (XE-1673).
    resume = request.headers.get("last-event-id", "")
    if resume and not RESUME_RE.fullmatch(resume):
        raise HTTPException(400, "Last-Event-ID must be an integer")
    holder = STREAMS.take(request)
    try:
        async with session() as s:
            head = await EventLog.head(s)
    except BaseException:
        STREAMS.release(holder)
        raise
    last_index = int(resume) if resume else (after if after is not None else head.index)
    wake: asyncio.Queue = asyncio.Queue(maxsize=1000)
    ctx.events.subscribe(wake)  # same-process appends shortcut the poll interval

    async def gen():
        nonlocal last_index
        idle_since = time.monotonic()
        try:
            while not await request.is_disconnected():
                async with session() as s:
                    rows = await EventLog.since(s, last_index, limit=STREAM_BATCH)
                for ev in rows:
                    last_index = ev.index
                    idle_since = time.monotonic()
                    yield {"event": "entry", "id": str(ev.index), "data": json.dumps(event_to_dict(ev))}
                if time.monotonic() - idle_since >= 15:
                    idle_since = time.monotonic()
                    yield {"event": "ping", "data": json.dumps({"ts": time.time_ns(), "last": last_index})}
                if len(rows) >= STREAM_BATCH:
                    # A full batch means there is more behind it: read on. The wait below is for a stream
                    # that has caught up; taken after every batch it held a resuming reader to one batch
                    # every three seconds however far behind it was (XE-4267).
                    continue
                try:
                    await asyncio.wait_for(wake.get(), timeout=3)
                    while not wake.empty():
                        wake.get_nowait()
                except asyncio.TimeoutError:
                    pass
        finally:
            ctx.events.unsubscribe(wake)
            STREAMS.release(holder)

    return EventSourceResponse(gen())


# ---- schedule and health ----------------------------------------------------------------------

@router.get("/schedule/next")
async def schedule_next(ctx: Ctx, db: Db):
    return {"jobs": await next_runs(ctx, db)}


@router.get("/health")
async def health(ctx: Ctx, db: Db):
    """The last recorded check, and whether it is recent enough to mean anything: a check older than a few
    cadences says the worker is not running, which is not ok whatever the row says (XE-0908)."""
    last = await records.last_health(db)
    stale = records.health_is_stale(ctx, last)
    return {"ok": bool(last and last.get("ok")) and not stale, "stale": stale,
            "last_check_age_s": records.health_age_s(last), "cadence_s": records.cadence_s(ctx),
            "last_check": last, "uptime_30d": await records.uptime_30d_shown(ctx, db),
            "paused": await pause_svc.is_paused(db)}


@router.get("/ready")
async def ready(ctx: Ctx, db: Db):
    try:
        await EventLog.head(db)
    except Exception as e:
        # what failed goes to the server's log; a caller is told that it did and nothing of how (XE-6983)
        log.warning("ready: the database read failed: %s: %s", type(e).__name__, e)
        raise HTTPException(503, "database not ready") from e
    return {"ready": True, "network_id": ctx.node.network_id}


# ---- signed member/officer actions on the public router (analysis, decision) -------------------

@router.post("/proposals/{h}/analysis", status_code=201)
async def proposal_analysis(request: Request, h: str, req: SignedRequest, ctx: Ctx, db: Db):
    v = await member_action(request, db, ctx, req, "add_analysis", proposal=h)
    pr = await portal.get(db, h, lock=True)
    await portal.add_analysis(ctx, db, pr, v)
    await db.commit()
    return portal.to_dict(pr)


@router.post("/proposals/{h}/decision", status_code=201)
async def proposal_decision(request: Request, h: str, req: SignedRequest, ctx: Ctx, db: Db):
    v = await member_action(request, db, ctx, req, "decide_proposal", proposal=h)
    if not (v.seat.is_member or v.seat.can("operational_review")):
        raise HTTPException(403, "decisions are recorded by members or an officer with operational_review")
    pr = await portal.get(db, h, lock=True)
    await portal.decide(ctx, db, pr, v)
    await db.commit()
    return portal.to_dict(pr)
