"""/v1/members/*: the seat holders' actions. Every POST carries a SignedRequest and goes through one door,
`auth.seat_request`: the address is metered, the signature checked, the seat and its right resolved from the
key, and only then is anything written. The path routes the request; the signature authorises it, so the
payload names the action (`member_action`) and the thing acted on. A resolution signature and an ops
approval have domains of their own, and those payloads are checked against the record they sign. The GETs
here are public reads of public records (sessions appear on /records and in the log); `whoami` is a key
lookup (XE-0652).

The action names are the API: `tests/test_seat_requests.py` holds the table and walks every route here.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from ..auth import SignedRequest, member_action, seat_request
from ..canonical import DOMAIN_OPS_APPROVAL, DOMAIN_RESOLUTION
from ..db import locked, release
from ..ratelimit import NODE_READ, enforce_ip
from ..services import inbox as inbox_svc
from ..services import pause as pause_svc
from ..services import records, resolutions, sessions
from ..text import clean_text, field_text
from .deps import Ctx, Db

router = APIRouter(prefix="/v1/members", tags=["members"])


@router.get("/whoami/{pub_key}")
async def whoami(pub_key: str, ctx: Ctx):
    s = ctx.config.seat_by_key(pub_key)
    if not s:
        raise HTTPException(404, "no seat for this key")
    return {"seat": s.id, "name": s.name, "kind": s.kind, "role": s.role, "may": list(s.may), "account": s.account}


# ---- resolutions ------------------------------------------------------------------------------

@router.post("/resolutions", status_code=201)
async def propose_resolution(request: Request, req: SignedRequest, ctx: Ctx, db: Db):
    v = await member_action(request, db, ctx, req, "propose_resolution")
    if field_text(v.payload, "matter") in resolutions.RESERVED_MATTERS and not v.seat.is_member:
        raise HTTPException(403, "reserved matters are proposed by members")
    r = await resolutions.propose(ctx, db, v)
    await db.commit()
    return resolutions.to_dict(r, ctx.config)


@router.post("/resolutions/{res_id}/sign", status_code=201)
async def sign_resolution(request: Request, res_id: str, req: SignedRequest, ctx: Ctx, db: Db):
    """payload = {resolution_id, body_hash, decision}; signed under the resolution domain."""
    v = await seat_request(request, db, ctx, req, DOMAIN_RESOLUTION, right=resolutions.SIGN_RIGHT, members_only=True,
                           resolution_id=res_id)
    r = await resolutions.get(db, res_id, lock=True)
    await resolutions.decide(ctx, db, r, v, field_text(v.payload, "decision"))
    await db.commit()
    return resolutions.to_dict(r, ctx.config)


@router.post("/resolutions/{res_id}/withdraw")
async def withdraw_resolution(request: Request, res_id: str, req: SignedRequest, ctx: Ctx, db: Db):
    v = await member_action(request, db, ctx, req, "withdraw_resolution", resolution_id=res_id)
    r = await resolutions.get(db, res_id, lock=True)
    await resolutions.withdraw(ctx, db, r, v)
    await db.commit()
    return resolutions.to_dict(r, ctx.config)


# ---- signing sessions (state chain) -----------------------------------------------------------

async def _shown(ctx, s) -> dict:
    """A session as these routes return it: counted against the keyset as it is now (`sessions.to_dict`).
    The keyset is the read the public pages share. Every caller asks once its transaction is over (the
    commit of what it wrote, or `release` for a read): the node is not waited on with the log or a
    connection held (XE-14181, XE-4318)."""
    return sessions.to_dict(s, await records.public_keyset(ctx))


@router.get("/sessions")
async def list_sessions(ctx: Ctx, db: Db, status: str | None = None, offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=200)):
    rows = await sessions.list_sessions(db, status, limit=limit, offset=offset)
    total = await sessions.count_sessions(db, status)
    await release(db)
    ks = await records.public_keyset(ctx)
    return {"sessions": [sessions.to_dict(s, ks) for s in rows], "total": total, "offset": offset, "limit": limit}


@router.get("/sessions/{sid}")
async def get_session(request: Request, sid: str, ctx: Ctx, db: Db):
    if sid in ("registry", "anchor"):
        # The two paths that open a session take a POST. Read with GET they matched this route as a
        # session id and answered "not found" for a path that exists (XE-11401).
        raise HTTPException(405, "Method Not Allowed", headers={"Allow": "POST"})
    enforce_ip(request, NODE_READ)   # `stale` asks the node for its tip
    s = await sessions.get(db, sid)
    await release(db)   # nothing below reads the database, and the node is not waited on with a connection held (XE-4318)
    d = await _shown(ctx, s)
    d["stale"] = await sessions.is_stale(ctx, s)
    return d


@router.post("/sessions/registry", status_code=201)
async def open_registry(request: Request, req: SignedRequest, ctx: Ctx, db: Db):
    v = await member_action(request, db, ctx, req, "open_registry_session", members_only=True)
    if await pause_svc.is_paused(db):
        raise HTTPException(409, "paused")
    out = await records.open_registry_session(ctx, db, v.actor)
    await db.commit()
    return out


@router.post("/sessions/anchor", status_code=201)
async def open_anchor(request: Request, req: SignedRequest, ctx: Ctx, db: Db):
    # Members only, like the registry: an anchor session takes the next number in the register (XE-0483).
    v = await member_action(request, db, ctx, req, "open_anchor_session", members_only=True)
    if await pause_svc.is_paused(db):
        raise HTTPException(409, "paused")
    out = await records.open_anchor_session(ctx, db, v.actor)
    await db.commit()
    return out


@router.post("/sessions/{sid}/approve", status_code=201)
async def approve_session(request: Request, sid: str, req: SignedRequest, ctx: Ctx, db: Db):
    """payload = {session_id, ops_digest}; signed under the ops-approval domain by a keyset key."""
    v = await seat_request(request, db, ctx, req, DOMAIN_OPS_APPROVAL, right=sessions.SIGN_RIGHT, session_id=sid)
    s = await sessions.get(db, sid, lock=True)
    await sessions.approve(ctx, db, s, v)
    await db.commit()
    return await _shown(ctx, s)


@router.post("/sessions/{sid}/rebuild")
async def rebuild_session(request: Request, sid: str, req: SignedRequest, ctx: Ctx, db: Db):
    """Rebuild the block at the live tip. Only when the tip has moved: a rebuild discards every signature
    collected so far, so at an unchanged tip one seat could loop it and stall signing (XE-0882)."""
    v = await member_action(request, db, ctx, req, "rebuild_session", right=sessions.SIGN_RIGHT, session_id=sid)
    s = await sessions.get(db, sid, lock=True)
    await sessions.rebuild_if_stale(ctx, db, s, actor=v.actor)
    await db.commit()
    return await _shown(ctx, s)


@router.post("/sessions/{sid}/sign", status_code=201)
async def sign_session_block(request: Request, sid: str, req: SignedRequest, ctx: Ctx, db: Db):
    """payload = {block_hash, block_signature}. The outer SignedRequest proves the seat; the inner
    block_signature is the raw ed25519 signature over the block hash bytes that goes on chain."""
    v = await member_action(request, db, ctx, req, "sign_session", right=sessions.SIGN_RIGHT, session_id=sid)
    s = await sessions.get(db, sid, lock=True)
    if field_text(v.payload, "block_hash") != s.block_hash:
        raise HTTPException(409, "block hash has changed (tip moved); fetch the session again and re-sign")
    await sessions.sign(ctx, db, s, v.pub_key, field_text(v.payload, "block_signature"), v.actor)
    await db.commit()
    return await _shown(ctx, s)


@router.post("/sessions/{sid}/cancel")
async def cancel_session(request: Request, sid: str, req: SignedRequest, ctx: Ctx, db: Db):
    v = await member_action(request, db, ctx, req, "cancel_session", members_only=True, session_id=sid)
    s = await sessions.get(db, sid, lock=True)
    await sessions.cancel(ctx, db, s, v, clean_text(v.payload.get("reason"), "reason", max_len=2000, required=False))
    await db.commit()
    return await _shown(ctx, s)


# ---- pause ------------------------------------------------------------------------------------

@router.post("/pause", status_code=201)
async def start_pause(request: Request, req: SignedRequest, ctx: Ctx, db: Db):
    v = await member_action(request, db, ctx, req, "start_pause", right="pause", members_only=True)
    r = await pause_svc.start(ctx, db, v)
    await db.commit()
    return pause_svc.to_dict(ctx, r)


@router.post("/pause/{pid}/extend")
async def extend_pause(request: Request, pid: str, req: SignedRequest, ctx: Ctx, db: Db):
    v = await member_action(request, db, ctx, req, "extend_pause", right="pause", members_only=True, pause_id=pid)
    r = await _pause(db, pid)
    await pause_svc.extend(ctx, db, r, v)
    await db.commit()
    return pause_svc.to_dict(ctx, r)


@router.post("/pause/{pid}/lift")
async def lift_pause(request: Request, pid: str, req: SignedRequest, ctx: Ctx, db: Db):
    v = await member_action(request, db, ctx, req, "lift_pause", right="pause", members_only=True, pause_id=pid)
    r = await _pause(db, pid)
    await pause_svc.lift(ctx, db, r, v)
    await db.commit()
    return pause_svc.to_dict(ctx, r)


@router.post("/pause/{pid}/post")
async def pause_post(request: Request, pid: str, req: SignedRequest, ctx: Ctx, db: Db):
    v = await member_action(request, db, ctx, req, "post_pause", right="pause", members_only=True, pause_id=pid)
    r = await _pause(db, pid)
    await pause_svc.set_post(ctx, db, r, v)
    await db.commit()
    return pause_svc.to_dict(ctx, r)


async def _pause(db, pid: str):
    from sqlalchemy import select
    from ..models import PauseRecord
    r = (await db.execute(locked(select(PauseRecord).where(PauseRecord.id == pid)))).scalar_one_or_none()
    if r is None:
        raise HTTPException(404, "pause not found")
    return r


# ---- inbox handling ---------------------------------------------------------------------------

@router.post("/inbox/untriaged")
async def inbox_untriaged(request: Request, req: SignedRequest, ctx: Ctx, db: Db):
    """HTTP messages no member has looked at yet. Signed by a seat holder: these are the one part of the
    inbox the public surfaces hold back (XE-0195), so reading them is a seat action like answering them."""
    await member_action(request, db, ctx, req, "list_untriaged")
    offset = req.payload.get("offset", 0)
    if not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= 2**31:
        raise HTTPException(400, "offset must be a non-negative integer")
    rows = await inbox_svc.list_untriaged(db, 100, offset)
    total = await inbox_svc.count_untriaged(db)
    await db.commit()   # the signature claim is a write even though the action is a read (XE-0647)
    return {"messages": [inbox_svc.to_dict(m) for m in rows], "total": total, "offset": offset, "limit": 100}


@router.post("/inbox/{mid}/reply", status_code=201)
async def inbox_reply(request: Request, mid: str, req: SignedRequest, ctx: Ctx, db: Db):
    # Replying publishes a held message and speaks for the DAO: members only (XE-0635).
    v = await member_action(request, db, ctx, req, "reply_message", members_only=True, message_id=mid)
    m = await inbox_svc.get(db, mid, lock=True)
    o = await inbox_svc.reply(ctx, db, m, v)
    await db.commit()
    return {"queued": o.id, "to": o.to_account}


@router.post("/inbox/{mid}/status")
async def inbox_status(request: Request, mid: str, req: SignedRequest, ctx: Ctx, db: Db):
    v = await member_action(request, db, ctx, req, "set_message_status", members_only=True, message_id=mid)
    m = await inbox_svc.get(db, mid, lock=True)
    await inbox_svc.set_status(ctx, db, m, v)
    await db.commit()
    return inbox_svc.to_dict(m)


# ---- notes ------------------------------------------------------------------------------------

@router.post("/notes", status_code=201)
async def post_note(request: Request, req: SignedRequest, ctx: Ctx, db: Db):
    """A signed public note from a seat holder, straight into the log (daily notes, explanations)."""
    v = await member_action(request, db, ctx, req, "post_note")
    text = clean_text(v.payload.get("text"), "text", max_len=20_000)
    title = clean_text(v.payload.get("title"), "title", max_len=160, required=False)
    ev = await ctx.events.append(db, "note", v.actor, {"title": title, "text": text,
                                                       "signature": v.signature, "timestamp": v.timestamp})
    await db.commit()
    return {"index": ev.index, "hash": ev.hash}
