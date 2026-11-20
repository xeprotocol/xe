"""Pause: the one lever that stops the harness, held by members only.

One member may pause for 72 hours on a written determination naming a ground. Both members may
extend by 7 days at a time. A public post is due within 4 hours; the harness drafts it in the
members' plain words and publishes it automatically at the deadline if nobody has edited it.
While paused: no outbound chat, no fee movements, no state-chain block built, signed or submitted,
no new registry or anchor sessions, no agent output. Reads, the log, the portal's vote intake, session
approvals (record-keeping) and the inbox stay up, so the DAO stays addressable: the worker keeps its
directory entry alive, a signed record naming only its own node peer, because letting it lapse would
turn away every message sent to the DAO during the pause (XE-1445). A pause is the company suspending
its own operations; it does not touch the chain. `is_paused` is read inside the transaction of every
chain write, not only at job start.
"""

from __future__ import annotations

import secrets
import time

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .. import signatures
from ..auth import Verified
from ..context import Context
from ..db import locked, serialize
from ..models import PauseRecord
from ..text import clean_text, field_text

H = 3600 * 1_000_000_000
# What the opening of a record session is serialised on, by kind (`records._sole_open`), and what `start`
# takes so that a pause and such an opening are one before the other.
RECORD_SESSION_LOCKS = {"anchor": "session.open.anchor", "registry": "session.open.registry"}
D = 24 * H


def in_force(r: PauseRecord) -> bool:
    """A pause is in force by its clock, not by its stored status: the worker marks a lapsed row `expired`
    on its next pass, and until then the row still reads `active`. Every reader and every member action on
    a pause asks this, so a lapsed pause cannot be extended back to life, lifted after it ended, or given a
    public post (XE-1726, XE-1893)."""
    return r.status == "active" and (r.indefinite or r.expires_at > time.time_ns())


def require_in_force(r: PauseRecord) -> None:
    if not in_force(r):
        raise HTTPException(409, "pause is not active" if r.status != "active" else "pause has expired")


async def active(db: AsyncSession) -> PauseRecord | None:
    # As the database holds them now: a session that read a pause before it was extended still held the
    # row with its first expiry, and judged the pause by that for as long as the session lived.
    q = select(PauseRecord).where(PauseRecord.status == "active").execution_options(populate_existing=True)
    rows = (await db.execute(q)).scalars().all()
    for r in rows:
        if in_force(r):
            return r
    return None


async def is_paused(db: AsyncSession) -> bool:
    return (await active(db)) is not None


def ended_at(r: PauseRecord, now: int) -> int:
    """When a pause stopped being in force, by the same clock `in_force` reads; `now` if it has not."""
    if r.lifted_at is not None:
        return min(r.lifted_at, now)
    return now if r.indefinite else min(r.expires_at, now)


async def paused_ns(db: AsyncSession, since_ns: int, until_ns: int | None = None) -> int:
    """How much of the span the system spent paused. A clock that counts time a job had to do its work
    takes this off: under a pause the job does nothing, by design, and that is not time it spent trying
    (XE-12679). One pause is active at a time (`ux_pause_one_active`), so the spans do not overlap."""
    until = time.time_ns() if until_ns is None else until_ns
    rows = (await db.execute(select(PauseRecord).where(PauseRecord.started_at < until))).scalars().all()
    return sum(max(0, ended_at(r, until) - max(r.started_at, since_ns)) for r in rows)


async def start(ctx: Context, db: AsyncSession, v: Verified) -> PauseRecord:
    cfg = ctx.config.pause
    ground = field_text(v.payload, "ground")
    text = clean_text(v.payload.get("determination"), "determination", max_len=20_000)
    if ground not in cfg.get("grounds", []):
        raise HTTPException(400, f"ground must be one of {cfg.get('grounds', [])}")
    if len(text) < 20:
        raise HTTPException(400, "a written determination is required")
    # A record session being opened at this moment is either before the pause or refused by it: the two
    # take the same lock, and the open asks whether a pause is in force once it holds it (XE-4126). The
    # open does not wait on the node while it holds the lock, so neither does this.
    for lock in RECORD_SESSION_LOCKS.values():
        await serialize(db, lock)
    await expire_lapsed(ctx, db)
    await db.flush()
    now = time.time_ns()
    r = PauseRecord(id=secrets.token_hex(8), determined_by=v.seat.id, ground=ground, determination=text,
                    started_at=now, expires_at=now + int(cfg.get("initial_hours", 72)) * H, indefinite=False,
                    extensions=[], lifted_by=[], post_text=_draft_post(ctx, ground), status="active")
    db.add(r)
    try:
        # The pause is a singleton and the database says so: one active row (`ux_pause_one_active`). Two
        # members pausing at once are serialised by the index, not by a read that each can pass (XE-1176).
        await db.flush()
    except IntegrityError as e:
        raise HTTPException(409, "already paused") from e
    await ctx.events.append(db, "pause.started", v.actor, {
        "pause_id": r.id, "ground": ground, "determination": text, "started_at": now, "expires_at": r.expires_at,
        "public_post_due": now + int(cfg.get("public_post_within_hours", 4)) * H,
    }, ref=f"pause:{r.id}")
    return r


def _draft_post(ctx: Context, ground: str) -> str:
    plain = {
        "exploit_or_irreversible_loss": "we found something that could cause irreversible loss",
        "legal_compulsion": "we have been legally required to",
        "both_members_agree": "the two of us agreed it was the right call",
    }.get(ground, "we judged it necessary")
    return (f"We have paused the automated side of the DAO because {plain}. Reads, the log and the portal stay up. "
            f"Nothing moves while this is in place. We will post again within the pause window with what we found "
            f"and what happens next.")


def _signers(ctx: Context) -> dict[str, str]:
    """The seats whose signature a pause counts: current members who hold the pause right, each with the
    key it holds today. The set that is counted is the set the routes let sign, so consent can always be
    reached (XE-1013)."""
    return {s.id: s.public_key for s in ctx.config.members if s.can("pause")}


def _consent(ctx: Context, sigs: list[dict]) -> tuple[bool, int, list[str]]:
    """Every seat in `_signers` must hold a signature that counts (`dao.signatures`): (met, live_count,
    set_aside_seats)."""
    seats = _signers(ctx)
    live, set_aside = signatures.counting(seats, sigs)
    return len(live) >= len(seats), len(live), set_aside


def _signed(ctx: Context, sigs: list[dict], v: Verified, refusal: str, **said: str) -> list[dict]:
    """`said` is what this signer wrote with the signature (a reason). It is kept on the signature, so what
    a record shows a member as having said is what that member signed (XE-7207)."""
    return signatures.add(_signers(ctx), sigs, {"seat": v.seat.id, "public_key": v.pub_key, "signature": v.signature,
                                                "timestamp": v.timestamp, **{k: x for k, x in said.items() if x}}, refusal)


def _without(sigs: list[dict], seat: str) -> list[dict]:
    return [s for s in sigs if s["seat"] != seat]


def _reasons(sigs: list[dict]) -> list[dict]:
    return [{"seat": s["seat"], "reason": s["reason"]} for s in sigs if s.get("reason")]


# Two things are collected on a pause, and they are opposite: signatures to extend it and signatures to lift
# it. Each needs every member, so each is consent to one outcome for the pause as it stood when the member
# signed. Two consequences, enforced in `extend` and `lift` below and nowhere else (XE-5577):
#
# - a member's latest signature is that member's position. Signing to extend withdraws the member's standing
#   signature to lift, and signing to lift withdraws the member's signature on an extension not yet applied;
# - an extension that applies starts the pause's next term, and nothing collected toward lifting the term
#   before it carries over. Without this, a member who signed to lift and then joined in extending could be
#   taken, by the other member alone, to have lifted the pause both had just agreed to keep.

async def extend(ctx: Context, db: AsyncSession, r: PauseRecord, v: Verified) -> PauseRecord:
    """Extensions need every current member: the first signature is recorded, the last applies it. Each
    signature carries its signer's own reason; the extension has no reason of its own to attribute to both."""
    require_in_force(r)
    pending = [e for e in r.extensions if not e.get("applied")]
    reason = clean_text(v.payload.get("reason"), "reason", max_len=2000, required=False)
    sigs = _signed(ctx, pending[0]["signatures"] if pending else [], v, "this member already signed this extension",
                   reason=reason)
    entry = {"signatures": sigs, "applied": False}
    withdrew = len(r.lifted_by) != len(_without(r.lifted_by, v.seat.id))
    r.lifted_by = _without(r.lifted_by, v.seat.id)
    met, n_live, set_aside = _consent(ctx, sigs)
    if met:
        entry["applied"] = True
        entry["signatures"] = signatures.counting(_signers(ctx), sigs)[0]   # what it was applied with, and no others
        base = max(r.expires_at, time.time_ns())
        r.expires_at = base + int(ctx.config.pause.get("extension_days", 7)) * D
        entry["new_expires_at"] = r.expires_at
        r.lifted_by = []
    r.extensions = [*[e for e in r.extensions if e.get("applied")], entry]
    await ctx.events.append(db, "pause.extended" if entry["applied"] else "pause.extension_signed", v.actor, {
        "pause_id": r.id, "expires_at": r.expires_at, "signatures": n_live,
        **({"reasons": _reasons(entry["signatures"])} if entry["applied"] else {"reason": reason}),
        **({"withdrew_lift_signature": True} if withdrew else {}),
        **({"set_aside": set_aside} if set_aside else {}),
    }, ref=f"pause:{r.id}")
    return r


async def lift(ctx: Context, db: AsyncSession, r: PauseRecord, v: Verified) -> PauseRecord:
    """Lifting early needs every current member, like an extension."""
    require_in_force(r)
    r.lifted_by = _signed(ctx, r.lifted_by, v, "already signed")
    withdrew = False
    for e in r.extensions:
        if not e.get("applied") and any(s["seat"] == v.seat.id for s in e.get("signatures", [])):
            withdrew = True
    if withdrew:   # rebuilt, not edited in place: the column is JSON and is saved when it is assigned
        r.extensions = [e if e.get("applied") else {**e, "signatures": _without(e.get("signatures", []), v.seat.id)}
                        for e in r.extensions]
    met, n_live, set_aside = _consent(ctx, r.lifted_by)
    if met:
        r.status = "lifted"
        r.lifted_by = signatures.counting(_signers(ctx), r.lifted_by)[0]   # what it was lifted with, and no others
        r.lifted_at = time.time_ns()
        await ctx.events.append(db, "pause.lifted", v.actor, {"pause_id": r.id, "lifted_at": r.lifted_at,
                                                               **({"set_aside": set_aside} if set_aside else {})}, ref=f"pause:{r.id}")
    else:
        await ctx.events.append(db, "pause.lift_signed", v.actor, {"pause_id": r.id, "signatures": n_live,
                                                                    **({"withdrew_extension_signature": True} if withdrew else {}),
                                                                    **({"set_aside": set_aside} if set_aside else {})}, ref=f"pause:{r.id}")
    return r


async def set_post(ctx: Context, db: AsyncSession, r: PauseRecord, v: Verified) -> PauseRecord:
    """The public post is written while the pause is in force; a lifted or expired pause's record stands."""
    require_in_force(r)
    text = clean_text(v.payload.get("text"), "text", max_len=20_000)
    r.post_text = text
    if r.posted_at:
        await ctx.events.append(db, "pause.post_updated", v.actor, {"pause_id": r.id, "text": text}, ref=f"pause:{r.id}")
    else:
        await publish_post(ctx, db, r, v.actor)
    return r


async def publish_post(ctx: Context, db: AsyncSession, r: PauseRecord, actor: str) -> None:
    r.posted_at = time.time_ns()
    await ctx.events.append(db, "pause.posted", actor, {"pause_id": r.id, "text": r.post_text}, ref=f"pause:{r.id}")


async def _due_rows(db: AsyncSession, *predicates) -> list[PauseRecord]:
    """Active rows matching the predicates, each FOR UPDATE SKIP LOCKED: a member's extend, lift or post on
    the same row either waits for this writer or is skipped by it, never overwritten (XE-0987)."""
    q = locked(select(PauseRecord).where(PauseRecord.status == "active", *predicates), skip_locked=True)
    return list((await db.execute(q)).scalars().all())


async def expire_lapsed(ctx: Context, db: AsyncSession) -> int:
    now = time.time_ns()
    rows = await _due_rows(db, PauseRecord.indefinite.is_(False), PauseRecord.expires_at <= now)
    for r in rows:
        r.status = "expired"
        await ctx.events.append(db, "pause.expired", "harness", {"pause_id": r.id, "expires_at": r.expires_at}, ref=f"pause:{r.id}")
    return len(rows)


async def tick(ctx: Context, db: AsyncSession) -> None:
    """Worker: expire lapsed pauses, then auto-publish overdue posts for the ones still in force."""
    await expire_lapsed(ctx, db)
    now = time.time_ns()
    due_h = int(ctx.config.pause.get("public_post_within_hours", 4))
    for r in await _due_rows(db, PauseRecord.posted_at.is_(None), PauseRecord.started_at <= now - due_h * H):
        if in_force(r):
            await publish_post(ctx, db, r, "harness")


async def history(db: AsyncSession, limit: int = 50, offset: int = 0) -> list[PauseRecord]:
    return list((await db.execute(select(PauseRecord).order_by(PauseRecord.started_at.desc(), PauseRecord.id.desc())
                                  .offset(offset).limit(limit))).scalars().all())


async def count_history(db: AsyncSession) -> int:
    return int((await db.execute(select(func.count()).select_from(PauseRecord))).scalar_one())


def to_dict(ctx: Context, r: PauseRecord) -> dict:
    """Signature counts are the counts the gate uses. What is still being collected on an active pause (an
    extension not yet applied, the lift) shows the signatures that count now, so a reader never sees "2"
    beside a step that is waiting for a second signature; what is done shows what it was done with."""
    def count(sigs: list[dict], pending: bool) -> int:
        return _consent(ctx, sigs)[1] if pending and r.status == "active" else len(sigs)
    return {
        "id": r.id, "status": r.status, "determined_by": r.determined_by, "ground": r.ground,
        "determination": r.determination, "started_at": r.started_at, "expires_at": r.expires_at,
        "indefinite": r.indefinite,
        "extensions": [{"applied": e.get("applied"), "signatures": count(e.get("signatures", []), not e.get("applied")),
                        "new_expires_at": e.get("new_expires_at"), "reasons": _reasons(e.get("signatures", []))}
                       for e in r.extensions],
        "lifted_at": r.lifted_at, "lift_signatures": count(r.lifted_by, True), "post_text": r.post_text, "posted_at": r.posted_at,
    }
