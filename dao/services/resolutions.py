"""Member resolutions: the company path.

A resolution is text (and optionally state-chain ops) proposed by a seat and signed by members.
Reserved matters need every member; ordinary matters need a majority of members. Once passed, a
resolution with ops opens a signing session; one without ops is simply recorded.
"""

from __future__ import annotations

import logging
import secrets
import time
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from xe.client import XeError

from .. import signatures
from ..auth import Verified
from ..context import Context
from ..db import locked, serialize
from ..faults import reason
from ..log import EventLog
from ..models import Proposal, Resolution
from ..text import clean_text, field_text
from . import portal, sessions

log = logging.getLogger("dao.resolutions")

RESERVED_MATTERS = {
    "amend_articles", "amend_operating_agreement", "admit_member", "remove_member", "dissolve",
    "change_keyset", "change_treasury_policy", "change_quorum", "designate_agent", "retire_agent",
    "change_schedule_b", "change_schedule_c", "spend", "borrow", "contract",
}
ORDINARY_MATTERS = {"note", "registry", "anchor", "parameter", "respond", "adopt_open_vote", "decline_open_vote", "other"}
SIGN_RIGHT = "sign_resolutions"   # the seat right that lets a member sign a resolution (`dao.api.members`)


def _signers(cfg) -> dict[str, str]:
    """The seats whose signature a resolution counts: the current members who hold the right to sign one,
    each with the key it holds today. The set that is counted is the set the route lets sign, as it is
    for a pause (XE-1013): a member without the right is not waited for, and a signature given by a seat
    that has since lost the right is set aside like one from a seat that has left."""
    return {s.id: s.public_key for s in cfg.members if s.can(SIGN_RIGHT)}


def _matter_rule(cfg, matter: str) -> tuple[int, str]:
    n = len(_signers(cfg))
    if matter in RESERVED_MATTERS:
        return max(n, 1), "all members"
    return (n // 2) + 1, "majority of members"


async def _next_number(db: AsyncSession) -> int:
    await serialize(db, "resolution.number")   # two proposers at once take consecutive numbers (XE-1290)
    return int((await db.execute(select(func.coalesce(func.max(Resolution.number), 0)))).scalar_one()) + 1


async def propose(ctx: Context, db: AsyncSession, v: Verified) -> Resolution:
    p = v.payload
    title = clean_text(p.get("title"), "title", max_len=160)
    body = clean_text(p.get("body"), "body", max_len=50_000)
    matter = p.get("matter") or "other"
    ops = p.get("ops")
    if matter not in RESERVED_MATTERS | ORDINARY_MATTERS:
        raise HTTPException(400, f"unknown matter {matter!r}")
    related = field_text(p, "related_proposal", max_len=64).strip().lower()
    if matter in ("adopt_open_vote", "decline_open_vote") and not related:
        raise HTTPException(400, f"{matter} names a proposal; give related_proposal")
    if matter == "decline_open_vote" and ops is not None:
        raise HTTPException(400, "decline_open_vote may not carry state-chain ops")
    if ops is not None:
        ops = sessions.normalise_ops(ops)
        # Checked now against the session kind the matter will open, so a resolution that cannot execute is
        # refused here and not at its deciding vote (XE-0349).
        sessions.check_ops(session_kind(matter), ops, sessions.seat_keys_of(ctx.config))
    # The link is the resolution's published claim about which open vote it concerns, so it names a proposal
    # that exists (XE-1945). Whether a general resolution may then decide that proposal is `portal.decide`'s
    # question; an open-vote matter is checked against the proposal's ops here so it cannot pass dead.
    pr = None
    if related:
        pr = (await db.execute(select(Proposal).where(Proposal.hash == related))).scalar_one_or_none()
    if related and pr is None:
        raise HTTPException(400, "related_proposal names no proposal")
    if matter == "adopt_open_vote":
        if pr.status != "open" and (pr.result or {}).get("outcome") != "passed":
            outcome = (pr.result or {}).get("outcome") or "has no tally"
            raise HTTPException(409, f"the vote {outcome}; adopt_open_vote needs a passed vote")
        if pr.status == "decided" and (pr.decision or {}).get("decision") == "decline":
            raise HTTPException(409, "this proposal has already been declined")
        if pr.ops and not portal.same_ops(ops, pr.ops):
            raise HTTPException(400, "adopt_open_vote must carry the linked proposal's exact ops")
    r = Resolution(id=secrets.token_hex(8), number=await _next_number(db), title=title, body=body, matter=matter,
                   ops=ops, proposed_by=v.seat.id, status="open", signatures=[], related_proposal=related)
    db.add(r)
    await ctx.events.append(db, "resolution.proposed", v.actor, {
        "resolution_id": r.id, "number": r.number, "title": title, "body": body, "matter": matter, "ops": ops,
        "reserved": matter in RESERVED_MATTERS, "related_proposal": r.related_proposal,
    }, ref=f"resolution:{r.id}")
    return r


def session_kind(matter: str) -> str:
    """The signing session a passed resolution opens. `change_keyset` is the one matter that may write a
    `sys.*` key, through a `keyset` session that accepts exactly `set sys.dao_keyset`; the chain then holds
    the rotation block to the current keyset's threshold like any other, and the harness signs nothing."""
    if matter == "change_keyset":
        return "keyset"
    # Every other matter opens a `parameter` session, `registry` and `anchor` included. A session of those
    # two kinds is a record session: the next state of a record the harness itself composes, one open at a
    # time (`records._sole_open`). A resolution's ops are the members' own words, and a session carrying
    # them under a record kind would hold that slot, or be opened beside the one that does (XE-2439).
    return "parameter"


def body_hash(r: Resolution) -> str:
    """What a member's signature commits to: everything about the resolution that decides what it does.
    The open vote it names is part of that (`portal.decide` adopts or declines that proposal on the
    strength of the pass), so it is in the hash wherever there is one; a resolution that names none hashes
    as it always did."""
    from ..canonical import canonical_json, sha256_hex
    return sha256_hex(canonical_json({"title": r.title, "body": r.body, "matter": r.matter, "ops": r.ops,
                                      **({"related_proposal": r.related_proposal} if r.related_proposal else {})}))


def live_signatures(ctx: Context, sigs: list[dict]) -> tuple[list[dict], list[str]]:
    """The stored signatures that count now, and the seats whose signature was set aside (`dao.signatures`)."""
    return signatures.counting(_signers(ctx.config), sigs)


async def decide(ctx: Context, db: AsyncSession, r: Resolution, v: Verified, decision: str) -> Resolution:
    """A member signs for or against. payload = {resolution_id, body_hash, decision}."""
    if r.status != "open":
        raise HTTPException(409, f"resolution is {r.status}")
    if decision not in ("for", "against"):
        raise HTTPException(400, "decision must be 'for' or 'against'")
    if v.payload.get("resolution_id") != r.id or v.payload.get("body_hash") != body_hash(r) or v.payload.get("decision") != decision:
        raise HTTPException(400, "signed payload does not match this resolution")
    r.signatures = signatures.add(_signers(ctx.config), r.signatures, {
        "seat": v.seat.id, "public_key": v.pub_key, "signature": v.signature, "decision": decision, "timestamp": v.timestamp,
    }, "this member has already signed")
    needed, rule = _matter_rule(ctx.config, r.matter)
    live, set_aside = live_signatures(ctx, r.signatures)
    fors = sum(1 for s in live if s["decision"] == "for")
    againsts = sum(1 for s in live if s["decision"] == "against")
    # A signature that passes a resolution with ops opens its session, and a session is opened against the
    # live keyset. The node is asked for it here, before anything is written to the log
    # (`sessions.look`); if it does not answer, the session is owed, as below.
    ks = await sessions.read_keyset(ctx) if fors >= needed and r.ops else None
    await ctx.events.append(db, "resolution.signed", v.actor, {
        "resolution_id": r.id, "decision": decision, "for": fors, "against": againsts, "needed": needed, "rule": rule,
        **({"set_aside": set_aside} if set_aside else {}),
    }, ref=f"resolution:{r.id}")
    n_members = len(_signers(ctx.config))
    if fors >= needed:
        r.status = "passed"
        r.signatures = live   # a decided resolution holds the signatures that decided it, and no others
        r.decided_at = datetime.now(timezone.utc)
        await ctx.events.append(db, "resolution.passed", "harness", {
            "resolution_id": r.id, "number": r.number, "title": r.title, "matter": r.matter, "for": fors, "against": againsts,
        }, ref=f"resolution:{r.id}")
        if r.ops:
            # The node not answering leaves the session owed, and the pass and the signature stand (XE-1710).
            # A refusal is different, and is the answer to the deciding signature itself: ops that no longer
            # fit the seats as they stand (a seat changed since the proposal) raise the 400 that names the
            # cause, the route records nothing, and the resolution stays open until it is withdrawn. Whether
            # such a resolution should instead get a recorded end is a product decision that has been left as
            # it is (XE-2030).
            try:
                async with db.begin_nested():
                    await open_session(ctx, db, r, ks=ks)
            except XeError as e:
                await _owed(ctx, db, r.id, "resolution.session_deferred", str(e)[:300])
    elif againsts > n_members - needed:
        r.status = "rejected"
        r.signatures = live
        r.decided_at = datetime.now(timezone.utc)
        await ctx.events.append(db, "resolution.rejected", "harness", {
            "resolution_id": r.id, "number": r.number, "for": fors, "against": againsts,
        }, ref=f"resolution:{r.id}")
    return r


async def open_session(ctx: Context, db: AsyncSession, r: Resolution, ks: dict | Exception | None = None) -> None:
    """Open the execution session a passed resolution with ops is owed. `ks` is the live keyset where the
    caller has read it, or what reading it raised (`sessions.create`)."""
    kind = session_kind(r.matter)
    w = ctx.config.windows
    timelock_h = int(w.get("upgrade_timelock_hours", 0) or 0) if w.get("upgrade_timelock_status") == "active" else 0
    not_before = time.time_ns() + timelock_h * 3600 * 1_000_000_000 if timelock_h else None
    s = await sessions.create(ctx, db, kind=kind, title=f"R{r.number}: {r.title}", ops=r.ops, actor="harness",
                              resolution_id=r.id, not_before=not_before, ks=ks)
    r.session_id = s.id


async def open_owed_session(ctx: Context, db: AsyncSession, r: Resolution, ks: dict | Exception | None = None) -> bool:
    """Worker: open the session an already passed resolution is owed, if it can be opened now. The
    resolution is passed and stays passed: opening its session is a separate act, and nothing that act can
    raise undoes the pass or stops the pass over the resolutions behind it. The node not answering
    (XE-1710) and the ops no longer fitting the seats as they stand (a seat changed after the pass, while
    the session was still owed; XE-1967) are both left on the record as what is owed, and tried again on
    every pass: the first clears when the node is back, the second if the seats change back. Anything
    else that stops it is recorded as refused in the same way, because "nothing" means nothing.
    Everything the attempt wrote is undone with it (a savepoint), so a failure leaves no half-made session.
    The resolution is named by an id read before the attempt: a row the savepoint undid is not read again
    to say what failed (XE-3724).

    `ks` is the live keyset as the pass over the owed resolutions read it, once, before it wrote anything,
    or what that read raised (`open_deferred_sessions`)."""
    rid = r.id
    try:
        async with db.begin_nested():
            await open_session(ctx, db, r, ks=ks)
        return True
    except XeError as e:
        kind, error = "resolution.session_deferred", str(e)[:300]
    except HTTPException as e:
        kind, error = "resolution.session_refused", str(e.detail)[:300]
    except Exception as e:
        log.exception("resolution %s: opening its session raised", rid)
        kind, error = "resolution.session_refused", reason(e)   # its text is in the server's log above (XE-6983)
    await _owed(ctx, db, rid, kind, error)
    return False


async def _owed(ctx: Context, db: AsyncSession, rid: str, kind: str, error: str) -> None:
    """Record why a passed resolution's session is still owed. Written when the reason changes kind, not on
    every pass and not on every rewording: a node that words its failure differently each time (a request
    id, a timestamp) would otherwise add an event to the log every minute for as long as it was down."""
    last = await EventLog.page(db, limit=1, ref=f"resolution:{rid}", public_only=False)
    if not last or last[0].kind != kind:
        await ctx.events.append(db, kind, "harness", {"resolution_id": rid, "error": error}, ref=f"resolution:{rid}")


async def open_deferred_sessions(ctx: Context, db: AsyncSession) -> int:
    """Worker: passed resolutions with ops whose session could not be opened at the deciding signature.
    Each is tried on its own; one that cannot be opened does not hold up the ones behind it, and neither
    does one whose attempt, or the record of what it is owed, the database refused: each is a step of its
    own, in a savepoint, named by an id read before it (XE-3724)."""
    q = locked(select(Resolution).where(Resolution.status == "passed", Resolution.ops.isnot(None), Resolution.session_id == "")
               .order_by(Resolution.number.asc()), skip_locked=True)
    n = 0
    owed = (await db.execute(q)).scalars().all()
    # The live keyset every one of these sessions is opened against, asked for once and before the first
    # of them writes to the log: asked inside the loop, the second resolution's question went to the node
    # with the head held by what the first had just recorded (XE-14181).
    ks = await sessions.read_keyset(ctx) if any(r.ops for r in owed) else None
    for r, rid, has_ops in [(r, r.id, bool(r.ops)) for r in owed]:
        try:
            async with db.begin_nested():
                opened = has_ops and await open_owed_session(ctx, db, r, ks)
        except Exception:
            log.exception("resolution %s: recording what its session is owed raised", rid)
            continue
        n += 1 if opened else 0
    return n


async def withdraw(ctx: Context, db: AsyncSession, r: Resolution, v: Verified) -> Resolution:
    if r.status != "open":
        raise HTTPException(409, f"resolution is {r.status}")
    if r.proposed_by != v.seat.id and not v.seat.is_member:
        raise HTTPException(403, "only the proposer or a member may withdraw")
    # Rows first, then the log head, as everywhere (`sessions.cancel`, `decide`, `inbox._lock_answered`): the
    # session row is taken before the first append, not after it (XE-12010).
    s = await sessions.get(db, r.session_id, lock=True) if r.session_id else None
    # A passing vote that raced this withdrawal may have opened the execution session already; it goes
    # with the resolution, so nothing the record calls withdrawn stays executable (XE-0672). Whether its
    # block is on the chain is asked now, before the withdrawal is written to the log (`sessions.look`).
    ending = s is not None and s.status in sessions.OPEN
    on_chain = ending and bool(s.block) and await sessions.landed(ctx, s)
    r.status = "withdrawn"
    r.decided_at = datetime.now(timezone.utc)
    await ctx.events.append(db, "resolution.withdrawn", v.actor, {"resolution_id": r.id}, ref=f"resolution:{r.id}")
    if ending:
        await sessions.cancel(ctx, db, s, v, "resolution withdrawn", on_chain=on_chain)
    return r


async def get(db: AsyncSession, res_id: str, *, lock: bool = False) -> Resolution:
    """`lock=True` takes the row FOR UPDATE: every path that changes a resolution loads it this way, so two
    writers queue instead of each saving its own copy of a list over the other's (XE-0672)."""
    q = select(Resolution).where(Resolution.id == res_id)
    r = (await db.execute(locked(q) if lock else q)).scalar_one_or_none()
    if r is None:
        raise HTTPException(404, "resolution not found")
    return r


async def list_resolutions(db: AsyncSession, status: str | None = None, limit: int = 200, offset: int = 0) -> list[Resolution]:
    """A page of the register, newest first. A page is not the register: `count_resolutions` says how many
    there are, and what is waiting on a member is asked of `open_resolutions` (XE-4601)."""
    q = select(Resolution).order_by(Resolution.number.desc()).offset(offset).limit(min(limit, 200))
    if status:
        q = q.where(Resolution.status == status)
    return list((await db.execute(q)).scalars().all())


async def count_resolutions(db: AsyncSession, status: str | None = None) -> int:
    q = select(func.count()).select_from(Resolution)
    if status:
        q = q.where(Resolution.status == status)
    return int((await db.execute(q)).scalar_one())


async def open_resolutions(db: AsyncSession) -> list[Resolution]:
    """Every resolution still open, unpaged, oldest first."""
    return list((await db.execute(select(Resolution).where(Resolution.status == "open").order_by(Resolution.number.asc()))).scalars().all())


def to_dict(r: Resolution, cfg) -> dict:
    """An open resolution shows the signatures that count now beside the number needed now, and names the
    seats whose stored signature was set aside, so what a reader adds up is what `decide` adds up. One that
    is decided shows the signatures it holds, which are the ones that were counted when it was decided
    (`decide` keeps no others). `needed` is today's number either way; the number a decision was held to
    is in its `resolution.signed` event."""
    needed, rule = _matter_rule(cfg, r.matter)
    shown, set_aside = signatures.counting(_signers(cfg), r.signatures) if r.status == "open" else (r.signatures, [])
    return {
        "id": r.id, "number": r.number, "title": r.title, "body": r.body, "body_hash": body_hash(r), "matter": r.matter,
        "reserved": r.matter in RESERVED_MATTERS, "ops": r.ops, "proposed_by": r.proposed_by, "status": r.status,
        "signatures": [{"seat": s["seat"], "decision": s["decision"], "timestamp": s["timestamp"]} for s in shown],
        **({"set_aside": set_aside} if set_aside else {}),
        "needed": needed, "rule": rule, "related_proposal": r.related_proposal, "session_id": r.session_id,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "decided_at": r.decided_at.isoformat() if r.decided_at else None,
    }
