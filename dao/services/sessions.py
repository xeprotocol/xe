"""State-chain signing sessions, in two steps, because the tip moves every ten minutes.

  1. approving  keyset holders approve the *ops digest* (what will be written). Durable: an approval
                never expires with the tip.
  2. signing    the harness builds a block at the live tip and keyset holders sign its hash. If the
                tip moves before enough signatures land, the block is rebuilt and signatures reset.
                Approvals from step 1 stand, so nobody has to re-read anything.
  → submitted / failed / cancelled

The harness holds no keyset key. It only assembles, counts, and submits.
"""

from __future__ import annotations

import json
import logging
import re
import secrets
import time
from dataclasses import dataclass

from fastapi import HTTPException
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from xe.client import XeError
from xe.keys import KeyError_, exact_hex, is_valid_public_key, verify_hex_signature
from xe.statechain import StateBlock, StateChainError, StateOp, build_block, check_ops_fit, validate_keyset

from ..auth import Verified
from ..canonical import canonical_json, sha256_hex
from ..context import Context
from ..db import locked
from ..faults import reason
from ..log import EventLog
from ..models import Anchor, SigningSession
from . import pause

log = logging.getLogger("dao.sessions")

KINDS = {"registry", "anchor", "parameter", "keyset"}
KEYSET_KEY = "sys.dao_keyset"
SIGN_RIGHT = "sign_statechain"   # the seat right that lets a key approve ops and sign a block
KEY_HEX_RE = re.compile(r"[0-9a-f]{64}")
MAX_KEYSET = 16
MAX_OPS = 32


def check_ops(kind: str, ops: list[dict], seat_keys: set[str] | None = None) -> None:
    """What a session of this kind may write. Every kind but `keyset` writes the harness's own `dao.*` keys.
    A `keyset` session is the one route to a `sys.*` key and it is exactly one op: set `sys.dao_keyset` to
    a well-formed keyset the seats can meet. The same check runs when a resolution is proposed and when a
    proposal is submitted (`check_proposal_ops`), so nothing can pass a vote and then be refused at
    execution (XE-0349, XE-1650)."""
    parsed = _ops_from_json(ops)
    for o in parsed:
        o.validate()
    if kind != "keyset":
        for o in parsed:
            if not o.key.startswith("dao."):
                raise HTTPException(400, f"harness sessions may only write dao.* keys (got {o.key})")
        return
    if len(parsed) != 1 or parsed[0].action != "set" or parsed[0].key != KEYSET_KEY:
        raise HTTPException(400, f"a keyset session is exactly one op: set {KEYSET_KEY}")
    _check_keyset(json.loads(parsed[0].value), seat_keys)


def check_proposal_ops(ops: list[dict], seat_keys: set[str] | None = None) -> None:
    """A proposal names no session kind, so its ops must be ones *some* kind could authorise: all `dao.*`
    keys (any kind but keyset), or exactly the one keyset op. Otherwise the vote is spent on ops no
    resolution can carry and adoption refuses forever (XE-1650)."""
    parsed = _ops_from_json(ops)
    if any(o.key == KEYSET_KEY for o in parsed):
        check_ops("keyset", ops, seat_keys)
    else:
        check_ops("parameter", ops, seat_keys)


def seat_keys_of(config) -> set[str]:
    """The keys a keyset may ask signatures from: those held by a human seat the routes let approve and
    sign a state-chain block (`SIGN_RIGHT`, the right `dao.api.members` requires on both). A seat that
    holds a key and not the right can do neither, so a keyset whose threshold leans on it is one the
    seats cannot meet (XE-2028, the same deadlock as XE-1705 by another door)."""
    return {s.public_key for s in config.human_seats if s.public_key and s.can(SIGN_RIGHT)}


def _check_keyset(value, seat_keys: set[str] | None = None) -> None:
    """The node's rule for `sys.dao_keyset`, as the protocol mirror states it (`xe.statechain.validate_keyset`:
    distinct keys, threshold between MIN_DAO_THRESHOLD and the key count), plus what the harness asks on
    top: the shape, lowercase hex, at most MAX_KEYSET keys, and every key a usable ed25519 point. A key
    nobody can sign with, if the threshold needs it, would leave the chain with no valid signer (XE-0694).
    The gate states no bound of its own, so it cannot be looser than the node on any of them (XE-1447).
    When the seats' keys are given, at least `threshold` of the keyset's keys must be seat keys: a keyset
    the seats cannot meet would end every later session, including the one to fix it (XE-1705)."""
    if not isinstance(value, dict) or set(value) != {"keys", "threshold"}:
        raise HTTPException(400, "keyset value must be {keys: [...], threshold: n}")
    keys, threshold = value["keys"], value["threshold"]
    if not isinstance(keys, list) or len(keys) > MAX_KEYSET:
        raise HTTPException(400, f"keyset holds at most {MAX_KEYSET} keys")
    if any(not isinstance(k, str) or not KEY_HEX_RE.fullmatch(k) for k in keys):
        raise HTTPException(400, "every keyset key is 64 lowercase hex digits")
    if not isinstance(threshold, int) or isinstance(threshold, bool):
        raise HTTPException(400, "keyset threshold must be an integer")
    try:
        validate_keyset(value)
    except StateChainError as e:
        raise HTTPException(400, f"keyset: {e}") from e
    for k in keys:
        if not is_valid_public_key(exact_hex(k, 32, "keyset key")):
            raise HTTPException(400, f"{k[:12]}… is not a usable ed25519 public key")
    if seat_keys is not None:
        held = sum(1 for k in keys if k in seat_keys)
        if held < threshold:
            raise HTTPException(400, f"keyset needs {threshold} signatures but only {held} of its keys are held by a seat; "
                                     "the seats could never meet it, nor change it back")


def ops_digest(ops: list[dict]) -> str:
    return sha256_hex(canonical_json(ops))


def normalise_ops(ops) -> list[dict]:
    """Store `value` as the exact compact JSON text that will be hashed. JSONB reorders object keys,
    so values must never be stored as parsed objects. Every op is validated as the node would, so a
    proposal or resolution cannot carry ops that could never be written."""
    if not isinstance(ops, list) or not ops:
        raise HTTPException(400, "ops must be a non-empty list")
    if len(ops) > MAX_OPS:
        raise HTTPException(400, f"at most {MAX_OPS} ops")
    out = []
    for o in ops:
        if not isinstance(o, dict) or not isinstance(o.get("action"), str) or not isinstance(o.get("key"), str):
            raise HTTPException(400, "each op is an object with a string action and key")
        try:
            op = StateOp.from_json(o)
            op.validate()
        except StateChainError as e:
            raise HTTPException(400, f"ops are malformed: {e}") from e
        except (TypeError, ValueError) as e:   # not ours to quote: the interpreter's words about the caller's value
            raise HTTPException(400, "ops are malformed") from e
        d = {"action": op.action, "key": op.key}
        if op.action == "set":
            d["value"] = op.value
        out.append(d)
    try:
        check_ops_fit(_ops_from_json(out))   # the node bounds the block, not only each op (XE-1917)
    except StateChainError as e:
        raise HTTPException(400, f"ops are malformed: {e}") from e
    return out


def _ops_from_json(ops: list[dict]) -> list[StateOp]:
    return [StateOp(o["action"], o["key"], o.get("value")) for o in ops]


def _block_from_session(s: SigningSession) -> StateBlock:
    blk = StateBlock(index=int(s.block["index"]), prev_hash=s.block["prev_hash"], ops=_ops_from_json(s.ops),
                     timestamp=int(s.block["timestamp"]), signatures=list(s.block_signatures))
    blk.hash = s.block_hash
    return blk


def require_executable(ctx: Context, s: SigningSession) -> None:
    """What a session writes is checked against the seats as they are now each time it moves toward the
    chain: when its block is built, when a signature is added, when it is submitted. `create` checks it
    once, and a session lives for days: a seat that has changed its key or lost the right to sign since
    then can leave a keyset session carrying a keyset the seats no longer meet, which would land and end
    every later session, the one to repair it included (XE-4131, the deadlock of XE-1705 reached after
    creation). The check is `check_ops`, the same one, so the two cannot differ."""
    try:
        check_ops(s.kind, s.ops, seat_keys_of(ctx.config))
    except HTTPException as e:
        raise HTTPException(409, f"this session can no longer be executed as approved: {e.detail}") from e


async def require_unpaused(db: AsyncSession) -> None:
    """Approving a session is record-keeping and stays open during a pause; building, signing and
    submitting a block are the company acting on the chain and stop. Lifted pauses release them."""
    if await pause.is_paused(db):
        raise HTTPException(409, "paused: no state-chain block is built, signed or submitted while a pause is active")


async def live_keyset(ctx: Context) -> dict:
    """`sys.dao_keyset` as the node serves it now: lower-case keys and an integer threshold, both checked
    by the client. A keyset without a threshold is malformed, not a 2-of-n."""
    ks = await ctx.chain.dao_keyset()
    return {"keys": [k.lower() for k in ks["keys"]], "threshold": ks["threshold"]}


async def read_keyset(ctx: Context) -> dict | Exception:
    """The live keyset for `create(ks=...)`, read ahead of a write to the log: the keyset, or what the
    read raised, for `create` to raise in its turn."""
    try:
        return await live_keyset(ctx)
    except Exception as e:
        return e


async def create(ctx: Context, db: AsyncSession, *, kind: str, title: str, ops: list[dict], actor: str,
                 resolution_id: str = "", not_before: int | None = None,
                 ks: dict | Exception | None = None) -> SigningSession:
    """`ks` is the live keyset where the caller has read it already (`read_keyset`), or what reading it
    raised. A caller that has written to the log in this transaction has: the node is not asked with the
    log held (`look`). What the read raised is raised here, where the read used to be, so a session whose
    ops are refused is refused for that whether or not the node answered."""
    if kind not in KINDS:
        raise HTTPException(400, f"unknown session kind {kind!r}")
    ops = normalise_ops(ops)
    check_ops(kind, ops, seat_keys_of(ctx.config))
    if isinstance(ks, Exception):
        raise ks
    ks = ks or await live_keyset(ctx)
    s = SigningSession(id=secrets.token_hex(8), kind=kind, title=title, ops=ops, ops_digest=ops_digest(ops),
                       status="approving", approvals=[], required_approvals=ks["threshold"], block=None,
                       block_hash="", block_signatures=[], rebuilds=0, resolution_id=resolution_id,
                       not_before=not_before)
    db.add(s)
    await ctx.events.append(db, "session.created", actor, {
        "session_id": s.id, "kind": kind, "title": title, "ops": ops, "ops_digest": s.ops_digest,
        "required_approvals": s.required_approvals, "keyset_keys": ks["keys"], "resolution_id": resolution_id,
        "not_before": not_before,
    }, ref=f"session:{s.id}")
    return s


async def get(db: AsyncSession, session_id: str, *, lock: bool = False) -> SigningSession:
    """`lock=True` takes the row FOR UPDATE: every path that changes a session loads it this way, so two
    writers queue instead of each saving its own copy of a list over the other's (XE-0672)."""
    q = select(SigningSession).where(SigningSession.id == session_id)
    s = (await db.execute(locked(q) if lock else q)).scalar_one_or_none()
    if s is None:
        raise HTTPException(404, "session not found")
    return s


OPEN = ("approving", "signing")


async def list_sessions(db: AsyncSession, status: str | None = None, limit: int = 100, offset: int = 0) -> list[SigningSession]:
    """A page of sessions, newest first, for listings. Not for deciding whether something is pending: a
    page cannot see past its own end, and sessions are never deleted (XE-1561). Ask `open_sessions`."""
    # the id last: rows made in one transaction share one `created_at`, and a page needs a total order (XE-3250)
    q = select(SigningSession).order_by(SigningSession.created_at.desc(), SigningSession.id.desc()).offset(offset).limit(limit)
    if status:
        q = q.where(SigningSession.status == status)
    return list((await db.execute(q)).scalars().all())


async def count_sessions(db: AsyncSession, status: str | None = None) -> int:
    q = select(func.count()).select_from(SigningSession)
    if status:
        q = q.where(SigningSession.status == status)
    return int((await db.execute(q)).scalar_one())


async def open_sessions(db: AsyncSession, kind: str | None = None) -> list[SigningSession]:
    """Every session still approving or signing, unpaged, oldest first; optionally of one kind."""
    q = select(SigningSession).where(SigningSession.status.in_(OPEN)).order_by(SigningSession.created_at.asc(), SigningSession.id.asc())
    if kind:
        q = q.where(SigningSession.kind == kind)
    return list((await db.execute(q)).scalars().all())


def counted(given: list[dict] | None, ks: dict) -> list[dict]:
    """Of a session's approvals, or of its block's signatures, the ones from keys that are in the keyset
    now. The one count: the two gates below take it, and so does everything that says how many a session
    has (its events, `to_dict`, the health check), so no figure shown for an open session is one the
    gates do not use (XE-3877)."""
    live = {k.lower() for k in ks["keys"]}
    return [x for x in (given or []) if x["public_key"] in live]


def approvals_met(s: SigningSession, ks: dict) -> bool:
    """Enough approvals from keys that are in the keyset now. A key rotated out takes its approval with it,
    and a raised threshold applies to sessions already open; the figure stored at creation is a record."""
    return len(counted(s.approvals, ks)) >= int(ks["threshold"])


def signatures_met(s: SigningSession, ks: dict) -> bool:
    """The same count on the block's signatures: enough of them from keys that are in the keyset now. Every
    place that asks whether the block can go to the chain asks this, so a signature from a key rotated out
    since it was given is counted nowhere (XE-2713)."""
    return len(counted(s.block_signatures, ks)) >= int(ks["threshold"])


async def approve(ctx: Context, db: AsyncSession, s: SigningSession, v: Verified) -> SigningSession:
    """`v.payload` must be {"session_id", "ops_digest"} and signed by a keyset key (checked via the
    member-action domain by the router); here we additionally require keyset membership."""
    if s.status != "approving":
        raise HTTPException(409, f"session is {s.status}, not approving")
    ks = await live_keyset(ctx)
    if v.pub_key not in ks["keys"]:
        raise HTTPException(403, "this key is not in the live sys.dao_keyset")
    if v.payload.get("ops_digest") != s.ops_digest or v.payload.get("session_id") != s.id:
        raise HTTPException(400, "approval payload does not match this session")
    if any(a["public_key"] == v.pub_key for a in s.approvals):
        raise HTTPException(409, "already approved by this key")
    s.approvals = [*s.approvals, {"public_key": v.pub_key, "signature": v.signature, "timestamp": v.timestamp,
                                  "seat": v.seat.id if v.seat else ""}]
    # With the approvals met the block is built now, unless a timelock or a pause holds it in approving
    # (the worker's timer job promotes it when clear). What the build needs of the chain is read here,
    # before the approval is written to the log (`look`).
    building = approvals_met(s, ks) and not (s.not_before and time.time_ns() < s.not_before) \
        and not await pause.is_paused(db)
    seen, not_built = None, None
    if building:
        try:
            seen = await look(ctx, db, s)
        except Exception as e:
            not_built = e
    await ctx.events.append(db, "session.approved", v.actor, {
        "session_id": s.id, "ops_digest": s.ops_digest, "approvals": len(counted(s.approvals, ks)), "required": ks["threshold"],
    }, ref=f"session:{s.id}")
    if building:
        try:
            if not_built is not None:
                raise not_built
            await rebuild(ctx, db, s, actor="harness", seen=seen)
        except Exception as e:
            # The approval is on the record, and building the block is a second step that does not take it
            # back, whatever stopped it: the node not answering (XE-1713), a pause that began since it was
            # read above, anything else. The worker's timer pass builds the block when it can be built.
            log.warning("session %s: approved, block not built: %s", s.id, e)
            await ctx.events.append(db, "session.build_deferred", "harness",
                                    {"session_id": s.id, "error": reason(e)},
                                    ref=f"session:{s.id}")
    return s


def require_timelock_run(s: SigningSession) -> None:
    """The upgrade timelock is the window between adoption and execution in which members can still cancel.
    Every path that moves a session towards the chain checks it here, so no route can shorten it (XE-0284)."""
    now = time.time_ns()
    if s.not_before and now < s.not_before:
        left = (s.not_before - now) // 1_000_000_000
        raise HTTPException(409, f"the upgrade timelock on this session runs for another {left // 3600}h {left % 3600 // 60}m")


@dataclass(frozen=True)
class Seen:
    """What `look` found: the session's block is on the chain (`landed`), or its approvals no longer meet
    the live keyset `ks` (`build` false), or it is to be built on `tip` (None for a chain with no block)."""
    landed: bool = False
    ks: dict | None = None
    tip: dict | None = None
    build: bool = False


async def look(ctx: Context, db: AsyncSession, s: SigningSession) -> Seen:
    """Everything a build asks, of the session and of the chain, and nothing written. Raises what refuses
    the build: a session that has ended, a timelock still running, a pause, ops the seats no longer meet,
    approvals short of the live keyset, a node that does not answer.

    This is the half of `rebuild` that waits on the node, apart from the half that writes, so that a
    caller with something to put on the log first can ask before it writes. An append takes the log head
    and holds it until the transaction ends, and every writer in the service appends: a build that
    followed an append in the same transaction had each of them waiting on the node, a minute a call
    and several calls in a row when it was slow (XE-14181). So the order everywhere is look, then
    write, and `rebuild(seen=...)` builds from what was seen."""
    if s.status not in OPEN:
        raise HTTPException(409, f"session is {s.status}")
    if s.status == "signing" and await landed(ctx, s):
        # The tip moved because this block is the tip: rebuilding would write the same ops twice (XE-1511).
        return Seen(landed=True)
    require_timelock_run(s)
    await require_unpaused(db)
    require_executable(ctx, s)
    ks = await live_keyset(ctx)
    if not approvals_met(s, ks):
        if s.status == "signing":
            return Seen(ks=ks)
        raise HTTPException(409, "the session does not hold enough approvals from the live keyset")
    try:
        tip = await ctx.chain.statechain_tip()
    except XeError as e:
        if e.status == 404:
            tip = None
        else:
            raise
    # Asked again, now that nothing more waits on the node: the reads above can take a minute each, and a
    # pause that began during them was followed by a block built all the same (XE-4126, for a build).
    await require_unpaused(db)
    return Seen(ks=ks, tip=tip, build=True)


async def rebuild(ctx: Context, db: AsyncSession, s: SigningSession, actor: str = "harness",
                  seen: Seen | None = None) -> SigningSession:
    """Build (or re-build) the block at the live tip. Resets block signatures. Only an approved session,
    counted against the keyset as it is now, and not before the timelock has run (`look`, which a caller
    that has already written to the log in this transaction runs first and passes in as `seen`)."""
    seen = seen or await look(ctx, db, s)
    if seen.landed:
        return await _submitted(ctx, db, s)
    if not seen.build:
        # The keyset moved under a session that was already approved (a rotation landed first): the
        # approvals it holds no longer meet the live threshold. It goes back to approving rather than
        # sitting in signing with a block nobody may sign; the new keys approve and it proceeds (XE-0988).
        ks = seen.ks
        s.block, s.block_hash, s.block_signatures, s.status = None, "", [], "approving"
        await ctx.events.append(db, "session.reapproval_needed", actor, {
            "session_id": s.id, "ops_digest": s.ops_digest, "approvals": len(counted(s.approvals, ks)),
            "held": len(s.approvals), "required": ks["threshold"],
        }, ref=f"session:{s.id}")
        return s
    # The pause is asked a last time with the log head held. `look` asked after its waits on the node,
    # but a caller that then waits its turn at the head (any append) was still building on that answer
    # when it got there, and a pause that had begun in between was followed on the log by a block built.
    # A pause begins with an append: holding the head, it has either begun and is read here, or it
    # begins after this block is built (XE-4126).
    await EventLog.hold(db)
    await require_unpaused(db)
    blk = build_block(seen.tip, _ops_from_json(s.ops), time.time_ns())
    s.block = {"index": blk.index, "prev_hash": blk.prev_hash, "timestamp": blk.timestamp, "hash": blk.hash}
    s.block_hash = blk.hash
    s.block_signatures = []
    s.rebuilds = (s.rebuilds or 0) + (1 if s.status == "signing" else 0)
    s.status = "signing"
    await ctx.events.append(db, "session.block_built", actor, {
        "session_id": s.id, "index": blk.index, "prev_hash": blk.prev_hash, "block_hash": blk.hash,
        "rebuilds": s.rebuilds,
    }, ref=f"session:{s.id}")
    return s


async def rebuild_if_stale(ctx: Context, db: AsyncSession, s: SigningSession, actor: str) -> SigningSession:
    """A member-requested rebuild. The first build of an approved session is always allowed; once a block
    exists it is rebuilt only when the tip has moved, because a rebuild discards every signature collected
    and at an unchanged tip one seat could loop it and stall signing for good (XE-0882)."""
    if s.status == "signing" and not await is_stale(ctx, s):
        raise HTTPException(409, "the block is current; collected signatures stand")
    return await rebuild(ctx, db, s, actor=actor)


async def sign(ctx: Context, db: AsyncSession, s: SigningSession, pub_key: str, signature: str, actor: str) -> SigningSession:
    """Collect a raw ed25519 signature over the block hash from a keyset key. Submit when enough."""
    if s.status != "signing":
        raise HTTPException(409, f"session is {s.status}, not signing")
    require_timelock_run(s)
    await require_unpaused(db)
    require_executable(ctx, s)
    pub_key = pub_key.lower()
    ks = await live_keyset(ctx)
    await require_unpaused(db)   # again, after the wait on the node (`look`)
    if pub_key not in ks["keys"]:
        raise HTTPException(403, "this key is not in the live sys.dao_keyset")
    try:
        verify_hex_signature(pub_key, signature, exact_hex(s.block_hash, 32, "block hash"))
    except KeyError_ as e:
        raise HTTPException(401, f"signature does not verify over block hash: {e}") from e
    if any(x["public_key"] == pub_key for x in s.block_signatures):
        raise HTTPException(409, "already signed by this key")
    s.block_signatures = [*s.block_signatures, {"public_key": pub_key, "signature": signature.lower()}]
    # The block goes to the node before the signature is written to the log, and the two are recorded
    # together once the node has answered (`look`). If the process stops in between, the session is still
    # `signing` with its block, and the worker's pass finds the block on the chain and records it.
    out = await attempt(ctx, db, s) if signatures_met(s, ks) else None
    await ctx.events.append(db, "session.block_signed", actor, {
        "session_id": s.id, "block_hash": s.block_hash, "signatures": len(counted(s.block_signatures, ks)),
        "required": ks["threshold"],
    }, ref=f"session:{s.id}")
    if out is None:
        # A signature that is kept and not yet submitted: asked once more with the log head held, as a
        # build is (`rebuild`), so none is recorded after a pause began while this waited for the head.
        # One that met the threshold was offered above, where `attempt` asked right before the submit.
        await require_unpaused(db)
    else:
        await settle(ctx, db, s, out)
    return s


async def is_stale(ctx: Context, s: SigningSession) -> bool:
    if s.status != "signing" or not s.block:
        return False
    try:
        tip = await ctx.chain.statechain_tip()
    except XeError as e:
        if e.status == 404:
            return False
        raise
    return tip.get("hash") != s.block["prev_hash"]


async def at_its_index(ctx: Context, s: SigningSession) -> str:
    """What the chain holds at the index the session's block was built for: `this` block, `another`, or
    `nothing` that settles it. `another` is said only of a block the node serves for that index, standing
    on the block this one was built on: the two were built for the same place on the same chain, the
    other one has it, and this one can never land. That answer ends the watch on an ended session for
    good, so it is not given on less. A block at the index on a different parent is a chain other than
    the one this block was built on (a fork, a node on another network), and what that chain holds
    settles nothing: it is `nothing`, and the chain is asked again. Raises if the chain cannot be read."""
    if not s.block:
        return "nothing"
    index = int(s.block["index"])
    try:
        got = await ctx.chain.statechain_block(index)
    except XeError as e:
        if e.status == 404:
            return "nothing"
        raise
    if not got or not got.get("hash"):
        return "nothing"
    if got["hash"] == s.block_hash:
        return "this"
    same_place = got.get("index") == index and bool(got.get("prev_hash")) and got.get("prev_hash") == s.block.get("prev_hash")
    return "another" if same_place else "nothing"


async def landed(ctx: Context, s: SigningSession) -> bool:
    """Whether the session's block is on the chain at its index. The chain is the record of what happened;
    the node's answer to a submit is not: it can refuse after it has applied the block (a gossip publish
    failing after AddBlock), and a session marked failed on that answer would say a rotation, a parameter
    change or an anchor did not happen when it did, with `failed` terminal and the anchor row gone
    (XE-1511). Raises if the chain cannot be read; the caller leaves the session as it is."""
    return await at_its_index(ctx, s) == "this"


async def _submitted(ctx: Context, db: AsyncSession, s: SigningSession) -> SigningSession:
    """The chain holds the session's block at its index, and the record says so: the session, and for an
    anchor the register row, in this one transaction. The row was once filled by the worker's next pass,
    and until then the register and the health check called a written anchor unwritten (XE-6256)."""
    was = s.status
    s.status = "submitted"
    s.submitted_index = int(s.block["index"])
    s.submitted_hash = s.block_hash
    if s.kind == "anchor":
        # Before the append: the row, then the log head, the order every writer takes them in (`_ended`
        # holds the row while it waits for the head; XE-12010).
        await _anchor_written(db, s)
    await ctx.events.append(db, "session.submitted", "harness", {
        "session_id": s.id, "kind": s.kind, "index": s.submitted_index, "hash": s.submitted_hash, "ops": s.ops,
        **({"was": was} if was not in OPEN else {}),
    }, ref=f"session:{s.id}")
    return s


async def _anchor_written(db: AsyncSession, s: SigningSession) -> None:
    """The register row for an anchor session whose block is on the chain. A session that ended first took
    its row with it (`_ended`); if its block landed after all, the row is written again from the op, which
    is the anchor (XE-4148). Should a later session have taken the number in between, the row goes to
    whichever block the chain holds: a row still waiting on its session is this block's now, since the
    number is written and what the register says of it is what was written (XE-6256).

    Where both blocks reach the chain, what the chain holds under `dao.anchor.<n>` is what the later of
    them wrote: a set replaces what was set before it. So the row names the block with the higher index,
    whichever of the two is recorded first. The row once stood as soon as it named any block, which kept
    the first to be recorded, and when that was the earlier block the register named an anchor the chain
    no longer held (XE-14127). The log carries both.

    The row is read locked and as the database holds it now (`locked`): two blocks for one number
    recorded at the same moment each read the row unwritten, and the one that committed second set it,
    whichever block that was. Now the second waits for the row and reads what the first left. Where the
    number has no row for either to wait on, both add one and the second is refused by the key on `n`;
    its transaction fails, and the worker's next pass records it against the row that is there."""
    a = (await db.execute(locked(select(Anchor).where(Anchor.session_id == s.id)))).scalar_one_or_none()
    if a is not None and a.statechain_index is not None and a.statechain_index >= s.submitted_index:
        return
    if a is None:
        try:
            value = json.loads(s.ops[0]["value"])
            n, event_index, head_hash = int(value["n"]), int(value["event_index"]), str(value["head_hash"])
        except (KeyError, IndexError, TypeError, ValueError):
            return
        a = (await db.execute(locked(select(Anchor).where(Anchor.n == n)))).scalar_one_or_none()
        if a is not None and a.statechain_index is not None and a.statechain_index >= s.submitted_index:
            return
        if a is None:
            a = Anchor(n=n, event_index=event_index, head_hash=head_hash, session_id=s.id)
            db.add(a)
        else:
            a.event_index, a.head_hash, a.session_id = event_index, head_hash, s.id
    a.statechain_index = s.submitted_index
    a.statechain_hash = s.submitted_hash


ENDED_WATCH_MAX = 50


async def ended_holding_a_block(db: AsyncSession, offset: int = 0) -> list[str]:
    """Sessions that ended `failed` or `cancelled` with a block that could still land: every one whose
    index the chain has not been seen to give to another block, newest first, `ENDED_WATCH_MAX` at a time
    from `offset`. A pass looks at one such page, and the worker moves the offset on each pass and starts
    over after a short page, so every one of them is looked at within a few rounds (one that leaves the
    list shifts the pages under the offset by a place, and the next round has what that passed by).

    What ends the watch on a session is the chain and not the calendar. A state block is built on a tip
    and stays landable for as long as that tip is the tip, which no number of days bounds; the watch once
    ended after seven, and a block that landed on the eighth stayed recorded as never written
    (XE-14215). `reconcile_ended` takes a session off the list in the two ways the chain can settle it:
    its block is there, or another is where it would have gone. The list is then the ended sessions
    built on the tip as it stands, which is few however many have ended before. Before the offset a pass
    took the newest fifty every time, and the fifty-first was looked at by no pass."""
    q = (select(SigningSession.id).where(SigningSession.status.in_(("failed", "cancelled")),
                                         SigningSession.block_hash != "", SigningSession.block_displaced.is_(False))
         .order_by(SigningSession.updated_at.desc(), SigningSession.id.desc()).offset(offset).limit(ENDED_WATCH_MAX))
    return list((await db.execute(q)).scalars().all())


async def reconcile_signing(ctx: Context, db: AsyncSession, s: SigningSession) -> bool:
    """The same for a session still `signing` whose block the chain holds (its submit was accepted and
    could not be confirmed, or the signed block was sent by another route). The worker's pass asks this
    of each signing session while a pause is in force, when it neither rebuilds nor submits: recording
    what the chain holds is not an act on the chain, and a pause that stopped it left a written anchor
    called unwritten for as long as the pause ran. True if it was recorded."""
    if s.status != "signing" or not await landed(ctx, s):
        return False
    await _submitted(ctx, db, s)
    return True


async def reconcile_ended(ctx: Context, db: AsyncSession, s: SigningSession) -> bool:
    """A session's recorded outcome follows the chain, whatever state it was left in. One that ended
    without its block on the chain, and whose block is there now (the node applied it after refusing it,
    or the signed block was sent by another route), is recorded submitted (XE-4148). True if it was.

    One whose index the chain has given to another block is marked so, and is not looked up again: that
    is the only thing that ends the watch on an ended session short of its block landing (XE-14215).
    Nothing is logged for it. The session's end is on the log already, and the mark says only that the
    chain has been asked for the last time."""
    if s.status not in ("failed", "cancelled"):
        return False
    held = await at_its_index(ctx, s)
    if held == "another":
        s.block_displaced = True
    if held != "this":
        return False
    await _submitted(ctx, db, s)
    return True


def ready_to_submit(s: SigningSession, ks: dict) -> bool:
    """A signing session holding a threshold of live signatures over its block: its submit is owed to the chain."""
    return s.status == "signing" and bool(s.block) and signatures_met(s, ks)


@dataclass(frozen=True)
class Outcome:
    """How a submit came out, as the chain says, with everything needed to record it already read.
    `kind` is `submitted` (the chain holds the block), `deferred` (still owed, for `error`), `moved` (the
    chain moved under the block: `moved` names how, `seen` is what to rebuild on, or `error` why it cannot
    be rebuilt yet) or `failed` (the node refused the block itself). `refusal` is the node's refusal as
    the client words it."""
    kind: str
    error: str = ""
    refusal: str = ""
    moved: str = ""
    seen: Seen | None = None


async def submit(ctx: Context, db: AsyncSession, s: SigningSession) -> SigningSession:
    """Submit the signed block. What happened to it is what the chain says, never what the node answered:
    the session is `submitted` when the chain holds the block at its index, whether the node said yes
    (a 200 from a node that then drops the block is not a write, XE-2361) or no (a refusal after the block
    was applied, XE-1511). A node failure never escapes and never, on its own, ends the session: only a
    refusal from a node that answered, on a chain that neither holds the block nor has moved under it,
    sets `failed`. Everything else leaves the session `signing` with the error on record, and the worker
    submits it again (XE-1677, XE-1689, XE-1817).

    In two halves, as a build is (`look`): `attempt` is everything that waits on the node and writes
    nothing, `settle` records what came of it."""
    return await settle(ctx, db, s, await attempt(ctx, db, s))


async def attempt(ctx: Context, db: AsyncSession, s: SigningSession) -> Outcome:
    require_timelock_run(s)
    await require_unpaused(db)
    require_executable(ctx, s)
    blk = _block_from_session(s)
    try:
        await ctx.chain.submit_statechain_block(blk)
    except XeError as e:
        return await _refused(ctx, db, s, e)
    try:
        if await landed(ctx, s):
            return Outcome("submitted")
    except XeError as read_err:
        return Outcome("deferred", f"submit accepted; could not confirm against the chain: {read_err}")
    return Outcome("deferred", "submit accepted, but the chain does not hold the block at its index yet")


async def _moved_under(ctx: Context, s: SigningSession) -> str | None:
    """Whether the chain has moved under the session's block, asked of the chain: the tip is no longer the
    block's `prev_hash`, or the signatures the block carries no longer meet the live keyset. These are the
    two ways a block that was right when it was signed stops being acceptable, and both are facts the node
    serves; the wording of a refusal is not one (XE-2216). Raises if the chain cannot be read."""
    if await is_stale(ctx, s):
        return "session.tip_moved"
    if not signatures_met(s, await live_keyset(ctx)):
        return "session.keyset_moved"
    return None


async def _refused(ctx: Context, db: AsyncSession, s: SigningSession, e: XeError) -> Outcome:
    # Before believing a refusal, ask the chain. If the block is there, it was accepted.
    try:
        if await landed(ctx, s):
            return Outcome("submitted")
        # 429, 5xx, no answer: the node said nothing about the block.
        moved = None if e.transient else await _moved_under(ctx, s)
    except XeError as read_err:
        return Outcome("deferred", f"submit: {e}; could not confirm against the chain: {read_err}")
    if e.transient:
        return Outcome("deferred", f"submit: {e}")
    if moved:
        # The chain moved under the block (its tip, or the keyset it is checked against): rebuild on what is
        # live. A rotation that leaves the approvals short sends it back to approving (XE-0988). What stops
        # the rebuild is recorded as the reason the submit is still owed, whichever kind it is: the node
        # not answering, or a refusal of the build (a pause that began since the signature was taken, ops
        # the seats no longer meet). The second kind used to escape from here as a 409, and took the
        # signature that had just been counted, and the record that the chain had moved, back with it
        # (XE-14509).
        try:
            return Outcome("moved", refusal=str(e), moved=moved, seen=await look(ctx, db, s))
        except XeError as build_err:
            return Outcome("moved", f"submit: {e}; rebuild: {build_err}", refusal=str(e), moved=moved)
        except HTTPException as build_err:
            return Outcome("moved", f"submit: {e}; rebuild: {build_err.detail}", refusal=str(e), moved=moved)
    # The node answered and refused; the chain does not hold the block, its tip is the block's parent and
    # its keyset is met by the block's signatures. The refusal is about the block, and building the same
    # ops again would draw it again: the session ends, with the refusal on the record.
    return Outcome("failed", refusal=str(e))


async def settle(ctx: Context, db: AsyncSession, s: SigningSession, out: Outcome) -> SigningSession:
    """Record what `attempt` found. Nothing here waits on the node."""
    if out.kind == "submitted":
        return await _submitted(ctx, db, s)
    if out.kind == "deferred":
        return await _deferred(ctx, db, s, out.error)
    if out.kind == "moved":
        await ctx.events.append(db, out.moved, "harness", {"session_id": s.id, "error": out.refusal, "block_hash": s.block_hash},
                                ref=f"session:{s.id}")
        if out.seen is None:
            return await _deferred(ctx, db, s, out.error)
        return await rebuild(ctx, db, s, seen=out.seen)
    s.status = "failed"
    s.error = out.refusal
    await _ended(db, s)
    await ctx.events.append(db, "session.failed", "harness", {"session_id": s.id, "error": out.refusal}, ref=f"session:{s.id}")
    return s


async def _deferred(ctx: Context, db: AsyncSession, s: SigningSession, error: str) -> SigningSession:
    """The submit is still owed and the worker will try it again. The row carries the latest reason; the log
    says so once per spell, not on every pass, as `resolutions._owed` does for a session not yet opened."""
    s.error = error[:500]
    last = await EventLog.page(db, limit=1, ref=f"session:{s.id}", public_only=False)
    if not last or last[0].kind != "session.submit_deferred":
        await ctx.events.append(db, "session.submit_deferred", "harness", {"session_id": s.id, "error": error[:300]},
                                ref=f"session:{s.id}")
    return s


async def cancel(ctx: Context, db: AsyncSession, s: SigningSession, v: Verified, reason: str,
                 on_chain: bool | None = None) -> SigningSession:
    """A member ends a session. One that holds a block is first checked against the chain: a block that
    landed is recorded as submitted, not cancelled, whatever the node said at the time (XE-1843, as for
    rebuild and submit). If the chain cannot be read the cancel waits (502). The answer carries the
    session as it now stands. `on_chain` is that check's answer where the caller has asked already,
    which one that has written to the log in this transaction has (`look`)."""
    if s.status not in OPEN:
        # Ended is ended: a session that was submitted, failed or cancelled is not ended a second time, and
        # the reason on its row (the node's refusal, for a failed one) is not written over (XE-6873).
        raise HTTPException(409, f"session is {s.status}")
    if s.block and (await landed(ctx, s) if on_chain is None else on_chain):
        return await _submitted(ctx, db, s)
    s.status = "cancelled"
    s.error = reason
    await _ended(db, s)
    await ctx.events.append(db, "session.cancelled", v.actor, {"session_id": s.id, "reason": reason}, ref=f"session:{s.id}")
    return s


async def _ended(db: AsyncSession, s: SigningSession) -> None:
    """A session that ends without reaching the chain leaves no record that says otherwise: the anchor row
    opened with it goes, so the register and the health check see only anchors that were written (XE-0990)."""
    if s.kind == "anchor":
        await db.execute(delete(Anchor).where(Anchor.session_id == s.id))


def to_dict(s: SigningSession, ks: dict | None) -> dict:
    """A session still open shows the approvals and the block signatures that count now beside the number
    needed now, and names the keys whose approval or signature is set aside, so what a reader adds up is
    what `approvals_met` and `signatures_met` add up (XE-3877; the rule `resolutions.to_dict` keeps). It
    showed everything it held over the threshold it was created under: after a rotation, "2/2" on a
    session the gate held at one of two.

    `ks` is the live keyset. Where it could not be read (None, or the `{"error": ...}` that
    `records.public_keyset` returns) nothing can be counted and nothing is said to be: the session shows
    what it holds, `required_approvals` is None and `counted` is False. A session that has ended shows
    what it holds and the number it was created under, which are a record and are not counted again."""
    readable = isinstance(ks, dict) and not ks.get("error")
    now = s.status in OPEN and readable
    held_a, held_s = s.approvals or [], s.block_signatures or []
    approvals, signatures = (counted(held_a, ks), counted(held_s, ks)) if now else (held_a, held_s)
    set_aside = sorted({x["public_key"] for x in [*held_a, *held_s]} - {x["public_key"] for x in [*approvals, *signatures]})
    if now:
        required = int(ks["threshold"])
    else:
        required = None if s.status in OPEN else s.required_approvals
    return {
        "id": s.id, "kind": s.kind, "title": s.title, "status": s.status, "ops": s.ops, "ops_digest": s.ops_digest,
        "approvals": [{"public_key": a["public_key"], "seat": a.get("seat", ""), "timestamp": a.get("timestamp")} for a in approvals],
        "required_approvals": required, "counted": now, **({"set_aside": set_aside} if set_aside else {}),
        "block": s.block, "block_hash": s.block_hash,
        "block_signatures": [x["public_key"] for x in signatures], "rebuilds": s.rebuilds,
        "submitted_index": s.submitted_index, "submitted_hash": s.submitted_hash, "error": s.error,
        "resolution_id": s.resolution_id, "not_before": s.not_before,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }
