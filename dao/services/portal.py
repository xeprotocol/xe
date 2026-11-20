"""The open portal: anyone proposes for a fee, anyone with XE votes, the result advises the DAO.

Rules are pinned to a proposal at open time (`proposal.rules`) so a later Schedule B change never
moves a live vote. Weight is the voter's XE balance at the snapshot, an hour and five minutes before open. Quorum is a count of
participating wallets, not an amount of XE. Agents' weight is bounded and they never count toward
quorum. Nothing here executes anything: a passed proposal becomes a decision item for the DAO.
"""

from __future__ import annotations

import json
import logging
import re
import time
from fractions import Fraction

from fastapi import HTTPException
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from xe.client import XeError
from xe.statechain import strict_loads

from ..auth import Verified, bind
from ..canonical import DOMAIN_PROPOSAL, canonical_json, sha256_hex

from ..chainops import SNAPSHOT_LEAD_TEXT, SNAPSHOT_RULE, account_snapshot, empty_snapshot, snapshot_time
from ..context import Context
from ..db import locked, serialize
from ..models import FeeLedger, Proposal, Resolution, SigningSession, Vote
from ..text import clean_text, field_text
from . import sessions

D = 24 * 3600 * 1_000_000_000
MAX_TITLE = 160
MAX_BODY = 20_000
REDERIVE_UNSETTLED_S = 20.0   # what one worker pass spends reading unsettled chains again (`rederive_stale`)
log = logging.getLogger("dao.portal")
HEX64 = re.compile(r"[0-9a-f]{64}")
FINAL = ("adopt", "decline")


def fee_account(ctx: Context) -> str:
    return ctx.config.accounts.get("fee", "")


def proposal_hash(author: str, title: str, body: str, ops, fee_block_hash: str, timestamp: int) -> str:
    return sha256_hex(DOMAIN_PROPOSAL + canonical_json({
        "author": author, "title": title, "body": body, "ops": ops, "fee_block_hash": fee_block_hash, "timestamp": timestamp,
    }))


async def _verify_fee(ctx: Context, db: AsyncSession, fee_block_hash: str, author: str, fee: int) -> dict:
    """The fee is a send block from the author to the fee account, ≥ fee, in XE, not already used."""
    if fee <= 0:
        return {"hash": "", "amount": 0}
    fee_acct = fee_account(ctx)
    if not fee_acct:
        raise HTTPException(503, "fee account is not configured")
    # Two submits reusing one block: the second waits here for the first to commit, then sees its row and
    # gets this 409 rather than losing on the unique key after the node read (XE-1290).
    await serialize(db, f"fee:{fee_block_hash}")
    used = (await db.execute(select(Proposal.hash).where(Proposal.fee_block_hash == fee_block_hash))).first()
    if used:
        raise HTTPException(409, "this fee block has already been used")
    try:
        b = await ctx.chain.block(fee_block_hash)
    except XeError as e:
        if e.status == 404:
            raise HTTPException(400, "fee block not found on the chain yet; wait for it to be seen and retry") from e
        raise   # the application's one answer to a node failure: logged there, and a fixed 502 to the caller (XE-6983)
    if b.get("type") != "send":
        raise HTTPException(400, "fee block must be a send")
    if b.get("asset") != "XE":
        raise HTTPException(400, "fee must be paid in XE")
    if (b.get("destination") or "").lower() != fee_acct:
        raise HTTPException(400, f"fee must be sent to {fee_acct}")
    if (b.get("account") or "").lower() != author:
        raise HTTPException(400, "fee must be sent from the proposing account")
    if b.get("amount", 0) < fee:
        raise HTTPException(400, f"fee is {fee} µXE; block sends {b.get('amount')}")
    if b.get("finalized") is not True:
        # A seen-but-unfinalised send can still be dropped by the node (xeprotocol/xe#55, XE-0034).
        # Accepting it would open a proposal whose fee may never arrive and later refund XE we never held.
        raise HTTPException(400, "fee block is not yet finalised; retry in a few seconds")
    return b


async def submit(ctx: Context, db: AsyncSession, v: Verified) -> Proposal:
    p = v.payload
    title = clean_text(p.get("title"), "title", max_len=MAX_TITLE)
    body = clean_text(p.get("body"), "body", max_len=MAX_BODY)
    ops = p.get("ops")
    fee_block_hash = field_text(p, "fee_block_hash").lower()
    if fee_block_hash and not HEX64.fullmatch(fee_block_hash):
        raise HTTPException(400, "fee_block_hash must be 64 hex characters")
    if ops is not None:
        ops = sessions.normalise_ops(ops)
        sessions.check_proposal_ops(ops, sessions.seat_keys_of(ctx.config))   # ops some resolution could carry (XE-1650)
    rules = ctx.config.pinned_rules()
    fee = int(rules["fee_micro_xe"])
    if fee and not fee_block_hash:
        raise HTTPException(400, f"a fee of {fee} µXE to {fee_account(ctx)} is required; include fee_block_hash")
    if fee_block_hash and not fee:
        # A fee block is recorded against a proposal, and published as its fee block, only once
        # `_verify_fee` has read it. With no fee due nothing is read, so there is nothing to record: a hash
        # taken on the caller's word would sit in the unique column and in `proposal.opened` for good, and
        # refuse the block's real payer if a fee is set later (XE-4290).
        raise HTTPException(400, "no fee is due on a proposal; leave fee_block_hash out")
    fee_block = await _verify_fee(ctx, db, fee_block_hash, v.account, fee)
    now = time.time_ns()
    h = proposal_hash(v.account, title, body, ops, fee_block_hash, v.timestamp)
    pr = Proposal(hash=h, title=title, body=body, ops=ops, author_account=v.account, author_pub_key=v.pub_key,
                  author_signature=v.signature, author_timestamp=v.timestamp, fee_block_hash=fee_block_hash or h,
                  status="open", opened_at=now, closes_at=now + int(rules["window_days"]) * D, rules=rules,
                  result=None, decision=None, analysis=[])
    db.add(pr)
    if fee:
        db.add(FeeLedger(fee_block_hash=fee_block_hash, proposal_hash=h, payer=v.account,
                         amount=fee_block.get("amount", 0), state="seen", tx_hashes={}))
    await ctx.events.append(db, "proposal.opened", v.actor, {
        "proposal": h, "title": title, "body": body, "ops": ops, "author": v.account, "fee_block_hash": fee_block_hash,
        "opened_at": now, "snapshot_at": snapshot_time(now), "closes_at": pr.closes_at, "rules": rules,
    }, ref=f"proposal:{h}")
    return pr


async def get(db: AsyncSession, h: str, *, lock: bool = False) -> Proposal:
    """`lock=True` takes the row FOR UPDATE: every path that changes a proposal loads it this way, so two
    writers queue instead of each saving its own copy of a list over the other's (XE-0672)."""
    q = select(Proposal).where(Proposal.hash == h.lower())
    if lock:   # and read the row as it is now, even if an unlocked copy is already in this session (XE-0960)
        q = locked(q)
    pr = (await db.execute(q)).scalar_one_or_none()
    if pr is None:
        raise HTTPException(404, "proposal not found")
    return pr


async def list_proposals(db: AsyncSession, status: str | None = None, offset: int = 0, limit: int = 50) -> list[Proposal]:
    # the hash last: a paged listing has a total order, or two reads of it can skip or repeat a row (XE-3250)
    q = select(Proposal).order_by(Proposal.opened_at.desc(), Proposal.hash.desc()).offset(offset).limit(min(limit, 200))
    if status:
        q = q.where(Proposal.status == status)
    return list((await db.execute(q)).scalars().all())


_AWAITING = or_(Proposal.status == "closed",
                and_(Proposal.status == "decided", Proposal.decision["decision"].astext.notin_(FINAL)))


async def awaiting_decision(db: AsyncSession, limit: int = 50, offset: int = 0) -> list[Proposal]:
    """Closed proposals with no decision, and decided ones whose decision was interim (deferred or
    referred). Work that is waiting: oldest first, so the one that has waited longest is on the first page
    however many close after it, and `count_awaiting_decision` says how many there are in all. Newest
    first with no offset, the longest-waiting dropped off every list past the page size (XE-4601, the
    rule `inbox.list_untriaged` keeps since XE-1565)."""
    q = (select(Proposal).where(_AWAITING).order_by(Proposal.opened_at.asc(), Proposal.hash.asc())
         .offset(offset).limit(min(limit, 200)))
    return list((await db.execute(q)).scalars().all())


async def count_awaiting_decision(db: AsyncSession) -> int:
    return int((await db.execute(select(func.count()).select_from(Proposal).where(_AWAITING))).scalar_one())


# ---- votes ------------------------------------------------------------------------------------

def _open(pr: Proposal) -> None:
    if pr.status != "open" or time.time_ns() >= pr.closes_at:
        raise HTTPException(409, "voting is closed")


async def eligibility(ctx: Context, pr: Proposal, account: str, is_agent: bool) -> tuple[dict, list[str], bool, int]:
    """What an account's vote on this proposal is worth: its snapshot, why it does not participate (if it
    does not), whether it participates, its weight. Derived from the proposal's pinned rules and snapshot
    time, at cast and again at close for any row derived under a different snapshot (XE-1617)."""
    return await eligibility_at(ctx, pr.rules, snapshot_time(pr.opened_at), account, is_agent)


async def eligibility_at(ctx: Context, rules: dict, at: int, account: str, is_agent: bool) -> tuple[dict, list[str], bool, int]:
    """The derivation itself, for a set of pinned rules and a snapshot time. The vote, the re-derivation at
    close and the public preview all call this one function."""
    pw = rules.get("participating_wallet", {})
    reasons = []
    try:
        snap = await account_snapshot(ctx.chain, account, at, rules.get("weight_asset", "XE"))
    except XeError as e:
        if e.transient or e.status in (401, 403, 407):
            # The node may answer next time; the caller decides whether to wait. A refusal to authorise
            # is in that class: it is about who asked (this service, or the proxy it asks through) and
            # says nothing of the account, and the client words every refusal alike (XE-14195).
            raise
        # A definite answer that the chain cannot be read for this account (413: past the page bound the
        # harness reads, XE-1189) is the account's answer, not the node's mood: it weighs nothing, and the
        # proposal is not held open for it (XE-1706).
        snap = empty_snapshot(at, unreadable=str(e)[:200])
        reasons.append(f"the account's chain could not be read: {e.message[:120]}")
    excluded = account in set(rules.get("excluded_accounts", []))
    if excluded:
        reasons.append("excluded account")
    if pw.get("must_exist_before_open", True) and not snap["exists"]:
        reasons.append(f"account did not exist at the snapshot, {SNAPSHOT_LEAD_TEXT} before the proposal opened")
    if snap["balance"] < int(pw.get("min_balance_micro_xe", 0)):
        reasons.append("balance below the participation minimum at snapshot")
    if is_agent and (pw.get("exclude_agent_accounts", True) or not rules.get("agents", {}).get("count_toward_quorum", False)):
        reasons.append("agent accounts do not count toward quorum")
    return snap, reasons, not reasons, (0 if excluded else int(snap["balance"]))


def _derived_as_defined(ctx: Context, pr: Proposal, row: Vote) -> bool:
    snap = (row.eligibility or {}).get("snapshot") or {}
    return (snap.get("at") == snapshot_time(pr.opened_at) and snap.get("rule") == SNAPSHOT_RULE
            and bool(row.is_agent) == (row.account in ctx.config.agent_accounts))


def unsettled(row: Vote) -> bool:
    return bool(((getattr(row, "eligibility", None) or {}).get("snapshot") or {}).get("unsettled"))


def is_current(ctx: Context, pr: Proposal, row: Vote) -> bool:
    """Whether the row's stored weight was derived under the proposal's snapshot as it is now defined, and
    under the account's present class (an account made or unmade an agent seat since it voted is re-derived
    too, XE-1724). A snapshot of a chain that held a block the node did not yet hold final is not current
    either: the block has been settled one way or the other since, or will be (XE-3129)."""
    return _derived_as_defined(ctx, pr, row) and not unsettled(row)


async def vote_of(db: AsyncSession, h: str, account: str) -> Vote | None:
    return (await db.execute(select(Vote).where(Vote.proposal_hash == h, Vote.account == account))).scalar_one_or_none()


async def rederive_stale(ctx: Context, db: AsyncSession, pr: Proposal, until: float | None = None) -> list[Vote]:
    """Rows written under an earlier snapshot time or rule carry a weight the proposal no longer means.
    Each is re-derived from the chain before the tally reads it; the vote itself (choice, signature,
    time) stands. A node error leaves the row as it is and raises, so the close waits for the next pass
    rather than closing on stale weight (XE-1617). It is raised after the rows read before it are written,
    each with its entry: a caller that keeps what was done (`rederive_open`) keeps whole rows, never a
    changed weight the log does not show.

    The rows are written before the first entry is appended. Appending takes the log head, and a vote
    being cast holds its row and then waits for the head: rows written one at a time between entries
    would take the two in the other order, and the node would be asked about each account with the log
    held shut (XE-12010).

    `until` is the worker's: past that moment (`time.monotonic()`) a row that is stale only because its
    chain was unsettled is left for a later pass. Whoever holds an account can keep its chain unsettled,
    and each such row is a whole chain read again; a pass spends a bounded time on them. The close gives
    no `until`, and reads every one."""
    stale, changed, node_error = [], [], None
    for row in await votes_for(db, pr.hash):
        if is_current(ctx, pr, row):
            continue
        if until is not None and time.monotonic() >= until and _derived_as_defined(ctx, pr, row):
            continue
        is_agent = row.account in ctx.config.agent_accounts
        try:
            snap, reasons, participating, weight = await eligibility(ctx, pr, row.account, is_agent)
        except XeError as e:   # this row and the ones behind it stay as they are
            node_error = e
            break
        if (row.weight, row.participating, row.is_agent) != (weight, participating, is_agent):
            changed.append(row)
        row.weight, row.participating, row.is_agent = weight, participating, is_agent
        row.eligibility = {"snapshot": snap, "not_participating_because": reasons}
        stale.append(row)
    await db.flush()
    for row in changed:
        await ctx.events.append(db, "vote.rederived", "harness", {
            "proposal": pr.hash, "account": row.account, "weight": row.weight, "participating": row.participating,
            "is_agent": row.is_agent,
        }, ref=f"proposal:{pr.hash}")
    if node_error is not None:
        raise node_error
    return stale


async def rederive_open(ctx: Context, db: AsyncSession) -> int:
    """Worker: re-derive stale rows on open proposals, so the published open tally (which counts only
    current rows) catches up within a pass of a rule change or a seat change (XE-1664). A transient node
    error leaves the rest for the next pass.

    Each proposal is one step, as in `close_due`: held in a savepoint and named by a hash read before the
    step, so that whatever fails under it, the database included, undoes that proposal's rows, leaves the
    session usable, and is logged without asking the session for anything (XE-3724).

    And each proposal that wrote is committed before the next is read. Its entries took the log head,
    and the next proposal's rows are read from the node account by account: in one transaction the pass
    after a rule change held every writer in the service out for as long as that took (XE-14181)."""
    n = 0
    until = time.monotonic() + REDERIVE_UNSETTLED_S
    open_ = (await db.execute(select(Proposal).where(Proposal.status == "open"))).scalars().all()
    for pr, h in [(pr, pr.hash) for pr in open_]:
        node_error = None
        try:
            async with db.begin_nested():
                try:
                    n += len(await rederive_stale(ctx, db, pr, until))
                except XeError as e:   # raised after the rows read before it were written: those are kept
                    node_error = e
        except Exception:   # this proposal's rows, not the node: the proposals behind it are not held up
            log.exception("proposal %s: re-deriving its stale votes raised", h[:12])
            continue
        await db.commit()
        if node_error is not None:
            log.warning("proposal %s: could not re-derive stale votes: %s", h[:12], node_error)
            break
    return n


async def vote(ctx: Context, db: AsyncSession, pr: Proposal, v: Verified) -> Vote:
    """payload = {proposal, choice, reason?}. One vote per account; a later vote replaces an earlier one.

    The node read (the voter's snapshot) happens on an unlocked copy of the proposal; the write happens
    under row locks taken afterwards: the proposal FOR UPDATE, so a close that lands during the read is seen
    before anything is recorded, and the account's existing vote FOR UPDATE, so two votes from one account
    compare timestamps against the same row (XE-0960). Votes serialise for the write, not for the read."""
    _open(pr)
    choice = field_text(v.payload, "choice")
    if choice not in ("for", "against", "abstain"):
        raise HTTPException(400, "choice must be for | against | abstain")
    if field_text(v.payload, "proposal").lower() != pr.hash:
        raise HTTPException(400, "signed payload names a different proposal")
    is_agent = v.account in ctx.config.agent_accounts
    snap, reasons, participating, weight = await eligibility(ctx, pr, v.account, is_agent)
    reason = clean_text(v.payload.get("reason"), "reason", max_len=2000, required=False)
    pr = await get(db, pr.hash, lock=True)
    _open(pr)
    existing = (await db.execute(locked(select(Vote).where(Vote.proposal_hash == pr.hash, Vote.account == v.account)))).scalar_one_or_none()
    if existing:
        # Replacement is by signer time, not arrival: a vote signed earlier than the one on record is stale
        # and cannot overwrite it, whoever replays it and whenever (XE-0033).
        if v.timestamp <= existing.timestamp:
            raise HTTPException(409, "a newer vote from this account is already recorded")
        existing.choice, existing.reason, existing.timestamp, existing.signature = choice, reason, v.timestamp, v.signature
        existing.pub_key, existing.weight, existing.participating, existing.is_agent = v.pub_key, weight, participating, is_agent
        existing.eligibility = {"snapshot": snap, "not_participating_because": reasons}
        row = existing
    else:
        row = Vote(proposal_hash=pr.hash, account=v.account, pub_key=v.pub_key, choice=choice,
                   reason=reason, timestamp=v.timestamp, signature=v.signature, weight=weight,
                   participating=participating, is_agent=is_agent, eligibility={"snapshot": snap, "not_participating_because": reasons})
        db.add(row)
    await ctx.events.append(db, "vote.cast", v.actor, {
        "proposal": pr.hash, "account": v.account, "choice": choice, "weight": weight, "participating": participating,
        "is_agent": is_agent, "replaced": existing is not None, "reason": row.reason[:500],
    }, ref=f"proposal:{pr.hash}")
    return row


async def votes_for(db: AsyncSession, h: str) -> list[Vote]:
    return list((await db.execute(select(Vote).where(Vote.proposal_hash == h).order_by(Vote.timestamp.asc(), Vote.account.asc()))).scalars().all())


def _share(parts: dict[str, int], total: int) -> dict[str, int]:
    """Split `total` across `parts` pro rata in whole units, largest remainders first, so the shares sum
    to `total` exactly: no micro-XE is lost to truncation, and an allowance of one is one (XE-1493)."""
    whole = sum(parts.values())
    if not whole or not total:
        return {k: 0 for k in parts}
    exact = {k: Fraction(v * total, whole) for k, v in parts.items()}
    out = {k: int(x) for k, x in exact.items()}
    for k in sorted(parts, key=lambda k: (exact[k] - out[k], parts[k]), reverse=True)[: total - sum(out.values())]:
        out[k] += 1
    return out


def tally(pr: Proposal, votes: list[Vote], ctx: Context | None = None) -> dict:
    """The count. With `ctx`, only rows derived under the proposal's current snapshot and class are
    counted and the rest are reported as `stale_rows`: a published figure never includes a weight the
    proposal no longer means (XE-1664); the worker re-derives such rows and the close re-derives them
    before it tallies, so at close there are none. A row whose chain was still unsettled when the close
    read it is counted at what the chain was certain of, and `unsettled_rows` says how many there were
    (XE-3129)."""
    rules = pr.rules
    agents = rules.get("agents", {})
    cap = float(agents.get("max_weight_share", 0.01))
    human = {"for": 0, "against": 0, "abstain": 0}
    agent = {"for": 0, "against": 0, "abstain": 0}
    participating = 0
    stale = 0
    if ctx is not None:
        counted = [v for v in votes if is_current(ctx, pr, v)]
        stale, votes = len(votes) - len(counted), counted
    for v in votes:
        (agent if v.is_agent else human)[v.choice] += v.weight
        if v.participating:
            participating += 1
    # Agents may tip a human decision, never make one: their weight counts up to cap × the weight humans
    # decided with (for and against), scaled pro rata across their votes. Measured against the human
    # decision and not the total cast, so where humans only abstain, or vote dust, the agents count for
    # nothing and the proposal fails on `decided == 0` rather than passing on the agents alone (XE-1459).
    human_decided = human["for"] + human["against"]
    agent_total = sum(agent.values())
    agent_allowed = min(agent_total, int(Fraction(str(cap)) * human_decided)) if agent_total else 0
    agent_counted = _share(agent, agent_allowed)
    counted = {k: human[k] + agent_counted[k] for k in human}
    scale = (agent_allowed / agent_total) if agent_total else 0.0
    decided = counted["for"] + counted["against"]
    quorum = int(rules.get("quorum_wallets", 20))
    quorum_met = participating >= quorum
    pass_mark = float(rules.get("pass_mark_fraction", 0.5))
    # compared exactly: weights are integers of µXE and the mark is the decimal the schedule wrote (XE-5578)
    passed = quorum_met and decided > 0 and Fraction(counted["for"], decided) > Fraction(str(rules.get("pass_mark_fraction", 0.5)))
    return {
        "votes": len(votes), "stale_rows": stale, "unsettled_rows": sum(1 for v in votes if unsettled(v)),
        "participating_wallets": participating, "quorum_wallets": quorum, "quorum_met": quorum_met,
        "weight": counted, "weight_human": human, "weight_agent_raw": agent, "agent_scale": round(scale, 6),
        "for_share": (counted["for"] / decided) if decided else 0.0, "pass_mark": pass_mark,
        "outcome": ("passed" if passed else ("failed" if quorum_met else "no_quorum")),
    }


def shown_tally(pr: Proposal, votes: list[Vote], ctx: Context | None = None) -> dict:
    """The tally a reader is shown. An open proposal's is the live count. One that has closed shows the
    count it closed on (`pr.result`, written once by `_close`), not a recount against the seats and the
    snapshot rule as they are today: its vote rows are never re-derived after the close, so a later seat
    change or rule bump would drop them from a recount and the page would show a different outcome from
    the one recorded, acted on and settled (XE-4460)."""
    if pr.status != "open" and pr.result:
        return pr.result
    return tally(pr, votes, ctx)


async def close_due(ctx: Context, db: AsyncSession) -> list[Proposal]:
    """Worker: close proposals whose window has ended; record result; queue the fee action.

    One proposal is one transaction: its row is taken, it is closed, and the close is committed before
    the next proposal is looked at. A close writes to the log, and the next proposal's stale votes are
    read from the node first: with every due proposal in one transaction, the second was read with the
    log head held from the first, and every writer in the service waited on the node (XE-14181). The row
    is taken here, not for the whole pass, and only if it is still open and due, so a pass that finds it
    held or already closed by another leaves it."""
    now = time.time_ns()
    due = select(Proposal).where(Proposal.status == "open", Proposal.closes_at <= now)
    hashes = list((await db.execute(due.with_only_columns(Proposal.hash).order_by(Proposal.closes_at, Proposal.hash))).scalars().all())
    closed = []
    for h in hashes:
        pr = (await db.execute(locked(due.where(Proposal.hash == h), skip_locked=True))).scalar_one_or_none()
        if pr is None:
            continue
        try:
            async with db.begin_nested():   # one proposal's close is one step: what it wrote goes with it if it fails
                await _close(ctx, db, pr)
        except XeError as e:   # stale weight is not tallied; this proposal closes on a later pass
            log.warning("proposal %s: could not re-derive stale votes: %s", h[:12], e)
            continue
        except Exception:   # this proposal stays open and is tried again; the ones behind it still close
            log.exception("proposal %s: closing it raised", h[:12])
            continue
        await db.commit()
        closed.append(pr)
    return closed


async def _close(ctx: Context, db: AsyncSession, pr: Proposal) -> None:
    await rederive_stale(ctx, db, pr)
    res = tally(pr, await votes_for(db, pr.hash))
    pr.result = res
    pr.status = "closed"
    fee = (await db.execute(select(FeeLedger).where(FeeLedger.proposal_hash == pr.hash))).scalar_one_or_none()
    if fee and fee.state == "seen":
        action = pr.rules.get("fee_on_quorum", "refund") if res["quorum_met"] else pr.rules.get("fee_below_quorum", "burn")
        fee.state = f"due_{action}"
    await db.flush()   # the rows, then the log head: the order every other writer takes them in (XE-12010)
    await ctx.events.append(db, "proposal.closed", "harness", {"proposal": pr.hash, "title": pr.title, "result": res}, ref=f"proposal:{pr.hash}")


async def _decision_resolution(db: AsyncSession, pr: Proposal, res_id: str, *, passed: bool = True) -> Resolution:
    """A resolution named by a decision must exist, be about this proposal, and still be live; for a decision
    other than a referral it must also have passed (XE-0201). A referral names one that is open or passed
    (XE-1847)."""
    q = (select(Resolution).where(Resolution.id == res_id)
         .with_for_update().execution_options(populate_existing=True))
    r = (await db.execute(q)).scalar_one_or_none()
    if r is None:
        raise HTTPException(400, "resolution_id names no resolution")
    if r.related_proposal != pr.hash:
        raise HTTPException(409, "that resolution is not about this proposal")
    if passed and r.status != "passed":
        raise HTTPException(409, f"that resolution is {r.status}, not passed")
    if not passed and r.status not in ("open", "passed"):
        raise HTTPException(409, f"that resolution is {r.status}; a referral names one that is open or passed")
    if r.session_id:
        sq = (select(SigningSession).where(SigningSession.id == r.session_id)
              .with_for_update().execution_options(populate_existing=True))
        s = (await db.execute(sq)).scalar_one_or_none()
        if s is None or s.status in ("cancelled", "failed"):
            state = s.status if s else "missing"
            raise HTTPException(409, f"that resolution's session is {state}; its ops will not execute")
    return r


def _key_sorted(value_text: str) -> str:
    """An op value's text with its object keys sorted at every depth and nothing else changed."""
    return json.dumps(strict_loads(value_text), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def same_ops(a: list[dict] | None, b: list[dict] | None) -> bool:
    """Whether two op lists write the same state: same actions and keys in order, and values that are the
    same JSON text once object keys are sorted. Values are stored as the exact bytes their author wrote (key
    order kept, because those bytes go on the chain), so byte equality would refuse `{"a":1,"b":2}` against
    `{"b":2,"a":1}`, which authorise the same thing (XE-1649, XE-1725). Each value is re-written in one
    spelling (keys sorted, no whitespace, one form per number and string) and the texts are compared, so
    the same JSON value spelled two ways is equal and nothing else is. Parsed values are not compared,
    because Python calls `1`, `1.0` and `true` equal and the chain does not: a resolution writing `1` does
    not authorise a proposal writing `true` (XE-2077)."""
    if a is None or b is None or len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if (x.get("action"), x.get("key")) != (y.get("action"), y.get("key")):
            return False
        if x.get("action") == "set":
            try:
                if _key_sorted(x["value"]) != _key_sorted(y["value"]):
                    return False
            except (KeyError, TypeError, ValueError):
                return False
    return True


async def decide(ctx: Context, db: AsyncSession, pr: Proposal, v: Verified) -> Proposal:
    """The DAO's response to a closed proposal: adopt / decline / defer / refer_to_resolution, with reasons.
    Members or officers with operational_review may record it, once (XE-0201): the record is the DAO's
    published position, so a single seat key cannot flip it afterwards. `adopt` needs the vote to have
    passed; `adopt` of a proposal carrying state-chain ops also needs a passed resolution about this
    proposal that authorises exactly those ops. `decline`, `defer` and `refer_to_resolution` are recordable
    on any closed vote, including a failed or no-quorum one; the last two are interim and may be followed by
    one adopt or decline. Nothing here executes anything; ops still move only through a resolution and a
    signing session."""
    bind(v, proposal=pr.hash)
    decision = field_text(v.payload, "decision")
    if decision not in ("adopt", "decline", "defer", "refer_to_resolution"):
        raise HTTPException(400, "decision must be adopt | decline | defer | refer_to_resolution")
    if pr.status == "decided":
        # `defer` and `refer_to_resolution` say "not yet": each may be followed by one final adopt or
        # decline, with the earlier record kept under `history` (XE-1127). adopt and decline are final.
        if (pr.decision or {}).get("decision") in FINAL or decision not in FINAL:
            raise HTTPException(409, "a decision is already recorded for this proposal")
    elif pr.status != "closed":
        raise HTTPException(409, "proposal is not closed")
    reasons = clean_text(v.payload.get("reasons"), "reasons", max_len=MAX_BODY)
    if len(reasons) < 10:
        raise HTTPException(400, "reasons are required")
    res_id = clean_text(v.payload.get("resolution_id"), "resolution_id", max_len=64, required=False)
    outcome = (pr.result or {}).get("outcome")
    if decision == "refer_to_resolution" and not res_id:
        # A referral to nothing would spend the proposal's one interim step on a record that names no
        # resolution (XE-1847).
        raise HTTPException(400, "refer_to_resolution names the resolution; give its resolution_id")
    resolution = await _decision_resolution(db, pr, res_id, passed=decision != "refer_to_resolution") if res_id else None
    if resolution is not None and resolution.matter == "adopt_open_vote":
        if outcome != "passed":
            msg = f"the vote {outcome or 'has no tally'}; adopt_open_vote needs a passed vote"
            raise HTTPException(409, msg)
        if pr.ops and not same_ops(resolution.ops, pr.ops):
            raise HTTPException(409, "that resolution does not authorise exactly this proposal's ops")
    if decision == "adopt":
        if outcome != "passed":
            raise HTTPException(409, f"the vote {outcome or 'has no tally'}; a proposal is adopted only when it passed")
        if resolution is not None and resolution.matter == "decline_open_vote":
            raise HTTPException(409, "that resolution declines this proposal; it cannot authorise adoption")
        if pr.ops:
            if resolution is None:
                raise HTTPException(409, "a proposal with ops is adopted via a passed resolution; give its resolution_id")
            if not same_ops(resolution.ops, pr.ops):
                raise HTTPException(409, "that resolution does not authorise exactly this proposal's ops")
    elif decision == "decline" and resolution and (resolution.matter == "adopt_open_vote" or resolution.ops):
        msg = "that resolution authorises adoption or ops; it cannot be cited to decline"
        raise HTTPException(409, msg)
    history = [*pr.decision.get("history", []), {k: x for k, x in pr.decision.items() if k != "history"}] if pr.decision else []
    pr.decision = {"decision": decision, "reasons": reasons, "by": v.seat.id, "timestamp": v.timestamp,
                   "resolution_id": res_id, "outcome": outcome, **({"history": history} if history else {})}
    pr.status = "decided"
    await ctx.events.append(db, "proposal.decided", v.actor, {"proposal": pr.hash, **pr.decision}, ref=f"proposal:{pr.hash}")
    return pr


async def add_analysis(ctx: Context, db: AsyncSession, pr: Proposal, v: Verified) -> Proposal:
    """Analysis informs a decision, so it is written before one is final: a decided record is closed to
    further analysis the same way it is closed to a second decision (XE-1770)."""
    bind(v, proposal=pr.hash)
    if pr.status == "decided" and (pr.decision or {}).get("decision") in FINAL:
        raise HTTPException(409, "a final decision is recorded for this proposal; its analysis is closed")
    text = clean_text(v.payload.get("text"), "text", max_len=MAX_BODY)
    entry = {"by": v.seat.id if v.seat else v.account, "timestamp": v.timestamp, "text": text}
    pr.analysis = [*pr.analysis, entry]
    await ctx.events.append(db, "proposal.analysis", v.actor, {"proposal": pr.hash, **entry}, ref=f"proposal:{pr.hash}")
    return pr


async def counts(db: AsyncSession) -> dict:
    rows = (await db.execute(select(Proposal.status, func.count()).group_by(Proposal.status))).all()
    return {s: int(c) for s, c in rows}


def to_dict(pr: Proposal, votes: list[Vote] | None = None, include_body: bool = True, ctx: Context | None = None) -> dict:
    d = {
        "hash": pr.hash, "title": pr.title, "author": pr.author_account, "status": pr.status, "opened_at": pr.opened_at,
        "snapshot_at": snapshot_time(pr.opened_at), "closes_at": pr.closes_at,
        # a proposal on which no fee was due keeps its own hash in the column, which names no block
        "fee_block_hash": "" if pr.fee_block_hash == pr.hash else pr.fee_block_hash,
        "rules": pr.rules, "ops": pr.ops,
        "result": pr.result, "decision": pr.decision, "analysis": pr.analysis,
    }
    if include_body:
        d["body"] = pr.body
    if votes is not None:
        d["tally"] = shown_tally(pr, votes, ctx)
        d["votes"] = [{"account": v.account, "choice": v.choice, "weight": v.weight, "participating": v.participating,
                       "is_agent": v.is_agent, "timestamp": v.timestamp, "reason": v.reason} for v in votes]
    return d
