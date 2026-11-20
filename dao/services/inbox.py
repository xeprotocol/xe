"""Inbox: third parties talk to the DAO directly, over XE chat or signed HTTP.

Every inbound message is verified (signature over the envelope id, PoW, key derives the account),
stored, logged, and acknowledged. One that fails the harness's own verification is still stored, so the
id is remembered and never fetched again, but it is never public: the node checks every envelope before
the harness sees it, so such a message means a node or a configuration the harness should not trust for
attribution, and the public record carries only what the harness itself verified (XE-1254). Replies are
written by a seat holder and sent from the DAO's own account over chat, so the correspondent gets an
answer on the channel they used.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from xe.chat import MAX_ENVELOPE_SKEW_NS, ChatError, Envelope, new_envelope, verify_envelope
from xe.chat_auth import chat_read_proof
from xe.client import UNREACHABLE, XeError
from xe.pow import WORKER_POW_DEADLINE_S

from ..auth import Verified, require_pow
from ..context import Context
from ..db import locked
from ..faults import reason
from ..log import EventLog
from ..models import InboxMessage, OutboxMessage
from ..text import clean_text, field_text, has_bad_control, scrub
from . import pause

log = logging.getLogger("dao.inbox")

OUTBOX_RETRY_DAYS = 7
NS = 1_000_000_000
AUTO_ACK = ("Received by the XE DAO and recorded in the public log. A person reads every message; "
            "replies come from this account. Nothing in this message is a commitment.")


def dao_account(ctx: Context) -> str:
    return ctx.config.accounts.get("dao", "")


async def store_envelope(ctx: Context, db: AsyncSession, env: Envelope, channel: str = "chat") -> InboxMessage | None:
    existing = (await db.execute(select(InboxMessage).where(InboxMessage.id == env.id))).scalar_one_or_none()
    if existing:
        return None
    verified = True
    try:
        verify_envelope(env, ctx.node.chat_pow_difficulty, check_freshness=False)
    except ChatError as e:
        verified = False
        log.info("unverified envelope %s: %s", env.id[:12], e)
    body, status = env.message, "new"
    if has_bad_control(body):
        # The signature covers the exact bytes, so we cannot clean a verified body and still call it verified.
        # Store a visibly scrubbed copy, marked unverified and spam, so the id is remembered and never re-fetched.
        body, verified, status = scrub(body), False, "spam"
        log.info("envelope %s carried control characters; stored scrubbed as spam", env.id[:12])
    m = InboxMessage(id=env.id, channel=channel, from_account=env.from_, to_account=env.to, pub_key=env.pub_key,
                     body=body, timestamp=env.timestamp, signature=env.signature, pow_nonce=env.pow_nonce,
                     verified=verified, status=status)
    db.add(m)
    ev = await ctx.events.append(db, "inbox.received", f"account:{env.from_}", {
        "id": env.id, "channel": channel, "from": env.from_, "verified": verified, "body": body[:4000],
        "timestamp": env.timestamp,
    }, ref=f"inbox:{env.id}", public=verified and status != "spam")
    if verified and channel == "chat" and not await pause.is_paused(db) and not await _acked_recently(db, env.from_):
        await queue_reply(ctx, db, m, f"{AUTO_ACK} Log index {ev.index}.", from_seat="harness", kind="ack")
    return m


ACK_EVERY_S = 3600


async def _acked_recently(db: AsyncSession, account: str) -> bool:
    """One acknowledgement per correspondent per hour. Every verified envelope is still stored and logged;
    only the courtesy reply is rationed, so a flood of cheap messages cannot fill the outbox with
    acknowledgements and hold members' replies behind them (XE-1845)."""
    since = datetime.now(timezone.utc) - timedelta(seconds=ACK_EVERY_S)
    q = select(func.count()).select_from(OutboxMessage).where(OutboxMessage.to_account == account,
                                                               OutboxMessage.from_seat == "harness",
                                                               OutboxMessage.created_at >= since)
    return int((await db.execute(q)).scalar_one()) > 0


async def http_submit(ctx: Context, db: AsyncSession, v: Verified) -> InboxMessage:
    """A signed message over HTTP. Costs the sender a chat-level proof of work (XE-0032).

    The receipt is logged privately: it is in the hash chain, but not on the public log until a member has
    looked at it (`publish_on_triage`). Anyone can still send; nobody can fill the permanent record unread.
    """
    require_pow(v, ctx.node.chat_pow_difficulty)
    body = clean_text(v.payload.get("message"), "message", max_len=8000)
    mid = secrets.token_hex(16)
    m = InboxMessage(id=mid, channel="http", from_account=v.account, to_account=dao_account(ctx), pub_key=v.pub_key,
                     body=body, timestamp=v.timestamp, signature=v.signature, pow_nonce=v.pow_nonce or 0,
                     verified=True, status="new")
    db.add(m)
    await ctx.events.append(db, "inbox.received", v.actor, {
        "id": mid, "channel": "http", "from": v.account, "verified": True, "body": body[:4000], "timestamp": v.timestamp,
    }, ref=f"inbox:{mid}", public=False)
    return m


async def publish_on_triage(ctx: Context, db: AsyncSession, m: InboxMessage, actor: str) -> None:
    """First time a member takes an HTTP message up (a reply, or a status other than `new` or `spam`), put
    it on the public log and mark the row `published`. Once is enough: a message marked spam and then
    reconsidered is published then, not twice.

    `published` is the fact the public surfaces read (`is_public`), and it is never unset. The status is
    not that fact: it goes back to `new` when a reply is given up or a member sets it so, and a message
    whose text is already in the public log, hash-chained, did not become private again by that. Keyed on
    the status, the inbox page dropped a message the log still carried and the members' untriaged list
    showed it as never seen (XE-4593)."""
    if m.channel != "http" or m.published:
        return
    m.published = True
    if await EventLog.page(db, 0, 1, "inbox.published", f"inbox:{m.id}"):
        return   # on the log from before the row carried the flag
    await ctx.events.append(db, "inbox.published", actor, {
        "id": m.id, "channel": m.channel, "from": m.from_account, "verified": m.verified, "body": m.body[:4000],
        "timestamp": m.timestamp,
    }, ref=f"inbox:{m.id}")


async def queue_reply(ctx: Context, db: AsyncSession, m: InboxMessage, text: str, from_seat: str, kind: str = "reply") -> OutboxMessage:
    """Queue a reply. A member's reply moves the message to `replying`; it becomes `answered` when the reply
    has gone out and returns to `new` if the reply is given up, so the record says what was delivered,
    not what was intended (XE-1776, XE-1846)."""
    o = OutboxMessage(id=secrets.token_hex(8), in_reply_to=m.id, from_seat=from_seat, to_account=m.from_account,
                      body=text, envelope={}, status="queued")
    db.add(o)
    if kind == "reply":
        m.status = "replying"
        m.reply_id = o.id
    await ctx.events.append(db, "outbox.queued", from_seat if from_seat == "harness" else f"seat:{from_seat}", {
        "id": o.id, "in_reply_to": m.id, "to": m.from_account, "kind": kind, "body": text[:4000],
    }, ref=f"inbox:{m.id}")
    return o


async def reply(ctx: Context, db: AsyncSession, m: InboxMessage, v: Verified) -> OutboxMessage:
    text = clean_text(v.payload.get("text"), "text", max_len=8000, max_bytes=8000)
    if not m.from_account:
        # An envelope stored unverified can name no sender. A reply to it is an envelope to nobody, which
        # the builder refuses (`xe.chat.new_envelope`): said here, before it is queued to be built.
        raise HTTPException(409, "this message names no sender; there is nobody to reply to")
    await publish_on_triage(ctx, db, m, v.actor)
    return await queue_reply(ctx, db, m, text, from_seat=v.seat.id)


async def set_status(ctx: Context, db: AsyncSession, m: InboxMessage, v: Verified) -> InboxMessage:
    status = field_text(v.payload, "status")
    if status not in ("new", "read", "closed", "spam"):
        raise HTTPException(400, "bad status")   # `replying` and `answered` are set by delivery, not by hand
    if status not in ("new", "spam"):
        await publish_on_triage(ctx, db, m, v.actor)
    m.status = status
    m.classification = clean_text(v.payload.get("classification"), "classification", max_len=32,
                                  required=False) or m.classification
    await ctx.events.append(db, "inbox.status", v.actor, {"id": m.id, "status": status, "classification": m.classification},
                            ref=f"inbox:{m.id}", public=status != "spam")
    return m


# The outbox, in one rule (XE-2148): a reply has one envelope at a time, the envelope is on disk before it
# is offered, and the row says `sent` only when the node has said it took that envelope or the node's own
# store holds it. Nothing is concluded from a send that raised: the node stores an envelope after the
# recipient's node has it and before it answers, so a timeout says nothing about delivery.
#
#   queued    no envelope is in play. One is built (signed, worked) and committed with the row.
#   sending   an envelope is in play. While it is fresh it is offered again as it is, which is safe however
#             many times it happens: the node and the recipient both keep one copy per envelope id. Once it
#             is too old for any node to take, the node's store says whether it ever landed: there, the row
#             is `sent`; not there, the row is `queued` again and a new envelope is built.
#   sent      the node took the envelope.
#
# The earlier versions each named the failure they had seen (a commit lost after the send, then a pass that
# died mid-send) and guessed for the rest; the guess for "the send raised" was "not taken", and the retry
# went out under a new id that nothing could match to the first.
#
# What this cannot see, stated rather than guessed at: the node's chat store is in memory and bounded, so a
# node restarted (or an account's store evicted) between a send and the read-back looks like "never held",
# and the reply goes out again under a new id; and a recipient whose node stored the envelope while ours
# never did (the answer between the two nodes was lost) is offered a second one after the first has expired.

FRESH_NS = MAX_ENVELOPE_SKEW_NS - 60 * 1_000_000_000     # still worth offering: a node will take it
EXPIRED_NS = MAX_ENVELOPE_SKEW_NS + 60 * 1_000_000_000   # no node will take it now, whatever its clock


async def flush_outbox(ctx: Context, db: AsyncSession) -> int:
    """Worker: send queued replies from the DAO account over chat. PoW off the loop. Every row is committed
    at each step it takes, so a crash or a pause landing mid-batch leaves each row saying exactly how far
    it got. Returns how many rows became `sent`.

    Under a pause nothing is built and nothing is offered. What was offered before the pause is still
    looked up in the node's store, which is a read: a reply the node took is recorded as sent while the
    store still holds it, rather than after a pause that may outlast the store."""
    if not ctx.signer.has("dao"):
        return 0
    n = await _resolve_sending(ctx, db)
    if await pause.is_paused(db):
        return n
    # Members' replies before acknowledgements, oldest first (XE-1845).
    order = (case((OutboxMessage.from_seat == "harness", 1), else_=0), OutboxMessage.created_at.asc())
    ids = list((await db.execute(select(OutboxMessage.id).where(OutboxMessage.status == "queued").order_by(*order).limit(10))).scalars().all())
    now = datetime.now(timezone.utc)
    for oid in ids:
        # Each row is a step of its own, named by an id read before it: what fails under one, the database
        # included, is rolled back and logged, and the rows behind it are still sent (XE-3724).
        try:
            o = await db.get(OutboxMessage, oid)
            if o is None or o.status != "queued":
                continue
            if await _retried_long_enough(db, o, now):
                # retried for a week; the channel is not going to open. Stop, and say so on the record.
                await _lock_answered(db, o)
                o.status = "failed"
                await ctx.events.append(db, "outbox.failed", "harness", {"id": o.id, "to": o.to_account, "error": o.error[:300]},
                                        ref=f"inbox:{o.in_reply_to}")
                await _reply_outcome(ctx, db, o, delivered=False)
                await db.commit()
                continue
            try:
                confirmed_network(ctx)
                kp = ctx.signer.keypair("dao", "chat.send")
                env = await asyncio.to_thread(new_envelope, kp, o.to_account, o.body, ctx.node.chat_pow_difficulty,
                                              None, WORKER_POW_DEADLINE_S)
            except Exception as e:   # nothing was built, so nothing was offered: the row is still `queued`
                o.error = reason(e, 500)
                log.warning("outbox %s: no envelope built: %s", o.id, e)
                await db.commit()
                if isinstance(e, TimeoutError):
                    # The proof of work ran out of time, which is this machine and the difficulty and
                    # not the row: the rows behind would search as long and find as little, each for
                    # the whole deadline, with every other job of the worker waiting behind the pass.
                    # The pass ends, as a fee settlement's does (`fees.settle_due`, XE-14351).
                    return n
                continue
            if await pause.is_paused(db):   # read after the work, right before the send (XE-1172)
                return n                    # the envelope is discarded; the row is still `queued`
            o.status, o.envelope, o.error = "sending", env.to_json(), ""
            await db.commit()
            n += await _offer(ctx, db, o)
        except Exception as e:
            await db.rollback()
            log.warning("outbox %s: %s: %s; left as it was last committed", oid, type(e).__name__, e)
    return n


async def _retried_long_enough(db: AsyncSession, o: OutboxMessage, now: datetime) -> bool:
    """A reply is given up after a week of being retried, and a week under a pause is not that: nothing is
    built or offered while one is in force, so the time it lasted is taken off the row's age. A reply
    queued the hour before a ten-day pause gets its week of sends when the pause ends, rather than being
    failed on the first pass after it without one attempt (XE-12679).

    A pause is the one stop the harness keeps a record of. Time the worker was not running, or ran
    without the DAO key, is not recorded anywhere and still counts toward the week: a reply that old when
    the worker comes back is given up on its first pass, and `outbox.failed` says so on the log."""
    if not o.created_at or now - o.created_at <= timedelta(days=OUTBOX_RETRY_DAYS):
        return False
    since, until = int(o.created_at.timestamp() * NS), int(now.timestamp() * NS)
    return until - since - await pause.paused_ns(db, since, until) > OUTBOX_RETRY_DAYS * 24 * 3600 * NS


async def _offer(ctx: Context, db: AsyncSession, o: OutboxMessage) -> bool:
    """Offer a `sending` row's envelope to the node. True: the node took it and the row is `sent`. False:
    the send raised, which says nothing either way, so the row stays `sending` for `_resolve_sending`.
    The caller has read the pause."""
    try:
        await ctx.chain.chat_send(o.envelope)
    except Exception as e:
        o.error = reason(e, 500)
        log.warning("outbox %s: send of %s raised; outcome unknown: %s", o.id, str(o.envelope.get("id"))[:12], e)
        await db.commit()
        return False
    await _sent(ctx, db, o)
    await db.commit()
    return True


async def _lock_answered(db: AsyncSession, o: OutboxMessage) -> None:
    """Locks are taken in one order everywhere: the inbox message, then the log head. A member's reply or
    status change holds the message while it appends its event, so the outbox takes the message before it
    appends what became of the reply, not after; the other way round, the two wait on each other."""
    if o.from_seat != "harness":
        await db.execute(locked(select(InboxMessage.id).where(InboxMessage.id == o.in_reply_to)))


async def _sent(ctx: Context, db: AsyncSession, o: OutboxMessage) -> None:
    await _lock_answered(db, o)
    o.status, o.sent_at, o.error = "sent", datetime.now(timezone.utc), ""
    await ctx.events.append(db, "outbox.sent", "harness", {"id": o.id, "envelope_id": o.envelope["id"], "to": o.to_account},
                            ref=f"inbox:{o.in_reply_to}")
    await _reply_outcome(ctx, db, o, delivered=True)


async def _resolve_sending(ctx: Context, db: AsyncSession) -> int:
    """Rows whose envelope was offered (or was about to be) and whose outcome is not on disk. The node's
    store is asked once for all of them. A store that cannot be read concludes nothing: no row becomes
    `sent` or `queued` on its account, and an envelope still fresh is offered again all the same."""
    rows = list((await db.execute(select(OutboxMessage).where(OutboxMessage.status == "sending")
                                  .order_by(OutboxMessage.created_at.asc()))).scalars().all())
    for o in [o for o in rows if not _in_play(o)]:   # no envelope to look for: nothing can have been offered
        o.status = "queued"
        rows.remove(o)
    await db.commit()
    if not rows:
        return 0
    # An envelope's age is taken once, as the store is asked. "Not in the store and expired" is only the
    # end of an envelope if it had expired before the store answered; measured later, row by row, a pass
    # slowed by its own sends would call one expired that a node could still have taken after the read.
    asked_at = time.time_ns()
    held: set[str] | None = None
    try:
        since = min(o.envelope["timestamp"] for o in rows) - 1
        store = await ctx.chain.chat_messages(await read_proof(ctx), since)
        held = {d["id"] for d in store if isinstance(d.get("id"), str)}
    except Exception as e:   # nothing is concluded for any row; a fresh envelope can still be offered again
        log.warning("outbox: %d replies in play and the node's chat store cannot be read: %s", len(rows), e)
    n = 0
    for oid in [o.id for o in rows]:
        # one row, one step, as in `flush_outbox`: a row the database refused does not hold up the rest (XE-3724)
        try:
            o = await db.get(OutboxMessage, oid)
            if o is None or o.status != "sending" or not _in_play(o):
                continue
            age = asked_at - o.envelope["timestamp"]
            if held is not None and o.envelope["id"] in held:
                await _sent(ctx, db, o)   # a record of what happened; nothing is written to the node
                n += 1
            elif age < FRESH_NS:
                # the same envelope again, which no reading of the store is needed for: both nodes keep one copy
                # per id. The pause is read here, after the store was (XE-1172); under one, nothing is offered.
                if not await pause.is_paused(db):
                    n += await _offer(ctx, db, o)
            elif held is not None and age > EXPIRED_NS:
                o.status = "queued"
                # What the last send said is not carried over: this text goes into the log if the reply is
                # given up, and a row written before XE-14195 holds the node's own words.
                o.error = "the node never held the envelope and it is now too old to offer; a new one will be built"
            await db.commit()
        except Exception as e:
            await db.rollback()
            log.warning("outbox %s: %s: %s; left as it was last committed", oid, type(e).__name__, e)
    return n


def _in_play(o: OutboxMessage) -> bool:
    e = o.envelope if isinstance(o.envelope, dict) else {}
    ts = e.get("timestamp")
    return isinstance(e.get("id"), str) and bool(e["id"]) and isinstance(ts, int) and not isinstance(ts, bool)


async def _reply_outcome(ctx: Context, db: AsyncSession, o: OutboxMessage, *, delivered: bool) -> None:
    """The inbox message a member's reply answers follows the reply: `answered` once it has gone out, back
    to `new` if it never will (XE-1776, XE-1846). Acknowledgements leave the message as it is.

    Delivery moves a message only out of `replying`, the one status delivery itself set. Any other status
    was put there by a member after the reply was queued (closed, spam, read, or back to new), and a
    member's decision is not undone by the outbox, in either direction (XE-2357). `reply_id` never names a
    reply that did not go out: when one is given up it names the last reply that was delivered, if there
    is one, and the message is `answered` by that reply, since a follow-up that failed does not unsend
    the answer before it (XE-2629).

    With none delivered, a member's reply that is still on its way is the one the message waits on: the
    link moves to it and the message stays `replying`, so its outcome is recorded when it has one. Rows
    are not resolved in the order they were queued (a `sending` row can outlast the give-up of a later
    one), and concluding `new` while an earlier reply was still in play left that reply's delivery with
    nothing to mark: sent, on the node, and the message reading unanswered (XE-12755). Only with nothing
    delivered and nothing in play is the link dropped and the message `new` again."""
    if o.from_seat == "harness":
        return
    # the row as it is now, not as this session last saw it: a member may have changed it since
    m = (await db.execute(locked(select(InboxMessage).where(InboxMessage.id == o.in_reply_to)))).scalar_one_or_none()
    if m is None or m.reply_id != o.id:
        return
    answer = o
    if not delivered:
        answer = (await db.execute(select(OutboxMessage).where(
            OutboxMessage.in_reply_to == m.id, OutboxMessage.status == "sent", OutboxMessage.from_seat != "harness")
            .order_by(OutboxMessage.sent_at.desc(), OutboxMessage.id.desc()).limit(1))).scalar_one_or_none()
        waiting = None if answer else (await db.execute(select(OutboxMessage).where(
            OutboxMessage.in_reply_to == m.id, OutboxMessage.status.in_(("queued", "sending")),
            OutboxMessage.from_seat != "harness", OutboxMessage.id != o.id)
            .order_by(OutboxMessage.created_at.desc(), OutboxMessage.id.desc()).limit(1))).scalar_one_or_none()
        m.reply_id = answer.id if answer else waiting.id if waiting else ""
        if waiting:
            return   # still `replying` if it was: that reply's outcome is the message's
    if m.status != "replying":
        return
    m.status = "answered" if answer else "new"
    await ctx.events.append(db, "inbox.status", "harness", {"id": m.id, "status": m.status, "reply": answer.id if answer else o.id},
                            ref=f"inbox:{m.id}")


def confirmed_network(ctx: Context) -> None:
    """The DAO key signs for a node only once that node is known to serve the network this deployment is
    for. A read proof opens the DAO's chat to whoever holds it and an envelope is the DAO speaking: made
    for a node that turned out to be another network's, they are that network's to use (XE-12620)."""
    if not ctx.node.network_id:
        raise XeError(UNREACHABLE, "the node's network is not confirmed; the DAO key signs nothing for it until it is")


async def read_proof(ctx: Context) -> dict[str, str]:
    confirmed_network(ctx)
    ch = await ctx.chain.chat_challenge()
    kp = ctx.signer.keypair("dao", "chat.read_proof")
    return chat_read_proof(kp, ch["challenge"])


CURSOR_MARGIN_NS = 15 * 60 * NS   # three times the node's envelope clock skew (5 minutes)
CURSOR_START_NS = 24 * 3600 * NS


async def chat_cursor(db: AsyncSession) -> int:
    """Where a backfill asks the node from: the newest stored chat envelope's timestamp less a margin wider
    than the node's clock skew allowance, or a day ago if nothing is stored. The day is where a harness
    with no chat history starts and nothing else: it is not a floor under the stored cursor. The node keeps
    an envelope for thirty days, so a worker that was down for a weekend comes back to everything sent
    while it was away, not to the last day of it (XE-2480). The cursor is derived from
    what is on disk, never from what was seen: an envelope that failed to store, or one dated five minutes
    ahead by its sender, cannot move it past honest messages (XE-1651, XE-1666, XE-1768). A stored
    timestamp further ahead than any node accepts is not a time anything arrived and is not counted: the
    sender picks an envelope's timestamp, and one dated next year would otherwise hold the cursor there.
    Over-fetching is harmless; `store_envelope` skips ids it holds."""
    now = time.time_ns()
    newest = (await db.execute(select(func.max(InboxMessage.timestamp)).where(
        InboxMessage.channel == "chat", InboxMessage.timestamp <= now + MAX_ENVELOPE_SKEW_NS))).scalar_one()
    return int(newest) - CURSOR_MARGIN_NS if newest else now - CURSOR_START_NS


async def backfill(ctx: Context, db: AsyncSession) -> int:
    """Pull messages the node holds since the stored cursor (used at start and after stream drops)."""
    if not ctx.signer.has("dao"):
        return 0
    proof = await read_proof(ctx)
    n = 0
    for d in await ctx.chain.chat_messages(proof, await chat_cursor(db)):
        if await receive(ctx, db, d):
            n += 1
    return n


async def receive(ctx: Context, db: AsyncSession, item) -> InboxMessage | None:
    """One item from the node's chat feed (the stream or a backfill): stored if it is an envelope addressed
    to the DAO that is not already held. An item that is not an envelope at all is logged and skipped, so
    one bad item costs itself and nothing behind it (XE-2209); both readers come through here."""
    try:
        env = Envelope.from_json(item)
    except ChatError as e:
        log.info("chat item skipped: %s", e)
        return None
    if env.to != ctx.signer.address("dao"):
        return None
    return await store_envelope(ctx, db, env)


async def list_messages(db: AsyncSession, status: str | None = None, limit: int = 100) -> list[InboxMessage]:
    q = select(InboxMessage).order_by(InboxMessage.timestamp.desc(), InboxMessage.id.desc()).limit(limit)
    if status:
        q = q.where(InboxMessage.status == status)
    return list((await db.execute(q)).scalars().all())


def is_public(m: InboxMessage) -> bool:
    """What the public surfaces may show (XE-0195). Only what the harness verified (XE-1254); spam never;
    an HTTP message once it is `published`, which is when its text reaches the public log
    (`publish_on_triage`) and holds whatever status it takes afterwards (XE-4593). Verified chat is logged
    on receipt and public from the start. `list_public` is the same rule in SQL."""
    return bool(m.verified and m.status != "spam" and (m.channel != "http" or m.published))


async def list_public(db: AsyncSession, limit: int = 100) -> list[InboxMessage]:
    """Public listing under `is_public`'s rule, in SQL so `limit` counts visible rows."""
    q = (select(InboxMessage).where(InboxMessage.verified.is_(True), InboxMessage.status != "spam")
         .where((InboxMessage.channel != "http") | InboxMessage.published.is_(True))
         .order_by(InboxMessage.timestamp.desc(), InboxMessage.id.desc()).limit(limit))
    return list((await db.execute(q)).scalars().all())


# What no member has taken up: the complement, among HTTP messages that are not spam, of what `is_public`
# shows. A published message that is `new` again (its reply was given up) is in the public inbox, not here.
_UNTRIAGED = (InboxMessage.channel == "http", InboxMessage.status == "new", InboxMessage.published.is_(False))


async def list_untriaged(db: AsyncSession, limit: int = 100, offset: int = 0) -> list[InboxMessage]:
    """For a seat holder, over a signed request: HTTP messages nobody has looked at yet, oldest first, so
    the one that has waited longest is on the first page however many arrive after it (XE-1565)."""
    q = select(InboxMessage).where(*_UNTRIAGED).order_by(InboxMessage.timestamp.asc(), InboxMessage.id.asc()).offset(offset).limit(limit)
    return list((await db.execute(q)).scalars().all())


async def count_untriaged(db: AsyncSession) -> int:
    return int((await db.execute(select(func.count()).select_from(InboxMessage).where(*_UNTRIAGED))).scalar_one())


async def get_public(db: AsyncSession, mid: str) -> InboxMessage:
    m = await get(db, mid)
    if not is_public(m):
        raise HTTPException(404, "message not found")
    return m


async def get(db: AsyncSession, mid: str, *, lock: bool = False) -> InboxMessage:
    """`lock=True` takes the row FOR UPDATE: every path that changes a message loads it this way, so two
    writers queue instead of each saving its own copy of a list over the other's (XE-0672)."""
    q = select(InboxMessage).where(InboxMessage.id == mid)
    m = (await db.execute(locked(q) if lock else q)).scalar_one_or_none()
    if m is None:
        raise HTTPException(404, "message not found")
    return m


async def replies_for(db: AsyncSession, mid: str) -> list[OutboxMessage]:
    return list((await db.execute(select(OutboxMessage).where(OutboxMessage.in_reply_to == mid).order_by(OutboxMessage.created_at.asc()))).scalars().all())


def to_dict(m: InboxMessage, replies: list[OutboxMessage] | None = None) -> dict:
    d = {"id": m.id, "channel": m.channel, "from": m.from_account, "body": m.body,
         "timestamp": m.timestamp, "verified": m.verified, "status": m.status, "classification": m.classification}
    if replies is not None:
        d["replies"] = [{"id": o.id, "from_seat": o.from_seat, "body": o.body, "status": o.status,
                         "sent_at": o.sent_at.isoformat() if o.sent_at else None, "error": o.error} for o in replies]
    return d
