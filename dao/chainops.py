"""Chain operations the harness performs with company-held keys, plus read-side helpers.

Writes here are limited to what Schedule B allows the harness to do on its own: receive into the
fee account, refund or burn a proposal fee, register in the directory, speak in chat. Nothing
here can touch the treasury or the keyset.
"""

from __future__ import annotations

import asyncio
import itertools
import logging
import time
from collections.abc import Awaitable, Callable

from xe.client import UNREACHABLE, XeClient, XeError
from xe.encoding import Block, sign_block
from xe.keys import KeyPair, exact_hex
from xe.pow import WORKER_POW_DEADLINE_S, compute_pow

from .context import Context

log = logging.getLogger("dao.chainops")


async def _pow(hash_hex: str, difficulty: int) -> int:
    # PoW is CPU work; keep it off the event loop, and never let it run unbounded (XE-1188).
    return await asyncio.to_thread(compute_pow, exact_hex(hash_hex, 32, "block hash"), difficulty, WORKER_POW_DEADLINE_S)


def _moved(account: str) -> XeError:
    """The account's chain grew between two reads of it. Nothing is built from the pair: the caller's next
    pass reads again."""
    return XeError(UNREACHABLE, f"the chain of {account[:12]} moved while it was being read; nothing is built on it")


async def _tip(chain: XeClient, account: str) -> tuple[str, dict[str, int]]:
    """(previous_hash, balances) for an account, as of one moment; previous == "0" for a fresh account.

    The two are two requests, and a block of ours names both: its `previous` and the balance it leaves.
    A block landing between them gave a tip from before it and a balance from after, and the block built
    on that pair is one the node refuses for its balance while nothing stands on its parent, so it was
    offered again, unchanged, for as long as the chain stayed where it was (XE-14160). The tip is read
    again after the balance: a chain only grows, so a tip that is the same on both sides of the balance
    is the tip the balance was read at. One that is not raises (`_moved`)."""
    prev = await chain.tip(account)
    bals = await chain.balances(account)
    if await chain.tip(account) != prev:
        raise _moved(account)
    return prev, bals


# Every block the harness writes to an account chain is built by `signed()`, and nothing is recorded from
# the node's answer to a submit: a 200 from a node that then drops the block is not a write, and a timeout
# after the node took it is not a failure (XE-2043, XE-2380). What is recorded comes from reading the chain.
#
# A block that moves value out (`build_send`, `build_burn`) is made at most once, in three steps:
#
#   build     builds, signs and works the block on a final tip, and notes the place it was built for.
#             Nothing has left the process: the caller puts the block on disk first, so every retry offers
#             the same block.
#   offer()   submits it. What the node answers is logged and decides nothing.
#   placed()  reads what stands at that place on the chain. It is the only thing a caller records from.
#
# Why the same block and not a fresh one: an account chain is a line, so of all the blocks ever built on
# one `previous` at most one can land. A retry that offers the block again cannot pay twice; a retry that
# builds a new block at a new tip can, if the first one landed after all. A block is therefore given up
# (`lost`) only when it provably cannot land: another block, final, stands on its `previous`.

async def signed(ctx: Context, b: Block, kp: KeyPair) -> Block:
    # The network id is part of what is signed. A process that started while the node was down has none,
    # and a block signed for "" is one no node will ever take: ask again, and sign nothing without it.
    if not ctx.node.network_id:
        await ctx.refresh_node()
    if not ctx.node.network_id:
        raise XeError(UNREACHABLE, "the node has not said which network this is; nothing is signed without it")
    sign_block(b, kp, ctx.node.network_id)
    b.pow_nonce = await _pow(b.hash, ctx.node.pow_difficulty)
    return b


async def placed(chain: XeClient, block: dict) -> str:
    """Where a block built by `build_send` or `build_burn` stands on its account's chain. `block["at"]` is
    the place it was built for: the number of blocks below it. One page is read, the parent and whatever
    follows it, so the answer is about one moment of one chain:

      landed    the block stands on its parent and is final
      pending   it stands there and is not final, or another block does that is not final either: nothing
                can be concluded yet. Ask again later; offer nothing, build nothing.
      open      nothing stands on its parent: it can still land, and offering the same block again is safe
      lost      another block stands on its parent and is final: it never can land

    Raises XeError if the chain cannot be read, or if what is served does not hold the parent where the
    block was built on it (a node that is behind, or wrong): nothing is concluded from a chain that is not
    the one the block was built on. The first version looked at the account's tip instead, and took any
    final tip other than the parent to mean `lost`, which a node one block behind also shows."""
    at = block["at"]
    try:
        page = (await chain.chain(block["account"], offset=max(at - 1, 0), limit=2 if at else 1))["blocks"]
    except XeError as e:
        if e.status != 404:
            raise
        page = []
    if at:
        if not page or page[0].get("hash") != block["previous"]:
            raise XeError(UNREACHABLE, f"the chain as served does not hold {block['previous'][:12]} at place {at - 1}, "
                                       f"where {block['hash'][:12]} was built on it; nothing is concluded")
        page = page[1:]
    if not page:
        return "open"
    final = page[0].get("finalized") is True
    if page[0].get("hash") == block["hash"]:
        return "landed" if final else "pending"
    return "lost" if final else "pending"


async def offer(ctx: Context, block: dict) -> str:
    """Submit a built block, then say where it stands (`placed`)."""
    try:
        await ctx.chain.submit_block(Block.from_json(block))
    except XeError as e:
        log.warning("submit of %s: %s", block["hash"][:12], e)
    return await placed(ctx.chain, block)


# One pass over an account's pending sends is bounded in number and in time (XE-3130). Anyone can send
# dust to a published account, each receive is a block with its own proof of work, and the worker runs
# its jobs one after another: a pass as long as the list would hold the timers, the sessions and the
# outbox for as long as someone kept sending. What a pass does not reach is still pending on the node and
# is reached by a later one. The budget is spent on XE before any other asset and on the largest amount
# first, so what waits is dust (a fee is not, tried before or not: among sends of one size the ones not
# yet tried go first, and no number of those puts a larger one back). A send that has been offered a
# receive twice and is pending all the same waits a doubling time, up to an hour, before it is tried
# again, so one that can never be received does not hold a place in every pass.
RECEIVE_PASS_MAX = 25
RECEIVE_PASS_S = 30.0
RECEIVE_RETRY_S = 60.0
RECEIVE_RETRY_MAX_S = 3600.0
# (account, send hash) -> (passes that offered it a receive, when the last one did). A pass the node or
# the database stopped before the submit offered nothing and counts against no send, and neither does a
# receive whose proof of work ran out of time or whose submit found no node to connect to. A send whose
# block cannot be made at all is counted as if offered: it will not be made on the next pass either, and
# the count is what moves it out of the way of the sends behind it. In this process
# only: after a restart every pending send is new again, which costs one pass. Entries leave with the send.
_offered: dict[tuple[str, str], tuple[int, float]] = {}


def receive_order(account: str, pending: list[dict], now: float) -> list[dict]:
    """The pending sends one pass offers a receive to, in order (see above). `now` is `time.monotonic()`."""
    live = {(account, p["send_hash"]) for p in pending}
    for key in [k for k in _offered if k[0] == account and k not in live]:
        del _offered[key]

    def tried(p: dict) -> tuple[int, float]:
        return _offered.get((account, p["send_hash"]), (0, 0.0))

    def waits(p: dict) -> bool:
        n, at = tried(p)
        return n >= 2 and now - at < min(RECEIVE_RETRY_S * 2 ** min(n - 1, 16), RECEIVE_RETRY_MAX_S)
    due = [p for p in pending if not waits(p)]
    return sorted(due, key=lambda p: (p["asset"] != "XE", -p["amount"], tried(p)[0]))[:RECEIVE_PASS_MAX]


async def receive_pending(ctx: Context, key_name: str, paused: Callable[[], Awaitable[bool]],
                          scope: str = "block.receive") -> int:
    """Offer a receive for the pending sends to the account held under `key_name`, as many as one pass has
    the budget for (`receive_order`). Returns how many the node said it took, which is a count for the log
    and nothing else: no receive is recorded from here. The caller records a receive when it reads it,
    final, on the account's chain (XE-2380).

    `paused()` is asked right before each submit, after the block's proof of work, so a pause that begins
    during a run stops the receives still to come (XE-2483). A send that cannot be received is logged and
    skipped whatever went wrong, since the ones behind it are independent (XE-0488). What is not about the
    send ends the pass instead, and is held against none of them: the node failing the read of our own tip,
    not naming its network or not being there to connect to for the submit (the sends behind would be
    told the same), and the pause check itself failing, which is the caller's database and is raised to it. A receive is not kept for a retry: one
    that did not land leaves its send pending on the node, where the next pass finds it, and the node
    takes one receive per send."""
    kp = ctx.signer.keypair(key_name, scope)
    taken = 0
    started = time.monotonic()
    pending = await ctx.chain.pending_for(kp.address)
    todo = receive_order(kp.address, pending, started)
    for i, p in enumerate(todo):
        if time.monotonic() - started >= RECEIVE_PASS_S:
            todo = todo[:i]
            break
        b = None
        try:
            prev, bals = await _tip(ctx.chain, kp.address)
            b = await signed(ctx, Block(type="receive", account=kp.address, previous=prev,
                                        balance=bals.get(p["asset"], 0) + p["amount"], timestamp=time.time_ns(),
                                        asset=p["asset"], source=p["send_hash"]), kp)
        except XeError as e:    # our own tip, or the network's name: the node, and not this send
            log.warning("receive into %s stopped at %s: %s", key_name, p["send_hash"][:12], e)
            todo = todo[:i]
            break
        except TimeoutError:
            # The proof of work ran out of time, which is this machine and the luck of the search and not
            # the send: no receive was offered, and the send is not held to have been offered one. Counted,
            # two slow searches put a fee that the node had never been shown into the wait a send gets
            # for being refused twice, up to an hour (XE-14286).
            log.warning("receive of %s into %s: proof of work ran out of time; tried again next pass", p["send_hash"][:12], key_name)
            continue
        except Exception as e:  # a bad entry: this send only
            log.warning("receive of %s into %s failed: %s: %s", p["send_hash"][:12], key_name, type(e).__name__, e)
        if b is not None:
            if await paused():
                break
            try:
                await ctx.chain.submit_block(b)
                taken += 1
            except Exception as e:
                if isinstance(e, XeError) and e.unsent:
                    # No connection: the node was shown nothing, and the sends behind would be shown
                    # nothing either. The pass ends, held against none of them, as it does when the
                    # node fails the read of our tip. Counted, a node that could not be reached for two
                    # passes put every send of those passes into the doubling wait (XE-14286).
                    log.warning("receive into %s stopped at %s: %s", key_name, p["send_hash"][:12], e)
                    todo = todo[:i]
                    break
                # a refusal, or a connection that gave no answer: this send only
                log.warning("receive of %s into %s failed: %s: %s", p["send_hash"][:12], key_name, type(e).__name__, e)
        key = (kp.address, p["send_hash"])
        _offered[key] = (_offered.get(key, (0, 0.0))[0] + 1, time.monotonic())
    if len(todo) < len(pending):
        log.info("receive into %s: %d of %d pending sends left for a later pass", key_name, len(pending) - len(todo), len(pending))
    return taken


async def build_send(ctx: Context, key_name: str, scope: str, destination: str, amount: int, memo: str = "",
                     asset: str = "XE") -> dict | None:
    """A signed send from the account under `key_name`; not submitted. See `_build_out`."""
    return await _build_out(ctx, key_name, scope, "send", amount, memo, asset, destination=destination)


async def build_burn(ctx: Context, key_name: str, scope: str, amount: int, memo: str = "", asset: str = "XE") -> dict | None:
    """A signed burn from the account under `key_name`; not submitted. See `_build_out`."""
    return await _build_out(ctx, key_name, scope, "burn", amount, memo, asset)


async def _build_out(ctx: Context, key_name: str, scope: str, type_: str, amount: int, memo: str, asset: str,
                     **fields) -> dict | None:
    """A block that moves value out of a harness account, built on the account's tip: its wire form, plus
    `at`, the place on the chain it was built for, which is what `placed` reads. None while that tip is not
    final: a block built on one that can still be dropped can be dropped with it and come back with it, and
    `placed` could not then say for certain that it is lost."""
    kp = ctx.signer.keypair(key_name, scope)
    at, last = await ctx.chain.chain_end(kp.address)
    if last is not None and last.get("finalized") is not True:
        return None
    have = (await ctx.chain.balances(kp.address)).get(asset, 0)
    # the balance is the balance at this tip only if the tip is still the tip (`_tip`, XE-14160)
    at_after, last_after = await ctx.chain.chain_end(kp.address)
    if (at_after, last_after and last_after.get("hash")) != (at, last and last.get("hash")):
        raise _moved(kp.address)
    if have < amount:
        raise XeError(409, f"insufficient {asset} in {key_name}: have {have}, need {amount}")
    b = Block(type=type_, account=kp.address, previous=last["hash"] if last else "0", balance=have - amount,
              timestamp=time.time_ns(), asset=asset, amount=amount, memo=memo[:64], **fields)
    return {**(await signed(ctx, b, kp)).to_json(), "at": at}


# ---- read side ---------------------------------------------------------------------------------

# A node accepts a block whose timestamp is within an hour of its clock either way, so a sender can date a
# block up to an hour early or late. Two things follow for a balance snapshot taken at a point in time.
#
# First, a block made after that point can carry a timestamp before it, as long as the gap is under an hour.
# So the snapshot for a proposal is not taken at the moment it opens but an hour and a margin earlier
# (`snapshot_time`): a block made at real time r is dated r - 1h at the earliest, which is after the snapshot
# whenever r is after the open. Nothing done once a proposal is visible can move its snapshot: not a new
# wallet, not a transfer, not a split (XE-0352). That is the whole of what the lead guarantees. It is not a
# holding period: XE borrowed before the open and returned after it weighs at the snapshot like any other
# balance, and the opener, who picks the moment of opening, can arrange that (XE-1098). What the portal
# promises is that the weights are fixed before anyone else learns there is a vote.
#
# Second, a receive dated before the snapshot whose source send is dated after it is possible on the wire and
# impossible in fact: the XE cannot be in the receiving wallet before it left the sending one. Counting it
# would let one balance vote from two wallets (send dated late, receive dated early), as many times as there
# are wallets. A receive only counts when its source send is also at or before the snapshot. Only receives
# dated within two hours of the snapshot can be affected, so only those are looked up. The same holds for
# every other block that brings the weight asset onto a chain from somewhere else: a lease settle mints XE
# to the provider for a lease named in its `source`, and a settle dated before the snapshot for a lease
# opened after it is the same impossibility as a receive before its send (XE-1789). `ARRIVALS` lists the
# block types that are checked this way; each names its cause in `source`.
#
# Third, a snapshot costs a bounded number of node reads whatever the chain looks like (XE-1460): each
# source send is looked up once, at most `CAUSAL_LOOKUP_CONCURRENCY` at a time, and after
# `MAX_CAUSAL_LOOKUPS` distinct sends the remaining receives in the window are excluded without a lookup.
# Excluding can only lower the weight, so a chain built to be expensive is read cheaply and conservatively.
# The budget is spent where the weight is: only receives of the weight asset are checked (a receive of
# another asset carries no weight, so its causality is nobody's concern here), largest amount first, so
# what the cap drops is dust. A voter's material receive is looked up ahead of thirty dust receives, their
# own or a stranger's, and a flood of foreign-asset dust spends nothing (XE-1548, XE-1589).
#
# Fourth, a weight rests only on blocks the node holds final, as a fee does (XE-0034, XE-3129). The walk
# ends at the first block that is not: that block can still be dropped, and every block after it stands on
# it. In ordinary running a block dated before the snapshot was final long before anyone could vote, so
# this decides nothing; when the chain served holds a block that is not final, the figure is what the chain
# is certain of, and the snapshot says `unsettled`. That is said whatever date the block carries: the place
# it holds may yet go to another block, and that one can be dated on either side of the snapshot. The
# source a receive names is held to the same: one that is not final has not happened yet, and its receive
# is not counted. That too is `unsettled`, and so is a source the node does not hold: either can be final
# and held on the next read, and a snapshot that left the receive out and called itself settled was never
# derived again, so the weight stayed short of a balance the chain went on to confirm (XE-14676). Only a
# source that is final and dated after the snapshot settles its receive as not counted. A row derived
# from an unsettled snapshot is not
# current (`portal.is_current`): it is derived again on every pass and at the close, so what is tallied is
# the chain as final as it was when the proposal closed. Leaving a block out can raise a figure as well as
# lower it (a send that is not final has not yet left), but never counts one balance twice: the receive
# of that send is no more final than the send is.
TIMESTAMP_WINDOW_NS = 3600 * 1_000_000_000
SNAPSHOT_MARGIN_NS = 5 * 60 * 1_000_000_000
SNAPSHOT_LEAD_NS = TIMESTAMP_WINDOW_NS + SNAPSHOT_MARGIN_NS
# The lead in words, for a voter told why an account does not count. Every statement of when the snapshot
# is taken gives this lead and no rounder one: an account opened sixty-two minutes before a proposal was
# told the cut-off was an hour, and was not counted (XE-10113).
SNAPSHOT_LEAD_TEXT = "an hour and five minutes"
CAUSAL_CHECK_NS = 2 * TIMESTAMP_WINDOW_NS
MAX_CAUSAL_LOOKUPS = 32
MAX_EXCLUDED_SHOWN = 32   # of the receives a snapshot left out, the ones it names; `excluded_count` is all of them
CAUSAL_LOOKUP_CONCURRENCY = 8
# Bumped whenever the figure this function derives for the same chain and `at` can change. A vote row
# stores the result it was derived from; at close, rows derived under another `at` or rule are re-derived
# before they are tallied (XE-1617).
SNAPSHOT_RULE = 6
# Block types that raise the asset balance by bringing value from another block, which `source` names.
ARRIVALS = ("receive", "lease_settle")


def snapshot_time(opened_at_ns: int) -> int:
    """The time a proposal's weight is read at: an hour and a margin before it opened (see above)."""
    return opened_at_ns - SNAPSHOT_LEAD_NS


def empty_snapshot(at_ns: int, unreadable: str = "") -> dict:
    """The snapshot of an account the chain has nothing for: not there, or (with `unreadable` set) one whose
    chain the harness cannot read on purpose, such as one past the page bound (XE-1706)."""
    d = {"exists": False, "balance": 0, "first_block_ts": None, "snapshot_block": "", "excluded_receives": [],
         "excluded_count": 0, "lookups_capped": False, "unsettled": False, "at": at_ns, "rule": SNAPSHOT_RULE}
    if unreadable:
        d["unreadable"] = unreadable
    return d


async def account_snapshot(chain: XeClient, account: str, at_ns: int, asset: str = "XE") -> dict:
    """Balance of `asset` as of `at_ns`, plus whether the account existed by then.

    XE accounts are chains; each block carries the post-state balance for its asset, so the balance at a
    time is the balance on the last counted block of that asset with timestamp <= at_ns. A receive of that
    asset whose source send is dated after at_ns (see above) is not counted: its amount is carried as
    `tainted`, which later sends and burns spend first, and what is still tainted at the end is taken off
    the balance (XE-1003). `snapshot_block` is the last counted block. Node reads are bounded and spent
    largest receive first (XE-1460, XE-1548, XE-1589, see above); `lookups_capped` says whether the bound
    was hit. `at` and `rule` record what the figure was derived under, so a stored result can be told
    from one derived under a different rule (XE-1617). Only blocks the node holds final are walked;
    `unsettled` says that the chain served holds one that is not, whatever its date (XE-3129).
    """
    empty = empty_snapshot(at_ns)
    try:
        served = await chain.full_chain(account)
    except XeError as e:
        if e.status == 404:
            return empty
        raise
    blocks = list(itertools.takewhile(lambda b: b.get("finalized") is True, served))
    unsettled = len(blocks) < len(served)
    if not blocks:
        return {**empty, "unsettled": unsettled}
    first_ts = blocks[0].get("timestamp", 0)
    window: list[tuple[int, str]] = []   # (amount, source) for each windowed receive of our asset
    prev = 0
    for b in blocks:
        if b.get("timestamp", 0) > at_ns:
            break
        if b.get("asset") != asset:
            continue
        new_bal = b.get("balance", 0)
        if b.get("type") in ARRIVALS and b.get("timestamp", 0) > at_ns - CAUSAL_CHECK_NS:
            window.append((max(new_bal - prev, 0), b.get("source") or ""))
        prev = new_bal
    by_amount: dict[str, int] = {}
    for amount, src in window:
        by_amount[src] = by_amount.get(src, 0) + amount
    sources = sorted(by_amount, key=lambda s_: -by_amount[s_])
    capped = len(sources) > MAX_CAUSAL_LOOKUPS
    causal = await _sends_at_or_before(chain, sources[:MAX_CAUSAL_LOOKUPS], at_ns)
    # a source that is not final, or not held, has not been decided: its receive is left out of this
    # figure, and the figure is not the last word (see above)
    unsettled = unsettled or any(v is None for v in causal.values())
    bal = 0        # the asset's on-chain balance after the last block seen
    tainted = 0    # the part of `bal` that arrived through excluded receives and has not left since
    snap = ""
    excluded: list[str] = []
    counted = 0
    for b in blocks:
        ts = b.get("timestamp", 0)
        if ts > at_ns:
            break
        ours = b.get("asset") == asset
        if ours and b.get("type") in ARRIVALS and ts > at_ns - CAUSAL_CHECK_NS and not causal.get(b.get("source") or "", False):
            excluded.append(b.get("hash", ""))
            new_bal = b.get("balance", 0)
            tainted += max(new_bal - bal, 0)
            bal = new_bal
            continue
        counted += 1
        if not ours:
            continue
        new_bal = b.get("balance", 0)
        if new_bal < bal:
            tainted = max(tainted - (bal - new_bal), 0)
        bal = new_bal
        snap = b.get("hash", "")
    # The first of the excluded receives and how many there are. The whole list went into the vote's row
    # and out of the snapshot route, and its length is whoever sends to the account's to choose: a few
    # thousand dust receives in the window were a few thousand hashes on every row derived from it (XE-14105).
    return {"exists": first_ts <= at_ns and counted > 0, "balance": max(bal - tainted, 0),
            "first_block_ts": first_ts, "snapshot_block": snap, "excluded_receives": excluded[:MAX_EXCLUDED_SHOWN],
            "excluded_count": len(excluded), "lookups_capped": capped,
            "unsettled": unsettled, "at": at_ns, "rule": SNAPSHOT_RULE}


async def _sends_at_or_before(chain: XeClient, send_hashes: list[str], at_ns: int) -> dict[str, bool | None]:
    """For each source block (a send, or the lease a settle pays out), one of three answers. True: it is
    on the chain, final, and dated at or before `at_ns`. False: it is final and is not, or the receive
    names no source; that does not change. None: the node does not hold it, or holds it and it is not
    final, and the next read may say otherwise. One read per distinct hash, a bounded number in flight; a
    hash not in the result is not causal."""
    gate = asyncio.Semaphore(CAUSAL_LOOKUP_CONCURRENCY)

    async def one(h: str) -> bool | None:
        if not h:
            return False
        async with gate:
            try:
                src = await chain.block(h)
            except XeError as e:
                if e.status == 404:
                    return None
                raise
        if src.get("finalized") is not True:
            return None
        ts = src.get("timestamp")
        return type(ts) is int and ts <= at_ns

    found = await asyncio.gather(*(one(h) for h in send_hashes))
    return dict(zip(send_hashes, found))
