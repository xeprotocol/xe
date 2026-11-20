"""Fee handling: receive into the fee account, then refund or burn per the pinned rules.

The chain is the ground truth; the ledger is a record of it, never ahead of it and never guessing. Nothing
is recorded from what the node answers to a submit, only from a block read back from the chain, final.

A settlement (a refund, a burn, or the return of what was paid above the fee) is one block:

- it is built once, signed, and committed to the row (`tx_hashes["settle_block"]`) before it is offered;
- every pass asks the chain what stands where that block was built to stand (`chainops.placed`). The block,
  final: the row is recorded settled, with its hash. Nothing: the same block is offered again. Another
  block, final: this one can never land, so it is dropped and a new one is built. Anything else: wait.

An account chain is a line, so the one block can land at most once, and a row can only be paid twice if
two blocks are built for it; the second is built only when the first provably cannot land. That replaces
the memo nonce and its search of the chain, which read "no block with this nonce yet" as "never sent",
forgot the nonce and paid again (XE-2043), and which recorded a settlement on the node's answer to the
submit without asking the chain at all (XE-2380). The first rule here was XE-0486/XE-0488: every chain
write is made exactly once, whatever the worker does around it. One pass runs at a time (the worker holds
`db.only_one` for the job), so a row has one block because one process builds it.

A block the node keeps refusing is offered for as long as nothing else stands in its place, with the reason
on the row. It is replaced when the fee account's chain next moves, which the next fee received does.

One block of ours at a time stands on any one place. A row's block that was offered and is not on the
chain yet may be on its way there, and the next row's block would be built on the same previous: two
blocks signed by the fee key for one place, of which the chain can keep one, and a proof of work spent
on the other. So a pass takes the rows already holding a block first, and once a row holds a block
a node could still take, no other row's block is built that pass (XE-4591). "Could still take" has an end:
a node accepts a block dated within an hour of its clock, so a block older than that (and a margin for
the clock) is not waited on, and the rows behind it build as before, which is also what moves the chain
past it. Receives are not held back by a standing block. A receive that loses the place to it is refused,
its send stays pending on the node, and the next pass offers it again; and a receive is what moves the
chain past a settlement block no node will take.

A receive is offered for every send pending to the fee account, and recorded for a fee the ledger knows
when the fee account's chain holds a final receive whose source is that fee's send. A fee whose receive is
not on the chain is not settled: there is nothing of the payer's to pay out.
"""

from __future__ import annotations

import logging
import time
import weakref

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from xe.client import PAGE, XeError, malformed

from .. import chainops
from ..context import Context
from ..faults import Fault, reason
from ..log import EventLog
from ..models import FeeLedger, Proposal
from ..signer import SignerError
from . import pause

log = logging.getLogger("dao.fees")

DUE = ("due_refund", "due_burn")
# the hour a node allows a block's timestamp either way, and a margin for its clock: waited out in full,
# since a block a node could still take is exactly the one another must not be built beside
STANDING_NS = chainops.TIMESTAMP_WINDOW_NS + 5 * 60 * 1_000_000_000
# How much earlier than its send a receive can be dated. A receive is made after its send was taken, and
# a node takes a block dated within the hour of its clock either way: the send up to an hour ahead, the
# receive up to an hour behind. Two hours, then, by the node's rule alone, and a margin for the clocks of
# two nodes. The same rule keeps an account's blocks in date order (none is dated before the one it
# stands on), which is what lets a search down a chain stop at the first block older than this.
RECEIVE_LEAD_NS = 2 * chainops.TIMESTAMP_WINDOW_NS + 5 * 60 * 1_000_000_000
# the pages of the fee account's chain one pass reads, whatever its rows ask of it (`_FeeChain`)
PASS_PAGES = 20
SOUGHT_MAX = 4096
SEEKING_NOTE = "the fee account's chain is still being read for this fee's receive; settlement waits for it"
# What earlier passes read of each node's fee chain, by the send they were looking for: (low, high), the
# places low <= p < high, every one of which held a final block that was not that send's receive. Kept
# with the node client, so for the life of the process; a restart reads again, a pass at a time.
_sought: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
UNRECEIVED_ERROR = "fee send was never received into the fee account; nothing to settle"
ARRIVING_NOTE = "the fee's receive is not final on the fee account's chain yet; settlement waits for it"


async def receive_all(ctx: Context, db: AsyncSession) -> int:
    """Offer a receive for every send pending to the fee account (fees arrive as pending sends). Returns
    how many the node took; `record_receives` is what puts a receive on record."""
    if not ctx.signer.has("fee"):
        return 0
    try:
        return await chainops.receive_pending(ctx, "fee", lambda: pause.is_paused(db))
    except SignerError as e:
        log.warning("fee receive refused: %s", e)
        return 0


async def record_receives(ctx: Context, db: AsyncSession) -> int:
    """Record the receive of every fee that has none on record and whose receive the chain now holds.
    Returns how many were recorded. The fee account's chain is read only when a row is waiting, and
    then a bounded part of it, from its end (`_FeeChain`)."""
    if not ctx.signer.has("fee"):
        return 0
    keys = list((await db.execute(select(FeeLedger.fee_block_hash).where(FeeLedger.state.in_(("seen",) + DUE))
                                  .order_by(FeeLedger.fee_block_hash))).scalars().all())
    chain = _FeeChain(ctx)
    n = 0
    # Two rounds over the rows. The first reads the end of the chain and nothing else, whichever row asks
    # and whatever earlier passes read for it, and answers every row it can from that: the receive of a
    # fee paid in the ordinary way is there. The second spends the rest of the pass's reads, in order, on
    # the rows that need more. A row whose receive lies deep, or is nowhere, then takes nothing from the
    # rows behind it, and a read that fails far down the chain fails after they have been answered.
    for near in (True, False):
        chain.near = near
        for key in keys:
            # Each row is a step of its own, named by a hash read before it (XE-3724): what the database
            # refuses for one is rolled back and logged, and the rows behind it are still recorded. The
            # node not answering is not a row's failure but every row's, and ends the pass.
            try:
                f = await db.get(FeeLedger, key)
                if f is not None and not (f.tx_hashes or {}).get("receive") and await _record_receive(ctx, db, f, chain):
                    n += 1
            except XeError:
                raise
            except Exception as e:
                await db.rollback()
                log.warning("fee %s: recording its receive failed: %s: %s", key[:12], type(e).__name__, e)
    return n


def _memo(chain) -> dict[str, tuple[int, int]]:
    try:
        return _sought.setdefault(chain, {})
    except TypeError:   # a client that cannot be weakly referenced keeps nothing between passes
        return {}


class _FeeChain:
    """The fee account's chain for one pass: a bounded number of its pages, read where a row needs them.

    Anyone can lengthen this chain: the worker receives every send to the fee account, dust included.
    It was read whole for every pass that had a row waiting, under the bound every whole read has, and
    past that bound the read failed on every pass: no fee's receive could be put on record again, and
    none was refunded or burned, for as long as the chain stayed that long, which is for good
    (XE-14723). What a row asks is where the receive of one send is. The harness made that receive
    itself, after the send existed, so it is near the end when it is first looked for and never older
    than the send. The search starts at the end and goes down, to the receive, to the first block older
    than the send could be, or to the first block of the chain.

    A pass makes `PASS_PAGES` page reads and no more, whatever the rows ask and however long the chain
    is. A search that runs out of them is not an answer (`read_through` says so) and goes on from where
    it stopped on the next pass: `_sought` keeps, for each send, the places already read and found to
    hold final blocks that are not its receive. A final block does not change, so those are never read
    for that send again, and a row with no receive anywhere costs a pass only the blocks added since
    the last one."""

    def __init__(self, ctx: Context, pages: int | None = None):
        self.ctx, self.limit, self.reads = ctx, PASS_PAGES if pages is None else pages, 0
        self.near = False                        # read the newest page and the one before it, and no other
        self._end: int | None = None            # how many blocks the chain held when this pass first asked
        self._pages: dict[int, list[dict]] = {}
        self._pending: set[str] | None = None
        self._floors: dict[str, int] = {}
        self._sought = _memo(ctx.chain)

    async def _at(self, place: int) -> dict | None:
        """The block at a place on the chain, below `_end`; None when it is on a page this pass has not
        read and has no reads left for, or is not reading yet (`near`)."""
        n = place // PAGE
        if n not in self._pages:
            if self.reads >= self.limit or (self.near and n < (self._end - 1) // PAGE - 1):
                return None
            self.reads += 1
            start = n * PAGE
            want = min(PAGE, self._end - start)
            blocks = (await self.ctx.chain.chain(self.ctx.signer.address("fee"), offset=start, limit=want))["blocks"]
            if len(blocks) != want:
                # a chain only grows, so every place below its end holds a block: a short page is not the chain
                raise malformed(f"chain page at {start} holds {len(blocks)} blocks of {want}")
            self._pages[n] = blocks
        return self._pages[n][place - n * PAGE]

    async def _floor(self, send_hash: str) -> int:
        """The time no receive of this send can be older than: the send's own date, less
        `RECEIVE_LEAD_NS`. 0, which no block is older than, for a send the node does not hold or one with
        no date. Asked once a pass."""
        if send_hash not in self._floors:
            try:
                ts = (await self.ctx.chain.block(send_hash)).get("timestamp")
            except XeError as e:
                if e.status != 404:
                    raise
                ts = None
            self._floors[send_hash] = max(ts - RECEIVE_LEAD_NS, 0) if type(ts) is int else 0
        return self._floors[send_hash]

    async def _seek(self, send_hash: str) -> tuple[dict | None, bool]:
        """The receive of a send on the fee account's chain, final or not, or None; and whether every
        place it could be at has been read, by this pass or an earlier one. (None, False) is no answer."""
        if self._end is None:
            self._end, _ = await self.ctx.chain.chain_end(self.ctx.signer.address("fee"))
        end = self._end
        low, high = self._sought.get(send_hash, (end, end))
        low, high = min(low, end), min(high, end)
        firm = end   # the lowest place seen to hold a block that is not final: it, and all above it, may yet change
        # first what has been added since an earlier pass looked: from the end down to where that one began
        for place in range(end - 1, high - 1, -1):
            b = await self._at(place)
            if b is None:
                # What the earlier passes read stands, and this stretch is read again. Unless the pass's
                # reads all went on it: then it is longer than a pass can read, and reading it again
                # would end here again, every pass. What was just read is kept in place of what the
                # earlier passes read, where every block of it is final, and the search goes on below it.
                if self.reads >= self.limit and firm == end:
                    self._keep(send_hash, place + 1, end)
                return None, False
            if b.get("type") == "receive" and b.get("source") == send_hash:
                return b, True
            if b.get("finalized") is not True:
                firm = place
        # then what lies below everything read so far
        floor = None
        for place in range(low - 1, -1, -1):
            b = await self._at(place)
            if b is None:
                break
            if b.get("type") == "receive" and b.get("source") == send_hash:
                return b, True
            if b.get("finalized") is not True:
                firm = place
            low = place
            # The newest page's worth is read whatever the send's date: that is where a receive made a
            # pass or two ago is, and it costs the send no lookup. Below it, the first block older than
            # the send could be ends the search: nothing under that block is this send's receive.
            if place < end - PAGE:
                if floor is None:
                    floor = await self._floor(send_hash)
                ts = b.get("timestamp")
                if type(ts) is int and 0 < ts < floor:
                    low = 0
                    break
        self._keep(send_hash, low, min(end, firm))
        return None, low == 0

    def _keep(self, send_hash: str, low: int, high: int) -> None:
        if high > low:
            if len(self._sought) >= SOUGHT_MAX and send_hash not in self._sought:
                self._sought.clear()   # every search starts over, a pass at a time; nothing is answered wrongly
            self._sought[send_hash] = (low, high)
        else:
            self._sought.pop(send_hash, None)

    def forget(self, send_hash: str) -> None:
        self._sought.pop(send_hash, None)

    async def receive_of(self, send_hash: str) -> dict | None:
        """The final receive of a send. One that is not final yet can still be dropped; it is found on a
        later pass, when it is."""
        b, _ = await self._seek(send_hash)
        return b if b is not None and b.get("finalized") is True and b.get("hash") else None   # the hash is what gets recorded

    async def arriving(self, send_hash: str) -> bool:
        """Whether a send with no final receive is still on its way in: its receive is on the chain and
        not final yet, or the node holds the send pending for the fee account, where a pass offers a
        receive for it. Neither is "never received"."""
        if (await self._seek(send_hash))[0] is not None:
            return True
        if self._pending is None:
            self._pending = {p["send_hash"] for p in await self.ctx.chain.pending_for(self.ctx.signer.address("fee"))}
        return send_hash in self._pending

    async def read_through(self, send_hash: str) -> bool:
        """Whether the chain has been read everywhere this send's receive could be. Until it has, that no
        receive was found says nothing."""
        return (await self._seek(send_hash))[1]


async def _record_receive(ctx: Context, db: AsyncSession, f: FeeLedger, chain: _FeeChain) -> bool:
    got = await chain.receive_of(f.fee_block_hash)
    if not got:
        return False
    chain.forget(f.fee_block_hash)
    f.tx_hashes = {**(f.tx_hashes or {}), "receive": got["hash"]}
    f.error = ""
    await ctx.events.append(db, "fee.received", "harness", {
        "block": got["hash"], "source": f.fee_block_hash, "amount": f.amount, "asset": got.get("asset"),
    }, ref=f"fee:{f.fee_block_hash}", public=True)
    await db.commit()
    return True


async def settle_due(ctx: Context, db: AsyncSession) -> int:
    """Refund or burn fees whose proposals have closed. Each row is committed as it moves. Returns how many
    rows reached `refunded` or `burned` this pass."""
    if not ctx.signer.has("fee"):
        return 0
    rows = (await db.execute(select(FeeLedger.fee_block_hash, FeeLedger.tx_hashes).where(FeeLedger.state.in_(DUE + ("settling",)))
                             .order_by(FeeLedger.updated_at.asc(), FeeLedger.fee_block_hash.asc()))).all()
    # rows that hold a block first, each group oldest first: theirs are the blocks that may be standing,
    # and whether one is has to be known before anything is built for a row that has none (XE-4591)
    keys = [key for key, tx in sorted(rows, key=lambda r: 0 if (r[1] or {}).get("settle_block") else 1)]
    chain = _FeeChain(ctx)
    n = 0
    standing = False
    for key in keys:
        f = await db.get(FeeLedger, key)
        try:
            if f.state in DUE and not (f.tx_hashes or {}).get("receive") and not await _received(ctx, db, f, chain):
                continue
            # with a block of ours standing, a row that has none is marked and not built: its block would
            # go where that one may yet land. The next pass takes it.
            if await _settle(ctx, db, f, build=not standing):
                n += 1
            elif _stands(f):
                standing = True
        except Exception as e:  # keep going; the row is as it was last committed, and is taken again next tick
            log.warning("fee settle failed for %s: %s: %s", key[:12], type(e).__name__, e)
            await db.rollback()
            f = await db.get(FeeLedger, key)
            f.error = reason(e, 500)
            await db.commit()
            # a row whose pass failed (the node could not be read) may hold a block all the same, and
            # that block stands whether or not this pass could look at it
            standing = standing or _stands(f)
            if (isinstance(e, XeError) and e.transient) or isinstance(e, TimeoutError):
                # the node said nothing, and would say it to every row behind: they wait for the next pass.
                # Any of them may hold a standing block this pass did not look at, and nothing is built
                # after this line, so none is built beside it. A proof-of-work search that ran out its
                # time is the same: the next row's would too, each for the whole deadline (XE-14351).
                break
    return n


def _stands(f: FeeLedger) -> bool:
    """Whether the row holds a settlement block that is not settled and that a node could still take."""
    block = (f.tx_hashes or {}).get("settle_block")
    if f.state != "settling" or not isinstance(block, dict):
        return False
    ts = block.get("timestamp")
    return isinstance(ts, int) and time.time_ns() - ts < STANDING_NS


async def _received(ctx: Context, db: AsyncSession, f: FeeLedger, chain: _FeeChain) -> bool:
    """A due row with no receive on record: is its receive on the chain (XE-0488)? If it is not, we never
    received this fee into the fee account, so there is nothing of the payer's to refund or burn: paying out
    here would spend other payers' XE (XE-0034). The row stays due and is looked at every pass.

    A receive that is on the chain and not final, or a send the node still holds pending, is not "never
    received": the row waits and nothing is said. The event fires once for a fee, and the log is what says
    whether it has: the row's `error` is overwritten by whatever last went wrong with the row, so a node
    failure between two passes would otherwise have the same fee announced again."""
    if await _record_receive(ctx, db, f, chain):
        return True
    if await chain.arriving(f.fee_block_hash):
        await _note(db, f, ARRIVING_NOTE)
        return False
    if not await chain.read_through(f.fee_block_hash):
        # the pass ran out of reads before the search was over: no receive found so far is not "never received"
        await _note(db, f, SEEKING_NOTE)
        return False
    await _note(db, f, UNRECEIVED_ERROR)
    ref = f"proposal:{f.proposal_hash}"
    if not await EventLog.page(db, limit=1, kind="fee.unreceived", ref=ref, public_only=False):
        await ctx.events.append(db, "fee.unreceived", "harness", {
            "proposal": f.proposal_hash, "payer": f.payer, "amount": f.amount, "fee_block_hash": f.fee_block_hash,
        }, ref=ref)
        await db.commit()
        log.warning("fee for %s was never received; not settling", f.proposal_hash)
    return False


async def _fee_due(db: AsyncSession, f: FeeLedger) -> int:
    """The fee the proposal pinned when it opened. A payer may have sent more; only this much is the fee."""
    rules = (await db.execute(select(Proposal.rules).where(Proposal.hash == f.proposal_hash))).scalar_one_or_none() or {}
    return min(int(rules.get("fee_micro_xe", f.amount)), f.amount)


def _phase_amount(f: FeeLedger, fee: int) -> int:
    """What the current settlement phase pays: the whole sum back on a refund; only the fee on a burn; and
    on `excess`, the part above the fee back to the payer, since the documented burn is the fee (XE-0740)."""
    as_ = f.tx_hashes["settle_as"]
    return f.amount if as_ == "refund" else fee if as_ == "burn" else f.amount - fee


_IN_FLIGHT = ("settle_as", "settle_block")


def _mark(f: FeeLedger, as_: str) -> None:
    """Begin a settlement phase: what is owed, and no block yet."""
    f.tx_hashes = {**{k: v for k, v in (f.tx_hashes or {}).items() if k not in _IN_FLIGHT}, "settle_as": as_}
    f.state = "settling"


async def _note(db: AsyncSession, f: FeeLedger, why: str) -> None:
    if f.error != why:
        f.error = why
        await db.commit()


async def _settle(ctx: Context, db: AsyncSession, f: FeeLedger, *, build: bool = True) -> bool:
    """Take a row as far as the chain allows this pass; True once it is `refunded` or `burned`. A burn that
    leaves an excess to return is two phases, one block each. With `build` false the row's own block is
    followed if it has one and no new block is built for it (`settle_due` says when)."""
    if "settle_nonce" in (f.tx_hashes or {}):
        # Marked by the release before this one, which named its block by a nonce in the memo and kept no
        # hash. Whether that block went out cannot be told from the row, so no block is built for it here.
        # In the service's own words (`Fault`): the row's `error` is where an operator reads what to do.
        raise Fault(f"settlement was begun under the memo-nonce scheme (nonce {f.tx_hashes['settle_nonce']}) "
                    "and is not continued automatically: check the fee account's chain for that memo")
    if f.state in DUE:
        _mark(f, "refund" if f.state == "due_refund" else "burn")
        await db.commit()
    fee = await _fee_due(db, f)
    while f.state == "settling":
        block = f.tx_hashes.get("settle_block")
        if block is None:
            block = await _build(ctx, db, f, fee) if build else None
            if block is None:
                return False
            # The block is on the row before it is offered: whatever happens next, this is the block the
            # next pass asks the chain about.
            f.tx_hashes = {**f.tx_hashes, "settle_block": block}
            await db.commit()
            where = "open"
        else:
            where = await chainops.placed(ctx.chain, block)
        if where == "open":
            if await pause.is_paused(db):
                return False
            where = await chainops.offer(ctx, block)
        if where == "landed":
            await _record_settled(ctx, db, f, block["hash"], fee)
        elif where == "lost":
            # Another block is final where this one would have stood: it can never land. The next pass
            # builds another.
            f.tx_hashes = {k: v for k, v in f.tx_hashes.items() if k != "settle_block"}
            f.error = f"settlement block {block['hash'][:12]} was not taken and can no longer land; another is built"
            await db.commit()
            return False
        else:
            if where == "open":
                await _note(db, f, f"settlement block {block['hash'][:12]} was offered and the node did not take it; "
                                   "the same block is offered again until the fee account's chain moves")
            return False   # offered and not final yet, or the node did not take it this time
    return True


async def _build(ctx: Context, db: AsyncSession, f: FeeLedger, fee: int) -> dict | None:
    """The block for the row's current phase; None if it is not to be built now (a pause, or a fee account
    whose tip is not final yet)."""
    if await pause.is_paused(db):
        # Read here, not only at the start of the job: a pause committed since then stops the burn or
        # refund before it is signed (XE-1172). The row stays `settling` and is taken up after the pause.
        return None
    as_ = f.tx_hashes["settle_as"]
    memo = f"fee {as_} {f.proposal_hash[:12]}"
    amount = _phase_amount(f, fee)
    if as_ == "burn":
        return await chainops.build_burn(ctx, "fee", "block.burn", amount, memo=memo)
    return await chainops.build_send(ctx, "fee", "block.send.refund", f.payer, amount, memo=memo)


async def _record_settled(ctx: Context, db: AsyncSession, f: FeeLedger, block_hash: str, fee: int) -> None:
    as_ = f.tx_hashes["settle_as"]
    amount = _phase_amount(f, fee)
    f.tx_hashes = {**{k: v for k, v in f.tx_hashes.items() if k not in _IN_FLIGHT}, as_: block_hash}
    f.error = ""
    payload = {"proposal": f.proposal_hash, "payer": f.payer, "amount": amount, "block": block_hash}
    if as_ == "excess":
        f.state = "burned"
        await ctx.events.append(db, "fee.excess_returned", "harness", payload, ref=f"proposal:{f.proposal_hash}")
    else:
        f.state = "refunded" if as_ == "refund" else "burned"
        await ctx.events.append(db, f"fee.{f.state}", "harness", payload, ref=f"proposal:{f.proposal_hash}")
        if as_ == "burn" and f.amount > fee:
            _mark(f, "excess")   # the burn is on record; what was sent above the fee goes back next
    await db.commit()
