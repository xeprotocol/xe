"""The worker: timers, chain listeners, cadence. Runs as its own container (`python -m dao.worker`).

Everything it does is either a read, a bounded company-key action permitted by Schedule B, or the
opening of a session that humans must sign. It never signs a state-chain block, never moves
treasury, never pauses.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import time
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import select

from xe.client import UNREACHABLE, XeError
from xe.directory import new_registration

from .auth import purge_seen_signatures
from .context import Context, build_context, set_context
from .db import locked, only_one, session
from .faults import reason
from .log import EventLog
from .models import SigningSession
from .services import fees, inbox, pause, portal, records, resolutions, sessions
from .settings import get_settings
from .worker_schedule import due_at, due_interval, job_table, last_detail, last_runs, mark_failed, mark_run

log = logging.getLogger("dao.worker")
NS = 1_000_000_000
DIRECTORY_RETRY_S = 120   # a failed registration is tried again this soon; the entry lapses on the node's clock


class Worker:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.stop = asyncio.Event()

    # ---- jobs -----------------------------------------------------------------------------

    async def job_health(self):
        # The node's identity is asked again with each check, so a process that started while the node was
        # down, or outlived a change of difficulty, does not keep what it had at boot (XE-2475). A node
        # that does not answer leaves it as it is.
        await self.ctx.refresh_node()
        await self._seal_legacy_log()
        async with session() as db:
            d = await records.health_pass(self.ctx, db)
            denials = await self._log_signer_denials(db)
            await mark_run(db, "health", {"ok": d["ok"]}, every_s=records.cadence_s(self.ctx))
            await db.commit()
        self._signer_denials_logged(denials)

    async def _seal_legacy_log(self) -> None:
        """The seal over the log's v1 rows, written once (XE-4017). In a transaction of its own, so the log
        head is not held locked through the health check's reads of the node; a failure here is this step's
        and the check still runs."""
        try:
            async with session() as db:
                if await self.ctx.events.seal_legacy(db) is not None:
                    await db.commit()
        except Exception as e:
            log.warning("sealing the log's v1 rows failed: %s: %s", type(e).__name__, e)

    async def _log_signer_denials(self, db) -> tuple[list[dict], list, dict]:
        """Uses of a company key the signer refused since the last check, onto the log (XE-3974). Like a
        degraded spell (XE-6048), a refusal that goes on is one entry when it starts, one when what is
        being refused changes and one when it stops, not one per check. No refusal goes uncounted for
        that: the checks in between are carried, and each entry counts every use since the one before it.

        Nothing is counted off here. This reads the signer's count and returns what the check's
        transaction, once it has committed, lets the worker stop counting (`_signer_denials_logged`). A
        check that fails after this (the schedule row, the commit, the append itself) has recorded
        nothing, and before, the count had already been emptied for it: those refusals were on no log
        and in no count (XE-14106)."""
        denied = self.ctx.signer.denials()
        pairs = [(x["key"], x["scope"]) for x in denied]
        carried = dict(getattr(self, "_denied_carried", {}))
        for x in denied:
            carried[(x["key"], x["scope"])] = carried.get((x["key"], x["scope"]), 0) + x["count"]
        if (denied and pairs != getattr(self, "_denied_before", [])) or (not denied and carried):
            entry = [{"key": k, "scope": sc, "count": n} for (k, sc), n in sorted(carried.items())]
            await self.ctx.events.append(db, "signer.denied", "harness",
                                         {"denied": entry, **({} if denied else {"ended": True})}, public=True)
            carried = {}
        return denied, pairs, carried

    def _signer_denials_logged(self, read: tuple[list[dict], list, dict]) -> None:
        """The check that read these refusals has committed: the signer stops counting them, and the
        worker keeps what the next check compares against and carries."""
        denied, pairs, carried = read
        self.ctx.signer.forget(denied)
        self._denied_before, self._denied_carried = pairs, carried

    async def job_directory(self):
        """Keep the DAO's directory entry alive: a fresh signed registration every 20 minutes against the
        node's 30-minute TTL. This runs through a pause on purpose (XE-1445): the entry is addressability,
        not action. It names only the DAO's own node peer and moves nothing, and without it every chat
        sent to the DAO fails at the sender's node thirty minutes into a pause, while the inbox is one of
        the things a pause keeps open. The `dao` key's narrowest scope, `directory.register`, is all it uses.

        A run that fails is tried again in `DIRECTORY_RETRY_S`, not a cadence later, since the entry lapses
        on the node's clock whatever this job's is (XE-12324). The log says so when a spell of failures
        begins and when it ends, not on every pass (XE-6048). A node that has not yet said which network
        it is, is asked again here: before, the job returned without a word on every pass until the worker
        was restarted (XE-2475)."""
        ctx = self.ctx
        if not ctx.signer.has("dao"):
            return
        every_s = job_table(ctx)["directory"]["every_s"]
        async with session() as db:
            try:
                if not ctx.node.network_id:
                    await ctx.refresh_node()
                if not ctx.node.network_id:
                    raise XeError(UNREACHABLE, "the node has not said which network this is; nothing is signed without it")
                kp = ctx.signer.keypair("dao", "directory.register")
                reg = new_registration(kp, ctx.node.network_id, ctx.directory_node_peer)
                await ctx.chain.directory_register(reg.to_json())
                before = await last_detail(db, "directory")
                await mark_run(db, "directory", {"ok": True})
                if before.get("ok") is not True:   # the first there has been, or the first after a spell of failures
                    await ctx.events.append(db, "directory.registered", "harness", {"after_failures": int(before.get("failures") or 0)}, public=False)
            except Exception as e:
                log.warning("directory register failed: %s: %s", type(e).__name__, e)
                await db.rollback()   # whatever failed, the database included, the failure is still marked (XE-3724)
                before = await mark_failed(db, "directory", {"ok": False, "error": reason(e)}, every_s, DIRECTORY_RETRY_S)
                if before.get("ok") is not False:
                    await ctx.events.append(db, "directory.register_failed", "harness", {"error": reason(e)}, public=False)
            await db.commit()

    @staticmethod
    async def _step(db, name: str, fn):
        """One step of a job. A job is a list of steps that do not depend on each other, and one of them
        failing never stops the ones behind it: the step is committed if it returns, rolled back and logged
        if it raises anything at all, and the job goes on either way. The first version of this guard named
        the one exception a step was expected to raise, and a step that raised another ended the job at that
        line on every pass, with the pause clock, the timelock and the purge behind it (XE-1967)."""
        try:
            out = await fn()
            await db.commit()
            return out
        except Exception as e:
            await db.rollback()
            log.warning("%s: %s: %s", name, type(e).__name__, e)
            return None

    async def job_fees(self):
        # One fee pass at a time, in this process or any other: a settlement is one block because one pass
        # builds it, and two passes over one row would each build their own.
        async with session() as db, only_one(db, "worker:fees") as alone:
            if not alone or await pause.is_paused(db):
                return
            await self._step(db, "fees: receive", lambda: fees.receive_all(self.ctx, db))
            await self._step(db, "fees: record receives", lambda: fees.record_receives(self.ctx, db))
            await self._step(db, "fees: settle", lambda: fees.settle_due(self.ctx, db))
            await mark_run(db, "fees")
            await db.commit()

    async def job_outbox(self):
        # One outbox pass at a time, for the reason there is one fee pass: a reply has one envelope because
        # one pass builds it, and two passes over one queued row would each build and send their own.
        async with session() as db, only_one(db, "worker:outbox") as alone:
            if not alone:
                return
            await self._step(db, "outbox", lambda: inbox.flush_outbox(self.ctx, db))
            await mark_run(db, "outbox")
            await db.commit()

    async def job_timers(self):
        async with session() as db:
            closed = await self._step(db, "close proposals", lambda: portal.close_due(self.ctx, db))
            if closed:
                log.info("closed %d proposals", len(closed))
            # open tallies catch up with a rule or seat change (XE-1664)
            await self._step(db, "re-derive open tallies", lambda: portal.rederive_open(self.ctx, db))
            # sessions owed to passed resolutions (XE-1710)
            await self._step(db, "sessions owed to resolutions", lambda: resolutions.open_deferred_sessions(self.ctx, db))
            await self._step(db, "pause clock", lambda: pause.tick(self.ctx, db))
            await self._step(db, "promote sessions", lambda: self._promote(db))
            purged = await self._step(db, "purge signature claims", lambda: purge_seen_signatures(db))
            if purged:
                log.debug("purged %d expired signature claims", purged)
            await mark_run(db, "timers")
            await db.commit()

    async def _promote(self, db) -> None:
        """Promote approved sessions whose timelock has run, once no pause is in force."""
        if await pause.is_paused(db):
            return
        now = time.time_ns()
        ks = None
        for sid in await self._session_ids(db, "approving"):
            # Each row is taken FOR UPDATE and committed on its own, so a member's cancel or approval
            # either waits for this pass or is seen by it; never overwritten (XE-0763).
            s = await self._take(db, sid, "approving")
            if s is None or (s.not_before and now < s.not_before):
                await db.rollback()
                continue
            try:
                ks = ks or await sessions.live_keyset(self.ctx)
                if sessions.approvals_met(s, ks):
                    await sessions.rebuild(self.ctx, db, s)
                await db.commit()
            except Exception as e:  # one session or a node hiccup must not hold up the ones behind it
                await db.rollback()
                log.warning("promote session %s: %s", sid, e)

    @staticmethod
    async def _session_ids(db, status: str) -> list[str]:
        return list((await db.execute(select(SigningSession.id).where(SigningSession.status == status))).scalars().all())

    @staticmethod
    async def _take(db, sid: str, *status: str) -> SigningSession | None:
        """Lock one session for this pass, or skip it: None if a route holds it or it has left `status`."""
        q = locked(select(SigningSession).where(SigningSession.id == sid, SigningSession.status.in_(status)), skip_locked=True)
        return (await db.execute(q)).scalar_one_or_none()

    async def job_sessions(self):
        """A signing session whose block is stale is rebuilt; one that holds a threshold of signatures and
        is not yet on the chain (its submit was deferred by a node that did not answer, XE-1677/XE-1689)
        is submitted again. A session that ended without its block on the chain is looked up there while
        the block could still land, and recorded submitted if it has (XE-4148): that is a record catching
        up with the chain, not an act on it, so a pause does not stop it, for an ended session or for one
        still signing (`sessions.reconcile_signing`)."""
        async with session() as db:
            paused = await pause.is_paused(db)
            ids = await self._session_ids(db, "signing")
            await db.commit()
            ks = None
            for sid in ids:
                s = await self._take(db, sid, "signing")
                if s is None:
                    await db.rollback()
                    continue
                try:
                    if paused:
                        # nothing is built or submitted; a block the chain already holds is recorded
                        await sessions.reconcile_signing(self.ctx, db, s)
                    elif await sessions.is_stale(self.ctx, s):
                        # What a rebuild needs of the chain is read before anything is written
                        # (`sessions.look`), and what refuses the rebuild (a pause begun since this pass
                        # started, ops the seats no longer meet) is raised there, with nothing staged for
                        # the rollback below to take back and write again on the next pass (XE-14509).
                        seen = await sessions.look(self.ctx, db, s)
                        if s.block_signatures and not seen.landed:
                            # partial signatures over a stale block cannot be submitted; reset and say so.
                            # Unless the tip moved because this block is the tip (its submit was deferred
                            # and it has landed since): nothing moved under the session, and `rebuild`
                            # records it submitted.
                            await self.ctx.events.append(db, "session.tip_moved", "harness", {
                                "session_id": s.id, "block_hash": s.block_hash,
                                # what the gates counted, and beside it what was held (XE-3877)
                                "had_signatures": len(sessions.counted(s.block_signatures, seen.ks)),
                                "held": len(s.block_signatures),
                            }, ref=f"session:{s.id}")
                        await sessions.rebuild(self.ctx, db, s, seen=seen)
                    else:
                        ks = ks or await sessions.live_keyset(self.ctx)
                        if sessions.ready_to_submit(s, ks):
                            await sessions.submit(self.ctx, db, s)
                    await db.commit()
                except Exception as e:
                    await db.rollback()
                    log.warning("session %s: %s", sid, e.detail if isinstance(e, HTTPException) else e)
            # One page of the ended sessions a pass, the next page on the next pass, and from the top again
            # after a short one: every one of them is looked at in turn, until its block is on the chain
            # or another is where it would have gone (XE-14215).
            offset = getattr(self, "_ended_offset", 0)
            ended = await sessions.ended_holding_a_block(db, offset)
            self._ended_offset = offset + len(ended) if len(ended) == sessions.ENDED_WATCH_MAX else 0
            await db.commit()
            for sid in ended:
                s = await self._take(db, sid, "failed", "cancelled")
                if s is None:
                    await db.rollback()
                    continue
                try:
                    await sessions.reconcile_ended(self.ctx, db, s)
                    await db.commit()
                except Exception as e:
                    await db.rollback()
                    log.warning("ended session %s: %s", sid, e)
            await mark_run(db, "sessions")
            await db.commit()

    async def job_daily(self):
        async with session() as db:
            head = await EventLog.head(db)
            counts = await portal.counts(db)
            snap = await records.snapshot_treasury(self.ctx, db)
            h = await records.last_health(db)
            await self.ctx.events.append(db, "note.daily", "harness", {
                "date": datetime.now(timezone.utc).date().isoformat(), "log_head": {"index": head.index, "hash": head.hash},
                "proposals": counts, "treasury": snap.balances,
                "health_ok": bool(h and h.get("ok")) and not records.health_is_stale(self.ctx, h),
                "paused": await pause.is_paused(db), "network_id": self.ctx.node.network_id,
            })
            await mark_run(db, "daily")
            await db.commit()

    async def job_weekly(self):
        async with session() as db:
            up = await records.uptime_30d(self.ctx, db)
            pending = await sessions.open_sessions(db)
            await self.ctx.events.append(db, "note.weekly", "harness", {
                "week_of": datetime.now(timezone.utc).date().isoformat(), "uptime_30d": up,
                "sessions_awaiting_signature": [s.id for s in pending if s.status == "signing"],
                "sessions_awaiting_approval": [s.id for s in pending if s.status == "approving"],
                "proposals": await portal.counts(db),
            })
            await mark_run(db, "weekly")
            await db.commit()

    async def job_anchor(self):
        async with session() as db:
            if await pause.is_paused(db):
                return
            # One open anchor session at a time is `records.open_anchor_session`'s rule, held under its lock
            # (XE-2439); this job asks, and takes the refusal as the answer.
            try:
                await records.open_anchor_session(self.ctx, db)
            except HTTPException as e:
                if e.status_code != 409:
                    raise
                if await pause.is_paused(db):
                    return   # a pause began while this ran: nothing was opened and the run is not marked (XE-4126)
                # The members already have an anchor session to sign, so this week's is that one. The run is
                # marked: asking again every tick until it is signed would change nothing. If it is cancelled
                # instead, a member opens the next by hand or the job does in a week; health shows the age.
                log.info("anchor: %s", e.detail)
            await mark_run(db, "anchor")
            await db.commit()

    async def job_monthly(self):
        async with session() as db:
            await self.ctx.events.append(db, "note.monthly", "harness", {
                "month": datetime.now(timezone.utc).strftime("%Y-%m"), "proposals": await portal.counts(db),
                "uptime_30d": await records.uptime_30d(self.ctx, db), "anchors": await records.anchors(db, 6),
            })
            await mark_run(db, "monthly")
            await db.commit()

    # ---- chat listener --------------------------------------------------------------------

    async def chat_loop(self):
        ctx = self.ctx
        if not ctx.signer.has("dao"):
            log.info("no dao key; chat listener off")
            return
        while not self.stop.is_set():
            try:
                # The backfill cursor comes from the stored inbox (inbox.chat_cursor), not from this loop: a
                # store that fails below raises out of the stream, and the next pass asks the node again from
                # what is on disk (XE-1651, XE-1666, XE-1768).
                #
                # The stream is not read past a backfill that failed, and that is deliberate: the cursor
                # is the newest envelope stored, so a live message taken in over an unread backlog would
                # move the cursor past the backlog and the next backfill would not ask for it. What keeps
                # this from being a stall is that the backfill can always be read: its bound is sized to
                # the most a node holds for one account (xe.client.MAX_CHAT_STORE_BYTES, XE-11882).
                #
                # The backfill is read once the stream is open, not before it: the node sends a stream
                # only what arrives after it was opened, so an envelope that landed between a backfill and
                # the stream opened after it was in neither. Read in this order the two overlap, and an
                # envelope in both is stored once (XE-5883).
                async def caught_up():
                    async with session() as db:
                        n = await inbox.backfill(ctx, db)
                        await db.commit()
                    if n:
                        log.info("backfilled %d chat messages", n)
                proof = await inbox.read_proof(ctx)
                async for d in ctx.chain.chat_events(proof, caught_up):
                    if self.stop.is_set():
                        break
                    async with session() as db:
                        await inbox.receive(ctx, db, d)
                        await db.commit()
            except (XeError, OSError, asyncio.TimeoutError) as e:
                log.warning("chat stream dropped: %s", e)
            except Exception as e:
                log.exception("chat loop error: %s", e)
            await asyncio.sleep(5)

    # ---- scheduler ------------------------------------------------------------------------

    async def scheduler(self):
        handlers = {
            "health": self.job_health, "directory": self.job_directory, "fees": self.job_fees, "outbox": self.job_outbox,
            "timers": self.job_timers, "sessions": self.job_sessions, "daily": self.job_daily, "weekly": self.job_weekly,
            "anchor": self.job_anchor, "monthly": self.job_monthly,
        }
        while not self.stop.is_set():
            try:
                table = job_table(self.ctx)
                async with session() as db:
                    last = await last_runs(db)
                for name, j in table.items():
                    due = due_interval(last.get(name), j["every_s"]) if "every_s" in j else due_at(last.get(name), j["prev"])
                    if due:
                        try:
                            await handlers[name]()
                        except Exception as e:
                            log.exception("job %s failed: %s", name, e)
            except Exception as e:
                log.exception("scheduler: %s", e)
            try:
                await asyncio.wait_for(self.stop.wait(), timeout=15)
            except asyncio.TimeoutError:
                pass

    async def run(self):
        await self.ctx.refresh_node()
        async with session() as db:
            await self.ctx.events.append(db, "worker.started", "harness", {
                "network_id": self.ctx.node.network_id, "git_commit": self.ctx.settings.git_commit,
                "config_hashes": self.ctx.config.hashes, "signer_keys": [k.name for k in self.ctx.signer.infos()],
            })
            await db.commit()
        tasks = [asyncio.create_task(self.scheduler()), asyncio.create_task(self.chat_loop())]
        await self.stop.wait()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await self.ctx.aclose()


def main():
    logging.basicConfig(level=get_settings().logging_level, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    ctx = build_context()
    set_context(ctx)
    w = Worker(ctx)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, w.stop.set)
    loop.run_until_complete(w.run())


if __name__ == "__main__":
    main()
