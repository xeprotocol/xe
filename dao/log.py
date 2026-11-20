"""The ledger of record: an append-only, hash-chained, signed event log.

  v2: event.hash = sha256("xe-dao/event/v2\\0" || canonical_json({index, ts, kind, actor, payload,
                                                                  prev_hash, public, ref}))
  v1: the same without public and ref (rows written before 5 Nov 2026; `events.v` says which)
  event.signature = ed25519(hash_bytes) by the harness key

A v1 row's hash says nothing about its `public` and `ref`, and the hash cannot be rewritten: the chain and
its anchors stand on it. So the two are bound another way. One v2 event, `log.v1_sealed`, records how many
v1 rows there are, the index of the last, and a digest over every one's (index, public, ref); `verify()`
recomputes the digest as it walks and fails a chain whose v1 rows are not as they were sealed (XE-4017).
The seal is of the rows as they stood when it was written, which is the most any later record can say.

Appends serialise on a row lock over log_head so two writers can never fork the chain, and refuse rather
than write unsigned when the harness key will not sign (XE-0462). `verify()` replays the whole chain,
recomputes every hash, and with `expected_signer` checks every signature against the one published key, so
a stripped or re-signed chain fails (XE-0494); `/v1/log/head` and the weekly anchor expose the head so
anyone can check the chain against the state chain.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass
from typing import Any, AsyncIterator

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from xe.keys import exact_hex, verify_hex_signature

from .canonical import DOMAIN_EVENT, DOMAIN_EVENT_V1_SEAL, DOMAIN_EVENT_V2, digest
from .db import locked
from .models import Event, LogHead
from .signer import Signer, SignerError

ZERO = "0" * 64


@dataclass
class Head:
    index: int
    hash: str


def event_hash(index: int, ts: int, kind: str, actor: str, payload: dict, prev_hash: str, *,
               public: bool = True, ref: str = "", v: int = 2) -> str:
    body: dict[str, Any] = {"index": index, "ts": ts, "kind": kind, "actor": actor, "payload": payload, "prev_hash": prev_hash}
    if v >= 2:
        body["public"] = bool(public)
        body["ref"] = ref
    return digest(DOMAIN_EVENT_V2 if v >= 2 else DOMAIN_EVENT, body).hex()


SEAL_KIND = "log.v1_sealed"
UNSEALED = "the v1 events are not sealed"


class Seal:
    """The running digest over the v1 rows, in index order: what the seal records and what a replay checks."""

    def __init__(self) -> None:
        self.rows, self.through, self._h = 0, -1, hashlib.sha256()

    def add(self, index: int, public: bool, ref: str) -> None:
        self._h.update(digest(DOMAIN_EVENT_V1_SEAL, {"index": index, "public": bool(public), "ref": ref}))
        self.rows, self.through = self.rows + 1, index

    def payload(self) -> dict:
        return {"rows": self.rows, "through": self.through, "digest": self._h.hexdigest()}


class LogError(RuntimeError):
    """The log could not be written as the deployment promises (a harness key that will not sign)."""


class EventLog:
    def __init__(self, signer: Signer):
        self.signer = signer
        self._listeners: list[Any] = []

    def subscribe(self, queue: Any) -> None:
        self._listeners.append(queue)

    def unsubscribe(self, queue: Any) -> None:
        if queue in self._listeners:
            self._listeners.remove(queue)

    async def append(self, db: AsyncSession, kind: str, actor: str, payload: dict, *, ref: str = "",
                     public: bool = True, ts: int | None = None) -> Event:
        """Append one event inside the caller's transaction. Caller commits.

        The head is read from the row, under its lock, every time. A session that has appended and committed
        still holds the head as it left it, and without `populate_existing` the locked read hands that copy
        back: a worker pass that commits between events would then chain its next event to a head another
        process has since moved, and the append fails on the index it reuses."""
        head = (await db.execute(locked(select(LogHead).where(LogHead.id == 1)))).scalar_one()
        index = head.index + 1
        ts = ts if ts is not None else time.time_ns()
        h = event_hash(index, ts, kind, actor, payload, head.hash, public=public, ref=ref, v=2)
        signer_pk, sig = "", ""
        if self.signer.has("harness"):
            try:
                signer_pk = self.signer.public_key("harness")
                sig = self.signer.sign("harness", "event.sign", exact_hex(h, 32, "event hash"))
            except SignerError as e:
                # a configured key that will not sign is an outage, not a reason to write an unsigned row
                raise LogError(f"harness key will not sign: {e}") from e
        ev = Event(index=index, ts=ts, kind=kind, actor=actor, payload=payload, prev_hash=head.hash, hash=h,
                   signer=signer_pk, signature=sig, public=public, ref=ref, v=2)
        db.add(ev)
        head.index = index
        head.hash = h
        await db.flush()
        for q in list(self._listeners):
            try:
                q.put_nowait(ev)
            except Exception:
                pass
        return ev

    @staticmethod
    async def hold(db: AsyncSession) -> None:
        """Take the head's lock as an append does, until the caller's transaction ends, and write nothing.
        For a caller whose next read has to be in the log's order: whatever begins with an append (a
        pause does) has either committed before this returns, and is read, or waits until the caller is
        done. As with an append, nothing waits on the node after it."""
        (await db.execute(locked(select(LogHead).where(LogHead.id == 1)))).scalar_one()

    _nothing_to_seal = False

    async def seal_legacy(self, db: AsyncSession) -> Event | None:
        """Write the seal over the v1 rows, once: when there are such rows, none is sealed yet and the
        harness key signs (an unsigned seal would bind nothing). Caller commits.

        Whether there is anything to do is read without a lock, and once the answer is no it stays no for
        this process: nothing is written under the old envelope any more, so a log that is sealed, or has
        no v1 row, is not asked again (the second question is a scan of the table). Only a seal about to
        be written takes the head's lock, and looks again under it, so two processes cannot each find none
        and write one."""
        if self._nothing_to_seal or not self.signer.has("harness"):
            return None
        sealed = select(Event.index).where(Event.kind == SEAL_KIND).limit(1)
        if (await db.execute(sealed)).first() is not None \
                or (await db.execute(select(Event.index).where(Event.v < 2).limit(1))).first() is None:
            self._nothing_to_seal = True
            return None
        await db.execute(locked(select(LogHead).where(LogHead.id == 1)))
        if (await db.execute(sealed)).first() is not None:
            self._nothing_to_seal = True
            return None
        seal = Seal()
        for index, public, ref in (await db.execute(
                select(Event.index, Event.public, Event.ref).where(Event.v < 2).order_by(Event.index.asc()))).all():
            seal.add(index, public, ref)
        return await self.append(db, SEAL_KIND, "harness", seal.payload(), public=True)

    @staticmethod
    async def head(db: AsyncSession) -> Head:
        """The head as the database has it now, not as this session last saw it (see `append`)."""
        head = (await db.execute(select(LogHead).where(LogHead.id == 1).execution_options(populate_existing=True))).scalar_one()
        return Head(head.index, head.hash)

    @staticmethod
    async def count(db: AsyncSession) -> int:
        return int((await db.execute(select(func.count()).select_from(Event))).scalar_one())

    @staticmethod
    async def page(db: AsyncSession, offset: int = 0, limit: int = 100, kind: str | None = None,
                   ref: str | None = None, public_only: bool = True, descending: bool = True) -> list[Event]:
        q = select(Event)
        if public_only:
            q = q.where(Event.public.is_(True))
        if kind:
            q = q.where(Event.kind == kind)
        if ref:
            q = q.where(Event.ref == ref)
        q = q.order_by(Event.index.desc() if descending else Event.index.asc()).offset(offset).limit(min(limit, 1000))
        return list((await db.execute(q)).scalars().all())

    @staticmethod
    async def since(db: AsyncSession, after: int, limit: int = 200, public_only: bool = True) -> list[Event]:
        q = select(Event).where(Event.index > after)
        if public_only:
            q = q.where(Event.public.is_(True))
        return list((await db.execute(q.order_by(Event.index.asc()).limit(limit))).scalars().all())

    @staticmethod
    async def get(db: AsyncSession, index: int) -> Event | None:
        return (await db.execute(select(Event).where(Event.index == index))).scalar_one_or_none()

    @staticmethod
    async def iter_all(db: AsyncSession, batch: int = 1000, upto: int | None = None) -> AsyncIterator[Event]:
        """Events in order, a batch at a time; with `upto`, none past that index."""
        start = 0
        while True:
            q = select(Event).where(Event.index >= start)
            if upto is not None:
                q = q.where(Event.index <= upto)
            rows = list((await db.execute(q.order_by(Event.index.asc()).limit(batch))).scalars().all())
            if not rows:
                return
            for r in rows:
                yield r
            start = rows[-1].index + 1

    _verify_cache: tuple[float, dict] | None = None
    _verify_lock: asyncio.Lock | None = None
    VERIFY_CACHE_S = 60

    @classmethod
    async def verify_cached(cls, db: AsyncSession, expected_signer: str = "") -> dict:
        """`verify()` for the public route: a full replay is O(log); one is kept for a minute per process so
        the route cannot be used to make the database re-read the whole chain on demand."""
        def fresh() -> dict | None:
            c = cls._verify_cache
            return {**c[1], "cached": True} if c and time.monotonic() - c[0] < cls.VERIFY_CACHE_S else None

        if (hit := fresh()) is not None:
            return hit
        # One replay at a time. Callers that arrive while one is running wait for it and take its answer:
        # without this, every request that found the cache empty started a replay of its own, and the
        # minute's cache bounded nothing at the moment it mattered (XE-3709).
        if cls._verify_lock is None:
            cls._verify_lock = asyncio.Lock()
        async with cls._verify_lock:
            if (hit := fresh()) is not None:
                return hit
            out = await cls.verify(db, expected_signer)
            cls._verify_cache = (time.monotonic(), out)   # stamped when the replay ended, not when it began
            return {**out, "cached": False}

    @staticmethod
    async def verify(db: AsyncSession, expected_signer: str = "") -> dict:
        """Replay the chain. Returns {ok, count, head, first_error}. With `expected_signer` (the deployment's
        published harness key) every event must carry a signature by that key: a stripped signature or a
        re-signed chain fails, which is the point of publishing the key.

        A verification is of the chain as it stood at one moment: the head is read first and the replay runs
        to that head and no further. The log is appended to while this runs (the replay is many reads and
        each sees what has committed since the last), so a replay of "every row" compared with a head read
        afterwards compared two different moments, and an append that landed in between was reported as
        tampering (XE-2960). Events past the sampled head are the next verification's.

        A v1 row's `public` and `ref` are in no hash, so they are checked against the seal (XE-4017): the
        digest over the v1 rows is rebuilt on the way and compared with what a `log.v1_sealed` entry
        recorded, and a v1 row after the seal is refused. While there are v1 rows and no seal, the log
        does not verify: those rows' `public` and `ref` are checked by nothing, and "ok" said of them is
        said of nothing. The answer is decided here, once, for everything that asks whether the log
        verifies (the public route, `dao verify-log`, the health check). It was left to each of them, and
        the three gave three answers: the route said ok with a flag beside it, the command exited 0, and
        the health check noted the error and stayed ok (XE-14510). The worker writes the seal before its
        next health check, so the answer is no for longer than that only where a seal cannot be written."""
        at = await EventLog.head(db)
        prev = ZERO
        expected_index = 0
        count = 0
        last_hash = ZERO
        seal, sealed = Seal(), False
        async for ev in EventLog.iter_all(db, upto=at.index):
            if ev.index != expected_index:
                return {"ok": False, "count": count, "first_error": f"gap at index {expected_index}", "head": last_hash}
            if ev.prev_hash != prev:
                return {"ok": False, "count": count, "first_error": f"prev_hash mismatch at {ev.index}", "head": last_hash}
            h = event_hash(ev.index, ev.ts, ev.kind, ev.actor, ev.payload, ev.prev_hash, public=ev.public, ref=ev.ref, v=ev.v)
            if h != ev.hash:
                return {"ok": False, "count": count, "first_error": f"hash mismatch at {ev.index}", "head": last_hash}
            if ev.v not in (1, 2):   # the two envelopes there are; any other number is hashed as one of them
                return {"ok": False, "count": count, "first_error": f"unknown envelope at {ev.index}", "head": last_hash}
            if expected_signer and (not ev.signature or ev.signer != expected_signer):
                return {"ok": False, "count": count, "first_error": f"event {ev.index} is not signed by the harness key",
                        "head": last_hash}
            if ev.signature:
                try:
                    if ev.signature != ev.signature.lower():   # one spelling of a signature, as it was written
                        raise ValueError("signature is not in lower case")
                    verify_hex_signature(ev.signer, ev.signature, exact_hex(ev.hash, 32, "event hash"))
                except ValueError:
                    return {"ok": False, "count": count, "first_error": f"bad signature at {ev.index}", "head": last_hash}
            if ev.v < 2:
                if sealed:
                    return {"ok": False, "count": count, "first_error": f"v1 event at {ev.index}, after the v1 rows were sealed",
                            "head": last_hash}
                seal.add(ev.index, ev.public, ev.ref)
            elif ev.kind == SEAL_KIND:   # the kind `seal_legacy` looks for; no caller chooses an entry's kind
                if ev.payload != seal.payload():
                    return {"ok": False, "count": count, "head": last_hash,
                            "first_error": f"the v1 events are not as they were sealed at {ev.index}"}
                sealed = True
            prev = h
            last_hash = h
            expected_index += 1
            count += 1
        if at.hash != last_hash or at.index != count - 1:
            return {"ok": False, "count": count, "head": last_hash, "first_error": "head row disagrees with chain"}
        # The head only moves forward, in the transaction that adds its event. The highest event is read
        # before the head, so an append between the two reads moves the head further and never leaves an
        # event past it: one found there is a head that was wound back.
        tail = (await db.execute(select(func.max(Event.index)))).scalar()
        now = await EventLog.head(db)
        if now.index < at.index or (tail is not None and tail > now.index):
            return {"ok": False, "count": count, "head": last_hash, "first_error": "head row is behind the chain"}
        out = {"ok": True, "count": count, "head": last_hash, "first_error": None}
        if seal.rows:
            out["legacy"] = {"rows": seal.rows, "sealed": sealed}
            if not sealed:
                out.update(ok=False, first_error=UNSEALED)
        return out


def log_key(signer) -> str:
    """The key a replay holds every entry to: the harness key where the signer has one, and otherwise
    none, which checks each signature against the key its entry names. Asked here by everything that
    replays the log, so that a signer with no harness key is one answer and not an error at one of them
    (XE-14510)."""
    return signer.public_key("harness") if signer.has("harness") else ""


def event_to_dict(ev: Event) -> dict:
    return {
        "index": ev.index, "ts": ev.ts, "kind": ev.kind, "actor": ev.actor, "payload": ev.payload,
        "prev_hash": ev.prev_hash, "hash": ev.hash, "signer": ev.signer, "signature": ev.signature, "ref": ev.ref,
        "public": ev.public, "v": ev.v,
    }
