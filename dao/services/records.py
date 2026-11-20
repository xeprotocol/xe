"""Chain-facing records: dao.registry, weekly anchors, treasury reads, health."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from fractions import Fraction

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from xe.client import XeError

from ..context import Context
from ..db import serialize
from ..faults import reason, worded
from ..log import EventLog, log_key
from ..models import Anchor, Event, HealthCheck, SigningSession, TreasurySnapshot
from . import pause, sessions

log = logging.getLogger("dao.records")


# ---- dao.registry ---------------------------------------------------------------------------

def registry_value(ctx: Context) -> dict:
    """The exact object that goes under dao.registry. Keep key order stable; it is hashed."""
    r = ctx.config.registry
    val = {
        "entity": r.get("entity", ""),
        "jurisdiction": r.get("jurisdiction", ""),
        "form": r.get("form", ""),
        "formation_date": r.get("formation_date", "") or "",
        "registered_office": r.get("registered_office", ""),
        "email": r.get("email", ""),
        "statement": " ".join((r.get("statement", "") or "").split()),
        "update_authority": r.get("update_authority", "sys.dao_keyset"),
        "surfaces": r.get("surfaces", {}),
        "repository": r.get("repository", ""),
        "licence": r.get("licence", ""),
        "charter_sha256": ctx.config.charter_hash,
        "accounts": {k: v for k, v in {
            "dao": ctx.config.accounts.get("dao", ""),
            "fee": ctx.config.accounts.get("fee", ""),
            "treasury": ctx.config.accounts.get("treasury", ""),
        }.items() if v},
        "log_signer": ctx.signer.public_key("harness") if ctx.signer.has("harness") else "",
        "version": 1,
    }
    return val


# ---- public node reads -------------------------------------------------------------------------
#
# The public pages and /v1/legal/* read the keyset, the registry and the treasury balances from the node on
# every request. Each is the same for everyone and changes on the order of weeks, so one read serves every
# caller for a few seconds: an unauthenticated burst costs the node one round trip per leg per window, not
# one per request (XE-0959). Member and worker paths that act on the keyset read it directly.

PUBLIC_READ_TTL_S = 10
_public_reads: dict[str, tuple[float, object]] = {}
_public_reading: dict[str, asyncio.Future] = {}


async def _shared(key: str, read):
    """One node read per key at a time as well as per interval: the requests that arrive while one is in
    flight wait for its answer instead of each asking the node (XE-4318). The read belongs to no one
    request, so a caller that goes away does not take it from the others."""
    hit = _public_reads.get(key)
    if hit and time.monotonic() - hit[0] < PUBLIC_READ_TTL_S:
        return hit[1]
    reading = _public_reading.get(key)
    if reading is None:
        async def once():
            try:
                value = await read()
                _public_reads[key] = (time.monotonic(), value)
                return value
            finally:
                _public_reading.pop(key, None)
        reading = _public_reading[key] = asyncio.ensure_future(once())
    return await asyncio.shield(reading)


async def public_keyset(ctx: Context) -> dict:
    """sys.dao_keyset for display; an unreachable node is shown as {"error": ...}, not raised."""
    async def read():
        try:
            return await ctx.chain.dao_keyset()
        except XeError as e:
            return {"error": reason(e), "keys": [], "threshold": 0}
    return await _shared("keyset", read)


async def onchain_registry(ctx: Context) -> dict:
    """`dao.registry` as the chain holds it, for display: {"value": what is written, or None if the key
    is not set} or, when the node could not be read, {"error": ...}. The two are different answers: a
    read that failed says nothing about whether the entry is there, and reported as "not written" it
    had the legal identifier deny an entry that exists whenever the node was slow (XE-8855, the rule
    `public_keyset` keeps)."""
    async def read():
        try:
            return {"value": await ctx.chain.statechain_key("dao.registry")}
        except XeError as e:
            return {"error": reason(e)}
    return await _shared("registry", read)


def registry_present(read: dict) -> bool | None:
    """True or False as the chain says; None when it could not be asked."""
    return None if "error" in read else read["value"] is not None


async def _sole_open(db: AsyncSession, kind: str) -> None:
    """A record session (anchor, registry) is opened only while no other of its kind is open. Each writes
    the next state of one record: an anchor takes the next number and names the one before it, the registry
    replaces the whole entry. Two open at once can land in either order, which leaves `dao.anchor.2` on the
    chain over a `prev_anchor` that never was (XE-2439). The rule is asked here, under a lock, by the one
    function per kind that opens such a session, so the worker's job and the members' route both inherit
    it; the first version asked it in the job alone. Sessions opened by a resolution are not record
    sessions and are not limited.

    The pause is asked here too, for the same reason and under the same lock: while one is in force no
    record session is opened (`pause`). It was asked by each caller as it began, and the open then waited
    on the node for the keyset, so a pause that started during that wait was followed by a new session
    all the same (XE-4126). `pause.start` takes this lock, so of a pause and an open at the same moment
    one is first: the open that is first is a session from before the pause, and the one that is second
    is refused. Nothing after this waits on the node: the keyset is read before it."""
    await serialize(db, pause.RECORD_SESSION_LOCKS[kind])
    if await pause.is_paused(db):
        raise HTTPException(409, f"paused: no {kind} session is opened while a pause is active")
    pending = await sessions.open_sessions(db, kind=kind)
    if pending:
        raise HTTPException(409, f"{kind} session {pending[0].id} is still open; it is finished or cancelled before another is opened")


async def open_registry_session(ctx: Context, db: AsyncSession, actor: str) -> dict:
    ks = await sessions.read_keyset(ctx)   # the one wait on the node, before the lock and the pause check
    await _sole_open(db, "registry")
    ops = [{"action": "set", "key": "dao.registry", "value": registry_value(ctx)}]
    s = await sessions.create(ctx, db, kind="registry", title="Write dao.registry", ops=ops, actor=actor, ks=ks)
    return sessions.to_dict(s, ks)


# ---- anchors ----------------------------------------------------------------------------------

async def latest_anchor(db: AsyncSession, *, written: bool = False) -> Anchor | None:
    """The newest anchor; `written=True` for only those that reached the chain. Numbering counts the one in
    flight, and `open_anchor_session` opens one at a time, so two sessions never take the same n (XE-1435)
    and none is written over a gap (XE-2439); health counts only what was written (XE-0990)."""
    q = select(Anchor).order_by(Anchor.n.desc()).limit(1)
    if written:
        q = q.where(Anchor.statechain_index.isnot(None))
    return (await db.execute(q)).scalar_one_or_none()


async def open_anchor_session(ctx: Context, db: AsyncSession, actor: str = "harness") -> dict:
    ks = await sessions.read_keyset(ctx)   # the one wait on the node, before the lock and the pause check
    await _sole_open(db, "anchor")   # one at a time: the second of two opens waits, then is refused
    head = await EventLog.head(db)
    last = await latest_anchor(db)
    n = (last.n + 1) if last else 1
    value = {"n": n, "event_index": head.index, "head_hash": head.hash, "ts": time.time_ns(),
             "prev_anchor": (last.head_hash if last else ""), "log": f"{ctx.settings.public_base_url}/v1/log"}
    ops = [{"action": "set", "key": f"dao.anchor.{n}", "value": value}]
    s = await sessions.create(ctx, db, kind="anchor", title=f"Anchor {n}: log head {head.hash[:12]} at index {head.index}",
                              ops=ops, actor=actor, ks=ks)
    db.add(Anchor(n=n, event_index=head.index, head_hash=head.hash, session_id=s.id))
    return sessions.to_dict(s, ks)


async def count_anchors(db: AsyncSession) -> int:
    return int((await db.execute(select(func.count()).select_from(Anchor))).scalar_one())


async def anchors(db: AsyncSession, limit: int = 50, offset: int = 0) -> list[dict]:
    rows = (await db.execute(select(Anchor).order_by(Anchor.n.desc()).offset(offset).limit(limit))).scalars().all()
    return [{"n": a.n, "event_index": a.event_index, "head_hash": a.head_hash, "session_id": a.session_id,
             "statechain_index": a.statechain_index, "statechain_hash": a.statechain_hash,
             "created_at": a.created_at.isoformat() if a.created_at else None} for a in rows]


# ---- treasury (read-only) ---------------------------------------------------------------------

async def treasury(ctx: Context) -> dict:
    return await _shared("treasury", lambda: _treasury(ctx))


async def _treasury(ctx: Context) -> dict:
    accts = {
        "treasury": ctx.config.accounts.get("treasury", ""),
        "dao": ctx.config.accounts.get("dao", ""),
        "fee": ctx.config.accounts.get("fee", ""),
    }
    out = {}
    for name, addr in accts.items():
        if not addr:
            out[name] = {"address": "", "balances": {}, "note": "not configured"}
            continue
        try:
            bals = await ctx.chain.balances(addr)
        except XeError as e:
            out[name] = {"address": addr, "balances": {}, "error": reason(e)}
            continue
        out[name] = {"address": addr, "balances": bals, "keyset": None}
        if name != "treasury":
            continue
        try:
            # a keyset (keys and threshold) or None, never another object: the page counts its keys (XE-14157)
            out[name]["keyset"] = _keyset_shape(await ctx.chain.keyset_of(addr))
        except XeError as e:
            # The balances were read and are shown. A keyset that could not be read is said to be that:
            # it is not "none", and it does not take the balances with it.
            out[name]["keyset_error"] = reason(e)
    return out


async def snapshot_treasury(ctx: Context, db: AsyncSession) -> TreasurySnapshot:
    t = await treasury(ctx)
    snap = TreasurySnapshot(ts=time.time_ns(), balances=t)
    db.add(snap)
    return snap


# ---- health -----------------------------------------------------------------------------------

TIP_STALE_S = 6 * 3600        # a tip older than this means the state chain is not advancing
SESSION_AGING_S = 24 * 3600   # a session approving/signing for longer than this is reported
AGING_SHOWN = 20              # of them, oldest first; the check says how many there are in all
ANCHOR_OVERDUE_S = 14 * 86400  # weekly anchor; twice the cadence without one degrades
STALE_CHECKS = 3               # /v1/health is stale (and not ok) after this many missed cadences
WINDOW_30D_NS = 30 * 86400 * 1_000_000_000


def cadence_s(ctx: Context) -> int:
    return int(ctx.config.cadence.get("health_check_minutes", 10)) * 60


def _keyset_shape(ks: dict | None) -> dict | None:
    if not isinstance(ks, dict) or not isinstance(ks.get("keys"), list):
        return None
    return {"keys": sorted(str(k).lower() for k in ks["keys"]), "threshold": int(ks.get("threshold") or 0)}


async def expected_keyset(db: AsyncSession) -> dict | None:
    """The keyset the members last wrote through a keyset session; before any, the keyset as it was when
    the harness started watching (the earliest health check that saw one). Last is by place on the chain
    (`submitted_index`), not by when the row was last touched: `updated_at` moves with any later write to
    the row, and an older rotation touched after a newer one made health report the live keyset as
    changed (XE-4127)."""
    s = (await db.execute(select(SigningSession).where(SigningSession.kind == "keyset", SigningSession.status == "submitted",
                                                       SigningSession.submitted_index.isnot(None))
                          .order_by(SigningSession.submitted_index.desc()).limit(1))).scalar_one_or_none()
    if s is not None:
        for op in s.ops or []:
            try:
                return _keyset_shape(json.loads(op.get("value", "")))
            except (ValueError, TypeError):
                continue
    first = (await db.execute(select(HealthCheck).where(HealthCheck.detail["keyset"].astext.isnot(None))
                              .order_by(HealthCheck.ts.asc()).limit(1))).scalar_one_or_none()
    return first.detail.get("keyset") if first else None


def _fault(leg: str, e: Exception) -> str:
    """What a failed leg writes into the health record, which anyone can read (`faults.reason`): the text
    of an exception this code did not word goes to the server's log, and its kind into the record
    (XE-6983)."""
    if not worded(e):
        log.warning("health: the %s leg failed: %s: %s", leg, type(e).__name__, e)
    return reason(e)


async def health(ctx: Context, db: AsyncSession, record: bool = False) -> dict:
    """The 10-minute check (BRIEF §8/§9): chain reachable, tip advancing, keyset unchanged, log consistent,
    signer up, last anchor age, pending signatures aging. Each leg compares what it fetches against the
    chain's own timestamps or the members' own records; a leg that cannot fetch records `<leg>_error`; any
    error or mismatch makes `ok` false, which the worker posts as `health.degraded`. A keyset that is not
    the one the members last wrote stays not ok until a keyset session writes it (BRIEF §13)."""
    detail: dict = {"node_url": ctx.settings.xe_node_url, "network_id": ctx.node.network_id, "cadence_s": cadence_s(ctx)}
    ok = True
    now = time.time_ns()
    prev = await last_health(db) or {}

    try:   # chain reachable
        ready, body = await ctx.chain.ready()
        detail["node_ready"] = ready
        detail["node"] = body   # the status code and the node's flags and counts; none of its text (XE-14223)
        ok = ok and bool(ready)
    except Exception as e:
        detail["node_ready"] = False
        detail["node_error"] = _fault("node", e)

    try:   # tip advancing
        tip = await ctx.chain.statechain_tip()
        detail["statechain_tip"] = {"index": tip.get("index"), "hash": tip.get("hash"), "timestamp": tip.get("timestamp")}
        age_s = (now - tip["timestamp"]) / 1e9
        detail["statechain_tip_age_s"] = round(age_s)
        if age_s > TIP_STALE_S:
            detail["tip_stale"] = True
            ok = False
    except Exception as e:
        detail["statechain_error"] = _fault("statechain", e)

    # Every leg that asks the node comes before the first that can write to the log (the keyset leg, when
    # the keyset has changed): the directory was asked last, after that entry, with the log held shut
    # for as long as the node took to answer (XE-14181).
    dao_addr = ctx.signer.address("dao") if ctx.signer.has("dao") else ""
    if dao_addr:   # directory
        try:
            detail["directory_registered"] = (await ctx.chain.directory(dao_addr)) is not None
        except Exception as e:
            detail["directory_error"] = _fault("directory", e)

    # A leg that reads or writes the database does it under a savepoint: a statement that fails there
    # fails that leg, and the legs behind it and the record of the check itself still have a transaction
    # to work in (XE-3724).
    try:   # keyset unchanged
        ks = _keyset_shape(await ctx.chain.dao_keyset())
        if ks is None:
            detail["keyset_error"] = "node returned no keyset"
        else:
            detail["keyset"] = ks
            async with db.begin_nested():
                if prev.get("keyset") and ks != prev["keyset"]:
                    await ctx.events.append(db, "keyset.changed", "harness", {"from": prev["keyset"], "to": ks}, public=True)
                expected = await expected_keyset(db)
            if expected and ks != expected:
                detail["keyset_unexpected"] = {"live": ks, "expected": expected}
                ok = False
    except Exception as e:
        detail["keyset_error"] = _fault("keyset", e)

    try:   # log consistent
        async with db.begin_nested():
            head = await EventLog.head(db)
            ver = await EventLog.verify_cached(db, log_key(ctx.signer))
        detail["log_head"] = {"index": head.index, "hash": head.hash}
        # The replay's own answer and nothing beside it: v1 events with no seal over them fail it there
        # (XE-4017, XE-14510). The worker writes the seal before this check, so that is a seal that could
        # not be written.
        detail["log_verified"] = bool(ver.get("ok"))
        if not ver.get("ok"):
            detail["log_first_error"] = ver.get("first_error")
            ok = False
    except Exception as e:
        detail["log_error"] = _fault("log", e)

    detail["signer_keys"] = [k.name for k in ctx.signer.infos()]   # signer up
    if not ctx.signer.has("harness"):
        detail["signer_error"] = "no harness key: events cannot be signed"

    try:   # last anchor age: measured from the last written anchor, or from the DAO's start if there is none (XE-1618)
        async with db.begin_nested():
            a = await latest_anchor(db, written=True)
            started = None if a else await started_at(db)
        detail["last_anchor"] = {"n": a.n, "age_s": round(now / 1e9 - a.created_at.timestamp())} if a else None
        unanchored_s = detail["last_anchor"]["age_s"] if a else (now - (started or now)) / 1e9
        if unanchored_s > ANCHOR_OVERDUE_S:
            detail["anchor_overdue"] = True
            ok = False
    except Exception as e:
        detail["anchor_error"] = _fault("anchor", e)

    try:   # pending signatures aging
        cutoff = datetime.fromtimestamp((now - SESSION_AGING_S * 1_000_000_000) / 1e9, tz=timezone.utc)
        async with db.begin_nested():
            waiting = (SigningSession.status.in_(("approving", "signing")), SigningSession.created_at < cutoff)
            aging = (await db.execute(select(SigningSession).where(*waiting).order_by(
                SigningSession.created_at.asc(), SigningSession.id.asc()).limit(AGING_SHOWN))).scalars().all()
            aging_total = (await db.execute(select(func.count()).select_from(SigningSession).where(*waiting))).scalar_one()
        # The oldest few and how many there are. Every one of them was a row in every health check, and a
        # degraded check is an entry on the public log: a hundred sessions left open made each check, each
        # log entry and each read of /v1/health that much larger for as long as they stayed (XE-14446).
        # Counted as the gate counts them, against the keyset this check read above; where that read
        # failed (it is `keyset_error`, and the check is not ok for it) the figures are what is held (XE-3877).
        ks_now = detail.get("keyset")
        detail["sessions_aging"] = [{"id": s.id, "kind": s.kind, "status": s.status,
                                     "signatures": len(sessions.counted(s.block_signatures, ks_now) if ks_now else s.block_signatures or []),
                                     "required": ks_now["threshold"] if ks_now else s.required_approvals}
                                    for s in aging]
        detail["sessions_aging_total"] = aging_total
    except Exception as e:
        detail["sessions_error"] = _fault("sessions", e)

    errors = sorted(k for k in detail if k.endswith("_error"))
    if errors:
        detail["errors"] = errors
    # Everything that makes the check not ok, by name, in one list: the legs that could not be read and
    # the ones that read something wrong. `ok` is that list being empty, and the list is what tells one
    # degraded spell from the next (`health_edge`). A directory entry that has lapsed is on it: nothing
    # sent to the DAO over chat arrives while it is missing (XE-12324).
    failing = set(errors) | {k for k in ("tip_stale", "keyset_unexpected", "anchor_overdue") if detail.get(k)}
    if not detail.get("node_ready") and "node_error" not in detail:
        failing.add("node_not_ready")
    if detail.get("log_verified") is False:
        failing.add("log_unverified")
    if detail.get("directory_registered") is False:
        failing.add("directory_unregistered")
    ok = not failing
    detail["failing"] = sorted(failing)
    detail["ok"] = ok
    detail["ts"] = now
    if record:
        db.add(HealthCheck(ts=now, ok=ok, detail=detail))
    return detail


def health_edge(before: dict | None, now: dict) -> str | None:
    """What a health check adds to the public log, given the check before it: `health.degraded` when a
    spell begins or what is failing changes, `health.recovered` when it ends, nothing while it lasts. A
    condition that persists across passes is written when it begins and when it ends, as the other
    writers do (`sessions._deferred`, `resolutions._owed`, `fees._note`); written on every failing pass
    it was 144 signed public entries a day for one fault (XE-6048). The per-check record that uptime is
    counted from is the `HealthCheck` row, which every pass still writes."""
    was_ok = before is None or bool(before.get("ok"))
    if now["ok"]:
        return None if was_ok else "health.recovered"
    if was_ok or before.get("failing") != now.get("failing"):
        return "health.degraded"
    return None


async def health_pass(ctx: Context, db: AsyncSession) -> dict:
    """One scheduled check: the row, and the log entry if this check is an edge (`health_edge`)."""
    before = await last_health(db)
    d = await health(ctx, db, record=True)
    edge = health_edge(before, d)
    if edge == "health.degraded":
        await ctx.events.append(db, edge, "harness", {k: v for k, v in d.items() if k != "node"}, public=True)
    elif edge == "health.recovered":
        await ctx.events.append(db, edge, "harness", {
            "was_failing": (before or {}).get("failing") or (before or {}).get("errors") or [], "ts": d["ts"],
        }, public=True)
    return d


def health_age_s(last: dict | None, now_ns: int | None = None) -> int | None:
    if not last or not last.get("ts"):
        return None
    return round(((now_ns or time.time_ns()) - int(last["ts"])) / 1e9)


def health_is_stale(ctx: Context, last: dict | None, now_ns: int | None = None) -> bool:
    """A check older than STALE_CHECKS cadences means the worker is not running; it is not ok (XE-0908)."""
    age = health_age_s(last, now_ns)
    return age is None or age > STALE_CHECKS * cadence_s(ctx)


async def last_health(db: AsyncSession) -> dict | None:
    row = (await db.execute(select(HealthCheck).order_by(HealthCheck.ts.desc()).limit(1))).scalar_one_or_none()
    return row.detail if row else None


async def started_at(db: AsyncSession) -> int | None:
    """When the DAO started, in ns: the earliest thing it recorded, which is the first event in its log, or
    the first health check where that is earlier or the log is empty. The clock every "since the beginning"
    measure runs from, so a leg that has no rows of its own (no anchor written, no health check recorded)
    is measured against the DAO's age rather than against nothing (XE-1618, XE-1620). None only when
    nothing was ever recorded: a reader that sees None has no rows to discard (XE-2199)."""
    firsts = [(await db.execute(select(func.min(col)))).scalar_one() for col in (Event.ts, HealthCheck.ts)]
    firsts = [int(x) for x in firsts if x is not None]
    return min(firsts) if firsts else None


async def uptime_30d(ctx: Context, db: AsyncSession) -> dict:
    """Checks that should have run but did not count as failures, so a stopped worker lowers the figure
    instead of freezing it (XE-0908). Expected checks run from the DAO's start, not from the first check
    the worker happened to record, so a worker that started late or never does not score full (XE-1620)."""
    now = time.time_ns()
    since = now - WINDOW_30D_NS
    rows = (await db.execute(select(HealthCheck.ts, HealthCheck.ok, HealthCheck.detail["cadence_s"].astext)
                             .where(HealthCheck.ts >= since).order_by(HealthCheck.ts.asc()))).all()
    total = len(rows)
    good = sum(1 for _, ok, _ in rows if ok)
    first = await started_at(db)
    if first is None:   # nothing was ever recorded, so there is nothing to count
        return {"checks": 0, "ok": 0, "expected": 0, "fraction": None}
    expected = max(total, expected_checks([(int(ts), int(c) if c else None) for ts, _, c in rows], max(since, first), now, cadence_s(ctx)))
    return {"checks": total, "ok": good, "expected": expected, "fraction": (good / expected) if expected else None}


UPTIME_SHOWN_S = 60.0
_uptime_shown: tuple[float, dict] | None = None
_uptime_lock = asyncio.Lock()


async def uptime_30d_shown(ctx: Context, db: AsyncSession) -> dict:
    """`uptime_30d` for a public read: worked out at most once a minute in each process, and handed to
    every request in between. The figure is a pass over thirty days of checks and moves only when the
    worker records one, every ten minutes; computed per request, anyone could have it computed as often
    as they could ask (XE-6119). One caller computes while the rest wait for its answer."""
    global _uptime_shown
    async with _uptime_lock:
        if _uptime_shown is None or time.monotonic() - _uptime_shown[0] >= UPTIME_SHOWN_S:
            _uptime_shown = (time.monotonic(), await uptime_30d(ctx, db))
        return _uptime_shown[1]


def expected_checks(rows: list[tuple[int, int | None]], start_ns: int, now_ns: int, default_s: int) -> int:
    """How many checks the window should hold: each stretch of it is divided by the cadence that was in
    force then, as the check that opened the stretch recorded it, so a cadence change rewrites nothing
    behind it (XE-1639). A row without a recorded cadence (written before this was kept) uses the current
    one; the stretch before the first check uses that check's cadence. The stretches are summed exactly and
    the window is rounded once: rounding each stretch to a whole check called every gap of up to a cadence
    and a half one check, so a worker running at two-thirds speed scored full (XE-2374)."""
    if now_ns <= start_ns:
        return 0
    edges = [(start_ns, (rows[0][1] if rows and rows[0][1] else default_s))]
    edges += [(ts, c or default_s) for ts, c in rows if ts > start_ns]
    expected = Fraction(0)
    for i, (ts, cadence) in enumerate(edges):
        end = edges[i + 1][0] if i + 1 < len(edges) else now_ns
        expected += Fraction(end - ts, max(int(cadence), 1) * 1_000_000_000)
    return int(expected + Fraction(1, 2))   # nearest whole check, over the whole window
