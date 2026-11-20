"""Cadence from Schedule B turned into due-times. Shared by the worker and /v1/schedule/next."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .context import Context
from .models import ScheduleRun

NS = 1_000_000_000


def _next_daily(now: datetime, hour: int) -> datetime:
    t = now.replace(hour=hour, minute=0, second=0, microsecond=0)
    return t if t > now else t + timedelta(days=1)


def _next_weekly(now: datetime, weekday: int, hour: int) -> datetime:
    # weekday: Monday = 1 ... Sunday = 7 (Schedule B convention)
    target = (weekday - 1) % 7
    t = now.replace(hour=hour, minute=0, second=0, microsecond=0)
    days = (target - now.weekday()) % 7
    t = t + timedelta(days=days)
    return t if t > now else t + timedelta(days=7)


def _next_monthly(now: datetime, day: int, hour: int = 9) -> datetime:
    t = now.replace(day=min(day, 28), hour=hour, minute=0, second=0, microsecond=0)
    if t > now:
        return t
    y, m = (now.year + (now.month // 12), (now.month % 12) + 1)
    return t.replace(year=y, month=m)


def _prev_monthly(now: datetime, day: int, hour: int = 9) -> datetime:
    """The most recent monthly time at or before now: the mirror of `_next_monthly`, so a dated job's
    "have we run since it was last due" is read off the calendar, not off a fixed period that is shorter
    than the month it stands for (XE-1192)."""
    t = now.replace(day=min(day, 28), hour=hour, minute=0, second=0, microsecond=0)
    if t <= now:
        return t
    y, m = (now.year - (1 if now.month == 1 else 0), 12 if now.month == 1 else now.month - 1)
    return t.replace(year=y, month=m)


def dated(nxt: datetime, prev: datetime, desc: str) -> dict:
    return {"at": nxt, "prev": prev, "desc": desc}


def job_table(ctx: Context) -> dict[str, dict]:
    c = ctx.config.cadence
    now = datetime.now(timezone.utc)
    daily = _next_daily(now, int(c.get("daily_note_hour_utc", 8)))
    weekly = _next_weekly(now, int(c.get("weekly_review_weekday", 1)), int(c.get("weekly_review_hour_utc", 9)))
    anchor = _next_weekly(now, int(c.get("anchor_weekday", 1)), int(c.get("anchor_hour_utc", 9)))
    monthly_day = int(c.get("monthly_report_day", 1))
    return {
        "health": {"every_s": int(c.get("health_check_minutes", 10)) * 60, "desc": "node reachable, tip advancing, keyset unchanged, log replays, sessions ageing, directory"},
        "directory": {"every_s": int(c.get("directory_reregister_minutes", 20)) * 60, "desc": "re-register the DAO account in the node directory"},
        "fees": {"every_s": 60, "desc": "receive pending fees; refund or burn settled ones"},
        "outbox": {"every_s": 30, "desc": "send queued replies over chat"},
        "timers": {"every_s": 60, "desc": "close votes whose window ended; expire pauses; publish overdue pause posts; promote timelocked sessions"},
        "sessions": {"every_s": 120, "desc": "rebuild signing-session blocks when the tip has moved and no signatures are pending"},
        "daily": dated(daily, daily - timedelta(days=1), "daily state note into the log; treasury snapshot"),
        "weekly": dated(weekly, weekly - timedelta(days=7), "weekly review note"),
        "anchor": dated(anchor, anchor - timedelta(days=7), "open the weekly anchor session (dao.anchor.n)"),
        "monthly": dated(_next_monthly(now, monthly_day), _prev_monthly(now, monthly_day), "monthly summary note"),
    }


async def last_runs(db: AsyncSession) -> dict[str, int]:
    rows = (await db.execute(select(ScheduleRun))).scalars().all()
    return {r.job: r.last_run_ts for r in rows}


async def mark_run(db: AsyncSession, job: str, detail: dict | None = None, every_s: int | None = None) -> None:
    """Record that a job ran. Without `every_s` the mark is the time the run ended, so an interval job runs
    its interval after it last finished. With it the job keeps to a grid: the mark is the time the run fell
    due (the last mark plus the interval), so the seconds a run takes and the scheduler's tick are not
    added to every interval. The health check is marked this way because its runs are counted against the
    cadence (`records.uptime_30d`), and a worker that ran every 615 seconds for a 600 second cadence would
    publish 97.6% for a month in which nothing was wrong. A run more than an interval late starts a new
    grid from now, so a worker that was down does not run a burst to catch up."""
    now = time.time_ns()
    row = (await db.execute(select(ScheduleRun).where(ScheduleRun.job == job))).scalar_one_or_none()
    if row is None:
        db.add(ScheduleRun(job=job, last_run_ts=now, detail=detail or {}))
        return
    due = row.last_run_ts + every_s * NS if every_s else now
    row.last_run_ts = due if now - (every_s or 0) * NS < due <= now else now
    row.detail = detail or {}


async def mark_failed(db: AsyncSession, job: str, detail: dict, every_s: int, retry_s: int) -> dict:
    """Record that an interval job ran and failed, so that it is tried again `retry_s` from now and not a
    whole interval from now. For a job whose effect expires on the other side (the directory entry lapses
    30 minutes after the last registration, and the job runs every 20): one failed run marked like a good
    one leaves 40 minutes between registrations (XE-12324). Returns the detail of the run before this one,
    so the caller can tell the first failure of a spell from the ones after it; the count of failures in
    the spell is kept in the detail."""
    now = time.time_ns()
    row = (await db.execute(select(ScheduleRun).where(ScheduleRun.job == job))).scalar_one_or_none()
    before = dict(row.detail or {}) if row else {}
    detail = {**detail, "failures": int(before.get("failures") or 0) + 1}
    ts = now - max(0, every_s - retry_s) * NS
    if row is None:
        db.add(ScheduleRun(job=job, last_run_ts=ts, detail=detail))
    else:
        row.last_run_ts, row.detail = ts, detail
    return before


async def last_detail(db: AsyncSession, job: str) -> dict:
    row = (await db.execute(select(ScheduleRun).where(ScheduleRun.job == job))).scalar_one_or_none()
    return dict(row.detail or {}) if row else {}


def due_interval(last_ts: int | None, every_s: int) -> bool:
    return last_ts is None or time.time_ns() - last_ts >= every_s * NS


def due_at(last_ts: int | None, prev: datetime) -> bool:
    """A dated job is due when we have not run since its most recent scheduled time."""
    prev_ns = int(prev.timestamp() * NS)
    return time.time_ns() >= prev_ns and (last_ts is None or last_ts < prev_ns)


async def next_runs(ctx: Context, db: AsyncSession) -> list[dict]:
    table = job_table(ctx)
    last = await last_runs(db)
    out = []
    for name, j in table.items():
        lr = last.get(name)
        if "every_s" in j:
            nxt = (lr or 0) + j["every_s"] * NS if lr else time.time_ns()
            out.append({"job": name, "desc": j["desc"], "every_s": j["every_s"], "last_run": lr, "next_run": nxt})
        else:
            out.append({"job": name, "desc": j["desc"], "last_run": lr, "next_run": int(j["at"].timestamp() * NS),
                        "next_run_iso": j["at"].isoformat()})
    return out
