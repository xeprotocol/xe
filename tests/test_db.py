"""Against a real Postgres: the log chain, the ticket flow, proposals, the outbox, and the triage import
of the actual doc. Skipped unless DESK_TEST_DATABASE_URL is set, e.g.
DESK_TEST_DATABASE_URL=postgresql+asyncpg://desk:pw@db:5432/desk_test (a scratch database; it is wiped).

The image carries neither pytest nor this directory; mount the tests and install pytest for the run.
Build first, or the tests run against whatever code the image was last built from. On the VPS (see
docs/DEPLOY.md):

  docker compose build app
  docker compose exec db psql -U desk -d desk -c "CREATE DATABASE desk_test"   # "already exists" is fine
  docker compose run --rm --no-deps -v $PWD/tests:/app/tests \
    -e DESK_TEST_DATABASE_URL=postgresql+asyncpg://desk:$(grep ^POSTGRES_PASSWORD .env | cut -d= -f2)@db:5432/desk_test \
    app sh -c "pip install -q pytest pytest-asyncio && pytest -q tests/test_db.py"
"""

import asyncio
import hashlib
import inspect
import json
import os
import re
import time
from collections import Counter
from pathlib import Path

import pytest
from fastapi import HTTPException
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from desk import auth, authz
from desk.auth import SignedRequest, signing_target, verify_signed
from desk.canonical import DOMAIN_LOGIN, DOMAIN_PAYOUT
from desk.config import load_config
from desk.context import Context, NodeIdentity
from desk.db import Base
from desk.log import EventLog, public_payload
from desk.models import (
    AgentToken, Challenge, Event, Note, Passkey, Proposal, Reply, ScheduleRun, SeenDelivery, Ticket, User,
)
from desk.services import proposals as psvc
from desk.services import channels
from desk.services import reporters as rsvc
from desk.services import notify, sync, tell, thread, triage, users
from desk.services import tickets as tsvc
from desk.services.github import GitHubError
from desk.services.tickets import utcnow
from desk.settings import Settings
from desk.signer import Signer
from desk.vault import Vault
from xe.keys import KeyPair

URL = os.environ.get("DESK_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not URL, reason="DESK_TEST_DATABASE_URL not set")
ROOT = Path(__file__).resolve().parents[1]


class _NoChain:
    async def node(self):
        return {"network_id": "testnet-0005", "id": "x", "version": "t"}

    async def aclose(self):
        pass


@pytest.fixture
async def db():
    eng = create_async_engine(URL)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text("INSERT INTO log_head (id, index, hash) VALUES (1, -1, repeat('0', 64))"))
        await conn.execute(text("INSERT INTO id_counters (kind, next) VALUES ('bounty', 1), ('support', 1)"))
    sm = async_sessionmaker(eng, expire_on_commit=False)
    async with sm() as s:
        yield s
    await eng.dispose()


@pytest.fixture
def ctx():
    signer = Signer(
        {"log": KeyPair.generate(), "vault": KeyPair.generate()},
        {"log": {"event.sign"}, "vault": {"vault.seal", "vault.open"}},
    )
    settings = Settings(
        DESK_BOUNTY_HOST="bounty.test",
        DESK_SUPPORT_HOST="support.test",
        PUBLIC_BASE_URL="https://bounty.test",
        GITHUB_BLOCKED_LOGINS="",  # the deployment's own list is not the suite's
    )
    c = Context(
        settings=settings,
        config=load_config(ROOT / "config"),
        signer=signer,
        vault=Vault(signer),
        chain=_NoChain(),
        events=EventLog(signer),
        node=NodeIdentity(network_id="testnet-0005"),
    )
    return c


async def _team(ctx, db, roles=("reviewer", "tier", "treasurer", "admin"), email="lead@xe.network"):
    """A team member. A second call in the same test needs its own email; one is derived from the roles."""
    if await users.by_email(db, email):
        email = "-".join(sorted(roles)) + "@xe.network"
    u = await users.create_user(ctx, db, "test", email, "Lead", list(roles))
    return authz.Principal(kind="user", user=u, roles=set(roles))


def _api_routes(app) -> list:
    """Every API route the app serves, each as it is served: `path`, `methods`, `endpoint`, `dependant`
    and `body_field` with the including router's prefix and dependencies applied. FastAPI used to copy
    an included router's routes into `app.routes`; it now keeps the router there and resolves its
    routes on demand, so `app.routes` holds no `APIRoute` for them and a walk of it found nothing
    (and a test that asserts "no route does X" over nothing passes). `iter_route_contexts` is what
    FastAPI's own OpenAPI builder walks; without it the list is the flat one."""
    from fastapi import routing

    walk = getattr(routing, "iter_route_contexts", None)
    found = list(walk(app.routes)) if walk else list(app.routes)
    out = [r for r in found if isinstance(getattr(r, "original_route", r), routing.APIRoute)]
    assert len(out) >= 60, len(out)  # the desk has well over this many; an empty walk asserts nothing
    return out


async def _agent(ctx, db, owner: User, scopes=("read:public", "write:notes", "write:proposals")):
    tok, _raw = await users.issue(
        ctx, db, authz.Principal(kind="user", user=owner, roles={"admin"}), owner, "m", "t", list(scopes), 30
    )
    return authz.Principal(kind="token", token=tok, scopes=set(scopes))


# ---- log --------------------------------------------------------------------------------------------


async def test_log_chain_verifies_and_detects_tamper(ctx, db):
    for i in range(4):
        await ctx.events.append(db, "test", "desk", {"i": i}, public=(i % 2 == 0))
    await db.commit()
    res = await EventLog.verify(db)
    assert res["ok"] and res["count"] == 4
    assert len(await EventLog.since(db, -1, public_only=True)) == 2
    key = ctx.signer.public_key("log")
    assert (await EventLog.verify(db, key))["ok"]
    # the envelope covers the private flag and the ref: declassifying a row is a hash mismatch
    await db.execute(text("UPDATE events SET public = true WHERE index = 1"))
    await db.commit()
    assert "hash mismatch at 1" in (await EventLog.verify(db, key))["first_error"]
    await db.execute(text("UPDATE events SET public = false WHERE index = 1"))
    await db.execute(text("UPDATE events SET payload = '{\"i\": 9}'::jsonb WHERE index = 2"))
    await db.commit()
    assert "hash mismatch at 2" in (await EventLog.verify(db))["first_error"]
    # a stripped signature, or one by another key, fails against the published key
    await db.execute(text("UPDATE events SET payload = '{\"i\": 2}'::jsonb WHERE index = 2"))
    await db.execute(text("UPDATE events SET signature = '' WHERE index = 2"))
    await db.commit()
    assert (await EventLog.verify(db))["ok"]  # unpinned: tolerated, as a dev desk without a key would be
    assert "not signed by the log key" in (await EventLog.verify(db, key))["first_error"]


async def test_no_request_replays_the_chain(ctx, db):
    """The rule (XE-0657): a replay's cost grows with the log, so only the worker runs one; a request is
    served the worker's last verdict from one row. Walked over every module that answers requests, so a
    route added later that replays fails here."""
    from desk import log as desklog
    from desk.api import public as pub
    from desk.worker import Worker

    # every module of the desk but the three that may: the log itself, the worker, and the operator's CLI
    root = Path(desklog.__file__).parent
    replayers = {"log.py", "worker.py", "cli.py"}
    walked = [f for f in sorted(root.rglob("*.py")) if str(f.relative_to(root)) not in replayers]
    assert {"api/public.py", "ui.py", "main.py", "bots/discord_bot.py"} <= {
        str(f.relative_to(root)) for f in walked
    }
    for f in walked:
        src = f.read_text(encoding="utf-8")
        for replay in (".verify(", "iter_all(", "replay_and_record"):
            assert replay not in src, f"{f.relative_to(root)} replays the chain ({replay})"
    # and in the worker the replay runs beside the loop: the jobs after it do not wait for it, and a
    # tick that finds one still running does not start a second

    class W(Worker):
        JOBS = {desklog.VERIFY_JOB: 0, "quick": 0}
        TICK_S = 0.01
        quick = replays = 0

        async def job_health(self):
            pass

        async def job_log_verify(self):
            self.replays += 1
            await asyncio.Event().wait()  # a replay that never finishes

        async def job_quick(self):
            self.quick += 1
            if self.quick == 5:
                self.stop.set()

    w = W(ctx)
    assert desklog.VERIFY_JOB in Worker.BACKGROUND and desklog.VERIFY_JOB in Worker.JOBS
    await asyncio.wait_for(w.run(), timeout=10)
    assert (w.quick, w.replays) == (5, 1) and w.running[desklog.VERIFY_JOB].cancelled()
    key = ctx.signer.public_key("log")
    for i in range(3):
        await ctx.events.append(db, "test", "desk", {"i": i})
    await db.commit()
    # before the worker's first replay the route says so; it does not replay to find out
    first = await pub.log_verify(db)
    assert first["ok"] is False and "not been replayed" in first["first_error"] and first["count"] == 0
    await EventLog.replay_and_record(db, key)
    await db.commit()
    seen = await pub.log_verify(db)
    assert seen["ok"] is True and seen["count"] == 3 and seen["checked_at"]
    assert seen["head"] == (await EventLog.head(db)).hash
    # the route reads the verdict: a row changed after the replay is found by the next replay, not by a
    # request (if this read ok=False the route would be replaying)
    await db.execute(text("UPDATE events SET payload = '{\"i\": 9}'::jsonb WHERE index = 1"))
    await db.commit()
    assert (await pub.log_verify(db))["ok"] is True
    await EventLog.replay_and_record(db, key)
    await db.commit()
    found = await pub.log_verify(db)
    assert found["ok"] is False and "hash mismatch at 1" in found["first_error"] and found["count"] == 1
    # a verdict the worker has stopped renewing lapses
    await db.execute(text("UPDATE events SET payload = '{\"i\": 1}'::jsonb WHERE index = 1"))
    await db.commit()
    good = await EventLog.replay_and_record(db, key)
    await db.commit()
    assert (await EventLog.last_verdict(db))["ok"] is True
    late = good["checked_at"] + desklog.VERIFY_MAX_AGE_NS + 1
    lapsed = await EventLog.last_verdict(db, now_ns=late)
    assert lapsed["ok"] is False and "worker has stopped" in lapsed["first_error"]


def test_event_views_hide_operational_fields_from_non_team():
    from desk.log import event_to_dict
    from desk.models import Event

    ev = Event(
        index=1, ts=1, kind="reporter.login", actor="reporter:1", payload={"how": "email", "ip": "10.0.0.9"},
        prev_hash="0" * 64, hash="1" * 64, signer="", signature="", public=False, ref="", v=2,
    )
    assert event_to_dict(ev)["payload"]["ip"] == "10.0.0.9"
    assert "ip" not in event_to_dict(ev, full=False)["payload"]
    # a public fact change names which assessment fields moved, not what they became or why
    facts = Event(
        index=2, ts=2, kind="ticket.facts", actor="user:1", prev_hash="1" * 64, hash="2" * 64, signer="",
        signature="", public=True, ref="XE-0001", v=2,
        payload={
            "ticket": "XE-0001", "reason": "confirmed at ledger.go:2117", "via": "",
            "changes": {"assessed_tier": {"from": None, "to": "high"}, "area": {"from": None, "to": "core"}},
        },
    )
    full = event_to_dict(facts)["payload"]
    assert full["changes"]["assessed_tier"]["to"] == "high" and full["reason"]
    pub = event_to_dict(facts, full=False)["payload"]
    assert pub["changes"] == {"area": {"from": None, "to": "core"}} and pub["held"] == ["assessed_tier"]
    assert "reason" not in pub and pub["ticket"] == "XE-0001"
    prop = Event(
        index=3, ts=3, kind="proposal.created", actor="token:1", prev_hash="2" * 64, hash="3" * 64, signer="",
        signature="", public=True, ref="XE-0001", v=2,
        payload={"ticket": "XE-0001", "proposal": 1, "field": "assessed_tier", "value": "critical"},
    )
    assert "value" not in event_to_dict(prop, full=False)["payload"]
    assert event_to_dict(prop, full=False)["payload"]["field"] == "assessed_tier"
    # the team's administration shrinks to ids outside the team: no addresses, roles, labels or scopes
    admin = Event(
        index=4, ts=4, kind="token.issued", actor="user:1", prev_hash="3" * 64, hash="4" * 64, signer="",
        signature="", public=True, ref="", v=2,
        payload={"token": 4, "owner": 2, "model": "claude", "label": "daily", "scopes": ["read:private"]},
    )
    assert event_to_dict(admin, full=False)["payload"] == {"token": 4, "owner": 2}


# ---- tickets ----------------------------------------------------------------------------------------


async def test_ticket_lifecycle(ctx, db):
    p = await _team(ctx, db)
    t = await tsvc.create(
        ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="A crash", body="steps", source="web")
    )
    assert t.id == "XE-0001"
    t2 = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="support", title="Faucet?", source="web"))
    assert t2.id == "XS-0001"
    await tsvc.set_facts(
        ctx,
        db,
        p,
        t,
        {"verdict": "valid", "assessed_tier": "high", "mainnet_gate": "before", "area": "node-api"},
    )
    with pytest.raises(HTTPException):
        await tsvc.set_facts(ctx, db, p, t, {"assessed_tier": "enormous"})
    with pytest.raises(HTTPException):
        await tsvc.set_status(ctx, db, p, t, "paid")
    await tsvc.set_status(ctx, db, p, t, "triaging")
    await tsvc.set_status(ctx, db, p, t, "accepted")
    await tsvc.set_facts(ctx, db, p, t, {"internal_ref": "#1068", "effort_eng": "1-4h"})
    # accepted and unfixed: the team sees the assessment, the public sees the ticket and no ranking
    mine, theirs = tsvc.to_dict(ctx, t, p), tsvc.to_dict(ctx, t, authz.ANON)
    assert mine["assessed_tier"] == "high" and mine["mainnet_gate"] == "before"
    assert mine["internal_ref"] == "#1068"
    assert theirs["assessed_tier"] is None and theirs["verdict"] is None and theirs["internal_ref"] == ""
    assert theirs["tracked"] is True and "mainnet_gate" not in theirs and "effort_eng" not in theirs
    assert "assignee_id" not in theirs
    await tsvc.set_status(ctx, db, p, t, "patched")
    assert t.status_changed_at is not None
    theirs = tsvc.to_dict(ctx, t, authz.ANON)
    assert theirs["assessed_tier"] == "high" and theirs["verdict"] == "valid"
    assert theirs["internal_ref"] == "#1068"
    assert "mainnet_gate" not in theirs  # planning data, never public
    # outbox: patched and never told
    assert [x.id for x in await tsvc.outbox(db, ctx.config, p)] == ["XE-0001"]
    r = await thread.add_reply(ctx, db, p, t, "Fixed in #27, thank you.")
    assert r.mirror == "none" and t.told_at is not None
    assert await tsvc.outbox(db, ctx.config, p) == []
    # a withdrawal is the reporter's own word: closed, never told, and still not owed a reply
    t3 = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="Test", source="web"))
    await tsvc.set_status(ctx, db, p, t3, "triaging")
    await tsvc.set_status(ctx, db, p, t3, "closed", closed_reason="withdrawn")
    assert await tsvc.outbox(db, ctx.config, p) == []
    # award needs the treasurer and approval before awarded
    with pytest.raises(HTTPException):
        await tsvc.set_status(ctx, db, p, t, "awarded")
    t.assessed_tier = t.assessed_tier or "medium"  # an award needs a tier (XE-0470)
    await tsvc.set_award(ctx, db, p, t, 5_000_000_000, approve=True)
    await tsvc.set_status(ctx, db, p, t, "awarded")
    await db.commit()
    # The status/award routes return to_dict after commit. updated_at is server-set on UPDATE; without
    # eager_defaults it is expired at flush and this read would be an implicit refresh, which an async
    # session turns into MissingGreenlet: a 500 after the write landed. Must read cleanly here.
    d = tsvc.to_dict(ctx, t, p)
    assert d["status"] == "awarded" and d["award_xe"] == 5_000_000_000 and d["updated_at"]
    board = await tsvc.leaderboard(db)
    assert board == []  # no reporter attached
    kinds = Counter(e.kind for e in await EventLog.page(db, 0, 100, ref=t.id))
    assert (
        kinds["ticket.status"] == 4
        and kinds["ticket.facts"] == 2  # the first assessment, then the internal ref and effort
        and kinds["reply.sent"] == 2  # the one written by hand at patched, the desk's own at awarded
        and kinds["ticket.award"] == 1
    )


async def test_counts_split_into_now_and_all_time(ctx, db):
    """Open is what is still being worked. Fixed, awarded and closed are all-time and never shrink as a
    ticket moves from the merge to the money. The list filters use the same split."""
    p = await _team(ctx, db)
    new = [tsvc.NewTicket(kind="bounty", title=n, source="web") for n in "abcd"]
    a, b, c, d = [await tsvc.create(ctx, db, p.actor, n) for n in new]
    for t, path in ((a, ["triaging", "accepted"]), (b, ["triaging", "accepted", "patched"]),
                    (c, ["triaging", "accepted", "patched", "awarded", "paid"])):
        for st in path:
            await tsvc.set_status(ctx, db, p, t, st, force=True)  # awarded/paid without the treasurer's click
    await tsvc.set_status(ctx, db, p, d, "closed", closed_reason="invalid")
    n = await tsvc.counts(db, p)
    assert (n["open"], n["fixed"], n["awarded_all"], n["closed"]) == (1, 2, 1, 1)
    assert n["open"] == n["new"] + n["triaging"] + n["needs-info"] + n["accepted"] + n["fixing"]
    async def ids(status):
        return {r.id for r in await tsvc.list_tickets(db, ctx.config, p, tsvc.Filters(status=status))}

    assert await ids("open") == {a.id}
    assert await ids("fixed") == {b.id, c.id}
    assert await ids("closed") == {d.id}


async def test_a_report_is_read_across_the_desk(ctx, db):
    """Before a verdict the reader is shown what else looks like the report: shared words, shared paths,
    the same reporter, duplicate links; the search reaches bodies; a page says how many there are in all;
    and the export means every ticket."""
    from desk.models import Reporter

    p = await _team(ctx, db)
    r1, r2 = Reporter(github_login="ada"), Reporter(github_login="mallory")
    db.add_all([r1, r2])
    await db.flush()

    async def mk(title, body="", reporter=None, area=None, visibility="public"):
        spec = tsvc.NewTicket(
            kind="bounty", title=title, body=body, source="web", reporter_id=reporter and reporter.id,
            area=area, visibility=visibility,
        )
        return await tsvc.create(ctx, db, p.actor, spec)

    a = await mk(
        "Quorum bypass via hex vote forgery", "A forged vote in src/consensus/vote.rs:120 counts twice.",
        r1, "consensus",
    )
    b = await mk("Vote malleability lets one validator vote twice",
                 "The check in src/consensus/vote.rs accepts both encodings.", r2, "consensus")
    c = await mk("Sync stalls on a bad peer", "crates/p2p/sync.go never times out.", r1, "p2p-sync")
    d = await mk("Unrelated typo on the docs page", "The scope page says 'teh'.", None, "sdk-docs-web")
    e = await mk("Private: quorum vote forgery, again", "", r2, "consensus", visibility="private")
    await db.commit()

    rows = await tsvc.similar(db, ctx.config, p, a, body=a.body)
    by = {s.ticket.id: s for s in rows}
    assert b.id in by and "same words" in by[b.id].why and "same area" in by[b.id].why
    assert "cites src/consensus/vote.rs" in by[b.id].why
    assert c.id in by and by[c.id].why == ["same reporter"]
    assert d.id not in by
    assert rows[0].ticket.id == b.id  # the strongest match leads
    # a reader without read:private is not shown the private one; the team is, by its title alone
    assert e.id in by
    assert e.id not in {s.ticket.id for s in await tsvc.similar(db, ctx.config, authz.ANON, a, body=a.body)}
    # a duplicate link counts either way round
    await tsvc.set_facts(ctx, db, p, b, {"duplicate_of": a.id})
    again = {s.ticket.id: s for s in await tsvc.similar(db, ctx.config, p, a)}
    assert "linked as duplicate" in again[b.id].why
    row = tsvc.similar_dict(ctx, by[b.id], authz.ANON, a)
    assert row["same_reporter"] is False and "internal_ref" not in row  # held while the bug is open
    # the search reaches public bodies
    hits = {t.id for t in await tsvc.list_tickets(db, ctx.config, authz.ANON, tsvc.Filters(q="encodings"))}
    assert hits == {b.id}
    # one reporter's filings, for the team only
    hers = tsvc.Filters(status="all", reporter=r1.id)
    assert {t.id for t in await tsvc.list_tickets(db, ctx.config, p, hers)} == {a.id, c.id}
    with pytest.raises(HTTPException) as refused:  # a public caller is refused the axis (XE-1560)
        await tsvc.list_tickets(db, ctx.config, authz.ANON, hers)
    assert refused.value.status_code == 403
    # a duplicate of a private ticket is not named to a reader who cannot open the target, on every
    # serializer that carries duplicate_of (XE-0799): one helper decides, list, get and similar consult it
    await tsvc.set_facts(ctx, db, p, c, {"duplicate_of": e.id})
    rows_c = [c, b]
    hidden = await tsvc.hidden_targets(db, authz.ANON, rows_c)
    assert hidden == {e.id}
    assert tsvc.to_dict(ctx, c, authz.ANON, hidden=hidden)["duplicate_of"] is None
    assert tsvc.to_dict(ctx, b, authz.ANON, hidden=hidden)["duplicate_of"] == a.id  # a public target is named
    sim_c = {s.ticket.id: s for s in await tsvc.similar(db, ctx.config, p, a)}
    assert tsvc.similar_dict(ctx, sim_c[c.id], authz.ANON, a, hidden)["duplicate_of"] is None
    assert await tsvc.hidden_targets(db, p, rows_c) == frozenset()  # the team is told
    own = authz.Principal(kind="reporter", reporter_id=r2.id)
    assert await tsvc.hidden_targets(db, own, rows_c) == frozenset()  # r2 filed e, and may know it
    # the text the desk writes to the reporter follows the same helper (XE-1990): on a public ticket the
    # audience is everyone, so a private target goes unnamed; a public target is linked; on a private
    # ticket the reporter may be told about their own private target
    tpl = "Same as {duplicate_url}."
    assert e.id not in await thread.render_template(ctx, db, "duplicate", c)
    assert thread.UNNAMED_DUPLICATE in await thread.fill_for(ctx, db, tpl, c)
    assert await thread.fill_for(ctx, db, tpl, b) == f"Same as {tsvc.ticket_url(ctx, a)}."
    f_own = await mk("Private: same again", "", r2, "consensus", visibility="private")
    await tsvc.set_facts(ctx, db, p, f_own, {"duplicate_of": e.id})
    assert await thread.fill_for(ctx, db, tpl, f_own) == f"Same as {tsvc.ticket_url(ctx, e)}."
    assert thread.fill(ctx, tpl, c) == tpl  # without an audience the placeholder stays, and a draft waits
    assert thread.review_reason(ctx, thread.fill(ctx, tpl, c), c) == "has an unfilled placeholder"
    # a page knows the size of the whole selection
    f = tsvc.Filters(status="all", limit=2)
    assert len(await tsvc.list_tickets(db, ctx.config, p, f)) == 2
    assert await tsvc.count_tickets(db, ctx.config, p, f) == 6
    # the export reads every ticket, each once, in one statement; and a pager of the list is given
    # each once too, because the list's order is total (XE-2271)
    every = await tsvc.every_ticket(db, ctx.config, p, tsvc.Filters(status="all"))
    assert len(every) == 6 and len({t.id for t in every}) == 6
    pages = [tsvc.Filters(status="all", offset=at, limit=2) for at in (0, 2, 4)]
    paged = [t.id for f in pages for t in await tsvc.list_tickets(db, ctx.config, p, f)]
    assert paged == [t.id for t in every]
    whole = await triage.export_markdown(ctx, db, p)
    assert "6 tickets." in whole and f"via {e.id}" in whole
    # it is the working layer's. An agent without read:private gets the public rows, and the private
    # target of a public duplicate is not named to it (XE-0799); anyone else is refused, and by the
    # exporter itself, whoever calls it
    reader = await _agent(ctx, db, p.user)
    part = await triage.export_markdown(ctx, db, reader)
    assert "4 tickets." in part and c.id in part and e.id not in part
    assert f"via {thread.UNNAMED_DUPLICATE}" in part
    for outsider in (authz.ANON, authz.Principal(kind="reporter", reporter_id=r1.id)):
        with pytest.raises(HTTPException) as no:
            await triage.export_markdown(ctx, db, outsider)
        assert no.value.status_code == 403


async def test_a_note_says_what_it_checked(ctx, db):
    p = await _team(ctx, db)
    agent = await _agent(ctx, db, p.user)
    t = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="x", source="web"))
    seen = {"desk": 692, "similar": ["xe-0130", "XE-0131"], "tracker": False, "tree": "xe@abc1234"}
    n = await thread.add_note(ctx, db, agent, t, "Read.", seen)
    assert n.checked == {**seen, "similar": ["XE-0130", "XE-0131"]}
    assert (await thread.add_note(ctx, db, agent, t, "Remark.")).checked == {}
    for bad in ({"desk": "many"}, {"tracker": 1}, {"tree": 7}, {"github": True}, ["desk"]):
        with pytest.raises(HTTPException):
            await thread.add_note(ctx, db, agent, t, "x", bad)


async def test_team_administration_never_reaches_the_public_log(ctx, db):
    p = await _team(ctx, db)
    tok = await _agent(ctx, db, p.user)
    await users.set_roles(ctx, db, p.actor, p.user, [])  # no roles: the token dies with them
    mine = {e.kind for e in await EventLog.page(db, 0, 200, public_only=False)}
    assert {"user.created", "token.issued", "user.roles", "token.revoked"} <= mine
    theirs = await EventLog.page(db, 0, 200, public_only=True)
    assert not any(e.kind.startswith(("user.", "token.", "team.")) for e in theirs)
    latest = await EventLog.since(db, 0, public_only=True)
    assert not any(e.kind.startswith(("user.", "token.")) for e in latest)
    # rows written public before the rule are still held back: the rule is in the read path
    row = (await db.execute(select(Event).where(Event.kind == "user.created"))).scalars().first()
    row.public = True
    await db.flush()
    assert not any(e.kind == "user.created" for e in await EventLog.page(db, 0, 200, public_only=True))
    assert tok.token is not None


async def test_private_ticket_is_sealed_and_hidden(ctx, db):
    p = await _team(ctx, db)
    t = await tsvc.create(
        ctx,
        db,
        p.actor,
        tsvc.NewTicket(
            kind="bounty",
            title="secret",
            body="the exploit",
            visibility="private",
            source="email",
            source_ref="E9",
        ),
    )
    assert t.body == "" and t.body_sealed and tsvc.body_for(ctx, t) == "the exploit"
    row = (await db.execute(text("SELECT body, body_sealed FROM tickets WHERE id = :id"), {"id": t.id})).one()
    assert row[0] == "" and b"exploit" not in bytes(row[1])
    assert await tsvc.list_tickets(db, ctx.config, authz.ANON, tsvc.Filters(status="all")) == []
    with pytest.raises(HTTPException) as e:
        await tsvc.get_for(db, authz.ANON, t.id)
    assert e.value.status_code == 404
    evs = await EventLog.page(db, 0, 10, ref=t.id, public_only=True)
    assert evs == []


async def test_private_history_leaves_the_public_log_and_replies_seal(ctx, db):
    team = await _team(ctx, db)
    t, _ = await sync.upsert_issue(ctx, db, "xeprotocol/xe", _issue(79, "public first", body="b"))
    await tsvc.set_status(ctx, db, team, t, "triaging")
    r = await thread.add_reply(ctx, db, team, t, "public words")
    assert (await EventLog.page(db, 0, 50, ref=t.id)) != []
    await tsvc.set_facts(ctx, db, team, t, {"visibility": "private"})
    # the history is gone from every public read path while the ticket is private; the one row that stays
    # says why (XE-0350, XE-0410)
    pub = await EventLog.page(db, 0, 50, ref=t.id)
    assert [e.kind for e in pub] == ["ticket.sealed"]
    sealed = pub[0]
    assert await EventLog.served_public(db, sealed) is True
    every = await EventLog.page(db, 0, 50, ref=t.id, public_only=False)
    created = next(e for e in every if e.kind == "ticket.created")
    assert created.public is True and await EventLog.served_public(db, created) is False
    assert all(e.ref != t.id or e.kind == "ticket.sealed" for e in await EventLog.since(db, -1, 1000))
    # the reply row followed the body into the vault (XE-0426), and a new reply on a private ticket seals
    await db.refresh(r)
    assert r.body == "" and r.body_sealed and thread.reply_body(ctx, r) == "public words"
    r2 = await thread.add_reply(ctx, db, team, t, "private words")
    assert r2.body == "" and thread.reply_body(ctx, r2) == "private words"
    # disclosed again: the history is served again
    await thread.add_patch_ref(ctx, db, team, t, repo="xeprotocol/xe", ref="9", kind="pr")
    for st in ("accepted", "patched"):
        await tsvc.set_status(ctx, db, team, t, st)
    await tsvc.set_status(ctx, db, team, t, "disclosed")
    assert await EventLog.served_public(db, created) is True
    # the chain still verifies: nothing was rewritten
    assert (await EventLog.verify(db))["ok"]


async def test_the_live_stream_serves_only_what_the_log_read_path_serves(ctx, db, monkeypatch):
    """The rule: an event reaches a reader outside the team only through the log's one read path (stored
    flag, admin kinds, the ticket's visibility now). The SSE stream used to trust the stored flag on the
    live branch (XE-1884, XE-1641, XE-1645); now replay and live both read back through `since`."""
    from contextlib import asynccontextmanager

    from desk.api import public as pub

    sm = async_sessionmaker(db.bind, expire_on_commit=False)

    @asynccontextmanager
    async def _session():
        async with sm() as s:
            yield s

    monkeypatch.setattr(pub, "session", _session)
    monkeypatch.setattr(pub, "STREAM_IDLE_S", 0.1)
    team = await _team(ctx, db)
    t, _ = await sync.upsert_issue(ctx, db, "xeprotocol/xe", _issue(81, "goes private live", body="b"))
    await db.commit()
    head = (await EventLog.head(db)).index

    calls = {"n": 0}

    class Req:
        headers: dict = {}

        async def is_disconnected(self):
            calls["n"] += 1
            return calls["n"] > 2  # one read before the wait, one after the wake-up, then gone

    who = type("W", (), {"principal": authz.ANON})()
    # the request's own session, as asking who is calling leaves it: a transaction open. The stream
    # does not keep it: a stream that did held a database connection for as long as it was open
    async with sm() as asked:
        assert (await asked.execute(select(User).where(User.id == team.user.id))).scalar_one()
        assert asked.in_transaction()
        resp = await pub.events_stream(ctx, asked, Req(), who, since=None)
        assert not asked.in_transaction() and not asked.identity_map
    route = inspect.getsource(pub.events_stream)
    assert route.index("await db.close()") < route.index("async def gen")
    gen = resp.body_iterator
    got: list[dict] = []

    async def consume():
        async for item in gen:
            got.append(item)

    task = asyncio.create_task(consume())
    await asyncio.sleep(0.05)  # the stream is now waiting on its wake-up
    # three live events: a public row on a ticket that is private now, an admin row, and ticket.sealed
    await tsvc.set_facts(ctx, db, team, t, {"visibility": "private"})
    await users.create_user(ctx, db, "test", "late@xe.network", "Late", ["reviewer"])
    await db.commit()
    await asyncio.wait_for(task, 5)
    served = [json.loads(i["data"]) for i in got if i.get("event") == "entry"]
    assert all(e["index"] > head for e in served)
    assert [e["kind"] for e in served] == ["ticket.sealed"]
    assert all(not e["kind"].startswith(("user.", "team.", "token.")) for e in served)
    # the same rows through the other public read paths agree
    assert [e.kind for e in await EventLog.since(db, head, 100)] == ["ticket.sealed"]
    assert pub._event_id("--") is None and pub._event_id("²") is None and pub._event_id("7") == 7


async def test_held_facts_stay_out_of_public_payloads(ctx, db):
    from desk.log import public_payload

    staged = {"ticket": "XE-0001", "award_xe": 5, "approved": True, "tier": "high", "step": "standard"}
    assert public_payload("ticket.award", staged) == {"ticket": "XE-0001"}  # XE-0604, XE-0735
    assert public_payload("ticket.status", {"via": "internal:xeprotocol/core#12", "reason": "x"}) == {
        "via": "internal",
    }  # XE-0612
    # a duplicate mark and a family ruling never name the canonical in the public log: it may be private
    # and the log's read path cannot tell (XE-0799, XE-1987)
    marked = public_payload(
        "ticket.facts", {"ticket": "x", "changes": {"duplicate_of": {"from": None, "to": "XE-0002"}}}
    )
    assert marked["changes"] == {} and marked["held"] == ["duplicate_of"]
    # a tier re-ruled under an approved award: the tier is a held fact that changed, and that an
    # approval was taken back is not said at all, by value or by name (XE-0735)
    reruled = public_payload(
        "ticket.facts",
        {
            "ticket": "x",
            "changes": {
                "assessed_tier": {"from": "high", "to": "minor"},
                "award_approved": {"from": True, "to": False},
            },
        },
    )
    assert reruled["changes"] == {} and reruled["held"] == ["assessed_tier"]
    assert public_payload("ticket.status", {"via": "family:XE-0002"}) == {"via": "family"}
    predates = public_payload("ticket.internal_predates", {"ticket": "x", "internal_ref": "#9"})
    assert "internal_ref" not in predates
    adopted = public_payload("proposal.adopted", {"ticket": "x", "reason": "it is High"})
    assert "reason" not in adopted  # XE-0768
    # fill never names a held tier and never reaches past known placeholders (XE-0733, XE-0956)
    team = await _team(ctx, db)
    t = await tsvc.create(ctx, db, team.actor, tsvc.NewTicket(kind="bounty", title="x", source="web"))
    await tsvc.set_facts(ctx, db, team, t, {"assessed_tier": "high"})
    assert thread.fill(ctx, "Tier: {tier}.", t) == "Tier: ."
    assert thread.fill(ctx, "{ticket_url.__class__} {0} {reason!r} {tier:>5} {unknown}", t) == (
        "{ticket_url.__class__} {0} {reason!r} {tier:>5} {unknown}"
    )
    for st in ("triaging", "accepted", "patched"):
        await tsvc.set_status(ctx, db, team, t, st)
    assert thread.fill(ctx, "Tier: {tier}.", t) == "Tier: High."
    # the team-only axes and the assessment go with notes access, not with being a token (XE-1560, XE-0696)
    linker = await _agent(ctx, db, team.user, scopes=("write:patch-refs",))
    assert not tsvc.sees_assessment(linker) and not authz.can(linker, "read:notes")
    reader = await _agent(ctx, db, team.user, scopes=("read:public",))
    assert tsvc.sees_assessment(reader)


async def test_text_is_cleaned_and_chat_closes_stay_in_their_lane(ctx, db):
    team = await _team(ctx, db)
    title, body = "nul\x00 in\nthe title", "body\x00 here\x07"
    spec = tsvc.NewTicket(kind="bounty", title=title, body=body, source="web")
    t = await tsvc.create(ctx, db, team.actor, spec)
    assert t.title == "nul in the title" and t.body == "body here"  # XE-1426
    assert tsvc.clean_text("a\udc80b") == "ab"
    # a Discord /close is for questions; an accepted report is closed from the desk (XE-0690, XE-0805)
    for st in ("triaging", "accepted"):
        await tsvc.set_status(ctx, db, team, t, st)
    with pytest.raises(HTTPException) as e:
        await channels.close_from_channel(ctx, db, t, user_id="1", reason="")
    assert e.value.status_code == 409 and t.status == "accepted"
    # the awarded record does not walk back (XE-0789), and an award needs a tier (XE-0470)
    with pytest.raises(HTTPException) as e:
        await tsvc.set_award(ctx, db, team, t, 1_000_000)
    assert e.value.status_code == 409 and "tier" in e.value.detail
    await tsvc.set_facts(ctx, db, team, t, {"assessed_tier": "minor"})
    await tsvc.set_award(ctx, db, team, t, 1_000_000)
    with pytest.raises(HTTPException) as e:
        await tsvc.set_award(ctx, db, team, t, tsvc.AWARD_MAX + 1)
    assert e.value.status_code == 400  # XE-0973
    with pytest.raises(HTTPException) as e:
        await tsvc.set_facts(ctx, db, team, t, {"visibility": None})
    assert e.value.status_code == 400
    await tsvc.set_status(ctx, db, team, t, "patched")
    await tsvc.set_award(ctx, db, team, t, None, approve=True)
    # the tier moves after approval: approval is taken back and the amount is re-checked (XE-0890)
    diff = await tsvc.set_facts(ctx, db, team, t, {"assessed_tier": "high"})
    assert t.award_approved_at is None and diff["award_approved"] == {"from": True, "to": False}
    await tsvc.set_award(ctx, db, team, t, 8_000_000_000)  # within 2x high
    await tsvc.set_facts(ctx, db, team, t, {"assessed_tier": "minor"})
    with pytest.raises(HTTPException) as e:
        await tsvc.set_award(ctx, db, team, t, None, approve=True)  # 8,000 XE is over 2x minor
    assert e.value.status_code == 400
    await tsvc.set_award(ctx, db, team, t, 1_000_000_000)
    await tsvc.set_award(ctx, db, team, t, None, approve=True)
    await tsvc.set_status(ctx, db, team, t, "awarded")
    with pytest.raises(HTTPException) as e:
        await tsvc.set_status(ctx, db, team, t, "triaging")
    assert e.value.status_code == 409


async def test_severity_sort(ctx, db):
    p = await _team(ctx, db)
    a = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="minor", source="web"))
    b = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="severe", source="web"))
    c = await tsvc.create(
        ctx,
        db,
        p.actor,
        tsvc.NewTicket(kind="bounty", title="claimed high", source="web", claimed_tier="high"),
    )
    await tsvc.set_facts(ctx, db, p, a, {"assessed_tier": "minor"})
    await tsvc.set_facts(ctx, db, p, b, {"assessed_tier": "severe"})
    rows = await tsvc.list_tickets(db, ctx.config, p, tsvc.Filters())
    assert [r.id for r in rows] == [b.id, a.id, c.id]
    # the public is shown the claim while the assessment is held, and sorts and filters on that
    anon = authz.ANON
    rows = await tsvc.list_tickets(db, ctx.config, anon, tsvc.Filters())
    assert [r.id for r in rows] == [c.id, a.id, b.id]
    assert [r.id for r in await tsvc.list_tickets(db, ctx.config, p, tsvc.Filters(tier="severe"))] == [b.id]
    assert await tsvc.list_tickets(db, ctx.config, anon, tsvc.Filters(tier="severe")) == []
    assert [r.id for r in await tsvc.list_tickets(db, ctx.config, anon, tsvc.Filters(tier="high"))] == [c.id]
    await tsvc.set_facts(ctx, db, p, b, {"verdict": "valid", "mainnet_gate": "later", "internal_ref": "#9"})
    assert await tsvc.list_tickets(db, ctx.config, anon, tsvc.Filters(verdict="valid")) == []
    with pytest.raises(HTTPException) as e:  # a team-only axis is refused, not quietly dropped (XE-1560)
        await tsvc.list_tickets(db, ctx.config, anon, tsvc.Filters(status="all", gate="later"))
    assert e.value.status_code == 403
    assert await tsvc.list_tickets(db, ctx.config, anon, tsvc.Filters(q="#9")) == []
    assert [r.id for r in await tsvc.list_tickets(db, ctx.config, p, tsvc.Filters(q="#9"))] == [b.id]
    for st in ("triaging", "accepted", "patched"):
        await tsvc.set_status(ctx, db, p, b, st)
    # patched is no longer "open"; across the whole desk the assessment now shows and sorts
    rows = await tsvc.list_tickets(db, ctx.config, anon, tsvc.Filters(status="all", tier="severe"))
    assert [r.id for r in rows] == [b.id]
    everything = await tsvc.list_tickets(db, ctx.config, anon, tsvc.Filters(status="all"))
    assert [r.id for r in everything] == [b.id, c.id, a.id]
    assert [r.id for r in await tsvc.list_tickets(db, ctx.config, anon, tsvc.Filters())] == [c.id, a.id]


# ---- proposals --------------------------------------------------------------------------------------


async def test_agent_proposes_human_adopts(ctx, db):
    p = await _team(ctx, db, roles=("reviewer",))
    agent = await _agent(ctx, db, p.user)
    t = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="x", source="web"))
    with pytest.raises(HTTPException):
        await psvc.propose(ctx, db, p, t, "verdict", "valid", "people set facts directly")
    # a status the desk could never apply is refused when proposed, not when a person clicks adopt (XE-1054)
    for bad in (
        {"status": "closed", "closed_reason": "by-design"},
        {"status": "closed"},
        {"status": "triaging", "closed_reason": "invalid"},
        "resolved",
        42,
    ):
        with pytest.raises(HTTPException) as e:
            await psvc.propose(ctx, db, agent, t, "status", bad, "no")
        assert e.value.status_code == 400, bad
    pr1 = await psvc.propose(ctx, db, agent, t, "verdict", "valid", "reproduced")
    pr2 = await psvc.propose(ctx, db, agent, t, "assessed_tier", "high", "targeted DoS")
    pr3 = await psvc.propose(ctx, db, agent, t, "reply_draft", "Thanks, reproduced. See {ticket_url}.", "")
    out = await psvc.decide(ctx, db, p, pr1, True)
    assert out["diff"]["verdict"]["to"] == "valid" and t.verdict == "valid"
    with pytest.raises(HTTPException) as e:
        await psvc.decide(ctx, db, p, pr2, True)  # reviewer lacks the tier role
    assert e.value.status_code == 403 and pr2.state == "pending"
    out = await psvc.decide(ctx, db, p, pr3, True)
    url = tsvc.ticket_url(ctx, t)
    assert out["reply_draft"] == f"Thanks, reproduced. See {url}." and t.status == "new"
    # the draft is kept on the ticket, for the team only, until a reply goes out
    assert t.draft == out["reply_draft"] and tsvc.to_dict(ctx, t, p)["draft"] == t.draft
    assert "draft" not in tsvc.to_dict(ctx, t, authz.ANON)
    assert (await db.execute(select(Reply))).scalars().all() == []
    await thread.add_reply(ctx, db, p, t, "Thanks, reproduced.")
    assert t.draft == ""
    with pytest.raises(HTTPException):
        await psvc.decide(ctx, db, agent, pr2, False)
    # a repeat proposal supersedes the pending one
    pr4 = await psvc.propose(ctx, db, agent, t, "assessed_tier", "medium", "second look")
    await db.refresh(pr2)
    assert pr2.state == "superseded" and pr4.state == "pending"
    note = await thread.add_note(ctx, db, agent, t, "internal")
    assert note.author == f"token:{agent.token.id}"
    pub = await EventLog.page(db, 0, 100, ref=t.id, public_only=True)
    assert not any("Thanks, reproduced" in str(e.payload) for e in pub), "drafts never land in the public log"


async def test_plain_acknowledgements_send_on_adopt_and_the_rest_wait(ctx, db):
    p = await _team(ctx, db, roles=("reviewer",))
    agent = await _agent(ctx, db, p.user)

    def mk(title):
        return tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title=title, source="web"))

    plain = await mk("plain")
    tiered = await mk("names a tier")
    closing = await mk("closes too")
    told = await mk("already written to")
    ack = "Thanks for the report. We have read it against the code and it is being handled; see {ticket_url}."
    d_plain = await psvc.propose(ctx, db, agent, plain, "reply_draft", ack, "acknowledgement")
    v_plain = await psvc.propose(ctx, db, agent, plain, "verdict", "valid", "reproduced")
    d_tier = await psvc.propose(ctx, db, agent, tiered, "reply_draft", "Thanks. We rate this High.", "")
    d_close = await psvc.propose(ctx, db, agent, closing, "reply_draft", "Thanks, we have read it.", "")
    s_close = await psvc.propose(
        ctx, db, agent, closing, "status", {"status": "closed", "closed_reason": "invalid"}, "no"
    )
    d_told = await psvc.propose(ctx, db, agent, told, "reply_draft", "Thanks, we have read it.", "")
    await thread.add_reply(ctx, db, p, told, "Already answered by hand.")

    # the text rule, on its own
    rr = thread.review_reason
    assert rr(ctx, thread.fill(ctx, ack, plain), plain) is None
    assert rr(ctx, "Thanks. We rate this High.", plain) == "names a tier"
    assert rr(ctx, f"Thanks. See {tsvc.ticket_url(ctx, plain)} and {plain.id}.", plain) is None
    assert rr(ctx, "Thanks. Tracked as XE-9999.", plain) == "names another ticket"
    assert rr(ctx, "Thanks. Tracked as XE-12345.", plain) == "names another ticket"  # ids grow past four
    assert rr(ctx, "Thanks. See https://example.com/x.", plain) == "has a link"
    assert rr(ctx, "Thanks. Fixed in 2 days.", plain) == "has a number"
    assert rr(ctx, "Thanks. The award follows the fix.", plain) == "mentions payment"
    # the text is judged as it is sent: a control character splitting a word is gone before the check
    # reads it, as it is gone before the reply is stored, and what is not plain text is held
    assert rr(ctx, "Thanks. The aw\x01ard follows the fix.", plain) == "mentions payment"
    for odd in ("rewa\u200brd", "\u0430ward", "re\u00adward", "\uff11 day"):  # zero-width, Cyrillic, ...
        assert rr(ctx, f"Thanks. The {odd} follows.", plain) == "has a character outside plain text", odd
    assert rr(ctx, "Thanks \u2014 we\u2019ve read it\u2026", plain) is None
    # a link is a link however it is spelled, and so is an address, a handle or a bare domain
    for way in ("Https://example.com", "[here](//example.com)", "![x](//example.com)", "<ftp://example.com>",
                "desk@example.com", "example.com", "www.example.com", "@someone"):
        assert rr(ctx, f"Thanks. More at {way} if needed.", plain) == "has a link", way
    assert rr(ctx, "Thanks, e.g. for the steps.", plain) is None
    # the programme's stock lines pass whatever words they carry; the rest is still checked
    stock = (
        "Thanks for the report. We have read it against the code and it is being handled alongside"
        " related multisig work. This ticket is updated when the fix lands, and the assessment and any"
        " award follow the fix."
    )
    assert ctx.config.plain_phrases and rr(ctx, stock, plain) is None
    assert rr(ctx, stock + " The award will be 500 XE.", plain) == "has a number"
    assert rr(ctx, stock + " We will pay it on Friday.", plain) == "mentions payment"
    design = (
        "Thanks for the report. We read it against the code: the behaviour is as designed today, and"
        " the design question it raises is with the team. This ticket is updated when there is a decision."
    )
    assert rr(ctx, design, plain) is None
    assert rr(ctx, "Thanks. Closing as invalid.", plain) == "explains a closure"
    assert rr(ctx, "Thanks. The gap is in `VerifyMultisig`.", plain) == "names code or a path"
    assert rr(ctx, "Thanks. The gap is in net/sync.", plain) == "names code or a path"
    assert rr(ctx, "x" * 301, plain).startswith("over ")

    # the ticket page's single adopt never sends, whatever the text
    out = await psvc.decide(ctx, db, p, d_plain, True)
    assert "sent" not in out and plain.draft == out["reply_draft"]
    assert (await db.execute(select(Reply).where(Reply.ticket_id == plain.id))).scalars().all() == []
    d_plain2 = await psvc.propose(ctx, db, agent, plain, "reply_draft", ack, "again")

    # the triage page's batch: the plain one goes out; the status is adopted before the draft on the
    # closing ticket, so that draft waits; a tier in the text waits; a reporter written to since waits
    ids = [d_plain2.id, v_plain.id, d_tier.id, d_close.id, s_close.id, d_told.id]
    out = await psvc.decide_many(ctx, db, p, ids, [], send_plain=True)
    assert out["skipped"] == []
    by = {d["proposal"]: d for d in out["decided"]}
    sent = by[d_plain2.id]
    assert sent["sent"] and sent["reply_text"].endswith(tsvc.ticket_url(ctx, plain) + ".")
    assert sent["sent"] in notify.take_owed(db)  # owed its mail where it was written
    assert by[d_tier.id]["review"] == "names a tier" and "sent" not in by[d_tier.id]
    assert by[d_close.id]["review"] == "the ticket is closed" and "sent" not in by[d_close.id]
    assert by[d_told.id]["review"] == "the reporter has been written to since"
    await db.refresh(plain)
    await db.refresh(tiered)
    await db.refresh(closing)
    replies = (await db.execute(select(Reply).where(Reply.ticket_id == plain.id))).scalars().all()
    assert len(replies) == 1 and replies[0].author_id == p.user.id and plain.draft == ""
    assert tiered.draft == "Thanks. We rate this High." and closing.draft == "Thanks, we have read it."
    assert closing.status == "closed"
    # a draft that rides with a pending closure waits even when the closure is not in the same batch
    again = await mk("closure pending elsewhere")
    d_again = await psvc.propose(ctx, db, agent, again, "reply_draft", "Thanks, we have read it.", "")
    await psvc.propose(ctx, db, agent, again, "duplicate_of", plain.id, "same")
    assert psvc.send_review(ctx, await psvc.pending_for(db, again), d_again, again) == "goes with a closure"
    # a draft is cleaned where it comes in, as a reply is where it goes out
    kept = await psvc.propose(ctx, db, agent, again, "reply_draft", "Thanks. Re\x02ad.\x00", "")
    assert kept.value == {"value": "Thanks. Read."}


async def test_a_family_of_duplicates_closes_in_one_ruling(ctx, db):
    p = await _team(ctx, db, roles=("reviewer",))
    agent = await _agent(ctx, db, p.user)
    canon = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="first", source="web"))
    dups = [
        await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title=f"again {i}", source="web"))
        for i in range(3)
    ]
    # the agent proposes the usual four on two of them, only duplicate_of on the third
    for t in dups[:2]:
        await psvc.propose(ctx, db, agent, t, "duplicate_of", canon.id, "same defect, filed later")
        await psvc.propose(ctx, db, agent, t, "verdict", "duplicate", "same defect")
        closing = {"status": "closed", "closed_reason": "duplicate"}
        await psvc.propose(ctx, db, agent, t, "status", closing, "dup")
        await psvc.propose(ctx, db, agent, t, "reply_draft", "Same as {duplicate_url}.", "")
    await psvc.propose(ctx, db, agent, dups[2], "duplicate_of", canon.id, "same defect, filed later")
    # an unrelated proposal and a proposal naming another canonical are not part of the family
    other = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="other", source="web"))
    await psvc.propose(ctx, db, agent, other, "duplicate_of", dups[0].id, "a different family")
    fam = await psvc.pending_duplicates_of(db, canon.id)
    assert [t.id for t, _ in fam] == sorted(t.id for t in dups)

    with pytest.raises(HTTPException):
        await psvc.close_duplicates(ctx, db, agent, canon)  # a person rules, never a token
    out = await psvc.close_duplicates(ctx, db, p, canon)
    assert [d["ticket"] for d in out["closed"]] == sorted(t.id for t in dups) and out["skipped"] == []
    for t in dups:
        await db.refresh(t)
        assert (t.status, t.closed_reason, t.duplicate_of) == ("closed", "duplicate", canon.id)
        assert t.verdict == "duplicate"
        assert t.draft == ""  # the adopted draft was replaced by the sent reply
    ids = [t.id for t in dups]
    replies = (await db.execute(select(Reply).where(Reply.ticket_id.in_(ids)))).scalars().all()
    assert len(replies) == 3 and all(canon.id in r.body and r.author_id == p.user.id for r in replies)
    # every proposal in the family is decided; the one naming another canonical still waits
    states = Counter(pr.state for pr in (await db.execute(select(Proposal))).scalars().all())
    assert states == {"adopted": 9, "pending": 1}
    assert await psvc.pending_duplicates_of(db, canon.id) == []
    # the log shows the ruling as the person's, hop by hop, with the family named
    evs = await EventLog.page(db, 0, 200, ref=dups[2].id)
    assert any(e.kind == "ticket.status" and e.payload.get("via") == f"family:{canon.id}" for e in evs)
    assert all(e.actor == p.actor for e in evs if e.kind.startswith("ticket."))


async def test_a_close_as_duplicate_tells_the_reporter_by_every_path(ctx, db):
    # the rule: adopting a close-as-duplicate sends the programme's duplicate reply, whichever path
    # adopts it; an agent's draft on that ticket is folded into it, neither sent nor left in the editor
    p = await _team(ctx, db, roles=("reviewer",))
    agent = await _agent(ctx, db, p.user)
    canon = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="first", source="web"))
    closing = {"status": "closed", "closed_reason": "duplicate"}

    async def filed(title):
        t = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title=title, source="web"))
        m = await psvc.propose(ctx, db, agent, t, "duplicate_of", canon.id, "same defect, filed later")
        s = await psvc.propose(ctx, db, agent, t, "status", closing, "dup")
        d = await psvc.propose(ctx, db, agent, t, "reply_draft", "Same as {duplicate_url}.", "")
        return t, m, s, d

    async def replies(t):
        return (await db.execute(select(Reply).where(Reply.ticket_id == t.id))).scalars().all()

    # the row on the triage page: the ids come in the page's order, draft first; the desk runs the mark,
    # then the close, then the draft, and the draft is folded, reported as decided, not skipped
    a, am, as_, ad = await filed("a")
    assert psvc.send_review(ctx, await psvc.pending_for(db, a), ad, a) == psvc.FOLDED
    out = await psvc.decide_many(ctx, db, p, [ad.id, as_.id, am.id], [], send_plain=True)
    assert out["skipped"] == []
    by = {d["proposal"]: d for d in out["decided"]}
    assert by[as_.id]["sent"] and canon.id in by[as_.id]["reply_text"] and by[as_.id]["folded"] == [ad.id]
    assert by[ad.id]["folded"] is True and "sent" not in by[ad.id]
    await db.refresh(a)
    await db.refresh(ad)
    assert (a.status, a.closed_reason, a.draft, ad.state) == ("closed", "duplicate", "", "adopted")
    rs = await replies(a)
    assert len(rs) == 1 and canon.id in rs[0].body and "Same as" not in rs[0].body
    assert rs[0].author_id == p.user.id

    # one chip on the ticket page, without send_plain: the close still tells; the mark was adopted first
    b, bm, bs, bd = await filed("b")
    await psvc.decide(ctx, db, p, bm, True)
    out = await psvc.decide(ctx, db, p, bs, True)
    assert out["sent"] and canon.id in out["reply_text"] and out["folded"] == [bd.id]
    assert {by[as_.id]["sent"], out["sent"]} <= set(notify.take_owed(db))  # both closes owe their mail
    await db.refresh(b)
    await db.refresh(bd)
    assert (b.status, b.draft, bd.state) == ("closed", "", "adopted")
    assert len(await replies(b)) == 1

    # a status proposal that closes for another reason sends nothing from here: the draft is kept on
    # the ticket and the desk's own sweep tells the reporter (`tell.tell_resting`, tested below)
    c = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="c", source="web"))
    invalid = {"status": "closed", "closed_reason": "invalid"}
    cs = await psvc.propose(ctx, db, agent, c, "status", invalid, "x")
    cd = await psvc.propose(ctx, db, agent, c, "reply_draft", "Thanks, we have read it.", "")
    out = await psvc.decide_many(ctx, db, p, [cd.id, cs.id], [], send_plain=True)
    by = {d["proposal"]: d for d in out["decided"]}
    assert "sent" not in by[cs.id] and by[cs.id]["closing"] is True
    assert by[cd.id]["review"] == "the ticket is closed" and c.draft == "Thanks, we have read it."
    assert await replies(c) == []

    # the close without its mark is refused as before, and nothing is sent
    e = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="e", source="web"))
    es = await psvc.propose(ctx, db, agent, e, "status", closing, "dup")
    out = await psvc.decide_many(ctx, db, p, [es.id], [])
    assert out["decided"] == [] and "duplicate_of" in out["skipped"][0]["why"]
    assert await replies(e) == []


async def test_a_marked_duplicate_with_the_close_still_pending_is_part_of_the_family(ctx, db):
    # the mark was adopted on its own (or set by hand); the status chip is all that is left on the row.
    # It still belongs to the duplicates view and to the family's one-click ruling.
    p = await _team(ctx, db, roles=("reviewer",))
    agent = await _agent(ctx, db, p.user)
    canon = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="first", source="web"))
    t = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="again", source="web"))
    mark = await psvc.propose(ctx, db, agent, t, "duplicate_of", canon.id, "same defect, filed later")
    closing = {"status": "closed", "closed_reason": "duplicate"}
    s = await psvc.propose(ctx, db, agent, t, "status", closing, "dup")
    await psvc.decide(ctx, db, p, mark, True)
    assert t.duplicate_of == canon.id and s.state == "pending"
    assert psvc.triage_views([s]) == {"duplicates"}
    row = psvc.TriageRow(t, [s])
    assert row.duplicate_of == canon.id
    fam = await psvc.pending_duplicates_of(db, canon.id)
    assert [(o.id, pr) for o, pr in fam] == [(t.id, None)]
    # a subset of the family is named by ids as stored, however the caller spelt them: an empty one
    # is none of the family, one outside it is said so, and `xe-0002` is XE-0002
    none = await psvc.close_duplicates(ctx, db, p, canon, only=[])
    assert none["closed"] == [] and none["skipped"] == []
    stray = await psvc.close_duplicates(ctx, db, p, canon, only=["xe-9999"])
    assert stray["closed"] == [] and [x["ticket"] for x in stray["skipped"]] == ["XE-9999"]
    out = await psvc.close_duplicates(ctx, db, p, canon, only=[f" {t.id.lower()} "])
    assert [d["ticket"] for d in out["closed"]] == [t.id] and out["skipped"] == []
    await db.refresh(t)
    await db.refresh(s)
    assert (t.status, t.closed_reason, t.verdict, s.state) == ("closed", "duplicate", "duplicate", "adopted")
    replies = (await db.execute(select(Reply).where(Reply.ticket_id == t.id))).scalars().all()
    assert len(replies) == 1 and canon.id in replies[0].body
    assert await psvc.pending_duplicates_of(db, canon.id) == []


async def test_a_family_with_a_paid_member_closes_the_rest(ctx, db):
    # XE-0862: a member the state machine will not close (paid is terminal) used to raise MissingGreenlet
    # on the way into `skipped`, because the row was expired by the savepoint rollback before its id was read
    p = await _team(ctx, db, roles=("reviewer",))
    agent = await _agent(ctx, db, p.user)
    canon = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="first", source="web"))
    a = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="a", source="web"))
    b = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="b", source="web"))
    for st in ("triaging", "accepted", "patched", "awarded", "paid"):
        await tsvc.set_status(ctx, db, p, b, st, force=True)
    for t in (a, b):
        await psvc.propose(ctx, db, agent, t, "duplicate_of", canon.id, "same defect, filed later")
    a_id, b_id = a.id, b.id  # the rollback expires b; its attributes need a refresh before they are read
    out = await psvc.close_duplicates(ctx, db, p, canon)
    assert [d["ticket"] for d in out["closed"]] == [a_id]
    assert [s["ticket"] for s in out["skipped"]] == [b_id] and "paid" in out["skipped"][0]["why"]
    await db.refresh(a)
    await db.refresh(b)
    assert (a.status, a.duplicate_of) == ("closed", canon.id)
    assert (b.status, b.duplicate_of) == ("paid", None), "the refused member is left exactly as it was"


async def test_bulk_decisions_skip_the_refused_and_keep_the_rest(ctx, db):
    # XE-0872: one refusal in a batch stopped the batch; now each decision is its own savepoint
    p = await _team(ctx, db, roles=("reviewer",))
    agent = await _agent(ctx, db, p.user)
    a = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="a", source="web"))
    b = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="b", source="web"))
    c = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="c", source="web"))
    for st in ("triaging", "accepted", "patched", "awarded", "paid"):
        await tsvc.set_status(ctx, db, p, b, st, force=True)
    ok1 = await psvc.propose(ctx, db, agent, a, "verdict", "valid", "reproduced")
    bad_path = await psvc.propose(ctx, db, agent, b, "status", "fixing", "no path from paid")
    bad_role = await psvc.propose(ctx, db, agent, c, "assessed_tier", "high", "reviewer lacks tier")
    ok2 = await psvc.propose(ctx, db, agent, c, "verdict", "valid", "reproduced too")
    gone = await psvc.propose(ctx, db, agent, a, "effort_eng", "<1h", "to be rejected")
    with pytest.raises(HTTPException):
        await psvc.decide_many(ctx, db, agent, [ok1.id], [])  # a person rules, never a token
    bp, br, b_id, c_id = bad_path.id, bad_role.id, b.id, c.id  # read before the savepoints roll back
    out = await psvc.decide_many(ctx, db, p, [ok1.id, bp, br, ok2.id, 999_999], [gone.id])
    assert len(out["decided"]) == 3
    why = {s["proposal"]: s["why"] for s in out["skipped"]}
    assert set(why) == {bp, br, 999_999}
    assert "paid to fixing" in why[bp] and why[999_999] == "no such proposal"
    assert {s.get("ticket") for s in out["skipped"]} == {b_id, c_id, None}
    for pr in (ok1, bad_path, bad_role, ok2, gone):
        await db.refresh(pr)
    assert (ok1.state, ok2.state, gone.state) == ("adopted", "adopted", "rejected")
    assert (bad_path.state, bad_role.state) == ("pending", "pending")
    await db.refresh(a)
    await db.refresh(b)
    await db.refresh(c)
    assert (a.verdict, c.verdict, b.status, c.assessed_tier) == ("valid", "valid", "paid", None)
    # a second pass on the same ids finds them decided already
    again = await psvc.decide_many(ctx, db, p, [ok1.id], [gone.id])
    assert again["decided"] == [] and [s["why"] for s in again["skipped"]] == ["not pending", "not pending"]


async def test_triage_rows_sort_tickets_into_views(ctx, db):
    p = await _team(ctx, db, roles=("reviewer", "tier"))
    agent = await _agent(ctx, db, p.user)

    def mk(title, **kw):
        return tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title=title, source="web", **kw))

    canon = await mk("canonical")
    dup = await mk("same again")
    closing = await mk("not a bug")
    finding = await mk("a real one")
    paid_reply = await mk("worth paying")
    await mk("nothing pending")  # stays off the page
    hidden = await mk("private pending", visibility="private")
    await tsvc.set_facts(ctx, db, p, finding, {"area": "sdk-docs-web"}, reason="t")
    await psvc.propose(ctx, db, agent, dup, "duplicate_of", canon.id, "same defect")
    closed = {"status": "closed", "closed_reason": "duplicate"}
    await psvc.propose(ctx, db, agent, dup, "status", closed, "dup")
    await psvc.propose(ctx, db, agent, dup, "verdict", "duplicate", "same defect")
    closed = {"status": "closed", "closed_reason": "invalid"}
    await psvc.propose(ctx, db, agent, closing, "status", closed, "no")
    await psvc.propose(ctx, db, agent, closing, "verdict", "invalid", "by design")
    await psvc.propose(ctx, db, agent, finding, "verdict", "valid", "reproduced")
    await psvc.propose(ctx, db, agent, finding, "assessed_tier", "high", "targeted DoS")
    await psvc.propose(ctx, db, agent, finding, "reply_draft", "Thanks, reproduced.", "")
    await tsvc.set_facts(ctx, db, p, paid_reply, {"assessed_tier": "minor"}, reason="t")
    await psvc.propose(ctx, db, agent, paid_reply, "award_xe", 100, "Bottom of the band, reason long enough.")
    await psvc.propose(ctx, db, agent, hidden, "verdict", "valid", "reproduced")
    await thread.add_note(ctx, db, agent, finding, "**Claim.** Crashes the node with one packet.\n\nMore.")
    await thread.add_note(ctx, db, agent, finding, "**Claim.** Second look: still crashes.")

    rows = await psvc.triage_rows(db, ctx.config, p)
    by = {r.ticket.id: r for r in rows}
    assert set(by) == {dup.id, closing.id, finding.id, paid_reply.id, hidden.id}
    assert by[dup.id].views == {"duplicates"} and by[dup.id].canonical.id == canon.id
    assert by[closing.id].views == {"closures"}
    assert by[finding.id].views == {"assessments", "replies"} and by[finding.id].tier == "high"
    assert by[paid_reply.id].views == {"awards"} and by[paid_reply.id].tier == "minor"
    # most severe first, by the proposed tier; the agent's latest note rides along, first line only
    assert rows[0].ticket.id == finding.id
    assert psvc.note_excerpt(by[finding.id].note) == "Second look: still crashes."
    assert by[dup.id].note is None
    # the views and the other filters narrow; the counts do not
    assert [r.ticket.id for r in await psvc.triage_rows(db, ctx.config, p, view="duplicates")] == [dup.id]
    assert [r.ticket.id for r in await psvc.triage_rows(db, ctx.config, p, view="replies")] == [finding.id]
    by_area = await psvc.triage_rows(db, ctx.config, p, area="sdk-docs-web")
    assert [r.ticket.id for r in by_area] == [finding.id]
    assert [r.ticket.id for r in await psvc.triage_rows(db, ctx.config, p, tier="minor")] == [paid_reply.id]
    counts = await psvc.triage_counts(db, p)
    assert counts["all"] == 5 and counts["proposals"] == 10
    assert (counts["duplicates"], counts["closures"], counts["assessments"]) == (1, 1, 2)
    assert (counts["awards"], counts["replies"]) == (1, 1)
    # a viewer without read:private sees neither the private row nor its count
    public_eyes = await _agent(ctx, db, p.user, scopes=("read:public",))
    assert hidden.id not in {r.ticket.id for r in await psvc.triage_rows(db, ctx.config, public_eyes)}
    assert (await psvc.triage_counts(db, public_eyes))["all"] == 4
    # the class: every report on the same engineering ticket rides on the row, the private one included
    for t in (finding, hidden, canon):
        await tsvc.set_facts(ctx, db, p, t, {"internal_ref": "#1090"}, reason="one class")
    klass = await tsvc.same_class(db, p, {"#1090", ""})
    assert [o.id for o in klass["#1090"]] == sorted([finding.id, hidden.id, canon.id]) and "" not in klass
    public_view = await tsvc.same_class(db, public_eyes, {"#1090"})
    assert [o.id for o in public_view["#1090"]] == sorted([finding.id, canon.id])
    rows = {r.ticket.id: r for r in await psvc.triage_rows(db, ctx.config, p)}
    assert {o.id for o in rows[finding.id].klass} == {hidden.id, canon.id}  # not its own sibling
    assert rows[dup.id].klass == []


def test_status_path_walks_forward_edges_only():
    assert tsvc.status_path("bounty", "new", "accepted") == ["triaging", "accepted"]
    assert tsvc.status_path("bounty", "new", "patched") == ["triaging", "accepted", "patched"]
    assert tsvc.status_path("bounty", "new", "closed") == ["closed"]
    assert tsvc.status_path("bounty", "new", "new") == []
    assert tsvc.status_path("bounty", "paid", "fixing") is None
    # awarded is a terminal: no walking through it to paid
    assert tsvc.status_path("bounty", "patched", "paid") is None
    # closed is a terminal too: new → closed → triaging is not a path, but new → triaging is
    assert tsvc.status_path("bounty", "closed", "accepted") == ["triaging", "accepted"]
    assert tsvc.status_path("support", "new", "needs-info") == ["triaging", "needs-info"]
    assert tsvc.status_path("support", "new", "accepted") is None


async def test_adopting_a_far_status_walks_the_path(ctx, db):
    p = await _team(ctx, db, roles=("reviewer",))
    agent = await _agent(ctx, db, p.user)
    # new → accepted, via triaging: two status events, one via
    t = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="a", source="web"))
    pr = await psvc.propose(ctx, db, agent, t, "status", "accepted", "reproduced and in scope")
    out = await psvc.decide(ctx, db, p, pr, True)
    assert out["status"] == "accepted" and out["path"] == ["triaging", "accepted"]
    assert t.status == "accepted"
    evs = await EventLog.page(db, 0, 100, ref=t.id, descending=False)
    moves = [(e.payload["from"], e.payload["to"]) for e in evs if e.kind == "ticket.status"]
    assert moves == [("new", "triaging"), ("triaging", "accepted")]
    assert {e.payload["via"] for e in evs if e.kind == "ticket.status"} == {f"proposal:{pr.id}"}
    # new → patched: three hops
    t2 = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="b", source="web"))
    pr2 = await psvc.propose(ctx, db, agent, t2, "status", "patched", "fix landed")
    out = await psvc.decide(ctx, db, p, pr2, True)
    assert out["path"] == ["triaging", "accepted", "patched"] and t2.status == "patched"
    # paid → fixing: no path, 409, nothing moves, proposal stays pending
    t3 = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="c", source="web"))
    for st in ("triaging", "accepted", "patched", "awarded", "paid"):
        await tsvc.set_status(ctx, db, p, t3, st, force=True)
    pr3 = await psvc.propose(ctx, db, agent, t3, "status", "fixing", "regressed")
    with pytest.raises(HTTPException) as e:
        await psvc.decide(ctx, db, p, pr3, True)
    assert e.value.status_code == 409 and "paid to fixing" in e.value.detail
    assert t3.status == "paid" and pr3.state == "pending"
    # closed as duplicate from new: one hop, with the reason
    t4 = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title="d", source="web"))
    await tsvc.set_facts(ctx, db, p, t4, {"duplicate_of": t.id})
    pr4 = await psvc.propose(
        ctx, db, agent, t4, "status", {"status": "closed", "closed_reason": "duplicate"}, "same as a"
    )
    out = await psvc.decide(ctx, db, p, pr4, True)
    assert out["path"] == ["closed"] and t4.status == "closed" and t4.closed_reason == "duplicate"
    # the current status is a no-op, as before
    pr5 = await psvc.propose(ctx, db, agent, t2, "status", "patched", "already there")
    moves = sum(e.kind == "ticket.status" for e in await EventLog.page(db, 0, 100, ref=t2.id))
    out = await psvc.decide(ctx, db, p, pr5, True)
    assert out["path"] == [] and t2.status == "patched"
    assert sum(e.kind == "ticket.status" for e in await EventLog.page(db, 0, 100, ref=t2.id)) == moves


async def test_agent_proposes_an_award_and_a_treasurer_sets_it(ctx, db):
    reviewer = await _team(ctx, db, roles=("reviewer", "tier"))
    agent = await _agent(ctx, db, reviewer.user)
    t = await tsvc.create(ctx, db, reviewer.actor, tsvc.NewTicket(kind="bounty", title="x", source="web"))
    await tsvc.set_facts(ctx, db, reviewer, t, {"assessed_tier": "medium"}, reason="t")
    for bad, why in ((2500.5, "float"), ("2500", "string"), (-1, "negative"), (True, "bool"), (5001, "over 2x ceiling")):
        with pytest.raises(HTTPException) as e:
            await psvc.propose(ctx, db, agent, t, "award_xe", bad, "a reason long enough to pass the check")
        assert e.value.status_code == 400, why
    with pytest.raises(HTTPException):
        await psvc.propose(ctx, db, agent, t, "award_xe", 2000, "short")
    pr = await psvc.propose(ctx, db, agent, t, "award_xe", 2000, "Top of the band: precise, right fix suggested.")
    with pytest.raises(HTTPException) as e:
        await psvc.decide(ctx, db, reviewer, pr, True)  # setting an award needs the treasurer role
    assert e.value.status_code == 403 and pr.state == "pending" and t.award_xe is None
    treasurer = await _team(ctx, db, roles=("reviewer", "treasurer"))
    out = await psvc.decide(ctx, db, treasurer, pr, True)
    assert out["award_xe"] == 2_000_000_000 and t.award_xe == 2_000_000_000
    assert t.award_approved_at is None, "adopting sets the amount; approval is a separate act"
    due = await tsvc.awards_due(db, ctx.config, treasurer)
    assert t.id not in [d.id for d in due], "a new ticket is not yet due; it has to be accepted first"
    await tsvc.set_status(ctx, db, treasurer, t, "triaging")
    await tsvc.set_status(ctx, db, treasurer, t, "accepted")
    assert t.id in [d.id for d in await tsvc.awards_due(db, ctx.config, treasurer)]
    # approval waits for the fix: not from accepted
    with pytest.raises(HTTPException) as e:
        await tsvc.set_award(ctx, db, treasurer, t, None, approve=True)
    assert e.value.status_code == 409 and "patched" in e.value.detail and t.award_approved_at is None
    assert tsvc.award_approvable(t) is not None
    await tsvc.set_status(ctx, db, treasurer, t, "patched")
    assert tsvc.award_approvable(t) is None
    await tsvc.set_award(ctx, db, treasurer, t, None, approve=True)
    assert t.award_approved_at is not None
    assert t.id not in [d.id for d in await tsvc.awards_due(db, ctx.config, treasurer)]
    # an approved amount cannot be changed, but approval can be taken back and the amount stays
    with pytest.raises(HTTPException) as e:
        t.assessed_tier = t.assessed_tier or "medium"  # an award needs a tier (XE-0470)
        await tsvc.set_award(ctx, db, treasurer, t, 1_000_000_000)
    assert e.value.status_code == 409
    await tsvc.set_award(ctx, db, treasurer, t, None, approve=False)
    assert t.award_approved_at is None and t.award_approved_by is None and t.award_xe == 2_000_000_000
    assert t.id in [d.id for d in await tsvc.awards_due(db, ctx.config, treasurer)]
    await tsvc.set_award(ctx, db, treasurer, t, None, approve=None)  # None leaves approval alone
    assert t.award_approved_at is None
    await tsvc.set_award(ctx, db, treasurer, t, None, approve=True)
    await tsvc.set_status(ctx, db, treasurer, t, "awarded")
    with pytest.raises(HTTPException) as e:
        await tsvc.set_award(ctx, db, treasurer, t, None, approve=False)  # awarded: the award stands
    assert e.value.status_code == 409 and t.award_approved_at is not None
    grouped = await psvc.pending_field_for(db, [t.id], "award_xe")
    assert grouped == {}  # adopted, so no longer pending


async def test_a_member_is_renamed_and_future_replies_carry_it(ctx, db):
    team = await _team(ctx, db)
    spec = tsvc.NewTicket(kind="bounty", title="Renaming test", body="b" * 50)
    t = await tsvc.create(ctx, db, "desk", spec)
    r1 = await thread.add_reply(ctx, db, team, t, "First reply, under the old name.")
    await users.set_name(ctx, db, "cli", team.user, "  Joseph   Denne ")
    assert team.user.name == "Joseph Denne"
    r2 = await thread.add_reply(ctx, db, team, t, "Second reply, under the new name.")
    assert r1.author_name == "Lead" and r2.author_name == "Joseph Denne"
    with pytest.raises(HTTPException):
        await users.set_name(ctx, db, "cli", team.user, "   ")
    # email: must look like one and be free
    await users.set_email(ctx, db, "cli", team.user, " Joseph@XE.network ")
    assert team.user.email == "joseph@xe.network"
    other = await users.create_user(ctx, db, "test", "other@xe.network", "Other", ["reviewer"])
    with pytest.raises(HTTPException):
        await users.set_email(ctx, db, "cli", other, "joseph@xe.network")
    with pytest.raises(HTTPException):
        await users.set_email(ctx, db, "cli", other, "not-an-address")


# ---- github sync ------------------------------------------------------------------------------------


def _issue(number, title, body="", state="open", login="ada", **kw):
    return {
        "number": number, "title": title, "body": body, "state": state, "labels": [], "comments": 0,
        "html_url": f"https://github.com/xeprotocol/xe/issues/{number}", "created_at": "2026-10-20T10:00:00Z",
        "updated_at": "2026-10-20T10:00:00Z", "user": {"login": login, "id": 7}, **kw,
    }


async def test_internal_tracker_moves_a_new_ticket_through_triaging(ctx, db):
    t, created = await sync.upsert_issue(ctx, db, "xeprotocol/xe", _issue(63, "Explorer search bar"))
    assert created and t.status == "new"
    # the tracker names it while open: new -> triaging -> accepted, not a forbidden jump
    stats = await sync.link_internal_issue(ctx, db, _issue(1068, "security: bounty bundle xe#63"))
    assert stats["linked"] == 1 and stats["moved"] == 1
    assert t.status == "accepted" and t.internal_ref == "#1068"
    # closed as completed: patched, and into the outbox
    stats = await sync.link_internal_issue(
        ctx, db, _issue(1068, "security: bounty bundle xe#63", state="closed", state_reason="completed")
    )
    assert stats["moved"] == 1 and t.status == "patched"
    # a ticket past the tracker's reach is left where it is
    t2, _ = await sync.upsert_issue(ctx, db, "xeprotocol/xe", _issue(64, "Another report"))
    team = await _team(ctx, db)
    for st in ("triaging", "accepted", "patched", "awarded", "paid"):
        await tsvc.set_status(ctx, db, team, t2, st, force=True)
    done = _issue(1069, "bundle xe#64", state="closed", state_reason="completed")
    stats = await sync.link_internal_issue(ctx, db, done)
    assert stats["moved"] == 0 and t2.status == "paid"
    # importing the same issue again finds the ticket; nothing is created twice
    await db.commit()
    other = await sync.upsert_issue(ctx, db, "xeprotocol/xe", _issue(63, "Explorer search bar"))
    assert other[0].id == t.id and other[1] is False


async def test_internal_tracker_names_desk_filed_reports_by_id(ctx, db):
    team = await _team(ctx, db)
    new = lambda title: tsvc.NewTicket(kind="bounty", title=title, source="web")  # noqa: E731
    web = await tsvc.create(ctx, db, team.actor, new("filed here"))
    dup = await tsvc.create(ctx, db, team.actor, new("again"))
    gh_t, _ = await sync.upsert_issue(ctx, db, "xeprotocol/xe", _issue(65, "filed on github"))
    # one internal ticket covers a GitHub report by number and two desk reports by id, one in lower case
    body = f"Covers xe#65, {web.id} and {dup.id.lower()}. Root cause in net/check."
    stats = await sync.link_internal_issue(ctx, db, _issue(1070, "security: netcheck bundle", body=body))
    assert stats["tagged"] == 3 and stats["linked"] == 3 and stats["moved"] == 3
    for t in (web, dup, gh_t):
        assert t.status == "accepted" and t.internal_ref == "#1070"
    # naming the same ticket both ways is one ticket, not two
    stats = await sync.link_internal_issue(ctx, db, _issue(1071, f"bundle xe#65 {gh_t.id}"))
    assert stats["tagged"] == 1 and stats["noted"] == 1  # already #1070; said once, not overwritten
    assert gh_t.internal_ref == "#1070"
    # the fix ships: closing the internal ticket patches every report linked to it, including one whose
    # mention was edited out of the body since; the link made earlier is what counts
    edited = f"Covers xe#65 and {dup.id}. Root cause in net/check."
    done = _issue(1070, "security: netcheck bundle", body=edited, state="closed", state_reason="completed")
    stats = await sync.link_internal_issue(ctx, db, done)
    assert stats["tagged"] == 3 and stats["moved"] == 3
    assert {t.status for t in (web, dup, gh_t)} == {"patched"}


def _pull(number, title, body="", state="open", merged=False, login="grace", association="MEMBER"):
    return {
        "number": number, "title": title, "body": body, "state": state,
        "merged_at": "2026-10-21T10:00:00Z" if merged else None,
        "html_url": f"https://github.com/xeprotocol/xe/pull/{number}",
        "user": {"login": login, "id": 9}, "author_association": association,
    }


async def test_a_patch_link_has_one_spelling(ctx, db):
    """The rule: a patch link's repository and ref are the key the PR follower matches, so they are
    stored in one spelling whoever makes the link (`thread.patch_key`, in `add_patch_ref`). A link
    made by hand under another spelling is the row the follower then finds, not a second one."""
    team = await _team(ctx, db)
    repo = "xeprotocol/xe"
    t, _ = await sync.upsert_issue(ctx, db, repo, _issue(410, "Frontier pages twice"))
    by_hand = await thread.add_patch_ref(
        ctx, db, team, t, repo="XEProtocol/XE", ref=" #0412 ", note="by hand"
    )
    assert (by_hand.repo, by_hand.ref, by_hand.url) == (repo, "412", f"https://github.com/{repo}/pull/412")
    sha = await thread.add_patch_ref(ctx, db, team, t, repo=repo, ref="DEADBEEFCAFE0123", kind="commit")
    assert sha.ref == "deadbeefcafe0123"
    assert await thread.add_patch_ref(ctx, db, team, t, repo=repo, ref="412", note="by hand") is None
    bad = (
        ("pr", "0"), ("pr", "12a"), ("pr", "\u0661\u0662"), ("pr", "9" * 11), ("pr", "deadbeef"),
        ("commit", "main"), ("commit", "abc"), ("branch", "412"),
    )
    for kind, ref in bad:
        with pytest.raises(HTTPException) as e:
            await thread.add_patch_ref(ctx, db, team, t, repo=repo, ref=ref, kind=kind)
        assert e.value.status_code == 400, (kind, ref)
    merged = _pull(412, "fix: page frontiers once", "Fixes #410", state="closed", merged=True)
    assert await sync.link_pull(ctx, db, repo, merged) == 1
    links = {p.ref: p for p in await thread.patches_for(db, t)}
    assert set(links) == {"412", "deadbeefcafe0123"} and len(await thread.patches_for(db, t)) == 2
    assert (links["412"].state, links["412"].note, links["412"].title) == (
        "merged", "by hand", "fix: page frontiers once"
    )
    assert t.status == "patched"


async def test_what_is_written_beside_a_patch_link_is_working_text(ctx, db):
    """The rule: what a person or an agent writes beside a patch link is the team's working text, as
    a note is, and a reader who does not see the ticket's notes is not shown it, wherever a link is
    served: the ticket, its patch-refs route and its page (`thread.patch_view`, the one place a row
    becomes a response) and the log's `patch.linked` payload. Two such notes named a sealed report
    and its subject on a public ticket (XE-3840)."""
    from desk import ui
    from desk.api import public as pub
    from desk.log import HELD_PAYLOAD_KEYS, event_to_dict
    from desk.models import Reporter

    team = await _team(ctx, db)
    reads_notes = await _agent(ctx, db, team.user, scopes=("read:public",))
    linker = await _agent(ctx, db, team.user, scopes=("write:patch-refs",))
    filed = Reporter(github_login="ada")
    db.add(filed)
    await db.flush()
    owner = authz.Principal(kind="reporter", reporter_id=filed.id)
    spec = tsvc.NewTicket(kind="bounty", title="Counted twice", source="web", reporter_id=filed.id)
    t = await tsvc.create(ctx, db, team.actor, spec)
    repo, said = "xeprotocol/dao", "Duplicate of XE-9999: the sealed report's subject"
    pr = await thread.add_patch_ref(ctx, db, linker, t, repo=repo, ref="47aadfc0", kind="commit", note=said)

    def shown(p, row=None):
        return thread.patch_view(row or pr, p, t)

    for outsider in (authz.ANON, owner, linker):
        assert shown(outsider)["note"] == "", outsider.kind
    for insider in (team, reads_notes):
        assert shown(insider)["note"] == said, insider.kind
    words = ("note", "title")
    link = {k: v for k, v in shown(team).items() if k not in words}
    assert {k: v for k, v in shown(authz.ANON).items() if k not in words} == link, "the link is public"
    assert link["repo"] == repo and link["ref"] == "47aadfc0" and link["url"].startswith("https://")
    # the log: the link was made, in public; what was said with it is not in the payload served
    ev = (await EventLog.page(db, 0, 10, kind="patch.linked", ref=t.id))[0]
    assert ev.public and ev.payload["note"] == said and event_to_dict(ev)["payload"]["note"] == said
    assert event_to_dict(ev, full=False)["payload"] == {
        "ticket": t.id, "repo": repo, "kind": "commit", "ref": "47aadfc0",
    }
    assert HELD_PAYLOAD_KEYS["patch.linked"] == {"note"}
    # a title is the repository's: the desk reads it from GitHub, so anyone may be shown it, and a
    # caller's is refused (the note is where a caller says something)
    # and so are the author, the address and the state: an address is free text after its `https://`
    theirs = ({"title": said}, {"author": said}, {"url": f"https://github.com/x/y/pull/1#{said}"},
              {"state": "merged"})
    for caller in (linker, reads_notes, team):
        for field in theirs:
            for ref in ("78", "47aadfc0"):  # a new link, and one the ticket has
                kind = "commit" if ref == "47aadfc0" else "pr"
                with pytest.raises(HTTPException) as e:
                    await thread.add_patch_ref(ctx, db, caller, t, repo=repo, ref=ref, kind=kind, **field)
                assert e.value.status_code == 400, (caller.kind, field)
    assert (pr.title, pr.author, pr.state, pr.url) == ("", "", "", thread.patch_url(repo, "commit", pr.ref))
    by_hand = await thread.add_patch_ref(ctx, db, linker, t, repo=repo, ref="78", note="the fix")
    assert await thread.add_patch_ref(
        ctx, db, authz.SYSTEM, t, repo=repo, ref="78", title="fix: count once", author="grace"
    )
    public = shown(authz.ANON, by_hand)
    assert (public["title"], public["author"], public["note"]) == ("fix: count once", "grace", "")
    # and a title or an address a caller gave before the writer refused one is held with the note:
    # the reader is shown where the repository and the ref say the patch is
    pr.title, pr.url = said, f"https://example.com/{said}"
    await db.flush()
    for outsider in (authz.ANON, owner, linker):
        assert shown(outsider)["title"] == "", outsider.kind
        assert shown(outsider)["url"] == "https://github.com/xeprotocol/dao/commit/47aadfc0", outsider.kind
        assert said not in json.dumps(shown(outsider)), outsider.kind
    assert shown(team)["title"] == said and shown(team)["url"] == pr.url
    # the sites: each serves the view, and nothing else under desk/ reads a link's note but the triage
    # export, which is refused to a reader who does not see the assessment
    for site in (pub.get_ticket, pub.get_patches, ui.ticket_page):
        src = inspect.getsource(site)
        assert src.count("patches_for(") == 1 == src.count("thread.patch_view(pr, p, t)"), site.__name__
    reads = {
        str(path.relative_to(ROOT / "desk"))
        for path in (ROOT / "desk").rglob("*")
        if path.suffix in (".py", ".html", ".js") and "pr.note" in path.read_text(encoding="utf-8")
    }
    assert reads == {"services/thread.py", "services/triage.py", "templates/ticket.html"}
    for outsider in (authz.ANON, owner, linker):
        with pytest.raises(HTTPException) as e:
            await triage.export_markdown(ctx, db, outsider)
        assert e.value.status_code == 403, outsider.kind


async def test_a_fixing_pull_moves_the_ticket_and_a_mention_only_links(ctx, db):
    repo = "xeprotocol/xe"
    t, _ = await sync.upsert_issue(ctx, db, repo, _issue(70, "Vote replay"))
    # "fixes #70" while open: new -> triaging -> accepted -> fixing, every hop logged
    assert await sync.link_pull(ctx, db, repo, _pull(80, "Reject replayed votes", "Fixes #70")) == 1
    assert t.status == "fixing"
    evs = await EventLog.page(db, 0, 100, ref=t.id, descending=False)
    moves = [(e.payload["from"], e.payload["to"]) for e in evs if e.kind == "ticket.status"]
    assert moves == [("new", "triaging"), ("triaging", "accepted"), ("accepted", "fixing")]
    assert {e.payload["via"] for e in evs if e.kind == "ticket.status"} == {f"github:{repo}#80"}
    # the same PR seen again (webhook "synchronize"): nothing new, nothing moved
    assert await sync.link_pull(ctx, db, repo, _pull(80, "Reject replayed votes", "Fixes #70")) == 0
    assert t.status == "fixing"
    # merged: patched, and so into the outbox
    await sync.link_pull(ctx, db, repo, _pull(80, "Reject replayed votes", "Fixes #70", state="closed", merged=True))
    assert t.status == "patched"
    assert t.id in [x.id for x in await tsvc.outbox(db, ctx.config, await _team(ctx, db))]
    # a bare mention links but does not move
    t2, _ = await sync.upsert_issue(ctx, db, repo, _issue(71, "Related nit"))
    assert await sync.link_pull(ctx, db, repo, _pull(81, "Tidy the voter", "see #71")) == 1
    assert t2.status == "new" and len(await thread.patches_for(db, t2)) == 1
    # a fixing PR closed unmerged drops the ticket back to accepted; a second live PR keeps it at fixing
    t3, _ = await sync.upsert_issue(ctx, db, repo, _issue(72, "Fork on equal height"))
    await sync.link_pull(ctx, db, repo, _pull(82, "First attempt", "Closes #72"))
    await sync.link_pull(ctx, db, repo, _pull(83, "Second attempt", "Closes #72"))
    assert t3.status == "fixing"
    await sync.link_pull(ctx, db, repo, _pull(82, "First attempt", "Closes #72", state="closed"))
    assert t3.status == "fixing"  # 83 is still open
    await sync.link_pull(ctx, db, repo, _pull(83, "Second attempt", "Closes #72", state="closed"))
    # back to where it was before any PR moved it (it was new: triaging), not a guessed accepted (XE-0634)
    assert t3.status == "triaging"
    # a stranger's open "fixes" PR holds nothing: the maintainer PR's unmerged close still returns the ticket
    t5, _ = await sync.upsert_issue(ctx, db, repo, _issue(73, "Stale peer list"))
    await sync.link_pull(ctx, db, repo, _pull(85, "Prune peers", "Fixes #73"))
    assert t5.status == "fixing"
    await sync.link_pull(ctx, db, repo, _pull(86, "junk", "fixes #73", login="rando", association="NONE"))
    assert t5.status == "fixing"
    await sync.link_pull(ctx, db, repo, _pull(85, "Prune peers", "Fixes #73", state="closed"))
    assert t5.status == "triaging"
    # a ticket already at fixing before two maintainer PRs open stays at fixing until both close
    team = await _team(ctx, db, roles=("reviewer", "treasurer"))
    t6, _ = await sync.upsert_issue(ctx, db, repo, _issue(74, "Manual fixing with two maintainer PRs"))
    for st in ("triaging", "accepted", "fixing"):
        await tsvc.set_status(ctx, db, team, t6, st)
    await sync.link_pull(ctx, db, repo, _pull(87, "First fix", "Fixes #74"))
    await sync.link_pull(ctx, db, repo, _pull(88, "Second fix", "Fixes #74"))
    await sync.link_pull(ctx, db, repo, _pull(87, "First fix", "Fixes #74", state="closed"))
    assert t6.status == "fixing"  # 88 is a maintainer's open fixing PR even though moved_from is ""
    await sync.link_pull(ctx, db, repo, _pull(88, "Second fix", "Fixes #74", state="closed"))
    assert t6.status == "accepted"
    # past patched, GitHub never moves a ticket
    t.assessed_tier = t.assessed_tier or "medium"  # an award needs a tier (XE-0470)
    await tsvc.set_award(ctx, db, team, t, 1_000_000, approve=True)
    await tsvc.set_status(ctx, db, team, t, "awarded")
    await sync.link_pull(ctx, db, repo, _pull(84, "Follow-up", "Fixes #70", state="closed", merged=True))
    assert t.status == "awarded"


async def test_a_strangers_fork_pull_links_but_moves_nothing_until_merged(ctx, db):
    repo = "xeprotocol/xe"
    t, _ = await sync.upsert_issue(ctx, db, repo, _issue(90, "Panic on short key"))
    # anyone can open a fork PR saying "fixes #90": it is linked, with its author on show, and that is all
    fork = _pull(100, "fix: short key", "Fixes #90", login="mallory", association="NONE")
    assert await sync.link_pull(ctx, db, repo, fork) == 1
    assert t.status == "new"
    refs = await thread.patches_for(db, t)
    assert [(r.ref, r.author, r.state) for r in refs] == [("100", "mallory", "open")]
    # closing it unmerged changes nothing either; it never moved the ticket
    closed = _pull(100, "fix: short key", "Fixes #90", state="closed", login="mallory", association="NONE")
    await sync.link_pull(ctx, db, repo, closed)
    assert t.status == "new"
    # a maintainer's PR does move it, and remembers where from
    assert await sync.link_pull(ctx, db, repo, _pull(101, "fix(core): guard pk[:12]", "Fixes #90")) == 1
    assert t.status == "fixing"
    assert (await thread.patch_ref(db, t, repo, "101")).moved_from == "new"
    # the stranger's PR closed again while the maintainer's is open: still fixing
    await sync.link_pull(ctx, db, repo, closed)
    assert t.status == "fixing"
    # the maintainer abandons theirs: back to triaging (nothing returns to new), not parked at accepted
    await sync.link_pull(ctx, db, repo, _pull(101, "fix(core): guard pk[:12]", "Fixes #90", state="closed"))
    assert t.status == "triaging"
    # a merge is a maintainer's act whoever wrote the PR, so the stranger's PR merged does mean patched
    merged = _pull(100, "fix: short key", "Fixes #90", state="closed", merged=True, login="mallory",
                   association="NONE")
    await sync.link_pull(ctx, db, repo, merged)
    assert t.status == "patched"
    # the bot's own PRs count as the team's without an association
    ctx.settings.github_bot_login = "xe-desk-bot"
    t2, _ = await sync.upsert_issue(ctx, db, repo, _issue(91, "Another"))
    bot = _pull(102, "fix", "Fixes #91", login="xe-desk-bot", association="NONE")
    await sync.link_pull(ctx, db, repo, bot)
    assert t2.status == "fixing"


class _Hub:
    """GitHub as the poll reads it: each repository's issues and pulls, a repository whose listing
    fails (`broken`), and an issue whose comments cannot be read (`unread`)."""

    enabled = True

    def __init__(self, issues, pulls, broken=(), unread=()):
        self._issues, self._pulls = issues, pulls
        self.broken, self.unread = set(broken), set(unread)

    async def issues(self, repo, since=None):
        if repo in self.broken:
            raise GitHubError(502, "bad gateway")
        for issue in self._issues.get(repo, []):
            yield issue

    async def comments(self, repo, number, since=None):
        if (repo, number) in self.unread:
            raise GitHubError(502, "bad gateway")
        for comment in ():
            yield comment

    async def pulls(self, repo):
        for pull in self._pulls.get(repo, []):
            yield pull


async def test_the_import_asks_nothing_of_github_with_a_transaction_open(ctx, db):
    """The rule: nothing is awaited from GitHub while the desk holds a lock every writer waits for.
    Writing an issue can take the log's head, held to the commit; the import wrote the issue and
    then asked GitHub for its comments, a request a page with retries that sleep, and until it
    answered no reader of a private ticket, no filing and no ruling could be logged."""
    repo = ctx.config.primary_repo
    open_at = []

    class Hub(_Hub):
        async def comments(self, repo, number, since=None):
            open_at.append(db.in_transaction())
            yield {
                "id": 9000 + number, "body": "seen too", "user": {"login": "bob", "id": 8},
                "created_at": "2026-10-20T11:00:00Z",
            }

    hub = Hub({repo: [_issue(601, "Read first", comments=1), _issue(602, "And again", comments=1)]}, {})
    stats = await sync.import_repo(ctx, db, hub, repo)
    assert open_at == [False, False]
    assert [stats[k] for k in ("issues", "created", "comments", "failed")] == [2, 2, 2, 0]
    loop = inspect.getsource(sync.import_repo)
    assert loop.index("client.comments(") < loop.index("await upsert_issue(")
    assert "client." not in loop[loop.index("await upsert_issue("):loop.index("await db.commit()")]


async def test_a_poll_reads_every_repository_and_one_that_fails_stops_none(ctx, db, monkeypatch):
    """The rule (XE-1160, XE-1806): a poll reads every repository and the tracker, each to its end,
    and what fails loses only what it had not committed: a repository whose listing fails stops no
    other, and an issue that fails stops neither the rest of its repository nor its PRs. The import
    commits as it goes; wrapped in a savepoint, its first commit closed the savepoint and the session
    refused the next statement, so no repository got past its first issue and no cursor was ever
    written. Asked through `poll` itself and the worker's job, which nothing else here calls."""
    from contextlib import asynccontextmanager

    from desk import worker

    xe, dao, sdk = ctx.config.repos[:3]
    core = ctx.config.internal_repo
    stamp = "2026-10-20T10:00:00Z"  # `_issue`'s updated_at
    hub = _Hub(
        {
            xe: [_issue(501, "First"), _issue(502, "Second", comments=1), _issue(503, "Third")],
            sdk: [_issue(7, "In the SDK")],
            core: [_issue(1201, "A chore that names no report"), _issue(1202, "bundle sdk#7")],
        },
        {xe: [_pull(510, "Fix the first", "Fixes #501")]},
        broken={dao},
        unread={(xe, 502)},
    )

    async def cursors():
        return [await sync.get_cursor(db, f"github:{r}:issues") for r in (xe, dao, sdk, core)]

    out = await sync.poll(ctx, db, hub)
    by = {s["repo"]: s for s in out}
    # the second issue failed after its ticket was written: it alone is gone, the third and the PR
    # behind it are read, and the cursor stays so the next pass reads the one that failed again
    assert [by[xe][k] for k in ("issues", "created", "pulls", "failed")] == [2, 2, 1, 1]
    assert await tsvc.find_by_source(db, "github", xe, "502") is None
    assert await tsvc.find_by_source(db, "github", xe, "503") is not None
    assert (await tsvc.find_by_source(db, "github", xe, "501")).status == "fixing"
    # a repository whose listing fails is an entry with no counts, and the ones after it are read
    assert "error" in by[dao] and "issues" not in by[dao]
    assert [by[sdk][k] for k in ("issues", "created", "failed")] == [1, 1, 0]
    # the tracker too, past its first commit
    assert [by[core][k] for k in ("issues", "linked", "failed")] == [2, 1, 0]
    assert (await tsvc.find_by_source(db, "github", sdk, "7")).internal_ref == "#1202"
    assert await cursors() == ["", "", stamp, stamp]
    seen = sync.poll_summary(out)
    assert (seen["ok"], seen["total"]) == (False, 6) and seen["stats"] is out
    assert sync.poll_summary([s for s in out if s["repo"] in (sdk, core)])["ok"] is True
    assert sync.poll_summary([by[xe]])["ok"] is False and sync.poll_summary([by[dao]])["ok"] is False

    # the next pass: the issue that failed is read, a PR opened since is followed, the cursor moves
    hub.unread.clear()
    hub._pulls[xe].append(_pull(511, "Fix the second", "Fixes #502"))
    by = {s["repo"]: s for s in await sync.poll(ctx, db, hub)}
    assert [by[xe][k] for k in ("issues", "created", "pulls", "failed")] == [3, 1, 1, 0]
    assert (await tsvc.find_by_source(db, "github", xe, "502")).status == "fixing"
    assert "error" in by[dao] and by[sdk]["created"] == 0 and by[core]["failed"] == 0
    assert await cursors() == [stamp, "", stamp, stamp]

    # the worker's job records the pass as it went: not a clean one while a repository fails
    @asynccontextmanager
    async def _session():
        yield db

    async def last_run():
        q = select(ScheduleRun).where(ScheduleRun.job == "github_poll")
        return (await db.execute(q)).scalar_one().detail

    monkeypatch.setattr(worker, "session", _session)
    w = worker.Worker.__new__(worker.Worker)
    w.ctx, w.gh = ctx, hub
    await w.job_github_poll()
    run = await last_run()
    assert run["ok"] is False and {xe, dao, sdk, core} <= {s["repo"] for s in run["stats"]}
    hub.broken.clear()
    await w.job_github_poll()
    assert (await last_run())["ok"] is True

    # and a pass that raises outright leaves nothing half-done behind the mark it writes
    async def half_done(ctx, db, client):
        await sync.set_cursor(db, "half", "done")
        await db.flush()
        raise RuntimeError("boom")

    monkeypatch.setattr(sync, "poll", half_done)
    await w.job_github_poll()
    assert await last_run() == {"ok": False, "error": "boom"}
    assert await sync.get_cursor(db, "half") == ""


async def test_a_source_moves_a_ticket_once_and_a_persons_status_then_stands(ctx, db):
    """The rule (XE-2080): a follower acts on a change at its source, once. A PR or a tracker issue
    read again in the state it was last acted on moves nothing, so a status a person set since stands;
    a real change at the source (merged, reopened, closed again, another PR) still moves the ticket.
    Asked of both followers and of each state they act on."""
    repo = "xeprotocol/xe"
    team = await _team(ctx, db)

    async def pull(n, issue, **kw):
        await sync.link_pull(ctx, db, repo, _pull(n, f"Fix {issue}", f"Fixes #{issue}", **kw))

    # a PR. Opened: fixing. A person takes it back to accepted; the open PR seen again leaves it there
    t, _ = await sync.upsert_issue(ctx, db, repo, _issue(150, "Vote replay, again"))
    await pull(160, 150)
    assert t.status == "fixing"
    await tsvc.set_status(ctx, db, team, t, "accepted")
    await pull(160, 150)
    assert t.status == "accepted"
    # merged: patched. The fix did not hold and a person walks it back; the merge replayed changes nothing
    await pull(160, 150, state="closed", merged=True)
    assert t.status == "patched"
    await tsvc.set_status(ctx, db, team, t, "fixing")
    for _ in range(2):
        await pull(160, 150, state="closed", merged=True)
        assert t.status == "fixing"
    # another PR merging is news, and patches it
    await pull(161, 150, state="closed", merged=True)
    assert t.status == "patched"
    # closed unmerged: back where it was. A person puts it at fixing by hand; the close replayed leaves it
    t2, _ = await sync.upsert_issue(ctx, db, repo, _issue(151, "Fork on equal height, again"))
    await pull(162, 151)
    await pull(162, 151, state="closed")
    assert t2.status == "triaging"
    await tsvc.set_status(ctx, db, team, t2, "accepted")
    await tsvc.set_status(ctx, db, team, t2, "fixing")
    await pull(162, 151, state="closed")
    assert t2.status == "fixing"
    # reopened is a change, and so is its merge
    await tsvc.set_status(ctx, db, team, t2, "accepted")
    await pull(162, 151)
    assert t2.status == "fixing"
    await pull(162, 151, state="closed", merged=True)
    assert t2.status == "patched"

    # the tracker. Open: accepted. A person takes it back to triaging; the open issue read again leaves it
    t3, _ = await sync.upsert_issue(ctx, db, repo, _issue(152, "Explorer search bar, again"))

    async def tracker(**kw):
        return await sync.link_internal_issue(ctx, db, _issue(1080, "security: bundle xe#152", **kw))

    assert (await tracker())["moved"] == 1 and t3.status == "accepted"
    await tsvc.set_status(ctx, db, team, t3, "triaging")
    assert (await tracker())["moved"] == 0 and t3.status == "triaging"
    # closed as completed: patched. Walked back; the closed issue read again changes nothing
    done = dict(state="closed", state_reason="completed")
    assert (await tracker(**done))["moved"] == 1 and t3.status == "patched"
    await tsvc.set_status(ctx, db, team, t3, "fixing")
    for _ in range(2):
        assert (await tracker(**done))["moved"] == 0 and t3.status == "fixing"
    # the issue is reopened (nothing to move at fixing) and closed again: that close is news
    assert (await tracker())["moved"] == 0 and t3.status == "fixing"
    assert (await tracker(**done))["moved"] == 1 and t3.status == "patched"
    # a link a person cleared stays cleared: the issue still naming the report does not put it back
    await tsvc.set_facts(ctx, db, team, t3, {"internal_ref": ""})
    stats = await tracker()
    assert (stats["linked"], stats["moved"], stats["noted"], t3.internal_ref) == (0, 0, 1, "")
    assert (await tracker(**done))["noted"] == 0 and (t3.internal_ref, t3.status) == ("", "patched")

    # a stranger's open PR is not the PR's say, and is not recorded as if it had been: seen again
    # once its author is a maintainer, it moves the ticket
    t6, _ = await sync.upsert_issue(ctx, db, repo, _issue(155, "A fork's fix"))
    await pull(164, 155, login="mallory", association="NONE")
    assert t6.status == "new"
    await pull(164, 155, login="mallory", association="MEMBER")
    assert t6.status == "fixing"

    # decided on the ticket as it is now. A poll is one session that keeps what it loaded; a person's
    # move made since is what the follower finds, and the change at the source is not used up on a
    # status that is no longer there
    sm = async_sessionmaker(db.bind, expire_on_commit=False)

    async def elsewhere(tid, status, **kw):
        async with sm() as other:
            await tsvc.set_status(ctx, other, team, await tsvc.get(other, tid), status, **kw)
            await other.commit()

    t4, _ = await sync.upsert_issue(ctx, db, repo, _issue(153, "Stale by the tracker phase"))
    await sync.link_internal_issue(ctx, db, _issue(1081, "security: bundle xe#153"))
    assert t4.status == "accepted"
    await db.commit()
    await elsewhere(t4.id, "triaging")
    assert t4.status == "accepted"  # what this pass still holds
    stats = await sync.link_internal_issue(ctx, db, _issue(1081, "security: bundle xe#153", **done))
    assert (stats["moved"], stats["noted"], t4.status) == (1, 0, "patched")
    t5, _ = await sync.upsert_issue(ctx, db, repo, _issue(154, "Closed by a person meanwhile"))
    await tsvc.set_status(ctx, db, team, t5, "triaging")
    await db.commit()
    await elsewhere(t5.id, "closed", closed_reason="invalid")
    assert t5.status == "triaging"
    await pull(163, 154, state="closed", merged=True)  # a merge while closed: seen, and it stays closed
    assert t5.status == "closed"
    await tsvc.set_status(ctx, db, team, t5, "triaging")  # reopened by a person: the old merge is not news
    await pull(163, 154, state="closed", merged=True)
    assert t5.status == "triaging"

    # only a close that says the work was done patches; any other reason is a note for a person
    t7, _ = await sync.upsert_issue(ctx, db, repo, _issue(156, "Closed for another reason"))
    bundle = "security: bundle xe#156"
    await sync.link_internal_issue(ctx, db, _issue(1082, bundle))
    for why in ("not_planned", "duplicate", "some_reason_github_adds_later"):
        await sync.link_internal_issue(ctx, db, _issue(1082, bundle, state="closed", state_reason=why))
        assert t7.status == "accepted", why
    notes = [n.body for n in await thread.notes_for(db, t7)]
    assert sum("was closed as" in body for body in notes) == 3 and any("as duplicate;" in b for b in notes)
    await sync.link_internal_issue(ctx, db, _issue(1082, bundle, **done))
    assert t7.status == "patched"

    # an open issue is one state whatever reason it carries: one that was ever reopened says so for
    # as long as it stays open, and is not news each time it is read
    t8, _ = await sync.upsert_issue(ctx, db, repo, _issue(157, "Reopened once, read often"))

    async def bundle8(**kw):
        return await sync.link_internal_issue(ctx, db, _issue(1083, "security: bundle xe#157", **kw))

    assert (await bundle8())["moved"] == 1 and t8.status == "accepted"
    await tsvc.set_status(ctx, db, team, t8, "triaging")
    assert (await bundle8(state_reason="reopened"))["moved"] == 0 and t8.status == "triaging"
    # a close that carries no reason at all patches, as one that says completed does
    assert (await bundle8(state="closed"))["moved"] == 1 and t8.status == "patched"
    # the tracker links a report once, and its own event is the memory of it. A person links the
    # report to another issue, which it then follows, and later clears that: the first issue, still
    # naming the report, does not put its link back
    await tsvc.set_facts(ctx, db, team, t8, {"internal_ref": "#1084"})
    other = await sync.link_internal_issue(ctx, db, _issue(1084, "security: another bundle"))
    assert (other["tagged"], other["moved"], t8.internal_followed) == (1, 0, "#1084:open:")
    await tsvc.set_facts(ctx, db, team, t8, {"internal_ref": ""})
    stats = await bundle8(state="closed")
    assert (stats["linked"], stats["moved"], stats["noted"], t8.internal_ref) == (0, 0, 1, "")
    # nor on a question, which is linked and never followed, so nothing else remembers the link
    ask = tsvc.NewTicket(kind="support", title="Which port does the node use?", source="web")
    q = await tsvc.create(ctx, db, team.actor, ask)
    names = _issue(1085, "docs: ports", body=f"Asked in {q.id}.")
    stats = await sync.link_internal_issue(ctx, db, names)
    assert (stats["linked"], stats["moved"], q.internal_ref, q.internal_followed) == (1, 0, "#1085", "")
    await tsvc.set_facts(ctx, db, team, q, {"internal_ref": ""})
    for noted in (1, 0):
        stats = await sync.link_internal_issue(ctx, db, names)
        assert (stats["linked"], stats["noted"], q.internal_ref) == (0, noted, ""), noted

    # a stranger's PR closed unmerged has no say, as its opening had none: it takes no ticket's lock
    # and is not recorded, where anyone can open and close a PR that says it fixes every report
    t9, _ = await sync.upsert_issue(ctx, db, repo, _issue(158, "Named by a stranger's closed PR"))
    await pull(165, 158, state="closed", login="mallory", association="NONE")
    link = await thread.patch_ref(db, t9, repo, "165")
    assert (t9.status, link.state, link.followed) == ("new", "closed", "")
    # the PR that moved the ticket is heard when it closes, whoever its author is by then
    await pull(166, 158)
    assert t9.status == "fixing"
    await pull(166, 158, state="closed", login="grace", association="NONE")
    assert t9.status == "triaging"
    # and in the source: the pre-lock and the follower ask the one question, each PR is committed
    # as it is read, and both followers ask the ticket's kind again once they hold its lock
    src = inspect.getsource(sync.link_pull) + inspect.getsource(sync._follow_pull_state)
    assert src.count("_has_a_say(") == 2
    loop = inspect.getsource(sync.import_repo)
    loop = loop[loop.index("async for pull in client.pulls"):]
    assert loop.index("await link_pull(") < loop.index("await db.commit()") < loop.index("set_cursor(")
    assert loop.count("await db.commit()") == 2  # after each PR, and after the cursor
    for fn in (sync._follow_pull_state, sync._follow_internal_state):
        held = inspect.getsource(fn)
        assert 't.kind != "bounty"' in held[held.index("await tsvc.lock(db, t)"):], fn.__name__


async def test_the_teams_own_words_on_the_thread_tell_the_reporter(ctx, db):
    # the rule: a reporter is told when the team writes on the ticket's own thread: a desk reply, a
    # maintainer's comment on the issue, a team member's message in the chat thread. Who maintains the
    # repo is GitHub's word (or the bot's login), never the reporter's own account, and a comment tells
    # from when it was written, so one from before a status move leaves the move untold
    repo = "xeprotocol/xe"
    team = await _team(ctx, db)
    ctx.settings.github_bot_login = "xe-desk-bot"
    t, _ = await sync.upsert_issue(ctx, db, repo, _issue(96, "Told on the issue", login="ada"))
    t2, _ = await sync.upsert_issue(ctx, db, repo, _issue(97, "Told by the bot", login="ada"))
    for moved in (t, t2):
        for st in ("triaging", "accepted"):
            await tsvc.set_status(ctx, db, team, moved, st)

    async def owed():
        return {x.id for x in await tsvc.outbox(db, ctx.config, team)}

    def said(n, login, association, at="2099-01-01T00:00:00Z", uid=None):
        user = {"login": login, "id": 1000 + n if uid is None else uid}
        return {"id": n, "user": user, "body": f"comment {n}", "created_at": at,
                "author_association": association}

    assert await owed() == {t.id, t2.id}
    await sync.upsert_comment(ctx, db, t, said(1, "mallory", "NONE"))
    await sync.upsert_comment(ctx, db, t, said(2, "eve", "CONTRIBUTOR"))
    await sync.upsert_comment(ctx, db, t, said(3, "Ada", "MEMBER", uid=7))  # the reporter herself
    assert t.told_at is None
    await sync.upsert_comment(ctx, db, t, said(4, "grace", "MEMBER", at="2020-01-01T00:00:00Z"))
    assert t.told_at.year == 2020 and await owed() == {t.id, t2.id}  # said before the move
    await sync.upsert_comment(ctx, db, t, said(5, "grace", "COLLABORATOR"))
    assert t.told_at.year == 2099 and await owed() == {t2.id}
    # an older comment seen later takes nothing back, and a comment with no date tells nothing
    await sync.upsert_comment(ctx, db, t, said(6, "grace", "OWNER", at="2021-01-01T00:00:00Z"))
    assert t.told_at.year == 2099
    await sync.upsert_comment(ctx, db, t2, {"id": 7, "user": {"login": "grace"}, "body": "undated",
                                            "author_association": "OWNER"})
    assert t2.told_at is None
    await sync.upsert_comment(ctx, db, t2, said(8, "xe-desk-bot", "NONE"))
    assert await owed() == set()
    # the badge on a message is still the bot's alone (XE-0200)
    assert [m.author_is_team for m in await thread.messages_for(db, t)] == [False] * 6
    assert [m.author_is_team for m in await thread.messages_for(db, t2)] == [False, True]
    # the chat thread: a team member's message tells, a stranger's does not
    q = await channels.open_from_channel(ctx, db, _post())
    q2 = await channels.open_from_channel(ctx, db, _post(thread_ref="778", title="Another question here"))
    assert q.told_at is None
    await channels.incoming(
        ctx, db, q, message_ref="m1", user_id="9", user_name="Bea", body="Looking.", is_team=True
    )
    await channels.incoming(
        ctx, db, q2, message_ref="m2", user_id="2002", user_name="x", body="me", is_team=False
    )
    assert q.told_at is not None and q2.told_at is None


async def test_the_desk_tells_a_resting_ticket_nobody_has(ctx, db):
    # the rule: a bounty ticket resting at accepted or patched, untold past the grace period, is sent the
    # stock reply for that status, signed by the desk. What a person has in hand (a reply, a draft, an
    # agent's draft to adopt), a fix the desk may not name, a move back and an import are left to the
    # outbox. The worker tells moves made since it first ran; what rested before that is swept by hand,
    # by the same rule. Only the desk itself sends without a person.
    repo = "xeprotocol/xe"
    team = await _team(ctx, db)
    agent = await _agent(ctx, db, team.user)

    async def mk(title, to="accepted", **kw):
        t = await tsvc.create(ctx, db, team.actor, tsvc.NewTicket(kind="bounty", title=title, **kw))
        await tsvc.set_status_via_path(ctx, db, team, t, to)
        return t

    async def said(t):
        return [thread.reply_body(ctx, r) for r in await thread.replies_for(db, t)]

    old = await mk("accepted before the desk began telling")
    assert await tell.tell_resting(ctx, db) == []  # the first run starts the clock and sends nothing
    plain = await mk("accepted, nobody wrote")
    sealed = await mk("accepted, private", body="the exploit", visibility="private")
    answered = await mk("accepted, answered by hand")
    await thread.add_reply(ctx, db, team, answered, "Accepted; more from us soon.")
    writing = await mk("accepted, a reply half written")
    writing.draft = "Thanks, we are"
    drafted = await mk("accepted, an agent's draft waiting")
    await psvc.propose(ctx, db, agent, drafted, "reply_draft", "Thanks. See {ticket_url}.", "ack")
    fixed = await mk("patched, the team linked the fix", to="patched")
    await thread.add_patch_ref(ctx, db, team, fixed, repo=repo, ref="41", kind="pr")
    bare = await mk("patched, nothing linked", to="patched")
    back = await mk("fixing, then the fix was withdrawn", to="fixing")
    await tsvc.set_status(ctx, db, team, back, "accepted")
    imported = await mk("accepted by the triage import", to="triaging")
    await tsvc.set_status(ctx, db, authz.SYSTEM, imported, "accepted", via="triage")
    merged, _ = await sync.upsert_issue(ctx, db, repo, _issue(120, "Fixed by a merged PR"))
    await sync.link_pull(ctx, db, repo, _pull(121, "Fix it", "Fixes #120"))
    await sync.link_pull(ctx, db, repo, _pull(121, "Fix it", "Fixes #120", state="closed", merged=True))
    stray, _ = await sync.upsert_issue(ctx, db, repo, _issue(122, "A stranger says they fixed it"))
    theirs = dict(login="rando", association="NONE")
    await sync.link_pull(ctx, db, repo, _pull(123, "junk", "Fixes #122", **theirs))
    await tsvc.set_status_via_path(ctx, db, team, stray, "patched")
    assert merged.status == "patched" and stray.status == "patched"
    assert [tell.nameable(p) for p in await thread.patches_for(db, stray)] == [False]

    # inside the grace period the words are still a person's to write
    assert await tell.tell_resting(ctx, db, now=utcnow() + tell.GRACE / 3) == []
    later = utcnow() + tell.GRACE * 2
    # without the vault key a private ticket waits; the rest are told
    full, ctx.vault = ctx.vault, Vault(Signer({"log": KeyPair.generate()}, {"log": {"event.sign"}}))
    told = await tell.tell_resting(ctx, db, now=later)
    ctx.vault = full
    assert {x["ticket"] for x in told} == {plain.id, fixed.id, merged.id}
    told += await tell.tell_resting(ctx, db, now=later)
    assert [x["ticket"] for x in told[3:]] == [sealed.id]
    assert sorted(notify.take_owed(db)) == sorted(x["reply"] for x in told)  # each is mailed after commit

    r = (await thread.replies_for(db, plain))[0]
    assert r.author_id is None and r.author_name == thread.DESK_NAME == "XE desk" and r.mirror == "none"
    assert "Read and accepted" in r.body and tsvc.ticket_url(ctx, plain) in r.body
    assert (await thread.messages_for(db, plain))[-1].author == thread.DESK_NAME
    sent = [e for e in await EventLog.page(db, 0, 50, ref=plain.id) if e.kind == "reply.sent"]
    assert [e.actor for e in sent] == ["desk"]
    r = (await thread.replies_for(db, sealed))[0]
    assert r.body == "" and r.body_sealed and "Read and accepted" in thread.reply_body(ctx, r)
    assert len(await said(fixed)) == 1 and f"fixed in {repo}#41." in (await said(fixed))[0]
    r = (await thread.replies_for(db, merged))[0]
    assert r.mirror == "queued" and f"fixed in {repo}#121." in r.body  # out to the issue by the worker

    # the rest are as they were, and still the outbox's
    left = (old, writing, drafted, bare, back, imported, stray)
    for t in left:
        assert await said(t) == [], t.title
    assert await said(answered) == ["Accepted; more from us soon."] and writing.draft == "Thanks, we are"
    owed = {x.id for x in await tsvc.outbox(db, ctx.config, team)}
    assert owed == {t.id for t in left}
    assert await tell.tell_resting(ctx, db, now=later) == []  # and a second run says nothing twice

    # what was missing arrives: a commit linked by a person, the stranger's PR merged by a maintainer
    await thread.add_patch_ref(ctx, db, team, bare, repo=repo, ref="deadbeefcafe0123", kind="commit")
    landed = _pull(123, "junk", "Fixes #122", state="closed", merged=True, **theirs)
    await sync.link_pull(ctx, db, repo, landed)
    again = await tell.tell_resting(ctx, db, now=later)
    assert {x["ticket"] for x in again} == {bare.id, stray.id}
    assert f"fixed in {repo}@deadbeefca." in (await said(bare))[0]
    assert f"fixed in {repo}#123." in (await said(stray))[0]

    # the backlog, swept by hand (`desk tell-backlog`): the same rule with no start. What it lists is
    # what it sends, what it leaves it gives a reason for, and a second sweep says nothing twice
    rows = {r.id: r for r in await tell.resting(ctx, db, now=later)}
    assert set(rows) == {t.id for t in (old, writing, drafted, back, imported)}
    assert [i for i, r in rows.items() if r.text] == [old.id]
    assert all(bool(r.text) != bool(r.why) for r in rows.values())
    assert "triage import" in rows[imported.id].why and "moved back" in rows[back.id].why
    assert await tell.tell_resting(ctx, db, now=later) == []  # the worker's run still leaves it
    swept = await tell.tell_resting(ctx, db, now=later, backlog=True)
    assert [x["ticket"] for x in swept] == [old.id] and "Read and accepted" in (await said(old))[0]
    assert await tell.tell_resting(ctx, db, now=later, backlog=True) == []
    assert old.id not in {x.id for x in await tsvc.outbox(db, ctx.config, team)}

    # a reply with no person behind it is the desk's alone: a token and a reporter are still refused
    for p in (agent, authz.Principal(kind="reporter", reporter_id=1), authz.ANON):
        with pytest.raises(HTTPException) as e:
            await thread.add_reply(ctx, db, p, plain, "not a person")
        assert e.value.status_code == 403


async def test_a_closed_report_is_told_in_the_programmes_words_whoever_closed_it(ctx, db):
    # the rule: a bounty report left closed and untold past the grace period is sent the programme's
    # closing reply for its reason by the desk, whatever closed it. The agent's adopted draft is the
    # reason inside that reply only when it came with the same agent's closure, the ticket is private
    # and the text passes the check; otherwise the stock reason goes. The triage page says beforehand
    # which it will be, by asking the question the sweep asks. Closures have a start of their own, so
    # switching the rule on tells nothing that was already closed; that is swept by hand.
    team = await _team(ctx, db)
    a = await _agent(ctx, db, team.user)
    b = await _agent(ctx, db, team.user)
    assert a.token.id != b.token.id
    invalid = {"status": "closed", "closed_reason": "invalid"}
    good = (
        "Thanks for the report. We read the vote path it describes against the tree: the tally refuses"
        " a vote that is not signed, so the sequence in the report stops at its first step and this"
        " closes as invalid."
    )
    ack = "Thanks, confirmed and with the team."

    async def mk(title, visibility="private"):
        new = tsvc.NewTicket(kind="bounty", title=title, body="steps", visibility=visibility)
        return await tsvc.create(ctx, db, team.actor, new)

    async def proposed(t, agent, draft=None, closing=invalid):
        out = []
        if draft is not None:
            out.append(await psvc.propose(ctx, db, agent, t, "reply_draft", draft, "why it closes"))
        if closing is not None:
            out.append(await psvc.propose(ctx, db, agent, t, "status", closing, "read against the tree"))
        return out

    async def page(t):
        """What the triage page's chip says of the draft waiting on `t`, before anyone adopts."""
        prs = [pr for pr in await psvc.pending_for(db, t) if pr.state == "pending"]
        return psvc.send_review(ctx, prs, next(pr for pr in prs if pr.field == "reply_draft"), t)

    async def adopt(t):
        """The triage page's row: every pending proposal on `t`, in one batch."""
        ids = [pr.id for pr in await psvc.pending_for(db, t) if pr.state == "pending"]
        out = await psvc.decide_many(ctx, db, team, ids, [], send_plain=True)
        assert out["skipped"] == []
        return {d["field"]: d for d in out["decided"]}

    async def said(t):
        return [thread.reply_body(ctx, r) for r in await thread.replies_for(db, t)]

    old = await mk("closed before the desk began telling closures")
    await tsvc.set_status(ctx, db, team, old, "closed", closed_reason="invalid")
    assert await tell.tell_resting(ctx, db) == []  # the first run starts the clock and sends nothing

    # a draft and a closure adopted from the triage page, and what the page says of each beforehand
    carried = await mk("private, the agent's reason passes")
    await proposed(carried, a, good)
    with pytest.raises(HTTPException) as e:  # a withdrawal is the reporter's word; nobody is told of one
        await psvc.propose(ctx, db, a, carried, "status", {**invalid, "closed_reason": "withdrawn"}, "")
    assert e.value.status_code == 400
    public = await mk("public, the same words", visibility="public")
    await proposed(public, a, good)
    coded = await mk("private, the reason names code")
    await proposed(coded, a, "Thanks. The check is in `VerifyMultisig`, so this closes as invalid.")
    asks = await mk("private, the reason asks for a reply")
    await proposed(asks, a, "Thanks. We could not find it; reply here and we will look again.")
    stale = await mk("private, another reading's acknowledgement")
    await proposed(stale, b, ack, closing=None)
    await proposed(stale, a)
    aged = await mk("private, the agent's own older acknowledgement")
    (d_aged,) = await proposed(aged, a, ack, closing=None)
    d_aged.created_at = utcnow() - tell.TOGETHER * 6
    await proposed(aged, a)
    late = await mk("private, the agent's own later acknowledgement")
    (d_late,) = await proposed(late, a, ack, closing=None)
    d_late.created_at = utcnow() + tell.TOGETHER * 6
    await proposed(late, a)
    want = {
        carried: psvc.CARRIED,
        public: "the ticket is public",
        coded: "names code or a path",
        asks: "asks for a reply a closed ticket cannot take",
        stale: "the draft and the closure are different agents'",
        aged: "the draft was not written with the closure",
        late: "the draft was not written with the closure",
    }
    for t, why in want.items():
        got = await page(t)
        assert got == (why if why == psvc.CARRIED else f"{psvc.STOCK}: {why}"), t.title
        assert psvc.tells(got)  # either way the reporter is told, so the row counts as one that sends
        did = await adopt(t)
        assert did["status"]["closing"] is True and "sent" not in did["reply_draft"], t.title
        assert t.status == "closed" and t.draft and await said(t) == [], t.title
    d_carried = next(pr.id for pr in await psvc.pending_for(db, carried) if pr.field == "reply_draft")

    # closed by hand: over a draft adopted on the ticket page, with nothing said, and as a duplicate
    hand = await mk("private, closed by hand over an adopted draft")
    (d_hand,) = await proposed(hand, a, good, closing=None)
    await psvc.decide(ctx, db, team, d_hand, True)
    await tsvc.set_status(ctx, db, team, hand, "closed", closed_reason="invalid")
    bare = await mk("private, closed by hand with nothing said")
    await tsvc.set_status(ctx, db, team, bare, "closed", closed_reason="out-of-scope")
    canon = await mk("the first filing", visibility="public")
    dup = await mk("the same again", visibility="public")
    await tsvc.set_facts(ctx, db, team, dup, {"duplicate_of": canon.id})
    await tsvc.set_status(ctx, db, team, dup, "closed", closed_reason="duplicate")

    # what the desk leaves to a person, and so to the outbox: the closing words sent and then the close;
    # a close said in the chat thread; a draft adopted well after the close, which is in an editor
    said_first = await mk("told, then closed")
    await thread.add_reply(ctx, db, team, said_first, "This is as designed, so it is not a bug.")
    await tsvc.set_status(ctx, db, team, said_first, "closed", closed_reason="invalid")
    chat = await mk("closed from its chat thread")
    await tsvc.set_status(ctx, db, team, chat, "closed", closed_reason="answered", via="discord:9")
    after = await mk("closed, the draft adopted on the ticket page an hour later")
    await proposed(after, a)
    await adopt(after)
    (d_after,) = await proposed(after, a, good, closing=None)
    await psvc.decide(ctx, db, team, d_after, True)
    d_after.decided_at = utcnow() + tell.TOGETHER * 6
    assert after.draft == good
    # and: a draft nobody has decided, a reporter already written to, the reporter's own withdrawal,
    # and a closure taken back inside the grace period
    waiting = await mk("closed by hand, an agent's draft undecided")
    await proposed(waiting, a, good, closing=None)
    await tsvc.set_status(ctx, db, team, waiting, "closed", closed_reason="invalid")
    answered = await mk("closed, and told by hand")
    await tsvc.set_status(ctx, db, team, answered, "closed", closed_reason="invalid")
    await thread.add_reply(ctx, db, team, answered, "Closed; this is as designed.")
    withdrawn = await mk("withdrawn by its reporter")
    await tsvc.set_status(ctx, db, team, withdrawn, "closed", closed_reason="withdrawn")
    reopened = await mk("closed, then reopened inside the grace period")
    await proposed(reopened, a, good)
    await adopt(reopened)
    await tsvc.set_status(ctx, db, team, reopened, "triaging")

    assert await tell.tell_resting(ctx, db, now=utcnow() + tell.GRACE / 3) == []  # a person's time
    later = utcnow() + tell.GRACE * 2
    rows = {r.id: r for r in await tell.resting(ctx, db, now=later)}
    assert not {answered.id, withdrawn.id, reopened.id} & set(rows)
    assert rows[waiting.id].why == "an agent's reply draft is waiting to be adopted"
    assert rows[said_first.id].why == "the reporter was written to just before the close"
    assert rows[chat.id].why == "closed from its chat thread, where the close was said"
    assert rows[after.id].why == "a reply draft was adopted after the close; it is in the editor"
    assert not (rows[said_first.id].text or rows[chat.id].text or rows[after.id].text)
    for t, why in want.items():  # the sweep answers as the page did
        r = rows[t.id]
        carries = (f"proposal:{d_carried}", "") if why == psvc.CARRIED else (tell.STOCK, why)
        assert (r.words, r.held) == carries and r.text, t.title
    by_hand = (tell.STOCK, "the closure was not an agent's proposal")
    assert (rows[hand.id].words, rows[hand.id].held) == by_hand
    assert (rows[bare.id].words, rows[bare.id].name) == (tell.STOCK, "out-of-scope")
    assert rows[dup.id].words == tell.STOCK and rows[old.id].text
    assert tell.describe(rows[coded.id]) == "tell, in stock words (draft not used: names code or a path)"
    assert tell.describe(rows[carried.id]) == f"tell, with the agent's reason (proposal:{d_carried})"

    notify.take_owed(db)  # anything an adoption above owed is that adoption's, not this sweep's
    told = await tell.tell_resting(ctx, db, now=later)
    assert {x["ticket"] for x in told} == {t.id for t in (*want, hand, bare, dup)}  # not `old`
    assert sorted(notify.take_owed(db)) == sorted(x["reply"] for x in told)  # each is mailed after commit

    # the agent's words reach one reporter, inside the programme's frame, and the log says whose they are
    line = "This report is closed as invalid."
    (body,) = await said(carried)
    assert body.startswith(good) and line in body and tsvc.ticket_url(ctx, carried) in body
    r = (await thread.replies_for(db, carried))[0]
    assert r.author_id is None and r.author_name == thread.DESK_NAME and r.body == "" and r.body_sealed
    log = await EventLog.page(db, 0, 50, ref=carried.id, public_only=False)
    sent = [e for e in log if e.kind == "reply.sent"]
    assert [(e.actor, e.payload["via"]) for e in sent] == [("desk", f"tell:proposal:{d_carried}")]
    # which is the team's to know: the reporter's own log says the desk told them, not in whose words
    assert public_payload("reply.sent", sent[0].payload)["via"] == "tell"
    # everywhere else the reason is the programme's, and the draft is dropped, not left in the editor
    stock = ctx.config.closing_reasons["invalid"]
    for t in (public, coded, asks, stale, aged, late, hand):
        (body,) = await said(t)
        assert body.startswith(stock) and line in body, t.title
        assert not any(w in body for w in ("VerifyMultisig", "confirmed", "tally", "reply here")), t.title
        assert t.draft == "", t.title
    sent = [e for e in await EventLog.page(db, 0, 50, ref=public.id) if e.kind == "reply.sent"]
    assert [e.payload["via"] for e in sent] == ["tell:stock"]
    (body,) = await said(bare)
    assert body.startswith(ctx.config.closing_reasons["out-of-scope"]) and "closed as out of scope" in body
    (body,) = await said(dup)
    assert canon.id in body and "closes as a duplicate" in body

    # nothing is said twice; what the desk left is still the outbox's; the backlog is the same rule,
    # run by hand, narrowed to a reason and stopped short when asked
    assert await tell.tell_resting(ctx, db, now=later) == []
    left = {old.id, waiting.id, said_first.id, chat.id, after.id}
    assert {x.id for x in await tsvc.outbox(db, ctx.config, team)} == left
    assert await tell.tell_resting(ctx, db, now=later, backlog=True, only="duplicate") == []
    swept = await tell.tell_resting(ctx, db, now=later, backlog=True, only="invalid", limit=1)
    assert [x["ticket"] for x in swept] == [old.id] and (await said(old))[0].startswith(stock)
    assert await tell.tell_resting(ctx, db, now=later, backlog=True) == []

    # the text rule for a reason: what a closure may say that an acknowledgement may not, and no more
    def rr(words):
        return thread.review_reason(ctx, words, carried, closing=True)

    assert rr(good) is None and thread.review_reason(ctx, good, carried) == "explains a closure"
    assert rr("Thanks. The network has no such path, so this is closed as invalid.") is None
    # the stock lines are written for a ticket that stays open, and do not pass inside a closure
    stock_line = ctx.config.plain_phrases[0]
    assert thread.review_reason(ctx, f"Thanks. {stock_line}", carried) is None
    assert rr(f"Thanks. {stock_line}") == "mentions payment"
    for words, why in (
        ("Thanks. See https://example.com/x.", "has a link"),
        ("Thanks. The same as XE-12345.", "names another ticket"),
        ("Thanks. Fixed 2 days ago.", "has a number"),
        ("Thanks. The check is in net/sync.", "names code or a path"),
        ("Thanks. We rate this High.", "names a tier"),
        ("Thanks. No award follows.", "mentions payment"),
        ("Thanks. We will look within the week.", "promises a time"),
        ("Thanks. Reply here with a reproduction.", "asks for a reply a closed ticket cannot take"),
        ("Thanks. Write to us with a reproduction.", "asks for a reply a closed ticket cannot take"),
        ("Thanks. The amount is ten thousand XE.", "mentions payment"),
        (f"Thanks. The same as {thread.UNNAMED_DUPLICATE}.", "has an unfilled placeholder"),
        ("Thanks. More at example.com if needed.", "has a link"),
        ("x" * (thread.REASON_LIMIT + 1), f"over {thread.REASON_LIMIT} characters"),
    ):
        assert rr(words) == why, words

    # the copy: every closing reason the desk owes a reply for has a template; none asks for a reply
    # (a closed ticket takes none); each but the duplicate's has a reason slot and a stock line for it
    for name in tsvc.CLOSED_REASONS_FOR["bounty"]:
        assert tell.owed("bounty", name) == (name != "withdrawn"), name
        if tell.owed("bounty", name):
            tpl = ctx.config.reply_templates[name]
            assert not thread._ASKS_BACK.search(tpl), name
            assert name == "duplicate" or ("{reason}" in tpl and ctx.config.closing_reasons[name].strip())
    assert not tell.owed("support", "answered")


async def test_a_blocked_login_is_neither_linked_nor_mirrored(ctx, db):
    # XE-0128: an account that opened a patch two hours after someone else's report and posted its own
    # payout addresses in the thread. Blocked, its PRs do not link, its comments do not land, and what
    # arrived before the block comes off on the next sight of it.
    from desk.models import Reporter

    repo = "xeprotocol/xe"
    t, _ = await sync.upsert_issue(ctx, db, repo, _issue(215, "GET /frontiers does full-lattice work"))
    farm = _pull(217, "fix: page frontiers", "Fixes #215", login="farmer", association="NONE")
    planted = {"id": 69, "user": {"login": "farmer"}, "body": "Fix in #217. Beneficiary: 23bd7ef9..."}
    assert await sync.link_pull(ctx, db, repo, farm) == 1
    assert await sync.upsert_comment(ctx, db, t, planted) is True
    farmer = {"login": "farmer", "id": 99}
    mine, _ = await sync.upsert_issue(ctx, db, repo, _issue(216, "Mine", body="v1", user=farmer))
    ctx.settings.github_blocked_logins = " Farmer ,other"  # case and spacing are not a way round it
    assert await sync.link_pull(ctx, db, repo, farm) == 0
    assert await thread.patches_for(db, t) == []
    assert await sync.upsert_comment(ctx, db, t, planted) is False
    msgs = await thread.messages_for(db, t)
    assert [m.body for m in msgs] == [sync.BLOCKED_MARK]
    # a new comment from the account never lands
    assert await sync.upsert_comment(ctx, db, t, {**planted, "id": 70}) is False
    assert len(await thread.messages_for(db, t)) == 1
    # a maintainer's PR against the same issue still does its work
    assert await sync.link_pull(ctx, db, repo, _pull(300, "fix(api): page frontiers", "Fixes #215")) == 1
    assert t.status == "fixing"
    # the rule is the account's, not the comment's: every way GitHub names it as an author (XE-1876).
    # An issue it opens is not a ticket and makes no reporter row, by the poll or by the webhook
    other = {"login": "Other", "id": 98}
    assert await sync.upsert_issue(ctx, db, repo, _issue(218, "Pay 23bd7ef9", user=farmer)) == (None, False)
    assert await sync.upsert_issue(ctx, db, repo, _issue(219, "Pay 23bd7ef9", user=other)) == (None, False)
    hook = {"action": "opened", "repository": {"full_name": repo}, "issue": _issue(220, "x", user=other)}
    assert await sync.handle_webhook(ctx, db, "issues", hook) == {"ignored": "blocked account"}
    said = {**hook, "action": "created", "comment": {"id": 71, "user": {"login": "ada"}, "body": "+1"}}
    assert await sync.handle_webhook(ctx, db, "issue_comment", said) == {"ignored": "blocked account"}
    for n in ("218", "219", "220"):
        assert await tsvc.find_by_source(db, "github", repo, n) is None
    assert (await db.execute(select(Reporter).where(Reporter.github_id == 98))).first() is None
    assert await sync.reporter_for(ctx, db, other) is None
    # one it opened before the block keeps its ticket and takes no more from it: not its edits, and
    # not its closing of the issue, which is as much its own act and which the poll puts no name to
    again, created = await sync.upsert_issue(
        ctx, db, repo, _issue(216, "Send it to 23bd7ef9", body="v2", state="closed", user=farmer)
    )
    assert again is mine and not created
    assert (mine.title, mine.body, mine.github_state) == ("Mine", "v1", "open")
    # the login is the account's to change, so the list also names it by GitHub's number: renamed,
    # it is the same account at every site
    ctx.settings.github_blocked_logins = "ID:99"
    renamed = {"login": "harvest", "id": 99}
    assert await sync.upsert_issue(ctx, db, repo, _issue(221, "Pay 23bd7ef9", user=renamed)) == (None, False)
    await sync.upsert_issue(ctx, db, repo, _issue(216, "Send it", body="v3", state="closed", user=renamed))
    assert (mine.title, mine.body, mine.github_state) == ("Mine", "v1", "open")
    assert await sync.reporter_for(ctx, db, renamed) is None
    assert await sync.upsert_comment(ctx, db, t, {"id": 72, "user": renamed, "body": "pay me"}) is False
    assert len(await thread.messages_for(db, t)) == 1
    refarm = {**_pull(301, "fix: page frontiers again", "Fixes #215", association="NONE"), "user": renamed}
    assert await sync.link_pull(ctx, db, repo, refarm) == 0
    assert [p.ref for p in await thread.patches_for(db, t)] == ["300"]
    assert await tsvc.find_by_source(db, "github", repo, "221") is None
    # every function that reads GitHub's author asks, bar the two reached only once it has been asked
    reads = {
        name
        for name, fn in inspect.getmembers(sync, inspect.isfunction)
        if fn.__module__ == sync.__name__ and 'get("user")' in inspect.getsource(fn)
    }
    asks = {name for name in reads if "account_blocked(" in inspect.getsource(getattr(sync, name))}
    assert reads - asks == {"comment_is_teams", "pull_is_maintainers"}
    ctx.settings.github_blocked_logins = ""
    await sync.upsert_issue(
        ctx, db, repo, _issue(216, "Mine, reworded", body="v2", state="closed", user=farmer)
    )
    # unblocked, and still the reporter's draft
    assert (mine.title, mine.body, mine.github_state) == ("Mine, reworded", "v2", "closed")


async def test_approved_awards_whose_ticket_has_not_caught_up_are_listed(ctx, db):
    team = await _team(ctx, db)
    t = await tsvc.create(ctx, db, team.actor, tsvc.NewTicket(kind="bounty", title="x", source="web"))
    for st in ("triaging", "accepted", "patched"):
        await tsvc.set_status(ctx, db, team, t, st)
    assert await tsvc.awards_approved_unawarded(db, ctx.config, team) == []
    t.assessed_tier = t.assessed_tier or "medium"  # an award needs a tier (XE-0470)
    await tsvc.set_award(ctx, db, team, t, 2_000_000, approve=True)
    rows = await tsvc.awards_approved_unawarded(db, ctx.config, team)
    assert [x.id for x in rows] == [t.id]
    assert tsvc.award_next_step(t)[1] == "awarded"  # public and patched: one click
    t.visibility = "private"
    assert tsvc.award_next_step(t)[1] is None and "disclose" in tsvc.award_next_step(t)[0]
    t.visibility = "public"
    await tsvc.set_status(ctx, db, team, t, "awarded")
    assert await tsvc.awards_approved_unawarded(db, ctx.config, team) == []
    assert tsvc.award_next_step(t) == ("done", None)


# ---- triage import ----------------------------------------------------------------------------------


async def test_triage_import_of_the_real_doc(ctx, db, triage_text):
    team = await _team(ctx, db)
    rows = triage.parse_triage(triage_text)
    stats = await triage.import_rows(ctx, db, rows, email_bodies={"E1": "e1", "E2": "e2", "E3": "e3"})
    await db.commit()
    assert stats["created"] == 90 and stats["notes"] >= 70
    tickets = {t.source_ref: t for t in (await db.execute(select(Ticket))).scalars().all()}
    assert len(tickets) == 90
    assert tickets["15"].status == "patched" and tickets["15"].internal_ref == "#1028"
    assert tickets["70"].status == "fixing"
    assert (
        tickets["89"].status == "closed"
        and tickets["89"].duplicate_of == tickets["15"].id
        and tickets["89"].internal_ref == "#1028"
    )
    assert tickets["E1"].visibility == "private" and tickets["E1"].duplicate_of == tickets["14"].id
    assert tickets["E1"].body == "" and tsvc.body_for(ctx, tickets["E1"]) == "e1"
    assert tickets["61"].duplicate_of == tickets["E1"].id
    # "support" in the sheet is a verdict on the bounty, not a move to the support door (60a95ed)
    assert (
        tickets["99"].kind == "bounty"
        and tickets["99"].status == "closed"
        and tickets["99"].internal_ref == "faucet#10"
    )
    assert tickets["57"].area == "ops-testnet"
    assert tickets["8"].assessed_tier == "severe" and tickets["8"].claimed_tier is None  # "mixed" bundle
    assert tickets["21"].mainnet_gate == "decide" and tickets["21"].status == "accepted"
    gates = Counter(t.mainnet_gate for t in tickets.values())
    assert gates["before"] == 35 and gates["later"] == 29 and gates["decide"] == 1  # as the rows say
    prs = {(p.repo, p.ref) for p in await thread.patches_for(db, tickets["15"])}
    assert prs == {("xeprotocol/xe", "27"), ("xeprotocol/xe", "111"), ("xeprotocol/xe", "1029")}
    notes = (await db.execute(select(Note).where(Note.ticket_id == tickets["96"].id))).scalars().all()
    assert len(notes) == 1 and "First reading" in notes[0].body and notes[0].author.startswith("token:")
    tok = (await db.execute(select(AgentToken))).scalars().one()
    assert tok.revoked_at is not None and tok.scopes == []
    # the outbox holds what was fixed and never told
    outbox = await tsvc.outbox(db, ctx.config, authz.SYSTEM)
    assert tickets["15"].id in {t.id for t in outbox}
    # re-running changes nothing
    again = await triage.import_rows(ctx, db, rows, email_bodies={})
    await db.commit()
    assert again["created"] == 0 and again["updated"] == 0 and again["notes"] == 0 and again["patches"] == 0
    assert (await EventLog.verify(db))["ok"]
    md = await triage.export_markdown(ctx, db, authz.SYSTEM)
    assert "XE-" in md and "`#1028`" in md and md.count("\n| ") >= 90
    public_md = await triage.export_markdown(ctx, db, await _agent(ctx, db, team.user))
    assert tickets["E1"].title in md and tickets["E1"].title not in public_md
    assert public_md.count("\n| ") == md.count("\n| ") - 3
    pending = (await db.execute(select(Proposal))).scalars().all()
    assert pending == [], "the import writes facts, not proposals"


# ---- reporters -------------------------------------------------------------------------------------


class _Upload:
    """Just enough of starlette's UploadFile for the service."""

    def __init__(self, name: str, data: bytes, content_type: str = "text/plain"):
        self.filename, self._data, self.content_type = name, data, content_type

    async def read(self, n: int = -1) -> bytes:
        d, self._data = self._data[:n] if n >= 0 else self._data, b""
        return d


def _signed(kp: KeyPair, domain: bytes, payload: dict) -> SignedRequest:
    ts = time.time_ns()
    sig = kp.sign_hex(signing_target(domain, payload, ts))
    return SignedRequest(payload=payload, timestamp=ts, pub_key=kp.pub_key_hex, signature=sig)


async def test_reporter_files_private_report_with_sealed_attachment(ctx, db, tmp_path):
    ctx.settings.blob_dir = tmp_path
    r = await rsvc.from_email(ctx, db, "alice@example.org", link_to=None)
    me = authz.Principal(kind="reporter", reporter_id=r.id)
    f = rsvc.Filing(
        kind="bounty",
        title="Escrow release double-counts",
        body="Steps: open an escrow, release twice within one block. Expected: one release. Got: two.",
        area="consensus",
        claimed_tier="high",
        private=True,
        files=[_Upload("poc.txt", b"the exploit bytes " * 10)],
    )
    t = await rsvc.file_ticket(ctx, db, r, f)
    await db.commit()
    assert t.visibility == "private" and t.reporter_id == r.id and t.claimed_tier == "high"
    assert tsvc.body_for(ctx, t).startswith("Steps")
    atts = await rsvc.attachments_for(db, t)
    assert len(atts) == 1 and atts[0].sealed
    on_disk = (tmp_path / atts[0].blob_path).read_bytes()
    assert b"exploit" not in on_disk
    a, data = await rsvc.open_attachment(ctx, db, me, t, 1)
    assert data.startswith(b"the exploit") and a.sha256 == hashlib.sha256(data).hexdigest()
    # the reporter sees their own private ticket; anonymous and another reporter do not
    assert (await tsvc.get_for(db, me, t.id)).id == t.id
    other = authz.Principal(kind="reporter", reporter_id=r.id + 1)
    for p in (authz.ANON, other):
        with pytest.raises(HTTPException) as e:
            await tsvc.get_for(db, p, t.id)
        assert e.value.status_code == 404
    assert not rsvc.owns(None, t)


async def test_a_critical_or_severe_claim_is_born_private_whoever_writes_it(ctx, db):
    """The rule (XE-1932, XE-2166, XE-2123): a bounty report claiming Critical or Severe is private from
    its first write. It is `tickets.create`'s, so it is asked of every writer of a new ticket: the
    reporter's form, the team's API, a bare `create` (what an import calls); however the tier is
    spelled; and a spelling the desk does not know is refused, not filed public with no tier."""
    from desk.api import team as team_api

    r = await rsvc.from_email(ctx, db, "bob@example.org", link_to=None)
    team = await _team(ctx, db)
    who = auth.Auth(principal=team)
    body = "A long enough description of how the mint can be triggered without authorisation here."

    async def by_form(tier, title):
        f = rsvc.Filing(kind="bounty", title=title, body=body, claimed_tier=tier, private=False)
        return await rsvc.file_ticket(ctx, db, r, f)

    async def by_team_api(tier, title):
        out = await team_api.create_ticket(
            ctx, db, who, None, team_api.NewTicketIn(title=title, body=body, claimed_tier=tier)
        )
        return await tsvc.get(db, out["id"])

    async def by_create(tier, title):
        spec = tsvc.NewTicket(kind="bounty", title=title, body=body, source="email", claimed_tier=tier)
        return await tsvc.create(ctx, db, "desk", spec)

    writers = {"the form": by_form, "the team API": by_team_api, "create": by_create}
    for name, write in writers.items():
        for tier in ("critical", "severe", "Critical", " SEVERE ", "severe\n"):
            t = await write(tier, f"Unauthorized mint via vault ({name})")
            assert (t.visibility, t.claimed_tier) == ("private", tier.strip().lower()), (name, tier)
            assert t.body == "" and tsvc.body_for(ctx, t) == body, (name, tier)
        t = await write("High", f"Something smaller ({name})")
        assert (t.visibility, t.claimed_tier, t.body) == ("public", "high", body), name
        for unknown in ("crit", "critical\u200b", "\uff43ritical"):
            with pytest.raises(HTTPException) as e:
                await write(unknown, f"Spelled some other way ({name})")
            assert e.value.status_code == 400, (name, unknown)
    # the ticket for a GitHub issue follows the issue, which is public where it was filed
    hub, _ = await sync.upsert_issue(
        ctx, db, "xeprotocol/xe", _issue(88, "Mint without a key", body="Severity: critical\n" + body)
    )
    assert (hub.visibility, hub.claimed_tier) == ("public", "critical")
    # a question claims nothing, at birth or by edit, and a ticket that arrives on the bounty by
    # conversion has made no claim: no conversion ends as a public report claiming Critical or Severe
    ask = tsvc.NewTicket(kind="support", title="Is this a bug or me", body=body, claimed_tier="critical")
    q = await tsvc.create(ctx, db, "desk", ask)
    assert (q.visibility, q.claimed_tier) == ("public", None)
    with pytest.raises(HTTPException) as e:
        await tsvc.set_facts(ctx, db, team, q, {"claimed_tier": "critical"})
    assert e.value.status_code == 400
    q.claimed_tier = "severe"  # a row written before this rule
    await channels.convert_to_bounty(ctx, db, q, user_id="9")
    assert (q.kind, q.claimed_tier, q.visibility) == ("bounty", None, "public")
    b = await by_create("high", "There and back again")
    for kind in ("support", "bounty"):
        await team_api.set_kind(ctx, db, who, None, b.id, kind)
        assert (b.kind, b.claimed_tier, b.visibility) == (kind, None, "public")
    # every conversion is the one function: no caller writes a ticket's kind itself
    for mod in (team_api, channels, triage, sync, psvc, rsvc):
        assert not re.search(r"\.kind\s*=[^=]", inspect.getsource(mod)), mod.__name__
    # without the vault key a private report is refused, not stored in the clear
    full, ctx.vault = ctx.vault, Vault(Signer({"log": KeyPair.generate()}, {"log": {"event.sign"}}))
    for name, write in writers.items():
        with pytest.raises(HTTPException) as e:
            await write("critical", f"No vault key loaded ({name})")
        assert e.value.status_code == 503, name
    ctx.vault = full


async def test_a_reporter_past_the_daily_cap_is_queued_not_refused(ctx, db):
    cap = ctx.config.daily_cap
    assert cap >= 2
    r = await rsvc.from_email(ctx, db, "flood@example.org", link_to=None)
    other = await rsvc.from_email(ctx, db, "once@example.org", link_to=None)
    team = await _team(ctx, db)
    body = "What I did, what happened, what I expected; enough words to pass the body check."
    filed = []
    for i in range(cap + 2):
        f = rsvc.Filing(kind="bounty", title=f"probe number {i} abcdef", body=body, claimed_tier="medium")
        filed.append(await rsvc.file_ticket(ctx, db, r, f))
    assert [t.queued for t in filed] == [False] * cap + [True, True], "the first `cap` are read first"
    # support questions are not capped, and one account's flood does not touch another's first report
    ask = rsvc.Filing(kind="support", title="how do I run a node", body=body)
    q = await rsvc.file_ticket(ctx, db, r, ask)
    first = rsvc.Filing(kind="bounty", title="a real finding", body=body)
    one = await rsvc.file_ticket(ctx, db, other, first)
    assert not q.queued and not one.queued
    # queued reports sort after everything else, in both orders, and can be filtered out
    ids = [t.id for t in await tsvc.list_tickets(db, ctx.config, team, tsvc.Filters(sort="age", limit=500))]
    tail = {filed[-2].id, filed[-1].id}
    assert set(ids[-2:]) == tail and one.id in ids[:-2]
    by_sev = [t.id for t in await tsvc.list_tickets(db, ctx.config, team, tsvc.Filters(limit=500))]
    assert set(by_sev[-2:]) == tail
    unqueued = await tsvc.list_tickets(db, ctx.config, team, tsvc.Filters(queued=False, limit=500))
    assert filed[-1].id not in {t.id for t in unqueued} and one.id in {t.id for t in unqueued}
    # the record a reviewer sees beside the name
    rec = (await rsvc.records(db, {r.id, other.id}))
    assert rec[r.id]["filed"] == cap + 2 and rec[r.id]["queued"] == 2 and rec[r.id]["today"] == cap + 2
    assert rec[other.id] == {
        "filed": 1, "real": 0, "duplicate": 0, "noise": 0, "awarded": 0, "unread": 1, "today": 1, "queued": 0
    }
    # a person reaching the ticket clears the mark; the reporter sees it was read in turn
    await tsvc.set_status(ctx, db, team, filed[-1], "triaging")
    assert filed[-1].queued is False
    assert tsvc.to_dict(ctx, filed[-2], team)["queued"] is True
    assert "queued" not in tsvc.to_dict(ctx, filed[-2], authz.ANON), "an account's pace is not public"
    as_r = authz.Principal(kind="reporter", reporter_id=r.id)
    assert tsvc.to_dict(ctx, filed[-2], as_r)["queued"] is True
    evs = await EventLog.page(db, 0, 50, ref=filed[-2].id, public_only=False)
    assert any(e.kind == "ticket.queued" for e in evs)
    assert not any(e.kind == "ticket.queued" for e in await EventLog.page(db, 0, 50, ref=filed[-2].id))


async def test_reporter_withdraws_and_replies(ctx, db):
    r = await rsvc.from_email(ctx, db, "carol@example.org", link_to=None)
    team = await _team(ctx, db)
    body = "What I did, what happened, what I expected; enough words to pass the body check."
    f = rsvc.Filing(kind="bounty", title="Explorer shows wrong tip", body=body)
    t = await rsvc.file_ticket(ctx, db, r, f)
    await tsvc.set_status(ctx, db, team, t, "triaging")
    await tsvc.set_status(ctx, db, team, t, "needs-info")
    m = await rsvc.reply(ctx, db, r, t, "Here is the version: 0.5.1")
    assert m is not None and t.status == "triaging"
    await rsvc.withdraw(ctx, db, r, t, "my mistake")
    assert t.status == "closed" and t.closed_reason == "withdrawn"
    with pytest.raises(HTTPException) as e:
        await rsvc.withdraw(ctx, db, r, t)
    assert e.value.status_code == 409
    stranger = await rsvc.from_email(ctx, db, "dave@example.org", link_to=None)
    with pytest.raises(HTTPException) as e:
        await rsvc.reply(ctx, db, stranger, t, "mine now")
    assert e.value.status_code == 403


async def test_a_finished_ticket_takes_no_reporter_message(ctx, db):
    """The rule (XE-1960): the reporter's reply box writes to a ticket only while it is open. Asked of
    every status the desk has, so a status added later is on one side or the other by `Ticket.is_open`,
    and the page shows the box by the same property."""
    r = await rsvc.from_email(ctx, db, "erin@example.org", link_to=None)
    body = "What I did, what happened, what I expected; enough words to pass the body check."
    f = rsvc.Filing(kind="bounty", title="Explorer shows wrong tip", body=body)
    t = await rsvc.file_ticket(ctx, db, r, f)
    statuses = set(tsvc.TRANSITIONS["bounty"]) | set(tsvc.TRANSITIONS["support"])
    assert {"closed", "paid", "new", "awarded"} <= statuses
    for status in sorted(statuses):
        t.status = status
        before = len(await thread.messages_for(db, t))
        if status in ("closed", "paid"):
            assert not t.is_open
            with pytest.raises(HTTPException) as e:
                await rsvc.reply(ctx, db, r, t, "one more thing")
            assert e.value.status_code == 409, status
            assert len(await thread.messages_for(db, t)) == before, status
        else:
            assert t.is_open
            assert await rsvc.reply(ctx, db, r, t, "one more thing") is not None, status
            assert len(await thread.messages_for(db, t)) == before + 1, status
    page = (Path(tsvc.__file__).parent.parent / "templates" / "ticket.html").read_text()
    box = page[page.index('class="compose reporter"'):page.index('id="reporter-reply"')]
    assert "{% if not t.is_open %}" in box


async def test_a_reporters_write_is_decided_on_the_ticket_as_it_is_now(ctx, db):
    """The rule (the XE-1960 sweep; XE-0463 at the reporter's side): what a reporter's message, a
    withdrawal or a thread command does depends on the ticket's status, and that status is read under
    the row lock, not as the request first read it. Each writer is handed a ticket that another session
    has since moved and committed."""
    team = await _team(ctx, db)
    r = await rsvc.from_email(ctx, db, "nina@example.org", link_to=None)
    body = "What I did, what happened, what I expected; enough words to pass the body check."
    sm = async_sessionmaker(db.bind, expire_on_commit=False)

    async def filed(title):
        t = await rsvc.file_ticket(ctx, db, r, rsvc.Filing(kind="bounty", title=title, body=body))
        await db.commit()
        return t

    async def elsewhere(t, *moves):
        async with sm() as other:
            mine = await tsvc.get(other, t.id)
            for status, reason in moves:
                await tsvc.set_status(ctx, other, team, mine, status, closed_reason=reason)
            await other.commit()

    # a reply box open in one tab, the ticket closed from another: the message is refused
    t = await filed("Explorer shows the wrong tip")
    before = len(await thread.messages_for(db, t))
    await db.commit()
    await elsewhere(t, ("closed", "invalid"))
    assert t.status == "new"  # as this session read it
    with pytest.raises(HTTPException) as e:
        await rsvc.reply(ctx, db, r, t, "one more thing")
    assert e.value.status_code == 409 and t.status == "closed"
    assert len(await thread.messages_for(db, t)) == before
    await db.commit()
    # a withdrawal racing the fix: the patched ticket is not closed over
    t = await filed("Faucet pays the same address twice")
    await elsewhere(t, ("triaging", None), ("accepted", None), ("patched", None))
    with pytest.raises(HTTPException) as e:
        await rsvc.withdraw(ctx, db, r, t, "never mind")
    assert e.value.status_code == 409 and (t.status, t.closed_reason) == ("patched", None)
    await db.commit()
    # a thread /close racing the team's acceptance: the accepted report stays open
    t = await filed("Node accepts a block from the future")
    await elsewhere(t, ("triaging", None), ("accepted", None))
    with pytest.raises(HTTPException) as e:
        await channels.close_from_channel(ctx, db, t, user_id="9", reason="")
    assert e.value.status_code == 409 and t.status == "accepted"
    await db.commit()
    # an answer in the chat thread racing the close: the message is kept, the question stays closed
    q = await channels.open_from_channel(ctx, db, _post())
    for status in ("triaging", "needs-info"):
        await tsvc.set_status(ctx, db, team, q, status)
    await db.commit()
    await elsewhere(q, ("closed", "answered"))
    m = await channels.incoming(
        ctx, db, q, message_ref="m1", user_id="1001", user_name="Ada", body="thanks", is_team=False
    )
    assert m is not None and (q.status, q.closed_reason) == ("closed", "answered")
    await db.commit()


async def test_a_check_on_a_ticket_is_made_on_the_row_as_it_is_now(ctx, db):
    """The rule (XE-0463): a check that decides whether a write to a ticket is allowed reads the row
    under its lock. `set_status` and `set_award` have held it; asked here of the other writers that
    test the status or the award first, each handed a ticket another session has since moved."""
    from desk.api import team as team_api

    team = await _team(ctx, db)
    sm = async_sessionmaker(db.bind, expire_on_commit=False)

    async def made(title, upto="patched", award=True):
        t = await tsvc.create(ctx, db, team.actor, tsvc.NewTicket(kind="bounty", title=title, body="b"))
        await tsvc.set_facts(ctx, db, team, t, {"assessed_tier": "medium"})
        path = ("triaging", "accepted", "patched")
        for status in path[: path.index(upto) + 1] if upto != "new" else ():
            await tsvc.set_status(ctx, db, team, t, status)
        if award:
            await tsvc.set_award(ctx, db, team, t, 5_000_000, approve=True)
        await db.commit()
        return t

    async def elsewhere(t, *acts):
        async with sm() as other:
            mine = await tsvc.get(other, t.id)
            for act in acts:
                await act(other, mine)
            await other.commit()

    async def refused(call, says):
        with pytest.raises(HTTPException) as e:
            await call()
        assert e.value.status_code == 409 and says in e.value.detail, e.value.detail
        await db.commit()  # the refusal took the row lock; let it go before the next move elsewhere

    def moved(status):
        return lambda s, mine: tsvc.set_status(ctx, s, team, mine, status)

    def paid(ref):
        return lambda s, mine: tsvc.mark_paid(ctx, s, team, mine, ref)

    # sealing a report, or changing its tier, races its award (XE-2250)
    t = await made("Sealed while being awarded")
    await elsewhere(t, moved("awarded"))
    assert t.status == "patched"  # as this session read it
    await refused(lambda: tsvc.set_facts(ctx, db, team, t, {"visibility": "private"}), "stays public")
    await refused(lambda: tsvc.set_facts(ctx, db, team, t, {"assessed_tier": "high"}), "the award stands")
    assert (t.status, t.visibility, t.assessed_tier) == ("awarded", "public", "medium")
    # a payment recorded twice: the second is told it is paid, and the first reference stands
    await elsewhere(t, paid("tx-first"))
    await refused(lambda: tsvc.mark_paid(ctx, db, team, t, "tx-second"), "this one is paid")
    assert (t.status, t.paid_ref) == ("paid", "tx-first")
    # moving a ticket to another reporter while it is being paid
    t = await made("Reassigned while being paid")
    await elsewhere(t, moved("awarded"), paid("tx"))
    await refused(lambda: rsvc.attach(ctx, db, team, t, email="pat@example.org"), "reporter on record stands")
    assert t.reporter_id is None
    # converting a report to a question while it is being accepted
    t = await made("Converted while being accepted", upto="new", award=False)
    await elsewhere(t, moved("triaging"), moved("accepted"))
    who = auth.Auth(principal=team)
    await refused(lambda: team_api.set_kind(ctx, db, who, None, t.id, "support"), "is not converted")
    assert (t.kind, t.status) == ("bounty", "accepted")
    # filling a blank amount that has just been filled: it fills blanks, it does not revise
    t = await made("Amount set while being filled", award=False)
    await elsewhere(t, lambda s, mine: tsvc.set_award(ctx, s, team, mine, 7_000_000))
    out = await psvc.fill_awards(ctx, db, team, [t.id], next(iter(ctx.config.award_steps)))
    assert out["filled"] == [] and out["skipped"] == [{"ticket": t.id, "why": "already has an amount"}]
    assert t.award_xe == 7_000_000
    await db.commit()


async def test_awarded_is_what_publishes_an_award(ctx, db):
    """The rule (XE-0735): an award's amount, and whether it is approved, are published by `awarded`.
    Before that they are served to whoever sees the assessment (the team, the agents that work the
    queue) and to nobody else, the reporter included: the steps are a published table, so an amount
    set on a patched ticket names a judgement nobody has announced. Asked of each way a reader
    outside the team gets a ticket's award: the row as the API and the pages serialise it, the
    social card, the leaderboard, the log, a reply filled from a template or a draft, and the
    templates that are not the team's."""
    from desk import og, ui
    from desk.log import event_to_dict

    team = await _team(ctx, db)
    agent = await _agent(ctx, db, team.user)
    linker = await _agent(ctx, db, team.user, scopes=("write:patch-refs",))  # a token outside the queue
    r = await rsvc.from_email(ctx, db, "olga@example.org", link_to=None)
    own = authz.Principal(kind="reporter", reporter_id=r.id)
    body = "What I did, what happened, what I expected; enough words to pass the body check."
    f = rsvc.Filing(kind="bounty", title="Ledger accepts a negative lease", body=body, claimed_tier="medium")
    t = await rsvc.file_ticket(ctx, db, r, f)
    await tsvc.set_facts(ctx, db, team, t, {"assessed_tier": "high", "verdict": "valid"})
    for status in ("triaging", "accepted"):
        await tsvc.set_status(ctx, db, team, t, status)
    inside, outside = (team, agent), (authz.ANON, own, linker)
    amount, nothing = 5_000_000, (None, False)

    def served(p):
        d = tsvc.to_dict(ctx, t, p)
        assert (d["award_xe"], d["award_approved"]) == tsvc.shown_award(t, p)
        return d["award_xe"], d["award_approved"]

    def card():
        return [text for text, _style in og.ticket_spec(ctx, t)["chips"] if text.endswith(" XE")]

    async def logged():
        evs = [e for e in await EventLog.page(db, 0, 50, ref=t.id) if e.kind == "ticket.award"]
        assert evs and all(e.public for e in evs)
        return [event_to_dict(e, full=False)["payload"] for e in evs]

    # accepted, with an amount set (it can be, from here on): the bug is unfixed and nothing is served
    await tsvc.set_award(ctx, db, team, t, amount, step="standard")
    assert [served(p) for p in inside] == [(amount, False)] * 2
    assert [served(p) for p in outside] == [nothing] * 3
    assert thread.fill(ctx, "Awarded: {award} XE.", t) == "Awarded:  XE."
    # patched, and then approved: the tier is public by now, the award is not
    await tsvc.set_status(ctx, db, team, t, "patched")
    assert tsvc.to_dict(ctx, t, authz.ANON)["assessed_tier"] == "high"
    assert [served(p) for p in outside] == [nothing] * 3
    await tsvc.set_award(ctx, db, team, t, None, approve=True)
    assert t.status == "patched" and t.award_approved_at is not None and not tsvc.award_published(t)
    assert [served(p) for p in inside] == [(amount, True)] * 2
    assert [served(p) for p in outside] == [nothing] * 3
    assert card() == [] and await tsvc.leaderboard(db) == []
    # a template or a draft filled before the move names no amount
    assert thread.fill(ctx, "Awarded: {award} XE.", t) == "Awarded:  XE."
    # the log says an award was set and changed, and not what it is or whether it is approved
    assert await logged() == [{"ticket": t.id}] * 2
    full = [e.payload for e in await EventLog.page(db, 0, 50, ref=t.id) if e.kind == "ticket.award"]
    assert {p["award_xe"] for p in full} == {amount} and {p["tier"] for p in full} == {"high"}
    # a tier re-ruled under the approved award takes the approval back: the log names the tier as a
    # held fact that changed and says nothing of the approval
    await tsvc.set_facts(ctx, db, team, t, {"assessed_tier": "medium"})
    assert t.award_approved_at is None
    facts = [e for e in await EventLog.page(db, 0, 50, ref=t.id) if e.kind == "ticket.facts"]
    reruled = [e for e in facts if "award_approved" in e.payload["changes"]]
    assert len(reruled) == 1 and reruled[0].public
    seen = event_to_dict(reruled[0], full=False)["payload"]
    assert seen["changes"] == {} and seen["held"] == ["assessed_tier"]
    await tsvc.set_award(ctx, db, team, t, None, approve=True)

    # `awarded` publishes it: the row, the card and the leaderboard carry it; the log still does not
    await tsvc.set_status(ctx, db, team, t, "awarded")
    assert tsvc.award_published(t)
    assert [served(p) for p in inside + outside] == [(amount, True)] * 5
    assert card() == ["5 XE"]
    assert [(row["reporter_id"], row["award_xe"]) for row in await tsvc.leaderboard(db)] == [(r.id, amount)]
    assert await logged() == [{"ticket": t.id}] * 3
    assert thread.fill(ctx, "Awarded: {award} XE.", t) == "Awarded: 5 XE."
    # a question is never awarded, whatever its row says
    t.kind = "support"
    assert not tsvc.award_published(t) and served(authz.ANON) == nothing
    t.kind = "bounty"

    # the templates: outside the team's own pages an award is read from `shown_award` (the ticket
    # page's `award`) or behind `award_published`; the leaderboard's rows are awarded ones already
    pages = ROOT / "desk" / "templates"
    for page in sorted(pages.rglob("*.html")):
        if "team" in page.relative_to(pages).parts or page.name == "leaderboard.html":
            continue
        for n, line in enumerate(page.read_text().splitlines(), 1):
            if re.search(r"\.award_xe|\.award_approved", line):
                assert "award_published(t)" in line, f"{page.name}:{n}"
    ticket_page = (pages / "ticket.html").read_text()
    assert "award[0]" in ticket_page and "t.award_" not in ticket_page
    assert "tsvc.shown_award(t, p)" in inspect.getsource(ui.ticket_page)


async def test_a_withdrawn_report_keeps_its_assessment_held(ctx, db):
    """The rule ("Who sees the facts" in the guide): the team's assessment of a confirmed, unfixed bug
    is not published. A reporter who withdraws an accepted report closes the ticket and fixes nothing,
    so the assessment stays held on it; asked of each way a reader outside the team gets a tier, a
    verdict or the tracker link. A ticket the team closes with a ruling publishes it, as before."""
    team = await _team(ctx, db)
    r = await rsvc.from_email(ctx, db, "olga@example.org", link_to=None)
    body = "What I did, what happened, what I expected; enough words to pass the body check."
    ruling = {"assessed_tier": "high", "verdict": "valid", "internal_ref": "#77"}

    async def accepted(title):
        f = rsvc.Filing(kind="bounty", title=title, body=body, claimed_tier="medium")
        t = await rsvc.file_ticket(ctx, db, r, f)
        await tsvc.set_facts(ctx, db, team, t, ruling)
        for status in ("triaging", "accepted"):
            await tsvc.set_status(ctx, db, team, t, status)
        return t

    def public(t):
        d = tsvc.to_dict(ctx, t, authz.ANON)
        return d["assessed_tier"], d["verdict"], d["internal_ref"], d["internal_url"]

    async def found(p, **filt):
        rows = await tsvc.list_tickets(db, ctx.config, p, tsvc.Filters(status="all", **filt))
        return {x.id for x in rows}

    held, ruled = await accepted("Ledger accepts a negative lease"), await accepted("Peer list never expires")
    nothing = (None, None, "", None)
    assert public(held) == nothing and public(ruled) == nothing  # accepted: held, as ever
    await rsvc.withdraw(ctx, db, r, held, "changed my mind")
    await tsvc.set_status(ctx, db, team, ruled, "closed", closed_reason="out-of-scope")
    assert (held.status, held.closed_reason) == ("closed", "withdrawn")
    # the row, as every page and the API ask it
    assert tsvc.assessment_held(held) and not tsvc.assessment_held(ruled)
    assert public(held) == nothing and public(ruled)[:3] == ("high", "valid", "#77")
    assert tsvc.shown_tier(held, authz.ANON) == "medium" and tsvc.shown_tier(ruled, authz.ANON) == "high"
    assert tsvc.to_dict(ctx, held, team)["assessed_tier"] == "high"  # the team sees its own ruling
    # the same rule as SQL: a public filter matches the claim on a held ticket, never the assessment
    assert await found(authz.ANON, tier="high") == {ruled.id}
    assert await found(authz.ANON, tier="medium") == {held.id}
    assert await found(authz.ANON, verdict="valid") == {ruled.id}
    assert await found(team, tier="high") == await found(team, verdict="valid") == {held.id, ruled.id}
    # reopened and fixed, it is published like any other
    for status in ("triaging", "accepted", "patched"):
        await tsvc.set_status(ctx, db, team, held, status)
    assert public(held)[:3] == ("high", "valid", "#77") and await found(authz.ANON, tier="high") == {
        held.id, ruled.id
    }


async def test_support_questions_take_topics_not_areas(ctx, db):
    r = await rsvc.from_email(ctx, db, "gail@example.org", link_to=None)
    body = "I wrote the seed down when I made the wallet but the paper is gone. Is there any way back in?"
    f = rsvc.Filing(kind="support", title="I have lost my key", body=body, area="wallet-keys")
    t = await rsvc.file_ticket(ctx, db, r, f)
    assert t.kind == "support" and t.area == "wallet-keys" and t.visibility == "public"
    # a bounty area is not a topic; it is dropped on filing and refused on edit
    f2 = rsvc.Filing(kind="support", title="When does the token launch", body=body, area="consensus")
    assert (await rsvc.file_ticket(ctx, db, r, f2)).area is None
    team = await _team(ctx, db)
    with pytest.raises(HTTPException):
        await tsvc.set_facts(ctx, db, team, t, {"area": "consensus"})
    await tsvc.set_facts(ctx, db, team, t, {"area": "safety"})
    assert t.area == "safety"
    # the support outbox is its own list: a question closed as answered with no answer written
    await tsvc.set_status(ctx, db, team, t, "triaging")
    await tsvc.set_status(ctx, db, team, t, "closed", closed_reason="answered")
    assert [x.id for x in await tsvc.outbox(db, ctx.config, team, kind="support")] == [t.id]
    assert await tsvc.outbox(db, ctx.config, team) == []  # the bounty outbox never shows a question
    await thread.add_reply(ctx, db, team, t, "A seed cannot be recovered by anyone; a new wallet is the way.")
    assert await tsvc.outbox(db, ctx.config, team, kind="support") == []


async def test_payout_binding_needs_matching_key(ctx, db):
    r = await rsvc.from_email(ctx, db, "erin@example.org", link_to=None)
    body = "A public report with enough body to be accepted by the filing checks, no secrets inside."
    f = rsvc.Filing(kind="bounty", title="Typo on the faucet page", body=body)
    t = await rsvc.file_ticket(ctx, db, r, f)
    kp, wrong = KeyPair.generate(), KeyPair.generate()
    v = await verify_signed(db, _signed(kp, DOMAIN_PAYOUT, {"address": wrong.address}), DOMAIN_PAYOUT)
    with pytest.raises(HTTPException) as e:
        await rsvc.bind_payout(ctx, db, r, v)
    assert e.value.status_code == 400
    v = await verify_signed(db, _signed(kp, DOMAIN_PAYOUT, {"address": kp.address}), DOMAIN_PAYOUT)
    out = await rsvc.bind_payout(ctx, db, r, v)
    assert out == {"address": kp.address, "tickets_updated": 1}
    assert r.xe_address == kp.address and t.payout_address == kp.address
    # an address is 64 hex like a seed; pasted as one it yields a key anyone can derive (XS-0008)
    trap = KeyPair.from_seed_hex(kp.address)
    v = await verify_signed(db, _signed(trap, DOMAIN_PAYOUT, {"address": trap.address}), DOMAIN_PAYOUT)
    with pytest.raises(HTTPException) as e:
        await rsvc.bind_payout(ctx, db, r, v)
    assert e.value.status_code == 400 and "public address" in e.value.detail
    assert r.xe_address == kp.address
    # the reporter can take the address off again; unpaid tickets lose it, and twice is a 409
    assert await rsvc.unbind_payout(ctx, db, r) == {"tickets_updated": 1}
    assert r.xe_address == "" and t.payout_address == "" and r.payout_proof == {}
    with pytest.raises(HTTPException) as e:
        await rsvc.unbind_payout(ctx, db, r)
    assert e.value.status_code == 409
    v = await verify_signed(db, _signed(kp, DOMAIN_PAYOUT, {"address": kp.address}), DOMAIN_PAYOUT)
    await rsvc.bind_payout(ctx, db, r, v)
    # the payout export lists tickets at awarded with the bound address, and nothing before that
    team = await _team(ctx, db)
    await tsvc.set_status(ctx, db, team, t, "triaging")
    t.assessed_tier, t.award_xe, t.award_approved_at = "minor", 5_000_000, utcnow()
    await db.flush()
    assert await rsvc.payout_rows(db) == []  # approved while triaging is not payable (XE-0300)
    for st in ("accepted", "patched", "awarded"):
        await tsvc.set_status(ctx, db, team, t, st)
    rows = await rsvc.payout_rows(db)
    assert rows and rows[0]["ticket"] == t.id and rows[0]["status"] == "awarded"
    assert rows[0]["award_xe"] == 5_000_000 and rows[0]["xe_address"] == kp.address
    assert rows[0]["stamped_address"] == kp.address and not rows[0]["address_changed"]
    # a rebind after the award refreshes the stamp: one address in both treasurer views (XE-0711)
    kp2 = KeyPair.generate()
    v = await verify_signed(db, _signed(kp2, DOMAIN_PAYOUT, {"address": kp2.address}), DOMAIN_PAYOUT)
    assert (await rsvc.bind_payout(ctx, db, r, v))["tickets_updated"] == 1
    rows = await rsvc.payout_rows(db)
    assert rows[0]["xe_address"] == kp2.address == rows[0]["stamped_address"] == t.payout_address
    # reporter-written cells never start a formula in the treasurer's spreadsheet (XE-0714)
    assert rsvc.csv_cell("=HYPERLINK(1)") == "'=HYPERLINK(1)" and rsvc.csv_cell("plain") == "plain"
    assert rsvc.csv_cell("-1") == "'-1" and rsvc.csv_cell(5) == "5" and rsvc.csv_cell(None) == ""


async def test_hex_in_a_signed_request_has_one_spelling(ctx, db):
    """The rule (XE-2215; XE-0699 on the DAO's copy): a key or a signature in a signed request is exactly
    its length in hex digits. Asked of every layer that reads one, so no layer leans on another: the
    request model both signed routes take, the decoders in `xe/`, and `verify_signed`, which must refuse
    before it writes the replay row. `bytes.fromhex` takes whitespace; none of these may."""
    import inspect
    import typing

    from pydantic import ValidationError

    from desk.main import app
    from desk.models import SeenSignature
    from xe import encoding, statechain
    from xe.keys import KeyError_, derive_address, is_hex, verify_hex_signature

    def respell(h):
        return [
            h[:2] + " " + h[2:], " " + h, h + " ", h + "\n", h[:-2] + "\t" + h[-2:],  # fromhex reads these
            "0x" + h, h[:-2], h + "00", "g" + h[1:], "",
            # the right length and not ASCII hex: what a later `\d`, `(?i)` or `$` would let through
            "\u0661" + h[1:], "\uff21" + h[1:], h[:-1] + "\n",
        ]

    kp = KeyPair.generate()
    good = _signed(kp, DOMAIN_LOGIN, {"host": "bounty.test"})
    target = signing_target(DOMAIN_LOGIN, good.payload, good.timestamp)
    base = {"payload": good.payload, "timestamp": good.timestamp}
    bad = [{"pub_key": k, "signature": good.signature} for k in respell(good.pub_key)]
    bad += [{"pub_key": good.pub_key, "signature": s} for s in respell(good.signature)]
    assert len(bad) == 26
    for fields in bad:
        with pytest.raises(ValidationError):  # the request model: a 422 at the route, before any handler
            SignedRequest(**base, **fields)
        with pytest.raises(KeyError_):  # the decoder, for a caller that did not come through the model
            verify_hex_signature(fields["pub_key"], fields["signature"], target)
        with pytest.raises(HTTPException) as e:
            await verify_signed(db, SignedRequest.model_construct(**base, **fields), DOMAIN_LOGIN)
        assert e.value.status_code == 401
    assert (await db.execute(select(SeenSignature))).scalars().all() == []
    for k in respell(good.pub_key):
        assert not is_hex(k, 32)
        with pytest.raises(KeyError_):
            derive_address(k)
        with pytest.raises(encoding.EncodingError):
            encoding._hex(k, "account")
        with pytest.raises(statechain.StateChainError, match="prev_hash"):
            blk = statechain.StateBlock(index=0, prev_hash=k, ops=[], timestamp=0)
            statechain.marshal_state_canonical(blk)
        with pytest.raises(statechain.StateChainError, match="64 hex"):
            statechain.validate_keyset({"keys": [k], "threshold": 1})
    # both routes that take a signed request take it through the model
    signed = [r for r in _api_routes(app) if "verify_signed(" in inspect.getsource(r.endpoint)]
    assert {r.path for r in signed} == {"/v1/reporter/auth/xe", "/v1/reporter/payout"}
    for r in signed:
        assert SignedRequest in typing.get_type_hints(r.endpoint).values(), r.path
    # either case is hex; it is one signature and one key, stored in one spelling
    upper = {"pub_key": good.pub_key.upper(), "signature": good.signature.upper()}
    v = await verify_signed(db, SignedRequest(**base, **upper), DOMAIN_LOGIN)
    assert (v.account, v.pub_key, v.signature) == (kp.address, kp.pub_key_hex, good.signature)
    with pytest.raises(HTTPException) as e:
        await verify_signed(db, good, DOMAIN_LOGIN)
    assert e.value.status_code == 409
    r = await rsvc.from_xe(ctx, db, v, link_to=None)
    pay = _signed(kp, DOMAIN_PAYOUT, {"address": kp.address})
    shout = SignedRequest(
        payload=pay.payload, timestamp=pay.timestamp, pub_key=pay.pub_key.upper(),
        signature=pay.signature.upper(),
    )
    await rsvc.bind_payout(ctx, db, r, await verify_signed(db, shout, DOMAIN_PAYOUT))
    assert r.payout_proof["pub_key"] == kp.pub_key_hex and r.payout_proof["signature"] == pay.signature


async def test_xe_login_and_identity_merge(ctx, db):
    kp = KeyPair.generate()
    v = await verify_signed(db, _signed(kp, DOMAIN_LOGIN, {"host": "bounty.test"}), DOMAIN_LOGIN)
    a = await rsvc.from_xe(ctx, db, v, link_to=None)
    assert kp.address in a.xe_login_addresses
    # an email account exists separately, with a ticket. Mail never merges: whoever clicks a link proved
    # the mailbox, not the other account (XE-0199)
    b = await rsvc.from_email(ctx, db, "frank@example.org", link_to=None)
    body = "Filed under the email identity before the two accounts were joined together by the reporter."
    f = rsvc.Filing(kind="support", title="Which port does a node use", body=body)
    t = await rsvc.file_ticket(ctx, db, b, f)
    with pytest.raises(HTTPException) as e:
        await rsvc.from_email(ctx, db, "frank@example.org", link_to=a)
    assert e.value.status_code == 409
    # a key signed in the email account's own session does merge: the signer holds both
    v2 = await verify_signed(db, _signed(kp, DOMAIN_LOGIN, {"host": "bounty.test"}), DOMAIN_LOGIN)
    merged = await rsvc.from_xe(ctx, db, v2, link_to=b)
    assert merged.id == b.id and kp.address in merged.xe_login_addresses
    await db.refresh(t)
    assert t.reporter_id == b.id
    assert (await rsvc.get(db, a.id)).xe_login_addresses == []  # emptied, kept so old log entries resolve
    a = b
    # link tokens: one use, then gone
    raw = await auth.create_reporter_link(db, "frank@example.org", a.id, "/my")
    link = await auth.consume_reporter_link(db, raw)
    assert link is not None and link.reporter_id == a.id and link.next_path == "/my"
    assert await auth.consume_reporter_link(db, raw) is None


async def test_a_recycled_github_login_cannot_claim_a_bound_row(ctx, db):
    victim = await rsvc.from_github(ctx, db, {"id": 1111, "login": "ghost", "name": "G"}, "", link_to=None)
    # the login lookup only claims rows no GitHub identity has signed in to (XE-0228)
    assert await rsvc.by_github(db, 9999, "ghost") is None
    other = await rsvc.from_github(ctx, db, {"id": 9999, "login": "ghost", "name": "X"}, "", link_to=None)
    assert other.id != victim.id and victim.github_id == 1111
    # and a row with one GitHub identity never takes a second
    with pytest.raises(HTTPException) as e:
        await rsvc.from_github(ctx, db, {"id": 4242, "login": "ghost2"}, "", link_to=victim)
    assert e.value.status_code == 409
    # an imported row (login only) is still claimed on first sign-in
    imported = await sync.reporter_for(ctx, db, {"id": None, "login": "newcomer"})
    assert imported.github_id is None
    claimed = await rsvc.from_github(ctx, db, {"id": 5, "login": "newcomer"}, "", link_to=None)
    assert claimed.id == imported.id and claimed.github_id == 5


async def test_disclosing_by_any_route_unseals_and_publishes(ctx, db):
    team = await _team(ctx, db)
    spec = tsvc.NewTicket(
        kind="bounty", title="sealed", body="the exploit", visibility="private", source="web"
    )
    t = await tsvc.create(ctx, db, team.actor, spec)
    for st in ("triaging", "accepted", "patched"):
        await tsvc.set_status(ctx, db, team, t, st)
    await thread.add_patch_ref(ctx, db, team, t, repo="xeprotocol/xe", ref="9", kind="pr")
    # a private report is not awarded, by force either: it is disclosed first (XE-0310, XE-2250)
    t.assessed_tier = t.assessed_tier or "medium"  # an award needs a tier (XE-0470)
    await tsvc.set_award(ctx, db, team, t, 5_000_000, approve=True)
    with pytest.raises(HTTPException):
        await tsvc.set_status(ctx, db, team, t, "awarded", force=True)
    assert t.status == "patched" and await tsvc.leaderboard(db) == []
    # a walked path (what a proposal adopts) reaches disclosed through set_status, which is the one
    # disclosure path: visibility flips, the body leaves the vault, the public event is written (XE-0210)
    path = await tsvc.set_status_via_path(ctx, db, team, t, "disclosed", via="proposal:1")
    assert path == ["disclosed"]
    assert t.visibility == "public" and t.body == "the exploit" and t.body_sealed is None
    kinds = [e.kind for e in await EventLog.page(db, 0, 20, ref=t.id, public_only=True)]
    assert "ticket.disclosed" in kinds
    # javascript: never reaches an href (XE-0234 A)
    with pytest.raises(HTTPException):
        await thread.add_patch_ref(
            ctx, db, team, t, repo="xeprotocol/xe", ref="10", kind="pr", url="javascript:1"
        )


async def test_an_award_is_public(ctx, db):
    """The rule (XE-2250, XE-0911): an awarded or paid ticket is public. Asked of every way a status is
    written (the ticket page, force, a walked path, an adopted proposal, the desk itself) and of the one
    way a ticket goes private; settle, which discloses first, is the way through."""
    team = await _team(ctx, db)
    agent = await _agent(ctx, db, team.user)
    upto = ("triaging", "accepted", "patched")

    async def mk(title, last="patched"):
        spec = tsvc.NewTicket(
            kind="bounty", title=title, body="the exploit", visibility="private", source="web"
        )
        t = await tsvc.create(ctx, db, team.actor, spec)
        for st in upto[: upto.index(last) + 1]:
            await tsvc.set_status(ctx, db, team, t, st)
        t.assessed_tier = "medium"
        if last == "patched":
            await thread.add_patch_ref(ctx, db, team, t, repo="xeprotocol/xe", ref=t.id[-4:], kind="pr")
            await tsvc.set_award(ctx, db, team, t, 5_000_000, approve=True)
        return t

    sealed, early = await mk("sealed, patched, approved"), await mk("sealed, accepted", last="accepted")
    pr = await psvc.propose(ctx, db, agent, sealed, "status", "awarded", "fix merged, award approved")
    moves = {
        "the ticket page": lambda: tsvc.set_status(ctx, db, team, sealed, "awarded"),
        "by force": lambda: tsvc.set_status(ctx, db, team, sealed, "awarded", force=True),
        "the desk itself": lambda: tsvc.set_status(ctx, db, authz.SYSTEM, sealed, "awarded"),
        "a walked path": lambda: tsvc.set_status_via_path(ctx, db, team, sealed, "awarded"),
        "a walked path from further back": lambda: tsvc.set_status_via_path(ctx, db, team, early, "awarded"),
        "an adopted proposal": lambda: psvc.decide(ctx, db, team, pr, True),
    }
    for name, move in moves.items():
        with pytest.raises(HTTPException) as e:
            await move()
        assert e.value.status_code == 409 and "disclose it first" in e.value.detail, name
        # refused before anything moved: the walk from accepted did not stop at patched
        assert (sealed.status, sealed.visibility, early.status) == ("patched", "private", "accepted"), name
    assert pr.state == "pending" and await rsvc.payout_rows(db) == []
    # the way through: disclosed, then awarded
    assert await tsvc.settle(ctx, db, team, sealed) == ["disclose", "awarded"]
    assert (sealed.status, sealed.visibility) == ("awarded", "public")
    assert [r["ticket"] for r in await rsvc.payout_rows(db)] == [sealed.id]
    # and it stays public: awarded or paid, it is not sealed again
    for status in tsvc.AWARD_STATUSES:
        if status == "paid":
            await tsvc.mark_paid(ctx, db, team, sealed, "tx-1")
        assert sealed.status == status
        with pytest.raises(HTTPException) as e:
            await tsvc.set_facts(ctx, db, team, sealed, {"visibility": "private"})
        assert e.value.status_code == 409 and sealed.visibility == "public", status
    assert sealed.body == "the exploit" and sealed.body_sealed is None
    # paid is an award status too: not reached on a sealed report, by force either
    with pytest.raises(HTTPException) as e:
        await tsvc.set_status(ctx, db, team, early, "paid", force=True)
    assert e.value.status_code == 409 and (early.status, early.visibility) == ("accepted", "private")
    # a report sealed again after its disclosure is not stranded: the page says disclose, not award;
    # awarding is refused; disclosing again unseals it, and settle walks both steps
    again = await mk("disclosed, then sealed again")
    await tsvc.disclose(ctx, db, team, again)
    await tsvc.set_facts(ctx, db, team, again, {"visibility": "private"})
    assert (again.status, again.visibility, again.body) == ("disclosed", "private", "")
    told = again.status_changed_at
    assert tsvc.award_next_step(again)[1] is None and tsvc.settle_steps(again) == ["disclose", "awarded"]
    with pytest.raises(HTTPException) as e:
        await tsvc.set_status(ctx, db, team, again, "awarded")
    assert e.value.status_code == 409 and "disclose it first" in e.value.detail
    await tsvc.disclose(ctx, db, team, again)
    assert (again.status, again.visibility, again.body) == ("disclosed", "public", "the exploit")
    assert again.status_changed_at == told  # the status did not move, so nobody is owed a word for it
    assert tsvc.award_next_step(again)[1] == "awarded"
    await tsvc.set_facts(ctx, db, team, again, {"visibility": "private"})
    assert await tsvc.settle(ctx, db, team, again) == ["disclose", "awarded"]
    assert (again.status, again.visibility) == ("awarded", "public")
    # a row that was awarded and private before the rule is left to be paid, and to nothing else
    old = await mk("awarded while sealed, before the rule")
    old.status = "awarded"
    await tsvc.mark_paid(ctx, db, team, old, "tx-2")
    assert (old.status, old.visibility) == ("paid", "private")
    # and no ticket is born at any status but new: `create` takes none
    assert "status" not in inspect.signature(tsvc.create).parameters


async def test_settling_walks_a_patched_report_to_awarded_through_the_same_paths(ctx, db):
    # the rule: settle does only what the ticket page's three buttons do, with their checks, and a
    # refused ticket in a batch is left exactly as it was
    team = await _team(ctx, db)
    reviewer = await _team(ctx, db, roles=("reviewer",), email="rev@xe.network")

    async def mk(title, visibility="public", amount=5_000_000, patch=True, upto="patched"):
        spec = tsvc.NewTicket(kind="bounty", title=title, body="b", visibility=visibility, source="web")
        t = await tsvc.create(ctx, db, team.actor, spec)
        for st in ("triaging", "accepted", "patched"):
            await tsvc.set_status(ctx, db, team, t, st)
            if st == upto:
                break
        if patch:
            await thread.add_patch_ref(ctx, db, team, t, repo="xeprotocol/xe", ref=t.id[-4:], kind="pr")
        t.assessed_tier = "medium"
        if amount is not None:
            await tsvc.set_award(ctx, db, team, t, amount)
        return t

    pub = await mk("public, set")
    prv = await mk("private, set", visibility="private")
    approved = await mk("public, approved")
    await tsvc.set_award(ctx, db, team, approved, None, approve=True)
    nopatch = await mk("private, no patch", visibility="private", patch=False)
    unset = await mk("public, no amount", amount=None)
    early = await mk("accepted, set", upto="accepted")
    await db.commit()

    # the view: patched or disclosed with an amount; the unset and the not-yet-patched are elsewhere
    ready = {t.id for t in await tsvc.awards_ready(db, ctx.config, team)}
    assert ready == {pub.id, prv.id, approved.id, nopatch.id}
    assert tsvc.settle_steps(pub) == ["approve", "awarded"]
    assert tsvc.settle_steps(prv) == ["approve", "disclose", "awarded"]
    assert tsvc.settle_steps(approved) == ["awarded"]

    # a reviewer may not approve, so cannot settle an unapproved one; a treasurer-less approved one is a
    # status change, which any team member may make
    with pytest.raises(HTTPException):
        await tsvc.settle(ctx, db, reviewer, pub)
    assert await tsvc.settle(ctx, db, reviewer, approved) == ["awarded"]
    assert approved.status == "awarded"

    # ids read before the batch: a savepoint rollback expires the refused rows, and a lazy load of an
    # expired attribute here is the MissingGreenlet of XE-0862
    pub_id, prv_id, np_id, un_id, ea_id = pub.id, prv.id, nopatch.id, unset.id, early.id
    out = await tsvc.settle_many(ctx, db, team, [pub_id, prv_id, np_id, un_id, ea_id, "XE-9999"])
    done = {d["ticket"]: d["steps"] for d in out["settled"]}
    assert done == {pub_id: ["approve", "awarded"], prv_id: ["approve", "disclose", "awarded"]}
    why = {s["ticket"]: s["why"] for s in out["skipped"]}
    assert set(why) == {np_id, un_id, ea_id, "XE-9999"}
    assert "linked patch" in why[np_id] and "nothing to approve" in why[un_id]
    assert "accepted" in why[ea_id] and why["XE-9999"] == "no such ticket"
    for t in (pub, prv, nopatch, unset, early):
        await db.refresh(t)
    assert (pub.status, prv.status, prv.visibility) == ("awarded", "awarded", "public")
    assert pub.award_approved_by == team.user.id and prv.body == "b" and prv.body_sealed is None
    # the refused private one kept its approval state, status and seal: nothing half-done
    assert (nopatch.status, nopatch.award_approved_at, nopatch.visibility) == ("patched", None, "private")
    assert (unset.status, early.status) == ("patched", "accepted")
    # every hop is in the log under the person, via settle
    evs = await EventLog.page(db, 0, 50, ref=prv.id)
    kinds = [(e.kind, e.payload.get("via")) for e in evs]
    assert ("ticket.status", "settle") in kinds and ("ticket.disclosed", None) in kinds
    assert all(e.actor == team.actor for e in evs)
    # settled once, there is nothing to settle again
    with pytest.raises(HTTPException):
        await tsvc.settle(ctx, db, team, pub)


async def test_marking_awarded_tells_the_reporter_by_every_path(ctx, db, monkeypatch):
    # the rule: a person marking a ticket awarded sends the programme's award reply under their name,
    # whichever path made the move; a move with nobody behind it, or an award of nothing, is left to
    # the outbox; the mail goes only for a reply that was committed
    mails: list[tuple[str, str, str]] = []

    async def fake_mail(settings, to, subject, body):
        mails.append((to, subject, body))
        return True

    monkeypatch.setattr(auth, "send_mail", fake_mail)
    ctx.settings.smtp_host = "mail.test"
    team = await _team(ctx, db)
    agent = await _agent(ctx, db, team.user)
    alice = await rsvc.from_email(ctx, db, "alice@example.org", link_to=None)
    alice_id, team_uid = alice.id, team.user.id

    async def ready(t, amount=5_000_000, approve=True):
        for st in ("triaging", "accepted", "patched"):
            await tsvc.set_status(ctx, db, team, t, st)
        await thread.add_patch_ref(ctx, db, team, t, repo="xeprotocol/xe", ref=t.id[-4:], kind="pr")
        t.assessed_tier = "medium"
        await tsvc.set_award(ctx, db, team, t, amount, approve=True if approve else None)
        return t

    async def mk(title, visibility="public", **kw):
        spec = tsvc.NewTicket(
            kind="bounty", title=title, body="b", visibility=visibility, source="web", reporter_id=alice_id
        )
        return await ready(await tsvc.create(ctx, db, team.actor, spec), **kw)

    async def replies(t):
        q = select(Reply).where(Reply.ticket_id == t.id).order_by(Reply.id.asc())
        return list((await db.execute(q)).scalars().all())

    page = await mk("the ticket page")
    page.draft = "half a thought"
    settled = await mk("settle, private", visibility="private", approve=False)
    batch = await mk("settle all", approve=False)
    proposed = await mk("an adopted proposal")
    pr = await psvc.propose(ctx, db, agent, proposed, "status", "awarded", "fix merged, award approved")
    hub, _ = await sync.upsert_issue(ctx, db, "xeprotocol/xe", _issue(90, "From GitHub"))
    await ready(hub)
    nobody = await mk("moved by the desk itself")
    nothing = await mk("an award of nothing", amount=0)
    batch_id = batch.id

    await tsvc.set_status(ctx, db, team, page, "awarded")
    assert await tsvc.settle(ctx, db, team, settled) == ["approve", "disclose", "awarded"]
    out = await tsvc.settle_many(ctx, db, team, [batch_id])
    assert [d["ticket"] for d in out["settled"]] == [batch_id] and out["skipped"] == []
    assert (await psvc.decide(ctx, db, team, pr, True))["status"] == "awarded"
    await tsvc.set_status(ctx, db, team, hub, "awarded")
    await tsvc.set_status(ctx, db, authz.SYSTEM, nobody, "awarded")
    await tsvc.set_status(ctx, db, team, nothing, "awarded")

    told_ids: list[int] = []
    for t in (page, settled, batch, proposed, hub):
        rs = await replies(t)
        assert len(rs) == 1 and t.status == "awarded", t.title
        r = rs[0]
        body = thread.reply_body(ctx, r)
        assert "Awarded: 5 XE, assessed as Medium." in body, t.title
        assert "https://bounty.test/account" in body and f"https://bounty.test/{t.id}" in body
        assert r.author_id == team_uid and t.told_at >= t.status_changed_at
        told_ids.append(r.id)
    # the private one was disclosed first, so its reply is public like the ticket; a GitHub ticket's is
    # queued for the worker to post as a comment; a reply someone was writing is still on the ticket
    assert (settled.visibility, (await replies(settled))[0].body_sealed) == ("public", None)
    assert (await replies(hub))[0].mirror == "queued" and (await replies(page))[0].mirror == "none"
    assert page.draft == "half a thought"
    # nobody to speak, or nothing to say: no reply, and the outbox holds exactly those
    assert await replies(nobody) == [] and await replies(nothing) == []
    assert {t.id for t in await tsvc.outbox(db, ctx.config, team)} == {nobody.id, nothing.id}

    # the mail: noted on the session as each reply is written, sent only for what was committed
    undone = await mk("rolled back after the reply")
    with pytest.raises(HTTPException):
        async with db.begin_nested():
            await tsvc.set_status(ctx, db, team, undone, "awarded")
            raise HTTPException(409, "the request failed after the reply was written")
    owed = notify.take_owed(db)
    assert owed[:5] == told_ids and len(owed) == 6 and notify.take_owed(db) == []
    await db.commit()
    opener = async_sessionmaker(db.bind, expire_on_commit=False)
    # four reporters with an address are mailed; the GitHub one is told by the comment, the rolled-back
    # reply does not exist, and an id that never did is ignored
    assert await notify.mail_owed(ctx, owed + [10_000_000], opener) == 4
    assert {to for to, _, _ in mails} == {"alice@example.org"} and len(mails) == 4
    assert all("Awarded: 5 XE" in text for _, _, text in mails)
    assert await notify.mail_owed(ctx, [], opener) == 0


async def test_filling_missing_awards_adopts_a_proposal_or_takes_the_step(ctx, db):
    # the rule: a blank amount is filled from the agent's proposal where there is one, else from the
    # named step of the tier's ceiling; an amount already set is never touched; nothing is approved
    team = await _team(ctx, db)
    reviewer = await _team(ctx, db, roles=("reviewer",), email="rev2@xe.network")
    agent = await _agent(ctx, db, team.user)

    async def mk(title, tier="medium", area=None, visibility="public"):
        spec = tsvc.NewTicket(kind="bounty", title=title, body="b", visibility=visibility, source="web")
        t = await tsvc.create(ctx, db, team.actor, spec)
        for st in ("triaging", "accepted", "patched"):
            await tsvc.set_status(ctx, db, team, t, st)
        t.assessed_tier = tier
        t.area = area
        return t

    proposed = await mk("agent proposed")
    why_500 = "reduced: the team found the root cause"
    pr = await psvc.propose(ctx, db, agent, proposed, "award_xe", 500, why_500)
    bare = await mk("no proposal")
    other = await mk("desk finding", tier="minor", area="other")  # a quarter of the step, 50-grain
    notier = await mk("no tier", tier=None)
    taken = await mk("already set")
    await tsvc.set_award(ctx, db, team, taken, 1_000_000)
    hidden = await mk("private, unseen by a reviewer", visibility="private")
    await db.commit()

    standard = ctx.config.award_xe("medium", "standard")
    assert standard == 850 and ctx.config.award_xe("minor", "standard", "other") == 50
    with pytest.raises(HTTPException):
        await psvc.fill_awards(ctx, db, team, [bare.id], "generous")
    # a reviewer has no award role: nothing is filled, each is reported, none raised
    out = await psvc.fill_awards(ctx, db, reviewer, [bare.id, proposed.id], "standard")
    assert out["filled"] == [] and len(out["skipped"]) == 2

    ids = [proposed.id, bare.id, other.id, notier.id, taken.id, hidden.id]
    # the ids as a caller may spell them: the proposal on `proposed` is found under any of them
    out = await psvc.fill_awards(ctx, db, team, [f" {ids[0].lower()} "] + ids[1:] + ["xe-9999"], "standard")
    got = {f["ticket"]: (f["award_xe"], f["from"]) for f in out["filled"]}
    assert got == {
        proposed.id: (500_000_000, f"proposal #{pr.id}"),
        bare.id: (standard * 1_000_000, "standard step"),
        other.id: (50_000_000, "standard step"),
        hidden.id: (standard * 1_000_000, "standard step"),
    }
    why = {s["ticket"]: s["why"] for s in out["skipped"]}
    assert "assessed tier" in why[notier.id] and why[taken.id] == "already has an amount"
    assert why["XE-9999"] == "no such ticket"
    for t in (proposed, bare, other, notier, taken, hidden):
        await db.refresh(t)
    assert (taken.award_xe, notier.award_xe) == (1_000_000, None)
    assert all(t.award_approved_at is None for t in (proposed, bare, other, taken, hidden))
    await db.refresh(pr)
    assert pr.state == "adopted"
    # the step is on the record for the team and held from the public log with the tier
    evs = [e for e in await EventLog.page(db, 0, 20, ref=bare.id) if e.kind == "ticket.award"]
    assert evs and evs[0].payload["step"] == "standard"
    assert "step" not in public_payload("ticket.award", evs[0].payload)
    # a second pass finds nothing blank
    again = await psvc.fill_awards(ctx, db, team, ids, "standard")
    assert again["filled"] == [] and all(s["why"] == "already has an amount" for s in again["skipped"]
                                         if s["ticket"] != notier.id)


async def test_payout_file_lists_only_awarded_tickets(ctx, db):
    team = await _team(ctx, db)
    async def mk(n):
        return await tsvc.create(ctx, db, team.actor, tsvc.NewTicket(kind="bounty", title=n, source="web"))

    live, closed, paid = await mk("live"), await mk("closed"), await mk("paid")
    for t in (live, closed, paid):
        for st in ("triaging", "accepted", "patched"):
            await tsvc.set_status(ctx, db, team, t, st)
        t.assessed_tier = t.assessed_tier or "medium"  # an award needs a tier (XE-0470)
        await tsvc.set_award(ctx, db, team, t, 1_000_000, approve=True)
        await tsvc.set_status(ctx, db, team, t, "awarded")
    await tsvc.set_status(ctx, db, team, closed, "closed", closed_reason="invalid", force=True)
    paid.paid_ref = "tx"
    await tsvc.set_status(ctx, db, team, paid, "paid")
    rows = await rsvc.payout_rows(db)
    assert [r["ticket"] for r in rows] == [live.id] and rows[0]["status"] == "awarded"
    # paid is recorded through mark_paid, treasurer only, awarded only; the record does not walk back
    live.assessed_tier = "minor"
    with pytest.raises(HTTPException) as e:
        await tsvc.mark_paid(ctx, db, team, closed, "tx2")
    assert e.value.status_code == 409
    await tsvc.mark_paid(ctx, db, team, live, " tx-abc ")
    assert live.status == "paid" and live.paid_ref == "tx-abc" and await rsvc.payout_rows(db) == []
    with pytest.raises(HTTPException) as e:
        await tsvc.set_status(ctx, db, team, live, "awarded")  # XE-0789
    assert e.value.status_code == 409


async def test_tokens_stop_when_the_owner_leaves_the_team(ctx, db):
    lead = await _team(ctx, db)
    agent = await _agent(ctx, db, lead.user, scopes=("read:public", "read:private", "write:notes"))
    assert agent.token.revoked_at is None
    await users.set_roles(ctx, db, "test", lead.user, [])
    assert agent.token.revoked_at is not None


async def test_making_a_ticket_private_seals_what_arrived_while_public(ctx, db, tmp_path):
    ctx.settings.blob_dir = str(tmp_path)
    team = await _team(ctx, db)
    t, _ = await sync.upsert_issue(ctx, db, "xeprotocol/xe", _issue(77, "public then private", body="b"))
    # a stranger quoting the marker is not the team (XE-0200); the bot login is
    ctx.settings.github_bot_login = "xe-desk-bot"
    mallory = {"id": 1, "user": {"login": "mallory"}, "body": "hi <!-- xe-desk -->"}
    bot = {"id": 2, "user": {"login": "xe-desk-bot"}, "body": "we read it"}
    await sync.upsert_comment(ctx, db, t, mallory)
    await sync.upsert_comment(ctx, db, t, bot)
    msgs = await thread.messages_for(db, t)
    assert [(m.author, m.author_is_team) for m in msgs] == [("mallory", False), ("xe-desk-bot", True)]
    assert msgs[0].body == "hi"
    r = await thread.add_reply(ctx, db, team, t, "queued for github")
    assert r.mirror == "queued"
    await tsvc.set_facts(ctx, db, team, t, {"visibility": "private"})
    msgs = await thread.messages_for(db, t)
    assert all(m.body == "" and m.body_sealed for m in msgs)
    # the reply pulled back from the mirror is sealed with the rest, and still on the thread
    said = sorted(thread.message_body(ctx, t, m) for m in msgs)
    assert said == ["hi", "queued for github", "we read it"]
    await db.refresh(r)
    assert r.mirror == "none"
    assert await sync.queued_replies(db) == [] or r not in await sync.queued_replies(db)


# ---- chat channels (the bot's database side) --------------------------------------------------------------


def _post(uid="1001", **kw) -> channels.ChannelPost:
    base = dict(
        platform="discord",
        thread_ref="555",
        thread_url="https://discord.com/channels/1/2/555",
        user_id=uid,
        user_name="Ada",
        user_handle="ada",
        title="When does the token launch",
        body="Saw a date in a Telegram group; is it real?",
        topic="launch-token",
    )
    base.update(kw)
    return channels.ChannelPost(**base)


async def test_discord_thread_becomes_a_support_ticket(ctx, db):
    t = await channels.open_from_channel(ctx, db, _post())
    await db.commit()
    assert t.kind == "support" and t.source == "discord" and t.source_ref == "555"
    assert t.area == "launch-token" and t.channel_state == "open" and t.visibility == "public"
    r = await channels.by_platform(db, "discord", "1001")
    assert r is not None and r.id == t.reporter_id and r.platform_ids["discord_handle"] == "ada"
    assert (await channels.ticket_for(db, "discord", "555")).id == t.id
    # the same person asking again is the same reporter
    t2 = await channels.open_from_channel(ctx, db, _post(thread_ref="556", title="And where is the wallet"))
    assert t2.reporter_id == r.id
    # the bot's lines come from the public register with the ticket filled in
    created = channels.bot_text(ctx, "created", t)
    assert t.id in created and "support.test" in created


async def test_discord_messages_thread_and_move_status(ctx, db):
    t = await channels.open_from_channel(ctx, db, _post())
    team = await _team(ctx, db)
    # the team's first word in the thread starts triage
    m = await channels.incoming(
        ctx, db, t, message_ref="m1", user_id="9", user_name="Bea", body="Looking.", is_team=True
    )
    assert m is not None and m.author_is_team and t.status == "triaging"
    # idempotent on the platform message id
    tk = dict(user_id="9", user_name="Bea", is_team=True)
    again = await channels.incoming(ctx, db, t, message_ref="m1", body="x", **tk)
    assert again is None
    # needs-info, then the reporter answers: back to triage; a stranger's message does not
    await tsvc.set_status(ctx, db, team, t, "needs-info")
    kw = dict(user_name="x", is_team=False)
    await channels.incoming(ctx, db, t, message_ref="m2", user_id="2002", body="me", **kw)
    assert t.status == "needs-info"
    await channels.incoming(ctx, db, t, message_ref="m3", user_id="1001", body="hi", **kw)
    assert t.status == "triaging"
    msgs = await thread.messages_for(db, t)
    assert [x.source_ref for x in msgs] == ["m1", "m2", "m3"]
    # attachments become lines, an empty message is nothing
    await channels.incoming(
        ctx, db, t, message_ref="m4", user_id="1001", user_name="Ada", body="", is_team=False,
        attachments=["https://cdn/x.png"],
    )
    last = (await thread.messages_for(db, t))[-1]
    assert "Attachment: https://cdn/x.png" in thread.message_body(ctx, t, last)
    blank = await channels.incoming(ctx, db, t, message_ref="m5", user_id="1001", body="  ", **kw)
    assert blank is None


async def test_desk_reply_is_queued_for_the_bot_not_the_worker(ctx, db):
    t = await channels.open_from_channel(ctx, db, _post())
    team = await _team(ctx, db)
    r = await thread.add_reply(ctx, db, team, t, "There is no announced date.")
    assert r.mirror == "queued"
    assert await sync.queued_replies(db) == []  # the worker leaves it alone
    pairs = await channels.queued_replies(db, "discord")
    assert [(x.id, y.id) for x, y in pairs] == [(r.id, t.id)]
    text = channels.reply_text(ctx, t, r)
    assert "XE team" in text and t.id in text
    await channels.mark_mirrored(ctx, db, r, t, message_ref="d9", url="https://discord.com/x")
    assert r.mirror == "sent" and r.mirror_ref == "https://discord.com/x"
    assert [x.source_ref for x in await thread.messages_for(db, t)][-1] == "d9"
    assert await channels.queued_replies(db, "discord") == []


class _Recorder:
    """A GitHub client that takes every write the desk makes and keeps a list of them."""

    enabled = True

    def __init__(self):
        self.writes: list[str] = []

    async def set_labels(self, repo, number, names):
        self.writes.append("labels")
        return list(names)

    async def set_state(self, repo, number, state, state_reason=None):
        self.writes.append("state")
        return {}

    async def comment(self, repo, number, body):
        self.writes.append("comment")
        url = f"https://github.com/{repo}/issues/{number}#issuecomment-1"
        return {"id": 9500 + len(self.writes), "html_url": url, "created_at": "2026-11-09T10:00:00Z"}

    async def create_issue(self, repo, title, body, labels):
        self.writes.append("issue")
        return {"number": 4000 + len(self.writes), "html_url": f"https://github.com/{repo}/issues/4000"}


async def test_nothing_about_a_private_ticket_is_written_to_its_channel(ctx, db):
    """The rule (XE-0299, XE-0700): the desk writes to a ticket's GitHub issue, and to its chat thread,
    only while the ticket is public. Asked of every outbound write the worker and the bot make (label,
    state, reply, the disclosure issue, the thread's closed mark), each beside a public twin that is
    written, so a harness that writes nothing would fail too; and of the source, so a write added to
    `sync` later without the question fails here."""
    import inspect
    import re

    import desk

    team = await _team(ctx, db)
    client = _Recorder()

    async def outbound(t, r):
        client.writes.clear()
        await sync.push_labels(ctx, db, client, t)
        await sync.push_state(ctx, db, client, t)
        await sync.mirror_reply(ctx, db, client, r)
        await sync.open_disclosure(ctx, db, client, t)
        return list(client.writes)

    async def from_github(n, title):
        t, _ = await sync.upsert_issue(ctx, db, "xeprotocol/xe", _issue(n, title, body="b"))
        await tsvc.set_status(ctx, db, team, t, "triaging")
        r = await thread.add_reply(ctx, db, team, t, "Not a bug: the tip is read from the cache.")
        await tsvc.set_status(ctx, db, team, t, "closed", closed_reason="invalid")
        return t, r

    async def disclosed(title):
        spec = tsvc.NewTicket(kind="bounty", title=title, body="the exploit", visibility="private")
        t = await tsvc.create(ctx, db, team.actor, spec)
        for st in ("triaging", "accepted", "patched"):
            await tsvc.set_status(ctx, db, team, t, st)
        await thread.add_patch_ref(ctx, db, team, t, repo="xeprotocol/xe", ref=t.id[-4:], kind="pr")
        await tsvc.set_status(ctx, db, team, t, "disclosed")
        return t, await thread.add_reply(ctx, db, team, t, "Disclosed today.")

    # a GitHub issue the team sealed after closing it: no label, no closed state, no comment
    open_t, open_r = await from_github(140, "Public and closed")
    sealed_t, sealed_r = await from_github(141, "Sealed after it was filed")
    await tsvc.set_facts(ctx, db, team, sealed_t, {"visibility": "private"})
    assert not sync.writes_to_issue(sealed_t) and sync.writes_to_issue(open_t)
    assert [t.id for t in await sync.tickets_needing_push(db)] == [open_t.id]
    assert await outbound(sealed_t, sealed_r) == []
    assert (sealed_t.github_state, sealed_t.github_labels, sealed_r.mirror) == ("open", [], "none")
    assert await outbound(open_t, open_r) == ["labels", "state", "comment"]
    # a private report disclosed and then sealed again before the worker came round: no issue is opened
    back_t, back_r = await disclosed("Disclosed, then sealed again")
    await tsvc.set_facts(ctx, db, team, back_t, {"visibility": "private"})
    out_t, out_r = await disclosed("Disclosed and left so")
    assert await outbound(back_t, back_r) == [] and back_t.source == "web"
    assert await outbound(out_t, out_r) == ["issue"] and out_t.source == "github"
    # a chat thread: the closed mark is not pushed for a sealed ticket
    chat = await channels.open_from_channel(ctx, db, _post(thread_ref="778", title="Lost my key"))
    twin = await channels.open_from_channel(ctx, db, _post(thread_ref="779", title="Which port is it"))
    for t in (chat, twin):
        await tsvc.set_status(ctx, db, team, t, "triaging")
        await thread.add_reply(ctx, db, team, t, "Answered in the thread.")
        await tsvc.set_status(ctx, db, team, t, "closed", closed_reason="answered")
    await tsvc.set_facts(ctx, db, team, chat, {"visibility": "private"})
    assert [t.id for t in await channels.needing_state_push(db, "discord")] == [twin.id]
    assert [t.id for _, t in await channels.queued_replies(db, "discord")] == [twin.id]

    # asked at the write, of the row as it is now. A pass selects its work once, keeps what it loaded
    # and may wait minutes on GitHub before it reaches a ticket; one sealed by someone else meanwhile
    # is still public in the pass's memory, with its text in clear
    late_t, late_r = await from_github(142, "Sealed while the worker was busy")
    late_d, _ = await disclosed("Sealed again while the worker was busy")
    late_post = _post(uid="1002", thread_ref="780", title="Sealed mid-pass")
    late_chat = await channels.open_from_channel(ctx, db, late_post)
    late_chat_r = await thread.add_reply(ctx, db, team, late_chat, "Check the port.")
    await db.commit()
    assert late_t.id in {t.id for t in await sync.tickets_needing_push(db)}
    assert late_r.id in {r.id for r in await sync.queued_replies(db)}
    assert late_chat_r.id in {r.id for r, _ in await channels.queued_replies(db, "discord")}
    await db.commit()
    async with async_sessionmaker(db.bind, expire_on_commit=False)() as other:
        for tid in (late_t.id, late_d.id, late_chat.id):
            await tsvc.set_facts(ctx, other, team, await tsvc.get(other, tid), {"visibility": "private"})
        await other.commit()
    held = (late_t.visibility, late_d.visibility, late_chat.visibility, late_r.mirror, late_chat_r.mirror)
    assert held == ("public", "public", "public", "queued", "queued")  # what the pass still holds
    assert await outbound(late_t, late_r) == []
    assert await sync.open_disclosure(ctx, db, client, late_d) == "" and client.writes == []
    assert not await channels.writes_to_thread(db, late_chat, late_chat_r)
    assert not await channels.writes_to_thread(db, late_chat)
    assert await channels.writes_to_thread(db, twin)
    assert (late_t.visibility, late_r.mirror, late_d.source, late_chat_r.mirror) == (
        "private", "none", "web", "none"
    )

    # every function in sync that writes to GitHub about a ticket re-reads it and asks the question,
    # in that order, before the write
    writers = []
    for name, fn in inspect.getmembers(sync, inspect.iscoroutinefunction):
        src = inspect.getsource(fn)
        write = re.search(r"client\.(set_labels|set_state|comment|create_issue)\(", src)
        if write:
            writers.append(name)
            asked = src[src.index("tsvc.as_it_is_now(db, t"):write.start()]
            assert "writes_to_issue(t)" in asked or 't.visibility != "public"' in asked, name
    assert sorted(writers) == ["mirror_reply", "open_disclosure", "push_labels", "push_state"]
    # and the bot, before the first thing it sends or changes in either loop of its pass
    bot = (Path(desk.__file__).parent / "bots" / "discord_bot.py").read_text()
    once = bot[bot.index("async def mirror_once"):bot.index("# ---- slash commands")]
    loops = once.split("for t in await ch.needing_state_push")
    assert len(loops) == 2
    for loop in loops:
        first_write = min(loop.index("th.send("), loop.index("th.edit("))
        assert loop.index("await ch.writes_to_thread(db, t") < first_write
    # a long reply is several messages: each is asked for, on the line before it is sent
    sends = [m.start() for m in re.finditer(r"th\.send\(", loops[0])]
    assert len(sends) == 1
    before = loops[0][:sends[0]].rstrip().splitlines()[-4:]
    assert before[0].strip() == "if not await ch.writes_to_thread(db, t, r):", before
    assert [ln.strip() for ln in before[1:]] == ["last = None", "break", "last = await"], before
    # GitHub saying wait is neither a send nor a failure: the reply stays queued for a pass that
    # asks again, where a failed one is never retried
    from desk.services.github import GitHubBusy

    class _Throttled(_Recorder):
        async def comment(self, repo, number, body):
            raise GitHubBusy(403, "rate limited; try again in 60s")

    _, busy_r = await from_github(143, "Answered while GitHub was throttling")
    with pytest.raises(GitHubBusy):
        await sync.mirror_reply(ctx, db, _Throttled(), busy_r)
    assert busy_r.mirror == "queued"
    # and nothing is awaited between the disclosure's question and its one write
    asked = inspect.getsource(sync.open_disclosure)
    asked = asked[asked.index('t.visibility != "public"'):asked.index("client.create_issue(")]
    assert asked.count("await") == 1


class _Issues:
    """GitHub's comment endpoint as the worker's client sees it: takes the comment, or refuses it."""

    enabled = True

    def __init__(self):
        self.n, self.refuse = 9000, False

    async def comment(self, repo, number, body):
        if self.refuse:
            raise GitHubError(422, "Validation Failed IssueComment.data: unprocessable")
        self.n += 1
        url = f"https://github.com/{repo}/issues/{number}#issuecomment-{self.n}"
        return {"id": self.n, "html_url": url, "created_at": "2026-11-09T10:00:00Z"}


async def test_a_reply_is_on_the_thread_whatever_the_channel_does(ctx, db):
    # the rule: a reply is on its ticket's thread from the moment it is sent, and once only, whatever
    # the channel then does with it: nothing to mirror, still queued, carried, echoed back, refused,
    # pulled back when the ticket goes private. Every mirror (the worker's, the bot's) goes through it.
    repo = "xeprotocol/xe"
    team = await _team(ctx, db)
    ctx.settings.github_bot_login = "xe-desk-bot"
    client = _Issues()

    async def on_thread(t):
        msgs = await thread.messages_for(db, t)
        rows = [(m.source, m.source_ref, m.author_is_team, thread.message_body(ctx, t, m)) for m in msgs]
        return sorted(rows)

    def bot_says(n, body):
        return {"id": n, "user": {"login": "xe-desk-bot"}, "body": body}

    # a desk ticket: nothing to mirror
    web = await tsvc.create(ctx, db, team.actor, tsvc.NewTicket(kind="bounty", title="filed on the desk"))
    r = await thread.add_reply(ctx, db, team, web, "Read.")
    assert r.mirror == "none" and await on_thread(web) == [("desk", f"reply:{r.id}", True, "Read.")]

    # a GitHub ticket: there while queued, and the same row under the comment's id once carried
    t, _ = await sync.upsert_issue(ctx, db, repo, _issue(130, "Carried"))
    r = await thread.add_reply(ctx, db, team, t, "On its way.")
    assert r.mirror == "queued" and await on_thread(t) == [("desk", f"reply:{r.id}", True, "On its way.")]
    assert await sync.mirror_reply(ctx, db, client, r) is True
    assert r.mirror == "sent" and await on_thread(t) == [("github", "9001", True, "On its way.")]
    # the webhook's echo of that comment is that row, not a second copy
    assert await sync.upsert_comment(ctx, db, t, bot_says(9001, "On its way.")) is False
    assert len(await on_thread(t)) == 1

    # the echo arriving before the worker has recorded the comment: its row stands, the desk's goes
    t2, _ = await sync.upsert_issue(ctx, db, repo, _issue(131, "Echo first"))
    r = await thread.add_reply(ctx, db, team, t2, "Seen twice?")
    assert await sync.upsert_comment(ctx, db, t2, bot_says(9002, "Seen twice?")) is True
    assert len(await on_thread(t2)) == 2
    assert await sync.mirror_reply(ctx, db, client, r) is True
    assert await on_thread(t2) == [("github", "9002", True, "Seen twice?")]

    # refused by GitHub: failed, and still readable here
    t3, _ = await sync.upsert_issue(ctx, db, repo, _issue(132, "Refused"))
    r = await thread.add_reply(ctx, db, team, t3, "GitHub will not take this.")
    client.refuse = True
    assert await sync.mirror_reply(ctx, db, client, r) is False
    client.refuse = False
    assert r.mirror == "failed" and "422" in r.mirror_error
    assert await on_thread(t3) == [("desk", f"reply:{r.id}", True, "GitHub will not take this.")]

    # pulled back when the ticket goes private: sealed with the rest of the thread, still on it
    t4, _ = await sync.upsert_issue(ctx, db, repo, _issue(133, "Goes private"))
    r = await thread.add_reply(ctx, db, team, t4, "Before it was sealed.")
    await tsvc.set_facts(ctx, db, team, t4, {"visibility": "private"})
    await db.refresh(r)
    assert r.mirror == "none" and (await thread.messages_for(db, t4))[0].body == ""
    assert await on_thread(t4) == [("desk", f"reply:{r.id}", True, "Before it was sealed.")]

    # a reply queued before replies were threaded on sending has no row; carried, it gets its one
    t5, _ = await sync.upsert_issue(ctx, db, repo, _issue(134, "Queued before"))
    r = await thread.add_reply(ctx, db, team, t5, "From before.")
    for m in await thread.messages_for(db, t5):
        await db.delete(m)
    await db.flush()
    assert await sync.mirror_reply(ctx, db, client, r) is True
    assert await on_thread(t5) == [("github", "9003", True, "From before.")]

    # a chat thread: the same, by the bot's hand
    q = await channels.open_from_channel(ctx, db, _post())
    r = await thread.add_reply(ctx, db, team, q, "There is no announced date.")
    assert await on_thread(q) == [("desk", f"reply:{r.id}", True, "There is no announced date.")]
    await channels.mark_mirrored(ctx, db, r, q, message_ref="d9")
    assert await on_thread(q) == [("discord", "d9", True, "There is no announced date.")]
    r = await thread.add_reply(ctx, db, team, q, "And a second word.")
    await channels.mark_failed(ctx, db, r, q, "thread not found")
    assert r.mirror == "failed" and [x[:2] for x in await on_thread(q)] == [
        ("desk", f"reply:{r.id}"), ("discord", "d9")
    ]


async def test_reporter_with_an_email_is_told_of_team_replies(ctx, db, monkeypatch):
    sent: list[tuple[str, str, str]] = []

    async def fake_mail(settings, to, subject, body):
        sent.append((to, subject, body))
        return True

    monkeypatch.setattr(auth, "send_mail", fake_mail)
    ctx.settings.smtp_host = "mail.test"
    team = await _team(ctx, db)
    words = "What I did, what happened, and what I expected instead, in enough words to pass the check."

    def filing(title, private):
        return rsvc.Filing(kind="bounty", title=title, body=words, private=private)

    # a key-only reporter: nobody to tell
    kp = KeyPair.generate()
    v = await verify_signed(db, _signed(kp, DOMAIN_LOGIN, {"host": "bounty.test"}), DOMAIN_LOGIN)
    silent = await rsvc.from_xe(ctx, db, v, link_to=None)
    t1 = await rsvc.file_ticket(ctx, db, silent, filing("Quiet report", True))
    assert await notify.reply_to_reporter(ctx, db, t1, team.name, "Looking.") is False
    # an email on the account: a private report gets the fact and the link, not the text
    r = await rsvc.from_email(ctx, db, "alice@example.org", link_to=None)
    t2 = await rsvc.file_ticket(ctx, db, r, filing("Private report", True))
    assert await notify.reply_to_reporter(ctx, db, t2, team.name, "Confirmed, fixing.") is True
    to, subject, body = sent[-1]
    assert to == "alice@example.org" and t2.id in subject and "Confirmed" not in body and t2.id in body
    # and says which account opens it and how to get in: the reader may be signed in to another one,
    # where the link says there is no such ticket (a report sent by email, read by a key's account)
    assert "holds this address (alice@example.org)" in body and "no such ticket" in body
    assert "Sign out, then sign in by email" in body and body.count("/signin") == 1
    assert f"{tsvc.ticket_url(ctx, t2).rsplit('/', 1)[0]}/signin" in body and "signed in as you" not in body
    # the other account is still refused, as it should be: the mail is what gets its holder in
    assert not authz.can_see(authz.Principal(kind="reporter", reporter_id=silent.id), t2)
    assert authz.can_see(authz.Principal(kind="reporter", reporter_id=r.id), t2)
    # a public one carries the text
    t3 = await rsvc.file_ticket(ctx, db, r, filing("Public typo", False))
    assert await notify.reply_to_reporter(ctx, db, t3, team.name, "Fixed in #27.") is True
    assert "Fixed in #27." in sent[-1][2]
    # a Discord-sourced question is told in its thread by the bot, not by mail
    t4 = await channels.open_from_channel(ctx, db, _post())
    assert await notify.reply_to_reporter(ctx, db, t4, team.name, "No date yet.") is False
    # mail off: nothing goes out, nothing breaks
    ctx.settings.smtp_host = ""
    assert await notify.reply_to_reporter(ctx, db, t3, team.name, "Again.") is False


async def test_close_convert_rename_from_the_channel_and_state_push(ctx, db):
    t = await channels.open_from_channel(ctx, db, _post())
    assert await channels.needing_state_push(db, "discord") == []
    assert await channels.close_from_channel(ctx, db, t, user_id="9", reason="stale, no reply") == "stale"
    assert t.status == "closed" and t.closed_reason == "stale" and t.channel_state == "closed"
    assert "Stale" in channels.closed_line(ctx, t) or "stale" in channels.closed_line(ctx, t)
    # closed on the desk instead: the bot finds it and marks the thread
    t2 = await channels.open_from_channel(ctx, db, _post(thread_ref="777", title="Lost my key, any way back"))
    team = await _team(ctx, db)
    await tsvc.set_status(ctx, db, team, t2, "triaging")
    await tsvc.set_status(ctx, db, team, t2, "closed", closed_reason="answered")
    assert [x.id for x in await channels.needing_state_push(db, "discord")] == [t2.id]
    await channels.mark_state(ctx, db, t2, "closed")
    assert await channels.needing_state_push(db, "discord") == []
    await channels.reopen_from_channel(ctx, db, t2, user_id="9")
    assert t2.status == "triaging" and t2.channel_state == "open"
    # a question that is a bug
    new = await channels.rename_from_channel(ctx, db, t2, user_id="9", title="Escrow releases twice")
    assert t2.title == new
    await channels.convert_to_bounty(ctx, db, t2, user_id="9")
    assert t2.kind == "bounty" and t2.area is None
    with pytest.raises(HTTPException):
        await channels.convert_to_bounty(ctx, db, t2, user_id="9")
    assert "proof of concept" in channels.bot_text(ctx, "converted", t2)


async def test_discord_identity_links_to_a_web_account(ctx, db):
    t = await channels.open_from_channel(ctx, db, _post())
    shell = await channels.by_platform(db, "discord", "1001")
    web = await rsvc.from_email(ctx, db, "ada@example.org", link_to=None)
    merged = await channels.from_platform(ctx, db, "discord", "1001", name="Ada", link_to=web)
    assert merged.id == web.id and merged.platform_ids["discord"] == "1001"
    await db.refresh(t)
    assert t.reporter_id == web.id
    assert [x.id for x in await rsvc.my_tickets(db, web)] == [t.id]
    # the merged-away row keeps no platform id, so the next Discord message keys to the live account
    # (XE-0473), and no session or link of the shell survives the merge (XE-0710)
    await db.refresh(shell)
    assert shell.platform_ids == {} and (await channels.by_platform(db, "discord", "1001")).id == web.id
    t2 = await channels.open_from_channel(ctx, db, _post(thread_ref="556"))
    assert t2.reporter_id == web.id


async def test_identities_come_off_an_account_and_other_sessions_end(ctx, db):
    kp = KeyPair.generate()
    v = await verify_signed(db, _signed(kp, DOMAIN_LOGIN, {"host": "bounty.test"}), DOMAIN_LOGIN)
    r = await rsvc.from_xe(ctx, db, v, link_to=None)
    with pytest.raises(HTTPException) as e:
        await rsvc.unlink(ctx, db, r, "xe", kp.address)  # the only way in stays
    assert e.value.status_code == 409
    r = await rsvc.from_email(ctx, db, "pat@example.org", link_to=r)
    assert rsvc.ways_in(r) == 2
    assert (await rsvc.unlink(ctx, db, r, "xe", kp.address))["ways_in"] == 1
    assert r.xe_login_addresses == [] and await rsvc.by_login_address(db, kp.address) is None
    with pytest.raises(HTTPException):
        await rsvc.unlink(ctx, db, r, "xe", kp.address)
    # sessions: this one stays, the others go, and so do outstanding links
    s1, _ = await auth.create_reporter_session(db, r, "email")
    s2, _ = await auth.create_reporter_session(db, r, "email")
    await auth.create_reporter_link(db, "pat@example.org", r.id, "/my")
    assert await rsvc.end_other_sessions(db, r, keep=s1.id) == 1
    from desk.models import ReporterLink, ReporterSession

    left = (await db.execute(select(ReporterSession.id).where(ReporterSession.reporter_id == r.id))).scalars()
    assert list(left) == [s1.id] and s2.id != s1.id
    links = (await db.execute(select(ReporterLink).where(ReporterLink.reporter_id == r.id))).scalars().all()
    assert links == []


async def test_one_time_links_are_claimed_once_and_burn_their_siblings(ctx, db):
    # a reporter link: the first consumer wins, the second gets nothing, and the other outstanding links
    # for the address die with it (XE-0709, XE-0782)
    a = await auth.create_reporter_link(db, "sam@example.org", None, "/my")
    b = await auth.create_reporter_link(db, "sam@example.org", None, "/my")
    assert (await auth.consume_reporter_link(db, a)) is not None
    assert await auth.consume_reporter_link(db, a) is None
    assert await auth.consume_reporter_link(db, b) is None
    # signed out, a link for a known address is a plain sign-in, not one bound to the account (XE-0363)
    r = await rsvc.from_email(ctx, db, "sam@example.org", link_to=None)
    c = await auth.create_reporter_link(db, "sam@example.org", None, "/my")
    link = await auth.consume_reporter_link(db, c)
    assert link.reporter_id is None
    assert (await rsvc.from_email(ctx, db, link.email, link_to=None)).id == r.id
    # team invites: the same rule (XE-0837)
    team = await _team(ctx, db)
    i1 = await auth.create_invite(db, team.user)
    i2 = await auth.create_invite(db, team.user, purpose="magic-link")
    assert (await auth.consume_invite(db, i1)) is not None
    assert await auth.consume_invite(db, i1) is None and await auth.consume_invite(db, i2) is None
    # a deactivated member's sessions are gone, not merely refused (XE-0838)
    s, _ = await auth.create_session(db, team.user)
    await users.set_active(ctx, db, "test", team.user, False)
    from desk.models import Session

    assert (await db.execute(select(Session).where(Session.user_id == team.user.id))).scalars().all() == []
    # lookups with a NUL or a lone surrogate match nothing and raise nothing (XE-0827)
    assert await users.by_email(db, "lead@xe\x00.network") is None
    assert await rsvc.by_email(db, "a\udc80@example.org") is None
    assert auth.safe_next(ctx.settings, "/my\\evil") == "/my" and auth.safe_next(ctx.settings, "/my") == "/my"
    assert auth.safe_next(ctx.settings, "/\\evil.com") == "/my"  # XE-1092


async def test_a_single_use_credential_is_claimed_by_one_statement(ctx, db):
    """The rule (XE-0709, XE-0837, XE-2053, XE-1735): a credential that works once is claimed by one
    conditional write, so of two concurrent uses the second waits on the first and then fails. Checked
    for every single-use credential the desk has, with two connections: the first claims and has not
    committed when the second tries. A claim that reads, checks and then writes lets the second read
    past the first and succeed, and fails here."""
    sm = async_sessionmaker(db.bind, expire_on_commit=False)
    team = await _team(ctx, db)
    uid = team.user.id
    await db.commit()

    async def raced(use):
        """`use(session)` twice: once here, uncommitted, and once on another connection."""
        async def quiet(s):
            try:
                return await use(s)
            except HTTPException:
                return None

        async with sm() as other:
            first = await quiet(db)
            second = asyncio.create_task(quiet(other))
            await asyncio.sleep(0.3)
            waited = not second.done()
            await db.commit()
            got = await second
            await other.rollback()
        return first, waited, got

    # challenges, every kind: the passkey ceremonies, TOTP setup, and both OAuth states
    for kind in ("register", "login", "totp", "oauth", "oauth-discord"):
        cid = await auth._store_challenge(db, kind, b"c", uid)
        await db.commit()
        with pytest.raises(HTTPException):
            await auth.take_challenge(db, cid, "another-kind")  # the wrong kind takes nothing
        first, waited, got = await raced(lambda s: auth.take_challenge(s, cid, kind))
        assert first is not None and first.kind == kind and first.user_id == uid, kind
        assert waited and got is None, kind
    # a team invite and a reporter's email link
    invite = await auth.create_invite(db, team.user)
    link = await auth.create_reporter_link(db, "race@example.org", None, "/my")
    await db.commit()
    for use in (lambda s: auth.consume_invite(s, invite), lambda s: auth.consume_reporter_link(s, link)):
        first, waited, got = await raced(use)
        assert first is not None and waited and got is None

    # two different links of one family, used in the same moment. Using one burns its siblings, so
    # each claimed its own row and then waited for the other's: a deadlock, which the database ends
    # with an error (XE-1903). They queue on the family's lock: one works, the other is told it was used
    async def both(make, use):
        a, b = await make(), await make()
        await db.commit()

        async def one(raw):
            async with sm() as s:
                got = await use(s, raw)
                await s.commit()
                return got is not None

        return sorted(await asyncio.gather(one(a), one(b)))

    def new_link():
        return auth.create_reporter_link(db, "pair@example.org", None, "/my")

    for _ in range(3):
        assert await both(new_link, auth.consume_reporter_link) == [False, True]
        assert await both(lambda: auth.create_invite(db, team.user), auth.consume_invite) == [False, True]
    # and every other writer of several of a family's rows queues on the same lock: an address's
    # lock for its links, the member's row for a member's invites
    for fn in (auth.consume_reporter_link, auth.drop_reporter_links):
        assert "family_lock(" in inspect.getsource(fn), fn.__name__
    for fn in (auth.consume_invite, users.set_active, users.set_email):
        assert "member_lock(" in inspect.getsource(fn), fn.__name__
    # the lock is the first thing taken, not only present: before the owner's row is written. A
    # sign-in takes the lock and then writes the row, so a writer in the other order is the other
    # half of the same deadlock
    for fn, lock, write in (
        (users.set_active, "member_lock(", "u.active ="),
        (users.set_email, "member_lock(", "u.email ="),
        (rsvc.unlink, "drop_reporter_links(", 'r.email = ""'),
        (rsvc.merge, "drop_reporter_links(", "t.reporter_id = into.id"),
        (rsvc.from_email, "identity_lock(", "r.email = email"),
    ):
        src = inspect.getsource(fn)
        assert -1 < src.index(lock) < src.index(write), fn.__name__
    # the two tables are written in one module, whatever is added to the others
    import desk as package

    for f in Path(package.__file__).parent.rglob("*.py"):
        for line in f.read_text().splitlines():
            if re.search(r"(delete|update)\((ReporterLink|Invite)\)", line):
                assert f.name == "auth.py", (f.name, line)
    # a TOTP code: the step it matched is taken once, and nothing at or before it is taken afterwards
    first, waited, got = await raced(lambda s: auth.claim_totp_step(s, team.user, 1000))
    assert first is True and waited and got is False
    assert await auth.claim_totp_step(db, team.user, 999) is False
    assert await auth.claim_totp_step(db, team.user, 1001) is True
    await db.commit()
    # a signed request's signature and a webhook delivery id: the row that marks it used is the claim, and
    # the second request is told so (a 409, a duplicate), not failed on the primary key
    signed = _signed(KeyPair.generate(), DOMAIN_LOGIN, {"host": "bounty.test"})
    first, waited, got = await raced(lambda s: verify_signed(s, signed, DOMAIN_LOGIN))
    assert first is not None and waited and got is None
    first, waited, got = await raced(lambda s: auth.claim_first(s, SeenDelivery, id="delivery-1"))
    assert first is True and waited and got is False
    # a passkey's counter: two sign-ins at one count, then one behind and one ahead
    pk, plain = (Passkey(user_id=uid, credential_id=c, public_key=b"key") for c in (b"counts", b"plain"))
    db.add_all([pk, plain])
    await db.commit()
    first, waited, got = await raced(lambda s: auth.claim_sign_count(s, pk, 5))
    assert first is True and waited and got is False
    assert await auth.claim_sign_count(db, pk, 5) is False
    assert await auth.claim_sign_count(db, pk, 6) is True
    # an authenticator that keeps no counter sends 0 each time, and is not locked out by it
    assert await auth.claim_sign_count(db, plain, 0) and await auth.claim_sign_count(db, plain, 0)
    await db.commit()
    # an OAuth state is spent by the callback that presents it, whatever the provider then says: the
    # same state again is "start again", not a second round trip
    from starlette.requests import Request

    from desk.api import authn
    from desk.api import reporter as rapi

    request = Request({"type": "http", "method": "GET", "path": "/", "query_string": b"", "headers": []})
    nobody = auth.Auth(authz.Principal())
    callbacks = (
        ("oauth", rapi.github_callback, "GitHub"), ("oauth-discord", rapi.discord_callback, "Discord")
    )
    for kind, callback, provider in callbacks:
        state = await auth._store_challenge(db, kind, b"", None)
        await db.commit()
        for said in (f"{provider} did not sign you in", rapi.OAUTH_EXPIRED):
            async with sm() as web:  # a request's own session, closed uncommitted when its route raises
                with pytest.raises(HTTPException) as e:
                    await callback(ctx, web, nobody, request, code="", state=state, error="access_denied")
            assert e.value.status_code == 400 and e.value.detail.startswith(said), kind
    # and no site claims one any other way. Outside desk/auth.py nothing reads, deletes or updates a
    # challenge or a replay table (the worker's expiry of old challenges aside), and a TOTP step is
    # assigned in one place, where setup writes the new secret and its step together
    root = Path(auth.__file__).parent
    direct = re.compile(r"\b(select|delete|update)\(\s*(Challenge|SeenSignature|SeenDelivery)\b")
    found = {}
    for f in sorted(root.rglob("*.py")):
        src = f.read_text(encoding="utf-8")
        name = str(f.relative_to(root))
        if name != "auth.py":
            found.update({name: direct.findall(src)} if direct.search(src) else {})
        assert len(re.findall(r"\.totp_last_step\s*=[^=]", src)) == (1 if name == "api/authn.py" else 0), name
    assert found == {"worker.py": [("delete", "Challenge")]}
    assert ".totp_last_step = " in inspect.getsource(authn.totp_confirm)


async def test_first_sign_ins_converge_on_one_row_and_names_fit(ctx, db):
    # a provider-verified email lands on the row that already holds it (XE-1012)
    r = await rsvc.from_email(ctx, db, "kim@example.org", link_to=None)
    gh_user = {"id": 77, "login": "kim", "name": "K" * 300}
    g = await rsvc.from_github(ctx, db, gh_user, "KIM@example.org", link_to=None)
    assert g.id == r.id and g.github_id == 77 and len(g.display_name) <= 128
    d = await channels.from_platform(ctx, db, "discord", "9001", name="Kim", email="kim@example.org")
    assert d.id == r.id and d.platform_ids["discord"] == "9001"
    # a long GitHub name or local part is cut, not a 500 (XE-1085)
    long_local = "l" * 200 + "@example.org"
    e = await rsvc.from_email(ctx, db, long_local, link_to=None)
    assert len(e.display_name) == 128
    h = await rsvc.from_github(ctx, db, {"id": 78, "login": "x", "name": "N" * 200}, "", link_to=None)
    assert len(h.display_name) == 128


async def test_a_cookie_write_carries_the_csrf_token(ctx, db):
    """The rule (XE-1545, XE-2101, XE-2139): a write driven by a session cookie carries that session's
    CSRF token. It lives in `deps.current`, the one place a route learns who is asking, so the test is
    over every write route the app has: each either goes through it or is on the short list of routes
    that read no session at all. A write route added later without it fails here."""
    from starlette.requests import Request

    from desk.api import deps
    from desk.main import app

    def calls(dep):
        out = {dep.call}
        for d in dep.dependencies:
            out |= calls(d)
        return out

    no_session = {
        ("POST", "/v1/github/webhook"),  # GitHub's HMAC over the body; no cookie is read
        ("POST", "/v1/auth/passkey/login/begin"),  # the team's sign-ins: nobody is signed in yet
        ("POST", "/v1/auth/passkey/login/finish"),
        ("POST", "/v1/auth/totp/login"),
        ("POST", "/v1/auth/invite/accept"),
    }
    routes = {(m, r.path): r for r in _api_routes(app) for m in r.methods}
    writes = {k: r for k, r in routes.items() if k[0] not in deps.SAFE_METHODS}
    assert len(writes) >= 40
    assert {k for k, r in writes.items() if deps.current not in calls(r.dependant)} == no_session

    def req(method, cookie="", csrf="", bearer=""):
        headers = []
        if cookie:
            headers.append((b"cookie", cookie.encode()))
        if csrf:
            headers.append((b"x-desk-csrf", csrf.encode()))
        if bearer:
            headers.append((b"authorization", f"Bearer {bearer}".encode()))
        scope = {"type": "http", "method": method, "path": "/", "query_string": b"", "headers": headers}
        return Request(scope)

    team = await _team(ctx, db)
    ts, traw = await auth.create_session(db, team.user)
    r = await rsvc.from_email(ctx, db, "cy@example.org", link_to=None)
    rs, rraw = await auth.create_reporter_session(db, r, "email")
    await db.commit()
    for name, raw, held in ((auth.SESSION_COOKIE, traw, ts), (auth.REPORTER_COOKIE, rraw, rs)):
        cookie = f"{name}={raw}"
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            for sent in ("", "x" * 32):
                with pytest.raises(HTTPException) as e:
                    await deps.current(db, req(method, cookie, sent))
                assert e.value.status_code == 403
            a = await deps.current(db, req(method, cookie, held.csrf))
            assert (a.session or a.reporter_session).id == held.id
        assert (await deps.current(db, req("GET", cookie))).csrf == held.csrf  # a read needs no token
    # one session's token is no use with another's cookie
    with pytest.raises(HTTPException) as e:
        await deps.current(db, req("POST", f"{auth.REPORTER_COOKIE}={rraw}", ts.csrf))
    assert e.value.status_code == 403
    # with no session there is nothing to forge: a signed-out write and a bearer token pass through
    assert (await deps.current(db, req("POST"))).principal.kind == "anon"
    admin = authz.Principal(kind="user", user=team.user, roles={"admin"})
    _tok, secret = await users.issue(ctx, db, admin, team.user, "m", "t", ["read:public"], 30)
    a = await deps.current(db, req("POST", f"{auth.SESSION_COOKIE}={traw}", "", secret))
    assert a.principal.kind == "token" and a.session is None
    # adding a way in to an account is a write. The GET that starts a sign-in reads no session and
    # names no account, however signed-in the browser that follows it; the POST names the caller's
    from urllib.parse import parse_qs, urlsplit

    from starlette.responses import Response

    from desk.api import authn
    from desk.api import reporter as rapi

    async def state_of(url):
        return (await db.get(Challenge, parse_qs(urlsplit(url).query)["state"][0])).detail

    rapi._attempts.clear()
    ctx.settings.github_oauth_client_id = "client"
    ctx.settings.discord_app_id, ctx.settings.discord_oauth_client_secret = "app", "secret"
    rcookie = f"{auth.REPORTER_COOKIE}={rraw}"
    nobody = auth.Auth(authz.Principal())
    for provider, start, link in (
        ("github", rapi.github_start, rapi.github_link), ("discord", rapi.discord_start, rapi.discord_link)
    ):
        path = f"/v1/reporter/auth/{provider}"
        assert deps.current not in calls(routes[("GET", path)].dependant), provider
        assert ("POST", f"{path}/link") in writes, provider
        went = await start(ctx, db, req("GET", rcookie), next="/account")
        assert await state_of(went.headers["location"]) == {"next": "/account", "link_to": None}
        who = await deps.current(db, req("POST", rcookie, rs.csrf))
        url = (await link(ctx, db, who, req("POST", rcookie, rs.csrf), rapi.LinkIn(next="/account")))["url"]
        assert await state_of(url) == {"next": "/account", "link_to": r.id}
        with pytest.raises(HTTPException) as e:
            await link(ctx, db, nobody, req("POST"), rapi.LinkIn())
        assert e.value.status_code == 401, provider
    # sign-out: a request that came with no session ends nothing and clears no cookie (a form on
    # another site posts without the cookie, and its response could otherwise sign the reader out)
    for route in (rapi.logout, authn.logout):
        resp = Response()
        assert await route(ctx, db, nobody, req("POST", rcookie), resp) == {"ok": True}
        assert "set-cookie" not in resp.headers
    assert await auth.reporter_session_from_request(db, req("GET", rcookie)) is not None
    # a browser holding both cookies is the team member to `current`; its reporter session ends too
    both = req("POST", f"{auth.SESSION_COOKIE}={traw}; {rcookie}", ts.csrf)
    who = await deps.current(db, both)
    assert who.session is not None and who.reporter_session is None
    resp = Response()
    await rapi.logout(ctx, db, who, both, resp)
    assert resp.headers["set-cookie"].startswith(f"{auth.REPORTER_COOKIE}=")
    assert await auth.reporter_session_from_request(db, both) is None
    assert (await deps.current(db, req("GET", f"{auth.SESSION_COOKIE}={traw}"))).session is not None
    resp = Response()
    await authn.logout(ctx, db, who, both, resp)
    assert resp.headers["set-cookie"].startswith(f"{auth.SESSION_COOKIE}=")
    assert (await deps.current(db, req("GET", f"{auth.SESSION_COOKIE}={traw}"))).principal.kind == "anon"


async def test_a_nul_in_a_request_is_refused_at_the_boundary(ctx):
    """The rule (XE-0827, XE-1426, XE-1015): Postgres refuses a NUL in text and in jsonb, so no request
    carries one as far as a statement. It is refused once at each way in: the path and the query
    string by `main.NoNul`, a JSON body by `auth.Body`, which every request model is. A route added
    later is behind the first; a model added later is the second, or fails here; and a route that
    takes a body some other way (a bare dict, the raw request) fails here too."""
    import typing

    from pydantic import BaseModel, ValidationError

    from desk import main
    from desk.api import agent, authn, deps
    from desk.api import public as pub
    from desk.api import reporter as rapi
    from desk.api import team as team_api

    assert any(m.cls is main.NoNul for m in main.app.user_middleware)

    async def through(path, query=b""):
        seen = []

        async def inner(scope, receive, send):
            seen.append("passed")

        async def send(message):
            seen.append(message.get("status", message["type"]))

        scope = {"type": "http", "method": "GET", "path": path, "query_string": query, "headers": []}
        await main.NoNul(inner)(scope, None, send)
        return seen[0]

    assert await through("/v1/tickets/XE-0001", b"area=consensus&q=100%25") == "passed"
    refused = (
        ("/v1/tickets/\x00", b""), ("/XE-00\x0001", b""), ("/v1/tickets", b"area=%00"),
        ("/log", b"kind=a%00b&x=1"),
    )
    for path, query in refused:
        assert await through(path, query) == 400, (path, query)
    # every model the API modules define, and the signed request: a NUL in a value, in a key, or deep
    # inside a free-form field is a validation error before any field is read
    models = {
        v
        for mod in (agent, authn, deps, pub, rapi, team_api, auth)
        for v in vars(mod).values()
        if isinstance(v, type) and issubclass(v, BaseModel) and v.__module__ == mod.__name__
    }
    models.discard(auth.Body)
    assert len(models) >= 30 and {SignedRequest, team_api.FactsIn, rapi.TextIn, agent.ProposalIn} <= models
    for m in models:
        assert issubclass(m, auth.Body), m.__name__
        bodies = (
            {"x": "a\x00b"}, {"a\x00": 1}, {"changes": {"deep": [{"k": ["\x00"]}]}},
            {"x": "a\udc80"}, {"\ud83d": 1}, {"value": {"deep": ["\ud83d"]}},
        )
        for body in bodies:
            with pytest.raises(ValidationError):
                m.model_validate(body)
    # and it is the routes that are asked, not only the models: every body any route declares is made
    # of those models and nothing else, and the raw request is read in two places, each of which
    # cleans what it reads (the filing's form fields, GitHub's signed payload)
    def classes(tp):
        args = typing.get_args(tp)
        return {tp} if not args else {c for a in args if a is not type(None) for c in classes(a)}

    routes = _api_routes(main.app)
    declared = {
        (r.path, f.name): classes(f.field_info.annotation) for r in routes for f in r.dependant.body_params
    }
    assert len(declared) >= 25
    for where, made_of in declared.items():
        assert made_of and all(isinstance(c, type) and issubclass(c, auth.Body) for c in made_of), where
    raw = {
        (r.endpoint.__name__, read)
        for r in routes
        for read in ("request.json(", "request.form(", "request.body(", "request.stream(")
        if read in inspect.getsource(r.endpoint)
    }
    assert raw == {("file_ticket", "request.form("), ("github_webhook", "request.body(")}
    clean = {"changes": {"area": "consensus"}}
    assert team_api.FactsIn.model_validate(clean).changes == clean["changes"]
    assert rapi.TextIn.model_validate({"body": "a whole pair \U0001f600 is text"}).body.endswith("text")
    # the one address stored as typed, which no model carries when it arrives on the filing form
    for bad in ("a\x00@b.co", "a@b\x00.co", "a\x7f@b.co"):
        with pytest.raises(HTTPException) as e:
            rsvc.clean_email(bad)
        assert e.value.status_code == 400
    assert rsvc.clean_email(" Ann@Example.org ") == "ann@example.org"


async def test_text_from_a_provider_is_made_storable_where_it_is_written(ctx, db, tmp_path):
    """The other half of the rule above. Text that does not arrive in a request body (GitHub's and
    Discord's words for an account at sign-in, what the chat bot hands over, a file's name on the
    filing form, the node's own answer) is made storable in the function that writes it, so every
    caller has it. Each flush below is the statement Postgres would have refused."""
    team = await _team(ctx, db)
    nul, half = "a\x00b", "half\udc80"
    g = await rsvc.from_github(ctx, db, {"id": 4711, "login": nul, "name": half}, "E\x00@x.co", link_to=None)
    await db.flush()
    assert (g.github_login, g.display_name, g.email) == ("ab", "half", "e@x.co")
    d = await channels.from_platform(
        ctx, db, "discord", "77\x00", name=half, handle=nul, email="d\udc80@x.co"
    )
    await db.flush()
    assert (d.display_name, d.email) == ("half", "d@x.co")
    assert d.platform_ids == {"discord": "77", "discord_handle": "ab"}
    # the chat bot: a member's display name, a title set in the thread, the words after /close, and
    # the platform's own error text
    q = await channels.open_from_channel(ctx, db, _post(uid="78", thread_ref="556", user_name=nul))
    m = await channels.incoming(
        ctx, db, q, message_ref="m1", user_id="78", user_name=nul + half, body="more", is_team=False
    )
    assert m.author == "abhalf"
    new = await channels.rename_from_channel(ctx, db, q, user_id="9", title="Escrow \x00releases\udc80 twice")
    assert new == q.title == "Escrow releases twice"
    r = await thread.add_reply(ctx, db, team, q, "A word.")
    await channels.mark_failed(ctx, db, r, q, "thread\x00 gone\udc80")
    await channels.close_from_channel(ctx, db, q, user_id="9", reason="answered\x00 in\udc80 chat")
    await db.flush()
    assert r.mirror_error == "thread gone" and (q.status, q.closed_reason) == ("closed", "answered")
    moves = select(Event).where(Event.ref == q.id, Event.kind == "ticket.status").order_by(Event.index.desc())
    assert (await db.execute(moves)).scalars().first().payload["reason"] == "answered in chat"
    # a file's name: a multipart part is decoded with the charset the client names, so it can carry
    # either character; the row is clean, and so is the refusal that quotes the name
    ctx.settings.blob_dir = tmp_path
    f = rsvc.Filing(
        title="Escrow release double-counts",
        body="Steps: open an escrow, release twice within one block. Expected: one release. Got: two.",
        files=[_Upload("po\x00c\udc80\n.txt", b"x", "text/\x00plain")],
    )
    t = await rsvc.file_ticket(ctx, db, g, f)
    await db.flush()
    a = (await rsvc.attachments_for(db, t))[0]
    assert (a.filename, a.content_type) == ("poc .txt", "text/plain")
    with pytest.raises(HTTPException) as e:
        await rsvc.save_attachment(ctx, db, t, _Upload("\udc80.txt", b""), actor="desk")
    assert e.value.status_code == 400 and e.value.detail == ".txt is empty"
    assert json.dumps(e.value.detail, ensure_ascii=False).encode("utf-8")

    # the node's answer goes into the health rows and three event payloads
    class _Node:
        async def node(self):
            return {"network_id": "test\x00net\udc80", "id": 7, "version": "v"}

    ctx.chain = _Node()
    node = await ctx.refresh_node()
    assert (node.network_id, node.node_id, node.version) == ("testnet", "", "v")


async def test_an_internal_ref_has_one_spelling(ctx, db):
    """The rule: a fact that is a key is stored in one spelling, whoever sets it. `internal_ref` is
    one (the tracker's state follows `#n`, a class is the tickets sharing it): it is normalised in
    `tickets.fact_value`, which `set_facts` stores from, and nothing else in desk/ assigns it."""
    import re
    from pathlib import Path

    import desk

    p = await _team(ctx, db, roles=("reviewer", "tier"))
    t, _ = await sync.upsert_issue(ctx, db, "xeprotocol/xe", _issue(63, "Explorer search bar"))
    others = [
        await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title=f"r{i}", source="web"))
        for i in range(6)
    ]
    # the tracker is xeprotocol/core, so `core#1068` is its `#1068` and not another repository's
    assert ctx.config.internal_repo == "xeprotocol/core"
    spellings = ("#1068", " #01068 ", "1068\n", "Faucet#010", "core#1068", "Core#01068")
    for o, spelt in zip(others, spellings):
        await tsvc.set_facts(ctx, db, p, o, {"internal_ref": spelt})
    assert [o.internal_ref for o in others] == ["#1068", "#1068", "#1068", "faucet#10", "#1068", "#1068"]
    klass = await tsvc.same_class(db, p, {"#1068"})
    assert [o.id for o in klass["#1068"]] == sorted(o.id for o in others if o is not others[3])  # one class
    # and the tracker moves a ticket a person linked: under another spelling the issue "also named"
    # the report and left it alone
    await tsvc.set_facts(ctx, db, p, t, {"internal_ref": "1070"})
    assert t.internal_ref == "#1070"
    stats = await sync.link_internal_issue(ctx, db, _issue(1070, "security: bounty bundle xe#63"))
    assert (stats["tagged"], stats["linked"], stats["noted"], stats["moved"]) == (1, 0, 0, 1)
    assert t.status == "accepted"
    # anything else is a 400, not a row that matches nothing or a value too long for the column
    refused = (
        "#", "##1068", "#1068x", "x" * 40, "#" + "9" * 10, "#0", "#\u0661\u0660\u0666\u0668", "#\uff11",
        "faucet#", "a b#1", "#-1", "#1 #2", 1068, 10.5, True, ["#1"], {"n": 1},
    )
    for bad in refused:
        with pytest.raises(HTTPException) as e:
            await tsvc.set_facts(ctx, db, p, others[3], {"internal_ref": bad})
        assert e.value.status_code == 400, bad
    assert others[3].internal_ref == "faucet#10"
    await tsvc.set_facts(ctx, db, p, others[3], {"internal_ref": ""})
    assert others[3].internal_ref == ""
    # the other key among the facts: a duplicate's target, by its stored id or not at all
    await tsvc.set_facts(ctx, db, p, others[0], {"duplicate_of": f" {others[1].id.lower()} "})
    assert others[0].duplicate_of == others[1].id
    for bad in (others[0].id, "XE-9999", 42, [others[1].id], "x" * 40):
        with pytest.raises(HTTPException) as e:
            await tsvc.set_facts(ctx, db, p, others[0], {"duplicate_of": bad})
        assert e.value.status_code == 400, bad
    for bad in ("x", "-1", "1e3", 1.0, True, [p.user.id], 999_999_999):
        with pytest.raises(HTTPException) as e:
            await tsvc.set_facts(ctx, db, p, others[0], {"assignee_id": bad})
        assert e.value.status_code == 400, bad
    await tsvc.set_facts(ctx, db, p, others[0], {"assignee_id": str(p.user.id)})
    assert others[0].assignee_id == p.user.id
    root = Path(desk.__file__).parent
    assigned = [
        str(f.relative_to(root))
        for f in root.rglob("*.py")
        if re.search(r"\.(internal_ref|duplicate_of|assignee_id)\s*=[^=]", f.read_text())
    ]
    assert assigned == []
    # `create` is the other writer of a fact with a vocabulary, and asks the area what fact_value does
    areas = (("bounty", "Consensus"), ("bounty", "nodes"), ("support", "consensus"), ("bounty", "x" * 40))
    for kind, bad in areas:
        with pytest.raises(HTTPException) as e:
            await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind=kind, title="made by hand", area=bad))
        assert e.value.status_code == 400, bad
    made = [
        await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind=kind, title="made by hand", area=area))
        for kind, area in (("support", "nodes"), ("bounty", "consensus"), ("bounty", ""), ("bounty", None))
    ]
    assert [m.area for m in made] == ["nodes", "consensus", None, None]


async def test_a_proposal_is_checked_as_the_fact_it_would_set(ctx, db):
    """The rule (XE-1054, for every field): a proposal holds a value the desk could apply, in the
    spelling it would store. Checked by the function `set_facts` stores from, so a fact added to
    one is checked in the other; asserted for every proposal field that is a fact."""
    from desk.models import PROPOSAL_FIELDS

    p = await _team(ctx, db, roles=("reviewer", "tier"))
    agent = await _agent(ctx, db, p.user)

    def mk(title, kind="bounty"):
        return tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind=kind, title=title, source="web"))

    canon, t, question = await mk("first"), await mk("again"), await mk("how do I", "support")
    facts = [f for f in PROPOSAL_FIELDS if f not in ("status", "reply_draft", "award_xe")]
    assert set(facts) <= set(tsvc.FACT_VOCAB) and len(facts) == 7
    bad = {
        "assessed_tier": ("High", "urgent", 3, ["high"]),
        "verdict": ("bogus", {"verdict": "valid"}),
        "duplicate_of": ("XE-9999", t.id, t.id.lower(), 42, [canon.id], "x" * 40),
        "internal_ref": ("x" * 40, "##1064", "#\u0661", 1064, ["#1"]),
        "mainnet_gate": ("soon", 1),
        "effort_eng": ("s", 4),
        "area": ("nowhere", "getting-started"),  # a support topic is not a bounty area
    }
    assert set(bad) == set(facts)
    for field, values in bad.items():
        for value in values:
            with pytest.raises(HTTPException) as e:
                await psvc.propose(ctx, db, agent, t, field, value, "no")
            assert e.value.status_code == 400, (field, value)
    with pytest.raises(HTTPException) as e:
        await psvc.propose(ctx, db, agent, question, "area", "consensus", "no")
    assert e.value.status_code == 400
    topic = await psvc.propose(ctx, db, agent, question, "area", "getting-started", "a first question")
    assert topic.value == {"value": "getting-started"}
    # the stored value is the stored spelling: the family of a canonical finds it before it is adopted
    dup = await psvc.propose(ctx, db, agent, t, "duplicate_of", f" {canon.id.lower()} ", "same defect")
    ref = await psvc.propose(ctx, db, agent, t, "internal_ref", "01064", "tracked there")
    assert (dup.value, ref.value) == ({"value": canon.id}, {"value": "#1064"})
    assert [(o.id, pr.id) for o, pr in await psvc.pending_duplicates_of(db, canon.id)] == [(t.id, dup.id)]
    out = await psvc.decide(ctx, db, p, ref, True)
    assert out["diff"]["internal_ref"]["to"] == "#1064" and t.internal_ref == "#1064"
    out = await psvc.decide(ctx, db, p, dup, True)
    assert t.duplicate_of == canon.id
    # the two fields that are not facts are asked the same question: a status the ticket's door does
    # not have, and an amount no award may be (with no tier yet there is no ceiling to stop it)
    for bad in ("accepted", "patched", {"status": "awarded"}):
        with pytest.raises(HTTPException) as e:
            await psvc.propose(ctx, db, agent, question, "status", bad, "no")
        assert e.value.status_code == 400, bad
    with pytest.raises(HTTPException) as e:
        over = tsvc.AWARD_MAX // 1_000_000 + 1
        await psvc.propose(ctx, db, agent, canon, "award_xe", over, "an amount no tier comes near")
    assert e.value.status_code == 400
    # a proposal to clear a fact holds null; the triage row does not read that as the id "None"
    clear = await psvc.propose(ctx, db, agent, canon, "duplicate_of", "", "not a duplicate after all")
    untier = await psvc.propose(ctx, db, agent, canon, "assessed_tier", "", "no tier yet")
    assert (clear.value, untier.value) == ({"value": None}, {"value": None})
    assert psvc.TriageRow(canon, [clear, untier]).duplicate_of is None
    assert psvc.proposed_tier(canon, [untier]) is None


async def test_a_value_the_desk_would_not_take_is_not_adopted_and_does_not_stay_pending(ctx, db):
    """The rule: a proposal is adopted only as a value the desk would take as a proposal today, and
    one it would not take does not stay pending. `value_for` is asked by `propose` and again by
    `decide`, so a check added to it binds what was already waiting: asserted for every proposal
    field, with a row written as it was stored before its rule landed."""
    from desk.models import PROPOSAL_FIELDS, Proposal

    p = await _team(ctx, db)
    agent = await _agent(ctx, db, p.user)

    def mk(title):
        return tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title=title, source="web"))

    t, other, closing = await mk("a report"), await mk("another"), await mk("closed in silence")
    stale = {
        "assessed_tier": "urgent",
        "verdict": "bogus",
        "duplicate_of": "XE-9999",
        "internal_ref": "dao@846c56d",  # a commit, proposed as the tracker ticket before that was a key
        "mainnet_gate": "soon",
        "effort_eng": "s",
        "area": "nowhere",
        "status": {"status": "closed", "closed_reason": "withdrawn"},  # closes in silence (`tell.UNOWED`)
        "reply_draft": 7,
        "award_xe": -1,
    }
    assert set(stale) == set(PROPOSAL_FIELDS)
    for field, value in stale.items():
        with pytest.raises(HTTPException) as e:
            await psvc.propose(ctx, db, agent, t, field, value, "a reason of twenty characters or more")
        assert e.value.status_code == 400, field
    # the close is on a ticket of its own, with the reply its agent drafted to go with it; the draft
    # that is no draft is on another, so each is refused for what it is
    home = {"status": closing, "reply_draft": other}
    rows = [
        Proposal(ticket_id=home.get(f, t).id, token_id=agent.token.id, field=f, value={"value": v})
        for f, v in stale.items()
    ]
    db.add_all(rows)
    await db.flush()
    ack = "Thanks for the report. We have read it against the code and it is being handled."
    rides = await psvc.propose(ctx, db, agent, closing, "reply_draft", ack, "")
    assert psvc.send_review(ctx, [rides], rides, closing) is None  # alone, it would be sent as it stands
    ids, rid, refs = [pr.id for pr in rows], rides.id, (t.id, closing.id, other.id)

    def facts(x):
        return (x.status, x.closed_reason, x.verdict, x.assessed_tier, x.duplicate_of, x.internal_ref,
                x.mainnet_gate, x.effort_eng, x.area, x.award_xe, x.draft)

    before = facts(t), facts(closing)
    out = await psvc.decide_many(ctx, db, p, [rid, *ids], [], send_plain=True)
    assert out["skipped"] == [] and sorted(d["proposal"] for d in out["decided"]) == sorted([rid, *ids])
    assert all(d["adopted"] is False and d["refused"] for d in out["decided"])
    for pr in (*rows, rides):
        await db.refresh(pr)
    assert {pr.state for pr in (*rows, rides)} == {"rejected"}
    assert {pr.decided_by for pr in (*rows, rides)} == {p.user.id}
    await db.refresh(t)
    await db.refresh(closing)
    assert (facts(t), facts(closing)) == before and (t.status, closing.status) == ("new", "new")
    evs = [e for ref in refs for e in await EventLog.page(db, 0, 100, ref=ref, public_only=False)]
    said = {e.payload["proposal"]: e.payload["reason"] for e in evs if e.kind == "proposal.rejected"}
    assert set(said) == {rid, *ids} and not [e for e in evs if e.kind == "proposal.adopted"]
    assert all(said[i].startswith("the desk does not take this value: ") for i in ids)
    # the draft went with its close: nothing was sent to a reporter whose report is still open
    assert said[rid] == psvc.ORPHANED and closing.told_at is None
    assert [d["refused"] for d in out["decided"] if d["proposal"] == rid] == [psvc.ORPHANED]
    assert not [e for e in evs if e.kind.startswith("reply.")]
    # one click on the ticket page meets the same answer, and so does the fill on the awards page
    # (which used to read the amount out of an adoption that had not happened)
    one = Proposal(ticket_id=other.id, token_id=agent.token.id, field="verdict", value={"value": "bogus"})
    amount = Proposal(ticket_id=other.id, token_id=agent.token.id, field="award_xe", value={"value": "9"})
    db.add_all([one, amount])
    await db.flush()
    answer = await psvc.decide(ctx, db, p, one, True, reason="looks right")
    assert (answer["adopted"], one.state, other.verdict) == (False, "rejected", None)
    assert "verdict must be one of" in answer["refused"]
    for st in ("triaging", "accepted", "patched"):
        await tsvc.set_status(ctx, db, p, other, st)
    other.assessed_tier = "medium"
    oid, aid = other.id, amount.id
    filled = await psvc.fill_awards(ctx, db, p, [oid], "standard")
    assert filled["filled"] == [] and f"proposal #{aid} rejected" in filled["skipped"][0]["why"]
    await db.refresh(amount)
    await db.refresh(other)
    assert amount.state == "rejected" and other.award_xe is None
    # what the desk refuses for the ticket's state or the person's role is not that: it is a skip,
    # still pending, as before; and a value the desk takes is adopted in the spelling it stores
    again = await mk("a third")
    for st in ("triaging", "accepted", "patched", "awarded", "paid"):
        await tsvc.set_status(ctx, db, p, again, st, force=True)
    no_path = await psvc.propose(ctx, db, agent, again, "status", "fixing", "no path from paid")
    reviewer = await _team(ctx, db, roles=("reviewer",), email="rev3@xe.network")
    no_role = await psvc.propose(ctx, db, agent, again, "assessed_tier", "high", "a reviewer lacks tier")
    as_sent = {"value": "1064"}  # kept as sent, from before a proposal held the stored spelling
    good = Proposal(ticket_id=again.id, token_id=agent.token.id, field="internal_ref", value=as_sent)
    db.add(good)
    await db.flush()
    np, nr, gid = no_path.id, no_role.id, good.id
    out = await psvc.decide_many(ctx, db, reviewer, [np, nr, gid], [])
    assert {s["proposal"] for s in out["skipped"]} == {np, nr}
    assert [(d["proposal"], d["adopted"]) for d in out["decided"]] == [(gid, True)]
    for pr in (no_path, no_role, good):
        await db.refresh(pr)
    await db.refresh(again)
    assert (no_path.state, no_role.state, good.state) == ("pending", "pending", "adopted")
    assert again.internal_ref == "#1064"
    # the two places the question is asked are the two that call `value_for`, and nothing else
    # between a stored proposal and the ticket checks a value on its own
    src = inspect.getsource(psvc)
    assert src.count("await value_for(") == 2
    assert "value_for(" in inspect.getsource(psvc.propose) and "value_for(" in inspect.getsource(psvc.decide)


async def test_the_daily_note_counts_what_the_public_counts(ctx, db):
    """The rule: a public event with no ticket behind it says nothing an anonymous reader could not
    count for themselves. The daily note is the one such event that carries ticket numbers."""
    from desk import worker

    p = await _team(ctx, db)
    for visibility in ("public", "private"):
        spec = tsvc.NewTicket(kind="bounty", title=f"a {visibility} report", visibility=visibility)
        t = await tsvc.create(ctx, db, p.actor, spec)
        for st in ("triaging", "accepted"):
            await tsvc.set_status(ctx, db, p, t, st)
    note = await worker.daily_counts(ctx, db)
    ours = await tsvc.counts(db, authz.SYSTEM, "bounty")
    assert (note["bounty"]["accepted"], ours["accepted"]) == (1, 2)
    assert note["bounty"] == await tsvc.counts(db, authz.ANON, "bounty")
    assert note["support"] == await tsvc.counts(db, authz.ANON, "support")
    owed = len(await tsvc.outbox(db, ctx.config, authz.SYSTEM))
    assert note["outbox"] == len(await tsvc.outbox(db, ctx.config, authz.ANON)) == owed - 1
    src = inspect.getsource(worker.Worker.job_daily) + inspect.getsource(worker.daily_counts)
    assert "SYSTEM" not in src and "daily_counts(" in inspect.getsource(worker.Worker.job_daily)
    # a note written before that, with the private tickets counted in, is served without its numbers
    old = {"date": "2026-11-01", "bounty": {"accepted": 2}, "support": {}, "outbox": 2, "network_id": "n"}
    assert public_payload("note.daily", old) == {"date": "2026-11-01", "network_id": "n"}
    new = {**old, **note}
    assert note["counted"] == "public" and public_payload("note.daily", new) == new


async def test_a_link_does_not_outlive_the_identity_it_was_sent_to(ctx, db):
    """The rule (XE-0710, XE-1904): when an address comes off an account, by a merge or by the
    reporter unlinking it, every sign-in link already mailed to it stops working. Asked of both
    places an address is taken off, and of both kinds of link (bound to the account, and plain)."""
    from desk.models import ReporterSession

    kept = await rsvc.from_email(ctx, db, "kept@example.org", link_to=None)
    shell = await rsvc.from_email(ctx, db, "old@example.org", link_to=None)
    plain = await auth.create_reporter_link(db, "old@example.org", None, "/my")
    bound = await auth.create_reporter_link(db, "extra@example.org", shell.id, "/my")
    theirs = await auth.create_reporter_link(db, "kept@example.org", None, "/my")
    await auth.create_reporter_session(db, shell, "email")
    shell_id = shell.id
    await rsvc.merge(ctx, db, into=kept, other=shell)
    assert (kept.email, shell.email) == ("kept@example.org", "")
    assert await auth.consume_reporter_link(db, plain) is None
    assert await auth.consume_reporter_link(db, bound) is None
    assert await rsvc.by_email(db, "old@example.org") is None  # and nothing brought the address back
    left = select(ReporterSession.id).where(ReporterSession.reporter_id == shell_id)
    assert (await db.execute(left)).first() is None
    assert (await auth.consume_reporter_link(db, theirs)) is not None  # the surviving account's own
    # unlinked by the reporter: the same
    kept.xe_login_addresses = ["a" * 40]
    sent = await auth.create_reporter_link(db, "kept@example.org", None, "/my")
    await rsvc.unlink(ctx, db, kept, "email")
    assert kept.email == "" and await auth.consume_reporter_link(db, sent) is None
    # written over by another address, through a link bound to the account: the same
    acct = await rsvc.from_email(ctx, db, "first@example.org", link_to=None)
    stale = await auth.create_reporter_link(db, "first@example.org", None, "/my")
    again = await rsvc.from_email(ctx, db, "second@example.org", link_to=acct)
    assert again.id == acct.id and acct.email == "second@example.org"
    assert await auth.consume_reporter_link(db, stale) is None
    # the team's table: an invite is keyed on the member and mailed to the member's address; it does
    # not sign anyone in once the address has changed, and is untouched when it has not
    team = await _team(ctx, db)
    invite = await auth.create_invite(db, team.user)
    await users.set_email(ctx, db, "test", team.user, "moved@xe.network")
    assert team.user.email == "moved@xe.network" and await auth.consume_invite(db, invite) is None
    fresh = await auth.create_invite(db, team.user)
    await users.set_email(ctx, db, "test", team.user, "moved@xe.network")
    assert (await auth.consume_invite(db, fresh)).id == team.user.id
    # every assignment to an account's address in the services is one of these, each read above: a
    # new one fails here and is asked the rule
    assigns = re.compile(r"\.email\s*(?:,[^=\n]*)?=[^=]")
    written = {
        mod.__name__.rsplit(".", 1)[-1]: len(assigns.findall(inspect.getsource(mod)))
        for mod in (rsvc, channels, users)
    }
    assert written == {"reporters": 5, "channels": 1, "users": 1}, written


async def test_a_request_body_is_bounded_as_it_is_read(ctx, monkeypatch):
    """The rule (XE-0777, XE-1905): no more of a request body is read than its route allows, whatever
    the headers say and whatever the method. Asked of both limits (a JSON body, the filing), of a body
    that declares no length, one that understates it and one whose length is not a number, and of a
    reader that lets the refusal through (FastAPI), one that does nothing with it and one that reads
    on after it has begun to answer. The filing's allowance is for a signed-in reporter's multipart
    body and nothing else on that path."""
    from fastapi import params
    from starlette.exceptions import HTTPException as AnyHTTPException

    from desk import main

    monkeypatch.setattr(main, "get_context", lambda: ctx)
    # outermost first. What is ahead of BodyLimit reads no body (`security_headers` passes `receive`
    # through, NoNul never calls it); a middleware added later is outside the limit, and is named here
    order = [m.cls.__name__ for m in main.app.user_middleware]
    assert order == ["BaseHTTPMiddleware", "NoNul", "BodyLimit", "MarkdownMirror"]
    json_max = main.BodyLimit.JSON_MAX
    filing_max = (ctx.settings.max_attachments * ctx.settings.max_attachment_mb << 20) + json_max
    chunk = b"x" * (256 << 10)

    async def run(path, total, headers=(), method="POST", reader="plain"):
        """`total` bytes, in chunks, to an app that reads the whole body: the status that came back and
        how many bytes the app was given."""
        sent, got, out = 0, 0, []

        async def receive():
            nonlocal sent
            n = min(len(chunk), total - sent)
            sent += n
            return {"type": "http.request", "body": chunk[:n], "more_body": sent < total}

        async def send(message):
            out.append(message)

        async def inner(scope, receive, send):
            nonlocal got
            more = True
            while more:
                m = await receive()
                got += len(m["body"])
                more = m["more_body"]
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        async def like_fastapi(scope, receive, send):
            try:
                await inner(scope, receive, send)
            except AnyHTTPException as e:
                await send({"type": "http.response.start", "status": e.status_code, "headers": []})
                await send({"type": "http.response.body", "body": b""})

        async def late(scope, receive, send):
            # the event stream: it has begun to answer and listens for the client leaving
            nonlocal got
            await send({"type": "http.response.start", "status": 200, "headers": []})
            while True:
                m = await receive()
                if m["type"] == "http.disconnect":
                    break
                got += len(m["body"])
            await send({"type": "http.response.body", "body": b""})

        raw = [(k.encode("latin-1"), v.encode("latin-1")) for k, v in headers]
        scope = {"type": "http", "method": method, "path": path, "query_string": b"", "headers": raw}
        app = {"plain": inner, "fastapi": like_fastapi, "late": late}[reader]
        await main.BodyLimit(app)(scope, receive, send)
        return out[0]["status"], got

    filing = "/v1/reporter/tickets"
    limits = (
        ("/v1/team/tickets/XE-0001/facts", (), json_max),
        (filing, (("content-type", "Multipart/Form-Data; boundary=x"),), filing_max),
        # any other body on the filing's path is not the one its allowance is for
        (filing, (("content-type", "application/x-www-form-urlencoded"),), json_max),
        (filing, (("content-type", "multipart/form-data-ish"),), json_max),
        (filing, (), json_max),
    )
    for path, base, limit in limits:
        for extra in ((), (("content-length", "10"),), (("content-length", "\u00b2"),)):
            for reader in ("plain", "fastapi"):
                status, got = await run(path, limit + 1, base + extra, reader=reader)
                assert status == 413 and got <= limit, (path, base, extra, reader)
            assert await run(path, limit, base + extra) == (200, limit)
        # declared honestly, it is refused before a byte is read; chunked with no length likewise
        assert await run(path, limit + 1, base + (("content-length", str(limit + 1)),)) == (413, 0)
        assert await run(path, 5, base + (("transfer-encoding", "chunked"),)) == (411, 0)
    for method in ("GET", "DELETE", "PUT", "PATCH"):
        assert (await run("/v1/x", json_max + 1, method=method))[0] == 413, method
    assert isinstance(main.BodyTooLarge(), HTTPException) and main.BodyTooLarge().status_code == 413
    # past the limit after the answer has begun, the reader is told the client has gone: no more is
    # read, and there is no error to surface where no refusal can be sent
    assert await run("/v1/events/stream", json_max + 1, method="GET", reader="late") == (200, json_max)
    # and no route has FastAPI read a form for it: a declared body is read before `current` says who
    # is calling, so the filing reads its own once it knows (the JSON routes have 2 MB at most)
    served = _api_routes(main.app)
    forms = [
        r.path for r in served if isinstance(getattr(r.body_field, "field_info", None), params.Form)
    ]
    assert forms == []
    route = [r for r in served if r.path == filing and "POST" in r.methods]
    assert len(route) == 1 and route[0].body_field is None
    # the real stack and the real parser: a JSON route, a body one byte over that declares no length.
    # FastAPI reads a model's body before any dependency, so no database is touched
    sent, out = 0, []

    async def receive():
        nonlocal sent
        if sent > json_max:
            await asyncio.Event().wait()  # as a server does: nothing more until the client leaves
        n = min(len(chunk), json_max + 1 - sent)
        sent += n
        return {"type": "http.request", "body": chunk[:n], "more_body": sent < json_max + 1}

    async def send(message):
        out.append(message)

    scope = {
        "type": "http", "method": "POST", "path": "/v1/reporter/auth/email", "query_string": b"",
        "headers": [(b"content-type", b"application/json")], "scheme": "https", "http_version": "1.1",
        "root_path": "", "raw_path": b"/v1/reporter/auth/email", "server": ("bounty.test", 443),
        "client": ("203.0.113.9", 4000),
    }
    await asyncio.wait_for(main.app(scope, receive, send), 30)
    assert out[0]["type"] == "http.response.start" and out[0]["status"] == 413


# ---- stats ------------------------------------------------------------------------------------------


async def test_stats_count_what_an_anonymous_reader_can(ctx, db):
    """The rule: `/stats` is one page for every reader. How many reports were filed, and when, counts
    every report; every other number, researchers among them, is counted over public reports as an
    anonymous reader is shown them. So a sealed report is one more report on its day and nothing
    else, a tier that is still held is in no breakdown, and the awards are the leaderboard's."""
    from desk.models import Reporter
    from desk.services import stats

    # no reader is asked for: there is one reading, and it is the anonymous one
    assert list(inspect.signature(stats.collect).parameters) == ["db", "now"]
    assert list(inspect.signature(stats.snapshot).parameters) == ["db"]
    now = utcnow()
    p = await _team(ctx, db)
    ada, bob = Reporter(github_login="ada"), Reporter(github_login="bob")
    db.add_all([ada, bob])
    await db.flush()

    async def mk(title, reporter, area, visibility="public"):
        spec = tsvc.NewTicket(
            kind="bounty", title=title, source="web", reporter_id=reporter.id, area=area,
            visibility=visibility,
        )
        return await tsvc.create(ctx, db, p.actor, spec)

    fixed, held = await mk("fixed", ada, "consensus"), await mk("held", ada, "node-api")
    await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="support", title="a question", source="web"))
    await tsvc.set_facts(ctx, db, p, fixed, {"assessed_tier": "high"})
    await tsvc.set_facts(ctx, db, p, held, {"assessed_tier": "medium"})
    for st in ("triaging", "accepted", "patched"):
        await tsvc.set_status(ctx, db, p, fixed, st)
    await tsvc.set_status(ctx, db, p, held, "triaging")
    await tsvc.set_award(ctx, db, p, fixed, 5_000_000_000, approve=True)  # approved, and not yet awarded
    before = await stats.collect(db, now)
    assert (before["reports"], before["researchers"]) == (2, 1)  # the question is not a report
    assert before["public"] == {
        "reports": 2, "open": 1, "fixed": 1, "closed": {},
        "fixed_by_tier": {"high": 1},  # the tier of the fix; the held one is nowhere
        "by_area": {"consensus": 1, "node-api": 1},
    }
    assert before["awards"] == {"xe": 0, "tickets": 0, "researchers": 0, "top": []}
    assert sum(d["awarded_xe"] for d in before["per_day"]) == 0

    # a sealed report, from someone new, fixed and with an approved award of its own
    sealed = await mk("sealed", bob, "p2p-sync", visibility="private")
    await tsvc.set_facts(ctx, db, p, sealed, {"assessed_tier": "severe"})
    for st in ("triaging", "accepted", "patched"):
        await tsvc.set_status(ctx, db, p, sealed, st)
    await tsvc.set_award(ctx, db, p, sealed, 9_000_000_000, approve=True)
    after = await stats.collect(db, now)
    assert after["reports"] == 3
    assert sum(d["reports"] for d in after["per_day"]) == 3 and sum(map(sum, after["by_hour"])) == 3
    # and nothing else: who filed it is not counted until a report of theirs is public
    assert after["researchers"] == before["researchers"] == 1
    assert after["public"] == before["public"] and after["awards"] == before["awards"]
    for series in ("researchers", "fixed", "awarded_xe"):
        assert [d[series] for d in after["per_day"]] == [d[series] for d in before["per_day"]], series
    assert after["log_entries"] == (await EventLog.head(db)).index + 1

    # `awarded` publishes the award, here as everywhere: the totals are the leaderboard's
    await tsvc.set_status(ctx, db, p, fixed, "awarded")
    done = await stats.collect(db, now)
    board = await tsvc.leaderboard(db)
    assert done["awards"]["xe"] == sum(b["award_xe"] for b in board) == 5_000_000_000
    assert sum(d["awarded_xe"] for d in done["per_day"]) == done["awards"]["xe"]
    assert done["awards"]["top"] == [{"name": "ada", "login": "ada", "award_xe": 5_000_000_000, "tickets": 1}]
    assert done["public"]["fixed"] == 1 and sum(d["fixed"] for d in done["per_day"]) == 1
    assert json.loads(json.dumps(done)) == done  # what `/v1/stats` returns as it stands


async def test_mailed_reports_are_filed_private_with_their_sender_and_only_once(ctx, db):
    """A report that came by email is a private ticket with its sender as the reporter, filed once
    however often the export is run; a mail that follows another is a note on that ticket, said to be
    the reporter's or not; what the desk would not keep is skipped with the reason; nobody is written
    to and nothing of it is public."""
    from desk.services import mailbox

    team = await _team(ctx, db)
    known = await rsvc.from_email(ctx, db, "known@example.org", link_to=None)
    spec = tsvc.NewTicket(kind="bounty", title="on the desk already", source="web")
    onfile = await tsvc.create(ctx, db, team.actor, spec)
    await rsvc.attach(ctx, db, team, onfile, email="known@example.org")

    def mail(ref, **kw):
        base = {"ref": ref, "from_email": "New.Sender@Example.org", "date": "2026-11-15T05:20:18Z",
                "subject": "[Critical] a double spend", "body": "Steps.\x00\n1. grind the hash"}
        return {**base, **kw}

    items = [
        mail("m-3", follows="m-1", subject="Re: a double spend", body="A correction."),  # before its report
        mail("m-1", claimed_tier="Critical", attachments=["poc.zip"]),
        mail("m-2", from_email="known@example.org", subject="a medium one", claimed_tier=None),
        mail("m-4", follows=onfile.id, from_email="known@example.org", body="More detail."),
        mail("m-5", follows=onfile.id, from_email="stranger@example.org", body="I retract it."),
        mail("m-6", follows="XE-9999"),
        mail("m-1"),
        mail("m-7", claimed_tier="urgent"),
        mail("m-8", from_email="not an address"),
        mail("m-9", date="yesterday"),
        mail("m-10", body=" \x01 "),
        mail("m-11", date="2026-11-15T05:20:18"),
        "not an object",
    ]
    oid = onfile.id

    async def mailed():
        q = select(Ticket).where(Ticket.source == "email").order_by(Ticket.id)
        return list((await db.execute(q)).scalars().all())

    def sizes(out):
        return {k: len(v) for k, v in out.items()}

    dry = await mailbox.import_emails(ctx, db, items, dry_run=True)
    assert sizes(dry) == {"created": 2, "existing": 0, "notes": 3, "skipped": 8}
    assert await mailed() == [] and await thread.notes_for(db, onfile) == []
    why = {s["ref"]: s["why"] for s in dry["skipped"]}
    assert set(why) == {"m-6", "m-1", "m-7", "m-8", "m-9", "m-10", "m-11", "item 12"}
    assert "twice" in why["m-1"] and "not on the desk" in why["m-6"] and "claimed_tier" in why["m-7"]

    out = await mailbox.import_emails(ctx, db, items)
    assert sizes(out) == sizes(dry) and {s["ref"]: s["why"] for s in out["skipped"]} == why
    first, second = await mailed()
    assert [(r["ref"], r["ticket"]) for r in out["created"]] == [("m-1", first.id), ("m-2", second.id)]
    for t in (first, second):
        assert (t.kind, t.visibility, t.status, t.body) == ("bounty", "private", "new", "")
        assert t.source_created_at is not None and t.told_at is None
    assert (first.source_ref, first.claimed_tier, second.claimed_tier) == ("m-1", "critical", None)
    assert tsvc.body_for(ctx, first) == "Steps.\n1. grind the hash"  # cleaned, sealed, the mail's text
    sender = await rsvc.get(db, first.reporter_id)
    assert sender.email == "new.sender@example.org" and second.reporter_id == known.id
    notes = sorted(n.body for n in await thread.notes_for(db, first))  # the follow-up, then where from
    assert len(notes) == 2 and "mail m-1" in notes[1] and "poc.zip" in notes[1]
    assert "new.sender" not in "".join(notes) and "A correction." in notes[0]
    assert "from the reporter's address" in notes[0]
    await db.refresh(onfile)
    theirs, not_theirs = sorted(n.body for n in await thread.notes_for(db, onfile))  # mail m-4, mail m-5
    assert "from the reporter's address" in theirs and "More detail." in theirs
    assert "NOT the reporter's" in not_theirs and "I retract it." in not_theirs
    assert (onfile.status, onfile.closed_reason) == ("new", None)  # a mail moves nothing
    # nobody was written to, and the public log has nothing of a mailed report
    assert (await db.execute(select(Reply))).scalars().all() == []
    for t in (first, second):
        assert await EventLog.page(db, 0, 50, ref=t.id) == []
        kinds = {e.kind for e in await EventLog.page(db, 0, 50, ref=t.id, public_only=False)}
        assert {"ticket.created", "ticket.reporter", "note.added"} <= kinds

    again = await mailbox.import_emails(ctx, db, items)
    assert sizes(again) == {"created": 0, "existing": 2, "notes": 3, "skipped": 8}
    assert {n["note"] for n in again["notes"]} == {"already there"}
    assert len(await mailed()) == 2 and len(await thread.notes_for(db, first)) == 2
    onfile = await tsvc.get(db, oid)
    assert len(await thread.notes_for(db, onfile)) == 2

    # the daily cap is the reporter's whichever door the report came through: a mailbox is not a way
    # round it
    cap = ctx.config.daily_cap
    flood = [mail(f"f-{i}", from_email="flood@example.org", subject=f"probe {i}") for i in range(cap + 1)]
    out = await mailbox.import_emails(ctx, db, flood)
    assert [bool(r["queued"]) for r in out["created"]] == [False] * cap + [True]
    last = await tsvc.get(db, out["created"][-1]["ticket"])
    assert last.queued and last.visibility == "private"


async def test_a_tickets_text_is_indexed_when_it_is_written_not_read_for_each_reader(ctx, db, monkeypatch):
    """`similar` and the list's search are anyone's to call, so what they match on is kept by the
    database and written when the ticket is: its words match from the next read, a body that contains
    a string is found through the trigram index, a sealed body stops matching either way, and nothing
    under `desk/` parses or reads every body for a reader (15 Nov: a few callers a second held every
    connection the desk has)."""
    from desk import models

    p = await _team(ctx, db)

    async def mk(title, body=""):
        spec = tsvc.NewTicket(kind="bounty", title=title, body=body, source="web")
        return await tsvc.create(ctx, db, p.actor, spec)

    async def by_words(t):
        rows = await tsvc.similar(db, ctx.config, p, t, body=tsvc.body_for(ctx, t))
        return {s.ticket.id for s in rows if "same words" in s.why}

    async def found(q, who=authz.ANON):
        f = tsvc.Filters(q=q, status="all")
        rows = await tsvc.list_tickets(db, ctx.config, who, f)
        assert len(rows) == await tsvc.count_tickets(db, ctx.config, who, f)
        return {t.id for t in rows}

    async def by_path(t):
        rows = await tsvc.similar(db, ctx.config, p, t, body=tsvc.body_for(ctx, t))
        return {s.ticket.id for s in rows if any(w.startswith("cites ") for w in s.why)}

    a = await mk("Escrow refund after settlement", "The lease escrow is refunded twice by archiveLease.")
    b = await mk("Unrelated title", "A second path refunds the escrow of a lease after settlement.")
    c = await mk("Typo on the scope page", "It says 'teh'.")
    assert await by_words(a) == {b.id}
    # "contains", for the search box and for the paths a report cites: case is not the reader's to
    # get right, `%` and `_` are characters, and a string the index cannot look up (no three letters
    # or digits in a row) is not asked of the bodies at all
    d = await mk("A 100% loss", "core/ledger.go drops the top_up; see Core/Ledger.go line 40.")
    e = await mk("Another report", "The same branch of core/ledger.go, reached from sync; topXup too.")
    assert await found("ARCHIVElease") == {a.id} and await found("core/ledger.go") == {d.id, e.id}
    assert await found("top_up") == {d.id} and await found("topXup") == {e.id}
    assert await found("100%") == {d.id} and await found("%") == {d.id}, "the one row with a percent sign"
    assert await found("of") == set(), "two letters are looked for in titles and ids, not in bodies"
    assert await found("an") == {e.id} and tsvc.body_contains("a/b") is None
    assert await by_path(d) == {e.id} and await by_path(e) == {d.id}
    # each path is a read of the index, so one that a shorter cited path is inside is not asked for
    cited = ["src/core/ledger.go", "core/ledger.go", "Core/Ledger.go", "net/gossip.go", "a/b.go"]
    assert tsvc._lookups(cited) == ["core/ledger.go", "net/gossip.go"]
    # a write is what parses: the row's words follow its title and body, with nothing run for it
    c.title = "The escrow of a lease is refunded twice"
    await db.flush()
    assert await by_words(a) == {b.id, c.id}
    # a sealed body is not text the database holds, so it is not words either; the title still is
    await tsvc.set_facts(ctx, db, p, b, {"visibility": "private"})
    assert await by_words(a) == {c.id}
    assert tsvc.body_for(ctx, b).startswith("A second path")
    assert await found("second path", p) == set() and await found("Unrelated", p) == {b.id}
    await tsvc.set_facts(ctx, db, p, e, {"visibility": "private"})
    assert await by_path(d) == set() and await found("core/ledger.go", p) == {d.id}
    # ranking is the costly part, so it is not done for every ticket sharing a word: the tickets
    # sharing the most words are counted from the index and only those are ranked
    f = await mk("Notes on escrow", "Nothing else in common.")
    assert await by_words(a) == {c.id, f.id}
    with monkeypatch.context() as only_one:
        only_one.setattr(tsvc, "_RANKED", 1)
        assert await by_words(a) == {c.id}, "one word shared against four: the fuller match is read"

    # the column is the database's: generated from the row, indexed, and spelled once
    q = "SELECT generation_expression FROM information_schema.columns WHERE table_name = 'tickets' "
    generated = (await db.execute(text(q + "AND column_name = 'search'"))).scalar_one()
    assert "to_tsvector" in generated
    q = "SELECT indexdef FROM pg_indexes WHERE tablename = 'tickets' AND indexname = "
    assert "gin (search)" in (await db.execute(text(q + "'ix_ticket_search'"))).scalar_one().lower()
    trgm = (await db.execute(text(q + "'ix_ticket_body_trgm'"))).scalar_one().lower()
    assert "gin (body gin_trgm_ops)" in trgm
    assert not hasattr(Ticket, "search"), "not mapped: no list, page or write reads the words back"
    migration = (ROOT / "alembic" / "versions" / "0013_ticket_words_indexed.py").read_text()
    assert f'TICKET_SEARCH = "{models.TICKET_SEARCH}"' in migration
    for stmt in models.TICKET_TEXT_DDL[2:]:  # the two indexes, as the migration spells them
        assert stmt.replace("CREATE INDEX", "CREATE INDEX IF NOT EXISTS") in migration
    # and no reader parses or reads every body: the one place a ticket's text becomes a tsvector is
    # that expression, and the one condition on a body is `body_contains`
    for path in sorted((ROOT / "desk").rglob("*.py")):
        src = path.read_text(encoding="utf-8")
        once = 1 if path.name == "models.py" else 0
        assert src.count("to_tsvector") == once, f"{path.name} parses a ticket's text for a reader"
        once = 1 if path.name == "tickets.py" and path.parent.name == "services" else 0
        assert len(re.findall(r"\bbody\.i?like\(", src)) == once, f"{path.name} reads every body"


async def test_authenticating_a_token_holds_nothing_for_the_length_of_the_request(ctx, db):
    """The rule: bookkeeping written on the way in is committed on the way in; a request holds no
    row lock for its whole length on account of who is asking. A token's `last_used_at` was set on
    the row and left to the request's transaction, so every request of one token waited for the one
    before it, holding a connection while it did, and a read never kept the write (15 Nov: eight
    readers on one token, the pool empty for everyone)."""
    team = await _team(ctx, db)
    issuer = authz.Principal(kind="user", user=team.user, roles={"admin"})
    tok, raw = await users.issue(ctx, db, issuer, team.user, "m", "t", ["read:public"], 30)
    await db.commit()
    assert tok.last_used_at is None
    sm = async_sessionmaker(db.bind, expire_on_commit=False)
    locked = select(AgentToken).where(AgentToken.id == tok.id).with_for_update(nowait=True)
    async with sm() as first, sm() as second:
        one = await auth.token_from_bearer(first, raw)
        assert one.last_used_at is not None and not first.dirty and not first.in_transaction()
        # the request goes on, as `resolve` does next: this read is what flushed the write
        assert (await first.execute(select(User).where(User.id == one.owner_id))).scalar_one()
        # a second request of the same token while the first is open: the row is free, and written
        row = (await second.execute(locked)).scalar_one()
        assert row.last_used_at == one.last_used_at, "committed on the way in, read or not"
        await second.rollback()
        two = await auth.token_from_bearer(second, raw)
        assert two.last_used_at == one.last_used_at and not second.dirty, "within the minute: no write"
    # a token not seen for a while is written again, once
    await db.execute(text("UPDATE agent_tokens SET last_used_at = now() - interval '5 minutes'"))
    await db.commit()
    async with sm() as third, sm() as fourth:
        late = await auth.token_from_bearer(third, raw)
        assert (auth.now() - late.last_used_at).total_seconds() < 30 and not third.in_transaction()
        assert (await fourth.execute(locked)).scalar_one().last_used_at == late.last_used_at
    # no row is assigned to on the way in by any of the three ways of asking
    for way in (auth.resolve, auth.token_from_bearer, auth.session_from_request,
                auth.reporter_session_from_request):
        assert not re.search(r"^\s+\w+\.\w+ = ", inspect.getsource(way), re.M), way.__name__


async def test_a_batch_commits_each_item_before_the_next(ctx, db, monkeypatch):
    """The rule: a batch holds the log's head, and the rows it locks, for one item's work and never
    for the batch's. An append holds the head until the commit and every writer waits on it; a
    reviewer adopting a wave of proposals in one request, a savepoint each and one commit at the
    end, stopped every logged read and write on the desk until it was done (15 Nov). Asked of a real
    batch as another writer finds the desk between its items, of the loop every batch runs in
    (`db.each_committed`), and of the source: a loop with a savepoint in it is that loop."""
    from sqlalchemy import func

    from desk.db import each_committed
    from desk.models import LogHead
    from desk.services import mailbox

    p = await _team(ctx, db)
    agent = await _agent(ctx, db, p.user)
    asked = []
    for title in "abc":
        t = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title=title, source="web"))
        asked.append(await psvc.propose(ctx, db, agent, t, "verdict", "valid", "reproduced"))
    await db.commit()
    sm = async_sessionmaker(db.bind, expire_on_commit=False)
    head = select(LogHead).where(LogHead.id == 1).with_for_update(nowait=True)
    adopted = select(func.count()).select_from(Proposal).where(Proposal.state == "adopted")
    found = []
    decide = psvc.decide

    async def watched(ctx_, db_, p_, pr, yes, **kw):
        # as another writer finds the desk when an item starts: the log's head is there to take,
        # and every decision before this one is there to read
        async with sm() as other:
            assert (await other.execute(head)).scalar_one()
            found.append((await other.execute(adopted)).scalar_one())
        return await decide(ctx_, db_, p_, pr, yes, **kw)

    monkeypatch.setattr(psvc, "decide", watched)
    out = await psvc.decide_many(ctx, db, p, [pr.id for pr in asked], [])
    assert len(out["decided"]) == 3 and out["skipped"] == [] and found == [0, 1, 2]
    assert not db.in_transaction(), "the last item is committed as the ones before it are"
    # the loop itself, however the body leaves an item: by `continue`, with its savepoint rolled
    # back, by `break`; nothing of one item is still open when the next begins
    began = []
    async for i in each_committed(db, range(4)):
        began.append(db.in_transaction())
        if i == 3:
            break
        await ctx.events.append(db, "test", "desk", {"i": i})
        if i == 0:
            continue
        try:
            async with db.begin_nested():
                await ctx.events.append(db, "test", "desk", {"i": -i})
                if i == 1:
                    raise HTTPException(409, "refused")
        except HTTPException:
            pass
    assert began == [False] * 4 and not db.in_transaction()
    async with sm() as other:
        kept = await EventLog.page(other, 0, 50, kind="test")
        assert sorted(e.payload["i"] for e in kept) == [-2, 0, 1, 2]
    # the sites: every batch is that loop, with its savepoint inside it, and a savepoint anywhere
    # else under desk/ is one this list does not know
    batches = (psvc.fill_awards, psvc.close_duplicates, psvc.decide_many, tsvc.settle_many,
               tell.tell_resting, mailbox.import_emails)
    for fn in batches:
        src = inspect.getsource(fn)
        assert "each_committed(db, " in src, fn.__name__
        assert src.index("each_committed(db, ") < src.index("begin_nested()"), fn.__name__
    savepoints = {
        str(path.relative_to(ROOT / "desk")): path.read_text(encoding="utf-8").count("begin_nested()")
        for path in (ROOT / "desk").rglob("*.py")
    }
    assert {k: n for k, n in savepoints.items() if n} == {
        "services/proposals.py": 3, "services/tickets.py": 1, "services/tell.py": 1,
        "services/mailbox.py": 2, "services/sync.py": 1,  # sync's is one issue, in no loop of its own
    }


async def test_one_item_that_fails_does_not_stop_a_batch_or_its_mail(ctx, db, monkeypatch):
    """The rule beside `each_committed`: a batch commits as it goes, so by the time one item fails
    the ones before it are done and their replies are owed their mail. An item that fails in a way
    the desk did not expect is undone, logged and passed over (`db.passed_over`), not let out of
    the loop, where it took the list of what was done with it; and a request that does raise still
    mails what it had committed (`deps.request_db`)."""
    from desk.api import deps
    from desk.db import FAILED

    p = await _team(ctx, db)
    agent = await _agent(ctx, db, p.user)
    asked = []
    for title in "abc":
        t = await tsvc.create(ctx, db, p.actor, tsvc.NewTicket(kind="bounty", title=title, source="web"))
        asked.append(await psvc.propose(ctx, db, agent, t, "verdict", "valid", "reproduced"))
    await db.commit()
    ids = [pr.id for pr in asked]  # read now: the rollback below expires the rows
    decide = psvc.decide

    async def breaks_on_the_second(ctx_, db_, p_, pr, yes, **kw):
        pid = pr.id
        out = await decide(ctx_, db_, p_, pr, yes, **kw)
        if pid == ids[1]:
            raise RuntimeError("the signer went away")  # after its writes: they are undone with it
        return out

    monkeypatch.setattr(psvc, "decide", breaks_on_the_second)
    out = await psvc.decide_many(ctx, db, p, ids, [])
    assert [d["proposal"] for d in out["decided"]] == [ids[0], ids[2]]
    assert [(s["proposal"], s["why"]) for s in out["skipped"]] == [(ids[1], FAILED)]
    sm = async_sessionmaker(db.bind, expire_on_commit=False)
    async with sm() as other:
        rows = (await other.execute(select(Proposal).order_by(Proposal.id))).scalars().all()
        assert [r.state for r in rows] == ["adopted", "pending", "adopted"]
    assert (await EventLog.verify(db))["ok"]
    # every batch has the same two ways out of an item, a refusal and a failure
    from desk.services import mailbox

    for fn in (psvc.fill_awards, psvc.close_duplicates, psvc.decide_many, tsvc.settle_many,
               tell.tell_resting, mailbox.import_emails):
        src = inspect.getsource(fn)
        loop = src[src.index("each_committed("):]
        assert loop.count("except HTTPException") == loop.count("except Exception") == 1, fn.__name__
        assert loop.count("passed_over(") == 1, fn.__name__
    # a reply a decision sends is owed its mail where it is written, so no route mails from a
    # batch's answer: the one call left in the team's routes is a person's own reply
    from desk.api import team as team_api

    assert inspect.getsource(team_api).count("reply_to_reporter(") == 1
    assert inspect.getsource(psvc.tell_duplicate).count("notify.owe(db, r)") == 1
    assert inspect.getsource(decide).count("notify.owe(db, r)") == 1  # the real one, not the stub above
    # the request's session: what was committed before a route raised is mailed, as it is when the
    # route returns; `mail_owed` itself reads only what is committed
    mailed = []

    async def record(_ctx, ids, opener=None):
        mailed.append(list(ids))
        return 0

    monkeypatch.setattr(deps, "sessionmaker", lambda: sm)
    monkeypatch.setattr(deps, "get_context", lambda: ctx)
    monkeypatch.setattr(notify, "mail_owed", record)
    for raised in (False, True):
        req = deps.request_db()
        s = await req.__anext__()
        notify.owe(s, type("R", (), {"id": 7 + raised})())
        with pytest.raises(RuntimeError if raised else StopAsyncIteration):
            await (req.athrow(RuntimeError("the route failed")) if raised else req.__anext__())
    assert mailed == [[7], [8]]
