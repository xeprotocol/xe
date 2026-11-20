"""Rule checks for open-vote resolution intake and proposal decision authority."""

import os
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from dao.auth import Verified
from dao.config import load_config
from dao.db import Base
from dao.log import EventLog
from dao.models import Proposal, Resolution, SigningSession
from dao.services import portal, resolutions
from dao.signer import Signer
from xe.keys import KeyPair

ROOT = Path(__file__).resolve().parents[1]
URL = os.environ.get("DAO_TEST_DATABASE_URL")
D = 24 * 3600 * 1_000_000_000
AUTHOR = "a" * 64


async def test_a_proposal_decision_and_open_vote_resolution_agree_on_direction_ops_and_liveness(monkeypatch):
    """An open-vote resolution (`adopt_open_vote`, `decline_open_vote`) names its proposal and carries ops
    only when adopting, refuses already-failed or declined proposals at intake, and `portal.decide` cites
    only a live resolution whose direction and ops agree with the decision recorded."""
    proposals: dict[str, Proposal] = {}
    res_rows: dict[str, Resolution] = {}
    sess_rows: dict[str, SigningSession] = {}
    locks: list[tuple[str, bool, bool]] = []

    class _Res:
        def __init__(self, row):
            self._row = row

        def scalar_one_or_none(self):
            return self._row

    class _FakeDb:
        def __init__(self):
            self.added = []

        def add(self, obj):
            self.added.append(obj)

        async def execute(self, stmt):
            entity = stmt.column_descriptions[0]["entity"]
            locked = stmt._for_update_arg is not None
            pop = bool(stmt.get_execution_options().get("populate_existing"))
            key = stmt.whereclause.right.value
            if entity is Proposal:
                return _Res(proposals.get(key))
            if entity is Resolution:
                locks.append(("resolution", locked, pop))
                return _Res(res_rows.get(key))
            if entity is SigningSession:
                locks.append(("session", locked, pop))
                return _Res(sess_rows.get(key))
            raise AssertionError(f"unexpected query: {stmt}")

    n = {"i": 0}

    async def next_num(_db):
        n["i"] += 1
        return n["i"]

    async def noop(*_a, **_k):
        return None

    monkeypatch.setattr(resolutions, "_next_number", next_num)
    cfg = load_config(ROOT / "config")
    ctx = SimpleNamespace(config=cfg, events=SimpleNamespace(append=noop))
    db = _FakeDb()

    ops_a = [{"action": "set", "key": "dao.param", "value": '{"b":1,"a":2}'}]
    ops_b = [{"action": "set", "key": "dao.param", "value": '{"a":2,"b":1}'}]
    ops_other = [{"action": "set", "key": "dao.other", "value": "1"}]

    def make_pr(ch: str, outcome: str | None, ops=None, status: str = "closed", decision=None) -> Proposal:
        pr = Proposal(
            hash=ch * 64, title="t", body="b", ops=ops, author_account="a" * 64, author_pub_key="b" * 64,
            author_signature="s", author_timestamp=1, fee_block_hash=ch * 64, status=status, opened_at=1,
            closes_at=2, rules={}, result={"outcome": outcome} if outcome else None, decision=decision,
            analysis=[],
        )
        proposals[pr.hash] = pr
        return pr

    pr_ops = make_pr("1", "passed", ops=ops_a)
    pr_prose = make_pr("2", "passed", ops=None)
    pr_failed = make_pr("3", "failed", ops=ops_a)
    pr_no_quorum = make_pr("4", "no_quorum", ops=None)
    pr_declined = make_pr("5", "passed", ops=ops_a, status="decided", decision={"decision": "decline"})
    pr_open = make_pr("6", None, ops=ops_a, status="open")

    def v_seat(payload: dict):
        return SimpleNamespace(
            payload=payload, seat=SimpleNamespace(id="cto", is_member=False), actor="seat:cto",
            timestamp=10, account="c" * 64, pub_key="d" * 64, signature="e" * 128,
        )

    # 1. resolutions.propose: open-vote matters name a proposal, refuse failed/declined votes, and match ops
    for matter in ("adopt_open_vote", "decline_open_vote"):
        for blank in ({}, {"related_proposal": ""}, {"related_proposal": None}):
            with pytest.raises(HTTPException) as e:
                req = v_seat({"title": "t", "body": "b", "matter": matter, **blank})
                await resolutions.propose(ctx, db, req)
            assert e.value.status_code == 400 and matter in e.value.detail
    for bad_ops in (ops_a, []):
        with pytest.raises(HTTPException) as e:
            await resolutions.propose(ctx, db, v_seat({
                "title": "t", "body": "b", "matter": "decline_open_vote",
                "related_proposal": pr_ops.hash, "ops": bad_ops,
            }))
        assert e.value.status_code == 400 and "decline_open_vote" in e.value.detail
    for bad_pr in (pr_failed, pr_no_quorum, pr_declined):
        with pytest.raises(HTTPException) as e:
            await resolutions.propose(ctx, db, v_seat({
                "title": "t", "body": "b", "matter": "adopt_open_vote",
                "related_proposal": bad_pr.hash, "ops": bad_pr.ops,
            }))
        assert e.value.status_code == 409, bad_pr.hash
    for bad_ops in (None, ops_other):
        with pytest.raises(HTTPException) as e:
            await resolutions.propose(ctx, db, v_seat({
                "title": "t", "body": "b", "matter": "adopt_open_vote",
                "related_proposal": pr_ops.hash, "ops": bad_ops,
            }))
        assert e.value.status_code == 400 and "exact ops" in e.value.detail

    r_open_adopt = await resolutions.propose(ctx, db, v_seat({
        "title": "t", "body": "b", "matter": "adopt_open_vote",
        "related_proposal": pr_open.hash, "ops": ops_b,
    }))
    assert r_open_adopt.related_proposal == pr_open.hash and portal.same_ops(r_open_adopt.ops, pr_open.ops)
    r_adopt_ops = await resolutions.propose(ctx, db, v_seat({
        "title": "t", "body": "b", "matter": "adopt_open_vote",
        "related_proposal": pr_ops.hash, "ops": ops_b,
    }))
    assert r_adopt_ops.related_proposal == pr_ops.hash and portal.same_ops(r_adopt_ops.ops, pr_ops.ops)
    r_decline_ok = await resolutions.propose(ctx, db, v_seat({
        "title": "t", "body": "b", "matter": "decline_open_vote", "related_proposal": pr_prose.hash,
    }))
    assert r_decline_ok.ops is None and r_decline_ok.related_proposal == pr_prose.hash
    r_prose_adopt = await resolutions.propose(ctx, db, v_seat({
        "title": "t", "body": "b", "matter": "adopt_open_vote", "related_proposal": pr_prose.hash,
    }))
    assert r_prose_adopt.ops is None
    r_prose_with_ops = await resolutions.propose(ctx, db, v_seat({
        "title": "t", "body": "b", "matter": "adopt_open_vote",
        "related_proposal": pr_prose.hash, "ops": ops_a,
    }))
    assert r_prose_with_ops.ops is not None
    # Non-open-vote matters keep optional links and counter-proposal ops (even on failed proposals)
    r_note = await resolutions.propose(ctx, db, v_seat({"title": "t", "body": "b", "matter": "note"}))
    assert r_note.related_proposal == ""
    counter_req = v_seat({
        "title": "t", "body": "b", "matter": "parameter",
        "related_proposal": pr_failed.hash, "ops": ops_other,
    })
    assert (await resolutions.propose(ctx, db, counter_req)).related_proposal == pr_failed.hash

    # 2. portal.decide: direction, ops agreement, FOR UPDATE locking, and session liveness across decisions
    def put_res(rid: str, pr: Proposal, matter: str, status: str = "passed", ops=None, sid: str = ""):
        r = Resolution(
            id=rid, number=len(res_rows) + 1, title="t", body="b", matter=matter, ops=ops,
            proposed_by="founder-a", status=status, signatures=[], related_proposal=pr.hash, session_id=sid,
        )
        res_rows[rid] = r
        return r

    def decide_req(pr: Proposal, decision: str, rid: str | None = None):
        body = {"proposal": pr.hash, "decision": decision, "reasons": "ten characters or more"}
        if rid is not None:
            body["resolution_id"] = rid
        return v_seat(body)

    put_res("dec-prose", pr_prose, "decline_open_vote")
    with pytest.raises(HTTPException) as e:
        await portal.decide(ctx, db, pr_prose, decide_req(pr_prose, "adopt", "dec-prose"))
    assert e.value.status_code == 409 and "declines" in e.value.detail and pr_prose.status == "closed"
    assert locks[-1] == ("resolution", True, True)

    put_res("adopt-prose", pr_prose, "adopt_open_vote")
    put_res("param-prose", pr_prose, "parameter", ops=ops_a)
    for rid in ("adopt-prose", "param-prose"):
        with pytest.raises(HTTPException) as e:
            await portal.decide(ctx, db, pr_prose, decide_req(pr_prose, "decline", rid))
        assert e.value.status_code == 409 and "cannot be cited to decline" in e.value.detail

    put_res("adopt-failed-open", pr_failed, "adopt_open_vote", status="open")
    put_res("adopt-failed-passed", pr_failed, "adopt_open_vote", status="passed")
    for dec, rid in (("refer_to_resolution", "adopt-failed-open"), ("defer", "adopt-failed-passed"),
                     ("adopt", "adopt-failed-passed"), ("decline", "adopt-failed-passed")):
        with pytest.raises(HTTPException) as e:
            await portal.decide(ctx, db, pr_failed, decide_req(pr_failed, dec, rid))
        assert e.value.status_code == 409, (dec, rid)

    put_res("adopt-mismatch", pr_ops, "adopt_open_vote", status="passed", ops=ops_other)
    for dec in ("refer_to_resolution", "defer", "adopt"):
        with pytest.raises(HTTPException) as e:
            await portal.decide(ctx, db, pr_ops, decide_req(pr_ops, dec, "adopt-mismatch"))
        assert e.value.status_code == 409 and "ops" in e.value.detail, dec

    # Dead signing sessions (`cancelled`, `failed`, missing) cannot authorise any decision citing it
    for state in ("cancelled", "failed", None):
        sid = f"sess-{state}"
        if state is not None:
            sess_rows[sid] = SigningSession(
                id=sid, kind="parameter", title="R", ops=ops_b, ops_digest="0" * 64, status=state,
                approvals=[], required_approvals=2, block=None, block_hash="",
                block_signatures=[], rebuilds=0,
            )
        rid = f"res-{state}"
        put_res(rid, pr_ops, "adopt_open_vote", status="passed", ops=ops_b, sid=sid)
        for dec in ("adopt", "refer_to_resolution", "defer"):
            locks.clear()
            with pytest.raises(HTTPException) as e:
                await portal.decide(ctx, db, pr_ops, decide_req(pr_ops, dec, rid))
            assert e.value.status_code == 409 and "will not execute" in e.value.detail, (state, dec)
            assert locks == [("resolution", True, True), ("session", True, True)]

    # Live sessions (owed "", approving, signing, submitted) and valid declines succeed
    for i, state in enumerate(("", "approving", "signing", "submitted")):
        pr_live = make_pr(chr(ord("a") + i), "passed", ops=ops_a)
        sid = f"live-{state}" if state else ""
        if state:
            sess_rows[sid] = SigningSession(
                id=sid, kind="parameter", title="R", ops=ops_b, ops_digest="0" * 64, status=state,
                approvals=[], required_approvals=2, block=None, block_hash="",
                block_signatures=[], rebuilds=0,
            )
        rid = f"ok-{i}"
        put_res(rid, pr_live, "adopt_open_vote", status="passed", ops=ops_b, sid=sid)
        await portal.decide(ctx, db, pr_live, decide_req(pr_live, "refer_to_resolution", rid))
        assert pr_live.decision["decision"] == "refer_to_resolution"
        await portal.decide(ctx, db, pr_live, decide_req(pr_live, "adopt", rid))
        assert pr_live.decision["decision"] == "adopt" and len(pr_live.decision["history"]) == 1

    await portal.decide(ctx, db, pr_prose, decide_req(pr_prose, "decline", "dec-prose"))
    assert pr_prose.decision["decision"] == "decline" and pr_prose.decision["resolution_id"] == "dec-prose"
    await portal.decide(ctx, db, pr_no_quorum, decide_req(pr_no_quorum, "decline"))
    assert pr_no_quorum.decision["decision"] == "decline" and pr_no_quorum.decision["resolution_id"] == ""


@pytest.mark.skipif(not URL, reason="DAO_TEST_DATABASE_URL not set")
async def test_open_vote_resolutions_and_decisions_agree_in_the_database():
    eng = create_async_engine(URL)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text("INSERT INTO log_head (id, index, hash) VALUES (1, -1, repeat('0', 64))"))
    sm = async_sessionmaker(eng, expire_on_commit=False)
    try:
        async with sm() as db:
            kp = KeyPair.generate()
            events = EventLog(Signer({"harness": kp}, {"harness": {"event.sign"}}))
            member = SimpleNamespace(
                id="founder-a", is_member=True, public_key="p" * 64,
                can=lambda r, _rs=frozenset(("pause", "sign_resolutions")): r in _rs,
            )
            cfg = SimpleNamespace(
                agent_accounts=set(), accounts={"dao": "d" * 64, "fee": "f" * 64}, human_seats=[],
                members=[member],
                pinned_rules=lambda: {
                    "fee_micro_xe": 1000, "window_days": 7, "participating_wallet": {},
                    "excluded_accounts": [], "agents": {},
                },
            )
            ctx = SimpleNamespace(
                chain=SimpleNamespace(), signer=SimpleNamespace(), events=events, config=cfg,
                node=SimpleNamespace(chat_pow_difficulty=0, pow_difficulty=0, network_id="xe-test"),
            )
            now = time.time_ns()

            def closed_pr(h: str, outcome: str, ops=None) -> Proposal:
                return Proposal(
                    hash=h, title="t", body="b", ops=ops, author_account=AUTHOR, author_pub_key="p" * 64,
                    author_signature="s", author_timestamp=now, fee_block_hash=h, status="closed",
                    opened_at=now - D, closes_at=now - 1, rules=cfg.pinned_rules(), analysis=[],
                    result={"outcome": outcome, "participating_wallets": 0, "quorum_wallets": 20},
                )

            ops = [{"action": "set", "key": "dao.x", "value": "1"}]
            pr_ops = closed_pr("a" * 64, "passed", ops=ops)
            pr_prose = closed_pr("b" * 64, "passed", ops=None)
            pr_failed = closed_pr("c" * 64, "failed", ops=ops)
            db.add_all([pr_ops, pr_prose, pr_failed])
            await db.flush()

            def proposing(matter: str, **extra):
                v = Verified(
                    account=AUTHOR, pub_key="p" * 64,
                    payload={"title": "t", "body": "b", "matter": matter, **extra},
                    timestamp=time.time_ns(), signature=os.urandom(64).hex(),
                )
                v.seat = member
                return v

            def seat_req(payload: dict, pr: Proposal):
                v = Verified(
                    account=AUTHOR, pub_key="p" * 64, payload={"proposal": pr.hash, **payload},
                    timestamp=time.time_ns(), signature=os.urandom(64).hex(),
                )
                v.seat = SimpleNamespace(id="cto")
                return v

            for matter in ("adopt_open_vote", "decline_open_vote"):
                with pytest.raises(HTTPException) as e:
                    await resolutions.propose(ctx, db, proposing(matter))
                assert e.value.status_code == 400
            with pytest.raises(HTTPException) as e:
                req = proposing("decline_open_vote", related_proposal=pr_ops.hash, ops=ops)
                await resolutions.propose(ctx, db, req)
            assert e.value.status_code == 400
            with pytest.raises(HTTPException) as e:
                req = proposing("adopt_open_vote", related_proposal=pr_failed.hash, ops=ops)
                await resolutions.propose(ctx, db, req)
            assert e.value.status_code == 409
            with pytest.raises(HTTPException) as e:
                await resolutions.propose(ctx, db, proposing("adopt_open_vote", related_proposal=pr_ops.hash))
            assert e.value.status_code == 400

            req_dec = proposing("decline_open_vote", related_proposal=pr_prose.hash)
            r_dec = await resolutions.propose(ctx, db, req_dec)
            r_dec.status = "passed"
            req_adopt = proposing("adopt_open_vote", related_proposal=pr_ops.hash, ops=ops)
            r_adopt = await resolutions.propose(ctx, db, req_adopt)
            r_adopt.status = "passed"
            dead = SigningSession(
                id="s-dead", kind="parameter", title="R", ops=ops, ops_digest="0" * 64, status="cancelled",
                approvals=[], required_approvals=2, block=None, block_hash="", block_signatures=[],
                rebuilds=0,
            )
            r_adopt.session_id = dead.id
            db.add(dead)
            await db.flush()

            with pytest.raises(HTTPException) as e:
                v1 = seat_req(
                    {"decision": "adopt", "reasons": "wrong direction", "resolution_id": r_dec.id}, pr_prose
                )
                await portal.decide(ctx, db, pr_prose, v1)
            assert e.value.status_code == 409
            with pytest.raises(HTTPException) as e:
                v2 = seat_req(
                    {"decision": "decline", "reasons": "wrong direction", "resolution_id": r_adopt.id}, pr_ops
                )
                await portal.decide(ctx, db, pr_ops, v2)
            assert e.value.status_code == 409
            with pytest.raises(HTTPException) as e:
                v3 = seat_req(
                    {"decision": "adopt", "reasons": "cancelled session", "resolution_id": r_adopt.id}, pr_ops
                )
                await portal.decide(ctx, db, pr_ops, v3)
            assert e.value.status_code == 409
            dead.status = "signing"
            await db.flush()
            v4 = seat_req(
                {"decision": "adopt", "reasons": "live session", "resolution_id": r_adopt.id}, pr_ops
            )
            await portal.decide(ctx, db, pr_ops, v4)
            assert pr_ops.decision["decision"] == "adopt"
    finally:
        await eng.dispose()
