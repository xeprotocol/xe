"""ORM tables.

Everything that matters ends up as an event in `events` (the ledger of record). The other tables
are the current-state projections the UI and API read from. A projection can always be rebuilt
from the events; the events can never be rebuilt from a projection.
"""

from __future__ import annotations

from datetime import datetime

from decimal import Decimal

from sqlalchemy import (
    BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, Numeric, SmallInteger, String, Text, TypeDecorator,
    UniqueConstraint, func, text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


class U64(TypeDecorator):
    """An unsigned 64-bit integer (proof-of-work nonces). BIGINT is signed and rejects the upper half."""
    impl = Numeric(20, 0)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return None if value is None else Decimal(int(value))

    def process_result_value(self, value, dialect):
        return None if value is None else int(value)


class Event(Base):
    """Append-only, hash-chained. v2: hash covers {index, ts, kind, actor, payload, prev_hash, public, ref};
    v1 rows (before the envelope change) hash the first six only; their `public` and `ref` are bound by the
    `log.v1_sealed` entry instead (dao/log.py, XE-4017)."""
    __tablename__ = "events"
    index: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    ts: Mapped[int] = mapped_column(BigInteger, nullable=False)              # unix ns
    kind: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)          # seat id, account, or "harness"
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    signer: Mapped[str] = mapped_column(String(64), nullable=False, default="")   # harness pubkey hex
    signature: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    public: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    ref: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)  # proposal hash, session id, ...
    v: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=2, server_default="1")  # hash envelope version


class LogHead(Base):
    """Single row, locked FOR UPDATE on every append so appends serialise."""
    __tablename__ = "log_head"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    index: Mapped[int] = mapped_column(BigInteger, nullable=False, default=-1)
    hash: Mapped[str] = mapped_column(String(64), nullable=False, default="0" * 64)


class Resolution(Base):
    __tablename__ = "resolutions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)             # content digest
    number: Mapped[int] = mapped_column(Integer, nullable=False, unique=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    matter: Mapped[str] = mapped_column(String(64), nullable=False)          # reserved | ordinary | charter
    ops: Mapped[list | None] = mapped_column(JSONB, nullable=True)           # optional state-chain ops it authorises
    proposed_by: Mapped[str] = mapped_column(String(64), nullable=False)     # seat id
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")  # open | passed | rejected | withdrawn
    signatures: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)   # [{seat, public_key, signature, ts, decision}]
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    related_proposal: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    session_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")


class PauseRecord(Base):
    __tablename__ = "pause_records"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    determined_by: Mapped[str] = mapped_column(String(64), nullable=False)   # seat id
    ground: Mapped[str] = mapped_column(String(64), nullable=False)
    determination: Mapped[str] = mapped_column(Text, nullable=False)
    started_at: Mapped[int] = mapped_column(BigInteger, nullable=False)     # ns
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)     # ns
    indefinite: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    extensions: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)  # [{by:[seat..], until, ts}]
    lifted_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    lifted_by: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    post_text: Mapped[str] = mapped_column(Text, nullable=False, default="")
    posted_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")  # active | expired | lifted
    __table_args__ = (Index("ux_pause_one_active", "status", unique=True, postgresql_where=text("status = 'active'")),)


class SigningSession(Base):
    """A state-chain write in two steps: durable approval of the ops, then signing of a block at the live tip."""
    __tablename__ = "signing_sessions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)             # registry | anchor | parameter | keyset
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    ops: Mapped[list] = mapped_column(JSONB, nullable=False)                  # [{action,key,value(raw json text)}]
    ops_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="approving")
    # approving | signing | submitted | failed | cancelled
    approvals: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)   # [{seat, public_key, signature, ts}]
    required_approvals: Mapped[int] = mapped_column(Integer, nullable=False, default=2)
    block: Mapped[dict | None] = mapped_column(JSONB, nullable=True)        # current unsigned block (wire form)
    block_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    block_signatures: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)  # over block_hash
    rebuilds: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    submitted_index: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    submitted_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    # the chain holds another block at the index this session's block was built for: it can never land
    block_displaced: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=text("false"))
    error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    resolution_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    not_before: Mapped[int | None] = mapped_column(BigInteger, nullable=True)  # timelock (ns)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class Proposal(Base):
    __tablename__ = "proposals"
    hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    ops: Mapped[list | None] = mapped_column(JSONB, nullable=True)           # optional exact state-chain ops
    author_account: Mapped[str] = mapped_column(String(64), nullable=False)
    author_pub_key: Mapped[str] = mapped_column(String(64), nullable=False)
    author_signature: Mapped[str] = mapped_column(String(128), nullable=False)
    author_timestamp: Mapped[int] = mapped_column(BigInteger, nullable=False)
    fee_block_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open", index=True)  # open | closed
    opened_at: Mapped[int] = mapped_column(BigInteger, nullable=False)       # ns
    closes_at: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    rules: Mapped[dict] = mapped_column(JSONB, nullable=False)               # pinned at open
    result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)        # tally at close
    decision: Mapped[dict | None] = mapped_column(JSONB, nullable=True)      # member decision, later
    analysis: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)  # ensemble attachments (P2)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Vote(Base):
    __tablename__ = "votes"
    __table_args__ = (UniqueConstraint("proposal_hash", "account", name="uq_vote_proposal_account"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    proposal_hash: Mapped[str] = mapped_column(String(64), ForeignKey("proposals.hash"), nullable=False)
    account: Mapped[str] = mapped_column(String(64), nullable=False)
    pub_key: Mapped[str] = mapped_column(String(64), nullable=False)
    choice: Mapped[str] = mapped_column(String(8), nullable=False)           # for | against | abstain
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    timestamp: Mapped[int] = mapped_column(BigInteger, nullable=False)      # signer's ns timestamp
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    weight: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)   # µXE at the snapshot (an hour and five minutes before open)
    participating: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_agent: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    eligibility: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class FeeLedger(Base):
    __tablename__ = "fee_ledger"
    fee_block_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    proposal_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    payer: Mapped[str] = mapped_column(String(64), nullable=False)
    amount: Mapped[int] = mapped_column(BigInteger, nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="seen")  # seen | due_refund | due_burn | settling | refunded | burned
    tx_hashes: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)   # receive, refund|burn|excess; settle_as + settle_block while settling
    error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class SeenSignature(Base):
    """A signed request we have accepted, so it cannot be accepted twice (XE-0033). Purged past the window."""
    __tablename__ = "seen_signatures"
    sig: Mapped[str] = mapped_column(String(128), primary_key=True)
    timestamp: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)   # signer's ns timestamp
    account: Mapped[str] = mapped_column(String(64), nullable=False, default="")


class InboxMessage(Base):
    __tablename__ = "inbox_messages"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)             # envelope id
    channel: Mapped[str] = mapped_column(String(8), nullable=False)           # chat | http
    from_account: Mapped[str] = mapped_column(String(64), nullable=False)
    to_account: Mapped[str] = mapped_column(String(64), nullable=False)
    pub_key: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    body: Mapped[str] = mapped_column(Text, nullable=False)
    timestamp: Mapped[int] = mapped_column(BigInteger, nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    pow_nonce: Mapped[int] = mapped_column(U64, nullable=False, default=0)
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="new")  # new | read | replying | answered | closed | spam
    classification: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    reply_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    # an HTTP message's text is on the public log (`inbox.published`); set once, never unset (XE-4593)
    published: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=text("false"))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class OutboxMessage(Base):
    __tablename__ = "outbox_messages"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)             # envelope id
    in_reply_to: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    from_seat: Mapped[str] = mapped_column(String(64), nullable=False)
    to_account: Mapped[str] = mapped_column(String(64), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    envelope: Mapped[dict] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")  # queued | sending | sent | failed
    error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Anchor(Base):
    __tablename__ = "anchors"
    n: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    event_index: Mapped[int] = mapped_column(BigInteger, nullable=False)
    head_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    session_id: Mapped[str] = mapped_column(String(64), nullable=False)
    statechain_index: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    statechain_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class HealthCheck(Base):
    __tablename__ = "health_checks"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[int] = mapped_column(BigInteger, nullable=False)
    ok: Mapped[bool] = mapped_column(Boolean, nullable=False)
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False)


class TreasurySnapshot(Base):
    __tablename__ = "treasury_snapshots"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[int] = mapped_column(BigInteger, nullable=False)
    balances: Mapped[dict] = mapped_column(JSONB, nullable=False)


class ScheduleRun(Base):
    """Last run marker per scheduled job, so restarts do not double-fire."""
    __tablename__ = "schedule_runs"
    job: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_run_ts: Mapped[int] = mapped_column(BigInteger, nullable=False)
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)


Index("ix_events_kind_index", Event.kind, Event.index)
# An index is declared here under the name its migration gave it, so a database built from the models
# (the tests') and one built by the migrations (the deployment's) are the same schema (XE-10697).
Index("ix_proposals_author", Proposal.author_account)
Index("ix_votes_proposal", Vote.proposal_hash)
Index("ix_fee_ledger_proposal", FeeLedger.proposal_hash)
Index("ix_inbox_from", InboxMessage.from_account)
Index("ix_outbox_reply", OutboxMessage.in_reply_to)
Index("ix_health_ts", HealthCheck.ts)
Index("ix_treasury_ts", TreasurySnapshot.ts)
# read in time order on every inbox page, and by status and age on every worker pass (XE-8172); migration 0007
Index("ix_inbox_timestamp", InboxMessage.timestamp, InboxMessage.id)
Index("ix_outbox_status", OutboxMessage.status, OutboxMessage.created_at)
Index("ix_sessions_status", SigningSession.status, SigningSession.created_at)
