"""Signed requests. Nobody logs in; people sign.

Every write from a human (member, officer, or the public) is a JSON body of the form

    {"payload": {...}, "timestamp": <ns>, "pub_key": <hex>, "signature": <hex>}

where signature = ed25519 over sha256(domain || canonical_json({"dao", "network", "payload", "timestamp"}))
and the account is derived from pub_key. A signature says three things besides its payload, and each is
checked in one place here:

- what kind of thing it is: the domain, fixed per kind of request, so a vote is never a resolution
  approval;
- who it is for: `dao` and `network` are this deployment's own account and the network it serves, both
  published at GET /v1. A request signed for one deployment is not a request to another that trusts the
  same key (XE-2068);
- for a seat's action, which action: the payload names it and the route accepts only its own, so a
  signature given to sign a block is not one to cancel the session (XE-2386).

Timestamps must be within ±10 minutes, and a signature is accepted once: it is written to
`seen_signatures` in the request's own transaction, so the claim lands with the write it authorised and
survives a restart (XE-0033). Rows older than the skew window are purged by the worker; a signature that
old is refused by the timestamp check anyway.
"""

from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from xe.keys import KeyError_, derive_address, exact_hex, verify_hex_signature
from xe.pow import WORKER_POW_DEADLINE_S, search_nonce

from .canonical import DOMAIN_MEMBER_ACTION, digest
from .config import Config, HumanSeat
from .models import SeenSignature
from .ratelimit import SEAT, RouteClass, enforce_account, enforce_ip

MAX_SKEW_NS = 10 * 60 * 1_000_000_000


# Exactly 64 / 128 hex digits, either case. `bytes.fromhex` would also accept whitespace, and the signature
# is the replay key, so the accepted spelling has to be the canonical one (XE-0699).
HEX32 = r"^[0-9a-fA-F]{64}$"
HEX64 = r"^[0-9a-fA-F]{128}$"


MAX_PAYLOAD_DEPTH = 16


def payload_fault(value: Any) -> str | None:
    """Why a payload cannot be signed for, or None. Walked with a stack, not by recursion, and before
    anything hashes it: `signing_target` runs ahead of the signature check, so whatever it cannot walk
    is a failure anyone can cause without a key.

    - Nesting past MAX_PAYLOAD_DEPTH. No payload the harness reads is deeper than a list of ops, and the
      digest is a recursive walk that ends in RecursionError some thousands of levels down (XE-4124).
    - A float. The digest spells a number the way Python does, and for a float no two implementations
      agree (1.0 or 1, 1e21 or 1e+21, NaN at all), so a signature over one is checkable only here; the
      browser signer has always refused to make one (XE-6656). Amounts and timestamps are integers."""
    stack = [(value, 1)]
    while stack:
        v, depth = stack.pop()
        if isinstance(v, float):
            return "numbers in a signed payload are integers"
        if isinstance(v, (dict, list)):
            if depth > MAX_PAYLOAD_DEPTH:
                return f"nested deeper than {MAX_PAYLOAD_DEPTH} levels"
            stack.extend((x, depth + 1) for x in (v.values() if isinstance(v, dict) else v))
    return None


class SignedRequest(BaseModel):
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: int
    pub_key: str = Field(pattern=HEX32)
    signature: str = Field(pattern=HEX64)
    # Required on routes that cost the sender something (POST /v1/inbox). A u64, as the chat envelope's is:
    # the work is hashed over its eight bytes, and masking a wider integer down to them would take any of
    # V + k * 2**64, negatives included, as the same nonce and store whichever was sent (XE-5982).
    pow_nonce: int | None = None

    @field_validator("pow_nonce")
    @classmethod
    def _u64(cls, v: int | None) -> int | None:
        if v is not None and not 0 <= v < 2**64:
            raise ValueError("pow_nonce is an unsigned 64-bit integer")
        return v

    @field_validator("payload")
    @classmethod
    def _signable(cls, v: dict[str, Any]) -> dict[str, Any]:
        fault = payload_fault(v)
        if fault:
            raise ValueError(fault)
        return v


@dataclass
class Verified:
    account: str
    pub_key: str
    payload: dict
    timestamp: int
    signature: str
    digest: bytes = b""
    pow_nonce: int | None = None
    seat: HumanSeat | None = None

    @property
    def actor(self) -> str:
        return f"seat:{self.seat.id}" if self.seat else f"account:{self.account}"


def addressee(ctx) -> dict[str, str]:
    """Who a signed request to this deployment is signed for: the DAO's own account and the network it
    serves. GET /v1 publishes both, and every signer puts them under the signature."""
    return {"dao": ctx.config.accounts.get("dao", ""), "network": ctx.node.network_id}


def signing_target(domain: bytes, to: dict[str, str], payload: dict, timestamp: int) -> bytes:
    """The 32 bytes a key holder signs. There is one of these and every signature the harness accepts is
    checked against it, so what a signature is bound to is decided here and nowhere else."""
    return digest(domain, {"dao": to["dao"], "network": to["network"], "payload": payload, "timestamp": timestamp})


def verify_signed(ctx, req: SignedRequest, domain: bytes) -> Verified:
    """Check the window and the signature, made for this deployment. Does not claim the signature; see
    `claim_signature`.

    A deployment that does not know which one it is accepts nothing. The network is empty until the node
    has answered with the one this deployment is configured for (XE-12620), and a signature over an empty
    network or an empty account names no deployment at all: it would be good at every deployment in that
    state, which is the replay the addressee is there to stop (XE-2068)."""
    now = time.time_ns()
    if abs(now - req.timestamp) > MAX_SKEW_NS:
        raise HTTPException(400, "signature timestamp is outside the ±10 minute window")
    to = addressee(ctx)
    if not to["dao"] or not to["network"]:
        raise HTTPException(503, "this deployment has not confirmed its account and network; "
                                 "no signed request is accepted until it has")
    target = signing_target(domain, to, req.payload, req.timestamp)
    try:
        account = derive_address(req.pub_key)
        verify_hex_signature(req.pub_key, req.signature, target)
    except KeyError_ as e:
        raise HTTPException(401, f"bad signature: {e}") from e
    return Verified(account=account, pub_key=req.pub_key.lower(), payload=req.payload, timestamp=req.timestamp,
                    signature=req.signature.lower(), digest=target, pow_nonce=req.pow_nonce)


# ---- proof of work on signed requests (XE-0032) ------------------------------------------------
#
# Same shape as chat PoW (nonce_LE8 || target, first 8 bytes read big-endian, valid when >= difficulty),
# with SHA-256 in place of BLAKE2b so a browser can compute it with WebCrypto alone. The target is the
# signing digest followed by the signer's public key, so the work is bound to this exact request from this
# sender. The digest alone names the message and not who sent it: any key can sign the same digest, and
# work found once would then pay for the same message from as many accounts as there are keys, each with
# its own rate bucket (XE-11360). The difficulty is the one the node advertises for chat, so an HTTP
# message costs the sender what a chat message would.

POW_RULE = ("pow_nonce (u64) such that sha256(nonce_le8 || signing_digest || pub_key)[0:8] read big-endian >= "
            "difficulty; pub_key is the signing key's 32 bytes")


def pow_target(digest: bytes, pub_key: str) -> bytes:
    """What an HTTP proof of work is computed over: the request and the key that signed it."""
    return digest + exact_hex(pub_key, 32, "public key")


def http_pow_hash(nonce: int, target: bytes) -> int:
    h = hashlib.sha256(struct.pack("<Q", nonce & 0xFFFFFFFFFFFFFFFF) + target).digest()
    return struct.unpack(">Q", h[:8])[0]


def validate_http_pow(target: bytes, nonce: int, difficulty: int) -> bool:
    return difficulty == 0 or http_pow_hash(nonce, target) >= difficulty


def compute_http_pow(target: bytes, difficulty: int, deadline_s: float = WORKER_POW_DEADLINE_S) -> int:
    """Brute force; ~2^18 hashes at the chat difficulty. For CLI clients and tests. Raises TimeoutError
    once `deadline_s` has passed, as every search does (`xe.pow.search_nonce`)."""
    if difficulty == 0:
        return 0
    return search_nonce(lambda nonce: http_pow_hash(nonce, target) >= difficulty, deadline_s)


def require_pow(v: Verified, difficulty: int) -> None:
    if difficulty == 0:
        return
    if v.pow_nonce is None:
        raise HTTPException(400, f"pow_nonce is required: {POW_RULE}, which is 0x{difficulty:016x}")
    if not validate_http_pow(pow_target(v.digest, v.pub_key), v.pow_nonce, difficulty):
        raise HTTPException(400, "pow_nonce does not meet the required difficulty")


async def claim_signature(db: AsyncSession, v: Verified) -> None:
    """Record the signature as used, inside the caller's transaction. 409 if it was used before.

    The primary key does the work: two concurrent requests with the same signature cannot both insert,
    and the row is only durable if the write it authorised commits too. The outcome is read from RETURNING,
    not from the cursor's rowcount, which SQLAlchemy only guarantees for UPDATE and DELETE and which some
    drivers report as -1 for an INSERT (XE-0590).
    """
    res = await db.execute(
        pg_insert(SeenSignature).values(sig=v.signature, timestamp=v.timestamp, account=v.account)
        .on_conflict_do_nothing(index_elements=["sig"])
        .returning(SeenSignature.sig)
    )
    if res.scalar_one_or_none() is None:
        raise HTTPException(409, "this signature has already been used")


async def accept(db: AsyncSession, v: Verified, cls: RouteClass) -> None:
    """Claim the signature, then charge the signer's allowance for this class of route: in that order, and
    the only way a route does either. An account's allowance is spent by requests that account makes. A
    signature is public once it is used (a vote, an approval and a resolution signature are all published
    with what they signed), so anyone can send a request again inside its ten minutes; that request is a
    replay, is refused as one here, and costs the signer nothing. Charged first, as it once was, each replay
    took a token from the signer and a stranger could keep a voter or a seat at its limit (XE-7311).

    A request refused for the allowance after its claim leaves no claim behind: the 429 ends the request and
    its transaction with it, so the same signature can be sent again once there is room."""
    await claim_signature(db, v)
    enforce_account(cls, v.account)


async def purge_seen_signatures(db: AsyncSession) -> int:
    """Drop claims older than the acceptance window; they can never be presented again."""
    cutoff = time.time_ns() - 2 * MAX_SKEW_NS
    res = await db.execute(delete(SeenSignature).where(SeenSignature.timestamp < cutoff))
    return res.rowcount or 0


def bind(v: Verified, **expected: str) -> Verified:
    """The signed payload must name what the route acts on. The URL says where a request was posted; only
    the payload says what the key holder agreed to, so the two must match: a signature over a cancel of
    session A is not a cancel of session B, whatever path it arrives on. Values compare case-insensitively
    (ids and hashes are hex)."""
    for field, want in expected.items():
        got = v.payload.get(field)
        if not isinstance(got, str) or got.lower() != str(want).lower():
            raise HTTPException(400, f"signed payload does not name this {field.replace('_', ' ')}")
    return v


def require_seat(v: Verified, cfg: Config, right: str | None = None, members_only: bool = False) -> Verified:
    seat = cfg.seat_by_key(v.pub_key)
    if seat is None:
        raise HTTPException(403, "this key does not hold a seat")
    if members_only and not seat.is_member:
        raise HTTPException(403, "this action is reserved to members")
    if right and not seat.can(right):
        raise HTTPException(403, f"seat {seat.id} does not hold the right {right!r}")
    v.seat = seat
    return v


async def seat_request(request: Request, db: AsyncSession, ctx, req: SignedRequest, domain: bytes, *,
                       right: str | None = None, members_only: bool = False, **names: str) -> Verified:
    """The one door for a signed request from a seat. In this order, so that a caller who holds no seat
    costs a signature check and nothing else:

    1. the address is metered, before anything is verified;
    2. the signature is checked (window, key, this deployment);
    3. the key must hold a seat with the right the route asks for; a key that does not is refused here,
       before the database is touched, so there is no claim to roll back and nothing written on behalf of
       a stranger (XE-2484);
    4. the payload must name what the route acts on (`bind`);
    5. the signature is claimed, in the transaction of the write it authorises, and then the seat is
       metered (`accept`): a seat's own key is bounded too, by its own requests and nobody's replays.

    A route that takes a seat's signature calls this (or `member_action`) and has no other way to get a
    `Verified` with a seat on it."""
    enforce_ip(request, SEAT)
    v = verify_signed(ctx, req, domain)
    require_seat(v, ctx.config, right=right, members_only=members_only)
    bind(v, **names)
    await accept(db, v, SEAT)
    return v


async def member_action(request: Request, db: AsyncSession, ctx, req: SignedRequest, action: str, *,
                        right: str | None = None, members_only: bool = False, **names: str) -> Verified:
    """A request under the member-action domain. The domain is shared by every action a seat can take, so
    the payload says which: `action` is required here, not left to each route, and a route cannot verify a
    member action without naming its own. A signature made for one action is refused by every other route,
    whatever ids the two payloads share (XE-2386)."""
    return await seat_request(request, db, ctx, req, DOMAIN_MEMBER_ACTION, right=right, members_only=members_only,
                              action=action, **names)
