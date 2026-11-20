"""/v1/legal/*: the Articles-facing surface. Stable paths, legal vocabulary, read-only.

These are the endpoints the Articles of Organization may name. They return the current legal
identifiers and records, and nothing else. Paths here never change without a reserved-matter
resolution.
"""

from __future__ import annotations

from fastapi import APIRouter, Query, Request

from .. import __version__
from ..log import EventLog
from ..ratelimit import NODE_READ, enforce_ip
from ..services import pause as pause_svc
from ..services import records, resolutions
from .deps import Ctx, Db

router = APIRouter(prefix="/v1/legal", tags=["legal"])


@router.get("/identifier")
async def identifier(request: Request, ctx: Ctx, db: Db):
    """The public identifier of the company's governance surface."""
    enforce_ip(request, NODE_READ)
    reg = ctx.config.registry
    # The node first, the database last: a session takes its connection at its first query and keeps it to
    # the end of the request, and a request that waits on the node with one in hand holds it for as long
    # as the node takes. Twenty of those are the pool (XE-4318).
    ks = await records.public_keyset(ctx)
    onchain = await records.onchain_registry(ctx)
    head = await EventLog.head(db)
    return {
        "entity": reg.get("entity"),
        "jurisdiction": reg.get("jurisdiction"),
        "form": reg.get("form"),
        "formation_date": reg.get("formation_date") or None,
        "registered_office": reg.get("registered_office"),
        "network_id": ctx.node.network_id,
        "network": ctx.node.badge,
        "statechain": {
            "update_authority": "sys.dao_keyset",
            "keyset": ks,
            "registry_key": "dao.registry",
            "registry_present": records.registry_present(onchain),
            **({"registry_error": onchain["error"]} if "error" in onchain else {}),
            "registry_endpoint": f"{ctx.settings.xe_node_url}/statechain/kv/dao.registry",
            "keyset_endpoint": f"{ctx.settings.xe_node_url}/statechain/keyset",
        },
        "surfaces": {
            "this": f"{ctx.settings.public_base_url}/v1/legal/identifier",
            **(reg.get("surfaces") or {}),
        },
        "repository": reg.get("repository"),
        "licence": reg.get("licence"),
        "software_version": __version__,
        "git_commit": ctx.settings.git_commit,
        "charter_sha256": ctx.config.charter_hash,
        "config_sha256": ctx.config.hashes,
        "log_head": {"index": head.index, "hash": head.hash},
        "non_membership_statement": ctx.config.copy_legal.get("non_membership_statement", "").strip(),
    }


@router.get("/registry")
async def registry(request: Request, ctx: Ctx):
    """dao.registry as intended (from config) and as present on the state chain."""
    enforce_ip(request, NODE_READ)
    read = await records.onchain_registry(ctx)
    if "error" in read:
        return {"intended": records.registry_value(ctx), "error": read["error"]}
    return {"intended": records.registry_value(ctx), "onchain": read["value"]}


@router.get("/keyset")
async def keyset(request: Request, ctx: Ctx):
    """The live sys.dao_keyset, as read from the node. The company holds no copy of these keys."""
    enforce_ip(request, NODE_READ)
    ks = await records.public_keyset(ctx)
    if "error" in ks:
        return {"error": ks["error"]}
    members = {s.public_key: s.id for s in ctx.config.human_seats if s.public_key}
    return {"keyset": ks, "holders": [{"public_key": k, "seat": members.get(k.lower(), "")} for k in ks.get("keys", [])]}


@router.get("/reserved-matters")
async def reserved_matters(ctx: Ctx):
    b = ctx.config.schedule_b
    return {
        "reserved_matters": sorted(resolutions.RESERVED_MATTERS),
        "thresholds": b.get("thresholds", {}),
        "agents_decide": b.get("agents_decide", []),
        "agents_do_not_decide": b.get("agents_do_not_decide", []),
        "members": [{"seat": s.id, "name": s.name, "role": s.role, "public_key": s.public_key or None} for s in ctx.config.members],
        "officers": [{"seat": s.id, "name": s.name, "role": s.role, "public_key": s.public_key or None}
                     for s in ctx.config.human_seats if not s.is_member],
    }


@router.get("/schedule")
async def schedule(ctx: Ctx):
    return {"schedule_b": ctx.config.schedule_b, "schedule_c": ctx.config.schedule_c, "hashes": ctx.config.hashes}


@router.get("/resolutions")
async def list_resolutions(ctx: Ctx, db: Db, status: str | None = Query(None, max_length=32),
                           offset: int = Query(0, ge=0, le=2**31 - 1), limit: int = Query(200, ge=1, le=200)):
    rows = await resolutions.list_resolutions(db, status, limit, offset)
    return {"resolutions": [resolutions.to_dict(r, ctx.config) for r in rows],
            "total": await resolutions.count_resolutions(db, status), "offset": offset, "limit": limit}


@router.get("/resolutions/{res_id}")
async def get_resolution(res_id: str, ctx: Ctx, db: Db):
    return resolutions.to_dict(await resolutions.get(db, res_id), ctx.config)


@router.get("/pause")
async def pause_state(ctx: Ctx, db: Db, offset: int = Query(0, ge=0, le=2**31 - 1), limit: int = Query(50, ge=1, le=200)):
    """`history` is a page, newest first, and `history_total` how many there are: every pause there has
    been can be read (XE-4601)."""
    a = await pause_svc.active(db)
    return {
        "paused": a is not None,
        "active": pause_svc.to_dict(ctx, a) if a else None,
        "rules": ctx.config.pause,
        "notice": ctx.config.copy_legal.get("pause_notice", "").strip(),
        "history": [pause_svc.to_dict(ctx, r) for r in await pause_svc.history(db, limit, offset)],
        "history_total": await pause_svc.count_history(db), "offset": offset, "limit": limit,
    }


@router.get("/treasury")
async def treasury(request: Request, ctx: Ctx):
    enforce_ip(request, NODE_READ)   # balances come from the node per call
    return {"accounts": await records.treasury(ctx), "policy": "members only; the harness holds no treasury key"}


@router.get("/anchors")
async def anchors(db: Db, offset: int = Query(0, ge=0, le=2**31 - 1), limit: int = Query(50, ge=1, le=200)):
    return {"anchors": await records.anchors(db, limit, offset), "total": await records.count_anchors(db),
            "offset": offset, "limit": limit}
