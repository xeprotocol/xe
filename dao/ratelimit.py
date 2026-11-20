"""Token buckets for the write routes, public and seat (XE-0032, XE-2484).

In-process, keyed by client IP and by signing account; uvicorn runs behind Caddy with --proxy-headers so
`request.client.host` is the real address. Good enough for one API process; a second layer belongs at the
proxy. Buckets are forgotten when they have been full for a while, so the table does not grow with the
set of addresses that ever wrote to us.
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass

from fastapi import HTTPException, Request


@dataclass
class Limit:
    per_minute: float
    burst: int


@dataclass(frozen=True)
class RouteClass:
    """One class of route with its own buckets: a burst of inbox posts from an address does not spend the
    votes of everyone behind it (XE-0478)."""
    name: str
    ip: Limit
    account: Limit


INBOX = RouteClass("inbox", Limit(10, 5), Limit(4, 2))
VOTE = RouteClass("vote", Limit(60, 20), Limit(12, 6))
PROPOSAL = RouteClass("proposal", Limit(10, 5), Limit(2, 2))
SNAPSHOT = RouteClass("snapshot", Limit(30, 10), Limit(30, 10))   # read, but each one walks a whole account chain on the node
NODE_READ = RouteClass("node_read", Limit(60, 20), Limit(60, 20))  # a public read that costs a node round trip (XE-0652)
# A signed request from a seat. The address is charged before the signature is checked, so a stranger's
# flood of well-formed requests is refused cheaply; the seat is charged once it is known, so one seat's key
# cannot append without bound either (XE-2484). People act a few times a minute; a member's tooling may burst.
SEAT = RouteClass("seat", Limit(120, 40), Limit(30, 15))


class Buckets:
    def __init__(self, sweep_every_s: float = 300):
        self._b: dict[str, tuple[float, float]] = {}  # key -> (tokens, last_ts)
        self._sweep_every = sweep_every_s
        self._last_sweep: float | None = None

    def take(self, key: str, lim: Limit, now: float | None = None) -> float:
        """Take one token. Returns 0 when allowed, else the seconds until the next token."""
        now = time.monotonic() if now is None else now
        tokens, last = self._b.get(key, (float(lim.burst), now))
        tokens = min(float(lim.burst), tokens + (now - last) * lim.per_minute / 60.0)
        if tokens >= 1.0:
            self._b[key] = (tokens - 1.0, now)
            self._maybe_sweep(now)
            return 0.0
        self._b[key] = (tokens, now)
        return (1.0 - tokens) * 60.0 / lim.per_minute

    def _maybe_sweep(self, now: float) -> None:
        if self._last_sweep is None:
            self._last_sweep = now
            return
        if now - self._last_sweep < self._sweep_every:
            return
        self._last_sweep = now
        # anything that has had time to refill completely is indistinguishable from absent
        self._b = {k: v for k, v in self._b.items() if now - v[1] < self._sweep_every}


_buckets = Buckets()


def client_key(host: str) -> str:
    """What a per-client allowance is counted against: the client's network, not the spelling of one
    address. An IPv4 address is itself; an IPv4-mapped IPv6 address is the IPv4 address it carries; any
    other IPv6 address is its /64, which is what one subscriber is routed. Keyed on the exact address,
    one host stepping through its own /64 had a fresh bucket for every request and could hold every
    stream slot (XE-10452). Anything that is not an address is keyed as given."""
    try:
        ip = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return host
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.version == 4:
        return str(ip)
    return str(ipaddress.IPv6Network((int(ip) >> 64 << 64, 64)))


def client_ip(request: Request) -> str:
    """The key every bucket and held-slot count takes for the caller (`client_key`)."""
    return client_key((request.client.host if request.client else "") or "unknown")


def _refuse(wait: float) -> None:
    if wait:
        secs = max(1, int(wait + 0.999))
        raise HTTPException(429, "too many requests; slow down", headers={"Retry-After": str(secs)})


def enforce_ip(request: Request, cls: RouteClass) -> None:
    """One token from the address's bucket for this class. Call first, before the signature is checked, so
    unsigned noise is refused cheaply; call once per request."""
    _refuse(_buckets.take(f"ip:{cls.name}:{client_ip(request)}", cls.ip))


class Held:
    """A cap on what one address holds open at once, for the long-lived responses a token bucket does not
    bound: a bucket limits how often a stream is opened, not how many are held (XE-1237 sibling sweep).
    `take` raises 429 past the cap; the caller releases in `finally`."""

    def __init__(self, name: str, per_ip: int, total: int):
        self.name, self.per_ip, self.total = name, per_ip, total
        self._by_ip: dict[str, int] = {}
        self._n = 0

    def take(self, request: Request) -> str:
        ip = client_ip(request)
        if self._n >= self.total or self._by_ip.get(ip, 0) >= self.per_ip:
            raise HTTPException(429, f"too many open {self.name}; close one first", headers={"Retry-After": "5"})
        self._by_ip[ip] = self._by_ip.get(ip, 0) + 1
        self._n += 1
        return ip

    def release(self, ip: str) -> None:
        self._n -= 1
        left = self._by_ip.get(ip, 0) - 1
        if left > 0:
            self._by_ip[ip] = left
        else:
            self._by_ip.pop(ip, None)


STREAMS = Held("streams", per_ip=4, total=256)


def enforce_account(cls: RouteClass, account: str) -> None:
    """One token from the signing account's bucket for this class, once the signature has named it. The
    address is not charged again."""
    _refuse(_buckets.take(f"acct:{cls.name}:{account}", cls.account))
