# Core Node HTTP API

This is the canonical reference for the core node's HTTP API. It reflects the
code as of this PR's base (`master` @ `b352ef8`) and is derived from
`core/api/handler.go` — the `Handler.routes()` table is the single source of
truth for the endpoint list, and the same list is served live at `GET /` as an
auto-discovery manifest. When the doc and a running node disagree, trust the
node and update this file.

The response snippets below use example values captured from a live testnet node
(build `xe/cf42410`, network `testnet-84ec09`); the `version` / `network_id`
fields you see against your own node will differ.

---

## Conventions

- **Base URL.** Local node: `http://127.0.0.1:8080` (flags `--api`, `--api-port 8080`, `--api-bind 127.0.0.1`). Testnet (behind Caddy/TLS): `https://ldn.core.test.network`, `ffm.core.test.network`, `nyc.core.test.network`.
- **Content type.** Requests and responses are `application/json` unless noted (the chat SSE stream is `text/event-stream`; the TCP tunnel hijacks the connection).
- **Amounts.** `uint64` **micro-units**: `1 XE = 1_000_000 mXE`, same for XUSD. Wire format is a plain JSON number.
- **Timestamps.** `int64` Unix **nanoseconds**.
- **Hashes / accounts / keys.** Lowercase hex, 32 bytes / 64 hex throughout. An **account address** and an **ed25519 public key** are both 64 hex but are **different values** — see [Addresses vs. keys](#addresses-vs-keys). Block/lease hashes are 64 hex (SHA-256). `"0"` denotes the open/genesis predecessor.
- **Pagination.** List endpoints take `?offset=N&limit=M` (default `limit=100`, max `1000`). `GET /statechain/blocks` uses `?start=N&limit=M` instead. Paging is stable only where the handler sorts before slicing (`/frontiers`, `/reputation`, `/directory`, `/statechain/kv` sort by account/key); `/accounts` pages an unsorted map and `/pending` is unordered on the in-memory store, so consecutive pages there can overlap or skip entries — prefer a single large `limit` over deep paging.
- **Errors.** Non-2xx responses are `{"error":"<message>"}`. Common: `400` bad input, `404` not found, `429` rate limited, `503` busy.
- **Rate limit.** Per-IP token buckets, split by request class → `429 {"error":"rate limit exceeded"}`: **reads** (any GET) 200 req/s sustained, burst 1000; **writes** (POST block/state submit, chat, directory register) 10 req/s, burst 50; **probes** (`GET /health`, `GET /ready`) 20 req/s, burst 100 in a bucket of their own, so browsing traffic can never 429 a supervisor's probe into killing a healthy node. Behind the local reverse proxy the real client IP is taken from the rightmost `X-Forwarded-For` hop. Clients doing bulk reads must handle `429` and back off — a plain sequential sweep of the public `*.core.test.network` URLs can trip the limiter because external clients behind Caddy/NAT share an egress bucket.
- **Body cap.** POST bodies are capped at **1 MiB** → `400`.
- **CORS.** `Access-Control-Allow-Methods: GET, POST, OPTIONS`; allowed origin is configurable (default `http://localhost:3000`). `OPTIONS` preflight returns `204`.
- **Auth.** The public API is unauthenticated **except** operator-only endpoints (`POST /lease/request`, the unfiltered `GET /chat/events` firehose, and the node-wide `GET /chat/contacts` list), which require `Authorization: Bearer <token>` where the token is set via `XE_API_ADMIN_TOKEN`. If no token is configured the endpoint returns `403`.

### Addresses vs. keys

An account **address** is no longer its ed25519 public key. It is the
SHA-256 of a domain tag and the key:

```
address = sha256("xe/account/v1" || pubkey_32)
```

Both are 32 bytes / 64 lowercase hex, so nothing about the wire shape changed —
but the values differ, and substituting one for the other fails validation.
Worked example (the live testnet treasury account):

| | value |
|---|---|
| public key | `cab9462b5c6c3abf83431ea42a3265b755c55989b0bf332869825908c9dbe780` |
| address | `378d0f5c20635de5a317ad73d5886e93cf6b0883a9d84a7ab89efac4b65a149b` |

**Which fields are which:**

| Kind | Fields |
|---|---|
| **Address** (identity) | block `account`, `destination`, `representative`; `/accounts/{address}/*` path params; `provider` / `consumer` on leases and certificates; directory `account`; chat `from` / `to` |
| **Public key** (credential) | block `pub_key`; directory `pub_key`; chat `pub_key`; multisig `keyset.keys` and `signatures[].public_key`; attestation `public_key`; vote `rep_pub_key`; lease `access_pub_key` (an SSH access key, unrelated to any account) |

**Why the split.** The address commits to the key instead of being it, so the
credential can be replaced without changing the identity — the same property
multisig addresses have always had, and the precondition for key rotation. A multisig account's address is its keyset digest, not a public key, so
it has no `pub_key` at all.

**Consequences for clients.** An account's public key is not derivable from its
address (SHA-256 is one-way), so anything that must verify a signature needs the
key delivered alongside the address:

- a block chain publishes it once, on the account's **first** block (`pub_key`);
- a directory registration and a chat envelope each carry their own `pub_key`,
  bound into the bytes they sign;
- `GET /accounts/{address}/keyset` returns a multisig account's keyset.

---

## Endpoint index

| Method | Path | Description |
|---|---|---|
| GET | `/` | Auto-discovery manifest (node id + endpoint list) |
| GET | `/node` | Node info: id, address, public key, version, network, peers, counts, lease timing |
| GET | `/health` | **Liveness.** Process up and internal loops running. Says nothing about consensus |
| GET | `/ready` | **Readiness.** Synced, peered, delegated weight present, quorum reachable, finality advancing |
| GET | `/network/activations` | Feature activation registry as of the state-chain tip + what this build implements |
| GET | `/network/readiness` | Delegated vote weight by advertised version and feature |
| GET | `/accounts` | All known accounts (paginated) |
| GET | `/accounts/{address}/balance` | Per-asset balance + spendable + final height |
| GET | `/accounts/{address}/chain` | Account block chain (paginated) |
| GET | `/accounts/{address}/keyset` | Multisig keyset for an account |
| GET | `/accounts/{address}/reputation` | Per-account reputation aggregate |
| GET | `/reputation` | Reputation aggregates for all accounts (paginated) |
| GET | `/frontiers` | Frontier hash for every account (paginated) |
| GET | `/supply` | Aggregate supply per asset and the conservation identity |
| GET | `/pending` | All pending sends (paginated) |
| GET | `/pending/{address}` | Pending sends to one account |
| GET | `/blocks/recent` | Most recent blocks across the lattice (`?limit=`, `?since=`) |
| GET | `/blocks/{hash}` | Block by hash |
| POST | `/blocks/send` | Submit a signed send block |
| POST | `/blocks/receive` | Submit a signed receive block |
| POST | `/blocks/lease` | Submit a signed lease block |
| POST | `/blocks/lease_accept` | Submit a signed lease_accept block |
| POST | `/blocks/lease_settle` | Submit a signed lease_settle block |
| POST | `/blocks/lease_cancel` | Submit a signed lease_cancel block |
| POST | `/blocks/lease_force_settle` | Submit a signed lease_force_settle block |
| POST | `/blocks/multisig_open` | Submit a signed multisig_open block |
| POST | `/blocks/multisig_update` | Submit a signed multisig_update block |
| POST | `/blocks/burn` | Submit a signed burn block (XE only) |
| POST | `/blocks/mint` | Submit a signed XUSD mint block (authorized minter only) |
| GET | `/conflicts` | All open conflicts (paginated) |
| GET | `/conflicts/{account}` | Open conflicts for one account |
| GET | `/delegation` | Representative vote weights (micro-XE) |
| GET | `/providers` | Compute providers + advertised resources |
| GET | `/certificate` | This node's perf certificate (provider mode) |
| GET | `/certificate/{provider}` | Current unexpired perf certificate for a provider |
| GET | `/certificate/hash/{hash}` | Retained perf certificate by hash, including expired |
| GET | `/leases` | All leases; `?state=` filter (paginated) |
| GET | `/leases/{hash}` | Lease by hash |
| POST | `/lease/request` | Request a lease — node signs + PoWs (**operator only**) |
| GET | `/vms` | All running VMs |
| GET | `/vms/{lease}` | VM info for a lease |
| POST | `/tunnel/{leaseHash}/tcp` | Open a TCP tunnel into a lease's VM (hijack) |
| GET | `/statechain/tip` | Latest state-chain block |
| GET | `/statechain/blocks` | Range of state-chain blocks (`?start=&limit=`) |
| GET | `/statechain/blocks/{index}` | State-chain block by index |
| GET | `/statechain/kv` | All / prefix KV entries (`?prefix=`, paginated) |
| GET | `/statechain/kv/{key...}` | KV entry by key |
| GET | `/statechain/keyset` | DAO keyset (M-of-N timekeepers) |
| POST | `/statechain/blocks` | Submit a state-chain block |
| POST | `/attestation/request` | Request a timekeeper attestation |
| GET | `/directory` | All directory registrations (paginated) |
| GET | `/directory/{account}` | Directory entry for an account |
| POST | `/directory/register` | Register own account in the directory |
| POST | `/chat/send` | Send a chat message |
| GET | `/chat/messages` | Fetch chat messages for an account |
| GET | `/chat/contacts` | Chat contacts for an account (ownership proof required); node-wide list is operator-only |
| GET | `/chat/events` | Chat event stream (SSE) |

---

## Node

### GET /
Auto-discovery manifest. No params.
```bash
curl https://ldn.core.test.network/
```
```json
{
  "name": "xe",
  "version": "xe/cf42410",
  "network_id": "testnet-84ec09",
  "address": "e04689f4da83a58d298906f4e47e5bff9f8c106960aa922f6080a9e31952c11d",
  "node_id": "12D3KooWJg4PQYGSfNCupBWZdEWbKj7pgdp5MmmUXbPdBcp6YDtT",
  "endpoints": [ { "method": "GET", "path": "/node", "description": "..." } ]
}
```

### GET /node
Node identity, peer list, and consensus-relevant lease timing. No params.
```bash
curl https://ldn.core.test.network/node
```
```json
{
  "id": "12D3KooWJg4PQYGSfNCupBWZdEWbKj7pgdp5MmmUXbPdBcp6YDtT",
  "address": "e04689f4da83a58d298906f4e47e5bff9f8c106960aa922f6080a9e31952c11d",
  "public_key": "50f931a581fb5186f4954a5c9549bea189c1fab42d147cd37a83072517ae57eb",
  "version": "xe/cf42410",
  "network_id": "testnet-84ec09",
  "peers": [
    { "id": "12D3KooWEqv1...", "address": "144.202.4.117:9000", "version": "xe/cf42410", "connected_at": 1781802930599045784 }
  ],
  "peer_count": 4,
  "accounts": 295,
  "block_count": 2929,
  "total_delegated_weight": 42000000000000,
  "representatives": 5,
  "finality_advances": 1847,
  "last_finality_ns": 1781802930599045784,
  "pow_difficulty": "fffff80000000000",
  "chat_pow_difficulty": "ffffc00000000000",
  "lease_timing": {
    "min_duration_secs": 60,
    "settle_grace_ns": 3600000000000,
    "force_settle_gap_ns": 1500000000000,
    "escrow_expiry_ns": 31536000000000000,
    "archive_gap_ns": 3600000000000,
    "max_attestation_skew_ns": 600000000000
  },
  "certificate": {
    "valid": true,
    "hash": "e862c88a64ad3f0b1d4e5c7a9b2f6081c3d5e7a9b1c3d5e7f9a1b3c5d7e9f0a2",
    "expires_at": 1782463000000000000
  }
}
```
> `address` is the node's ledger **account address**; `public_key` is its ed25519 **verifying key**. Both are published because the key is not recoverable from the address: use `address` to send to or query the node's account, and `public_key` to configure the node as a timekeeper (`sys.timekeepers` holds keys) or to check a vote it signed. `GET /` reports `address` only.
>
> `total_delegated_weight` (micro-XE), `representatives`, `finality_advances` and `last_finality_ns` are the consensus liveness signals. **Health gates must assert both halves.** Zero total delegated weight is silent finality death: blocks commit and gossip, nothing ever finalizes, every balance is unspendable — and nothing else on this endpoint changes. But non-zero weight is not sufficient either: weight delegated to an address no key controls (e.g. a public key mistakenly used as an account address) reads as perfectly healthy weight and finalizes nothing. So assert `total_delegated_weight > 0` **and** that `finality_advances` is rising. `finality_advances` counts final-height watermark advances since process start; genesis, which is final on every node by construction, is deliberately not counted, so a network that has finalized nothing since block 0 reports `0` rather than looking like progress. `last_finality_ns` is 0 until the first advance.
>
> `certificate` reports **this node's own** performance certificate. `valid` is true only when the node holds one that has not expired; `hash` and `expires_at` are omitted when it does not. A node in `--provide` mode reporting `"certificate": {"valid": false}` **cannot be leased from at all** — a lease block requires a valid `CertificateHash` — so operators and convergence gates should assert on this. Non-providers always report `{"valid": false}`; to look up another provider's certificate use `GET /certificate/{provider}`.

---

## Network upgrades & feature activation

Full operator procedure: [`docs/activations.md`](activations.md).

### GET /network/activations
The `sys.activations` registry rendered against this node's state-chain tip,
together with the features this **binary** implements. No params.
```json
{
  "tip_index": 41230,
  "tip_timestamp": 1793558400000000000,
  "features": [
    { "name": "messaging", "at_index": 41000, "not_before_ns": 1793558400000000000,
      "active": true, "known_to_binary": true }
  ],
  "known_features": ["messaging", "noop"],
  "gated_block_types": { "message": "messaging" },
  "unsupported_active": [],
  "unsupported_pending": [],
  "min_protocol_version": "1.1.0",
  "protocol_version": "1.1.0"
}
```
A feature is `active` when **both** trigger terms are met by the tip:
`tip_index >= at_index` and `tip_timestamp >= not_before_ns` (either term may be
`0`, meaning unconstrained). Both read the converged state chain and nothing
else — never the node's own clock.

> **`unsupported_active` is the field to alert on.** Non-empty means the chain
> has activated a feature this build cannot enforce: blocks belonging to it are
> refused and their account chains stall on this node while upgraded peers carry
> on. The refusal is transient, not terminal, so the node recovers by itself
> once upgraded. `unsupported_pending` is the same warning, delivered before the
> deadline.

### GET /network/readiness
Delegated vote weight behind each advertised protocol version and feature — the
number the DAO gates an activation on (≥90% for 7 consecutive days). No params.
```json
{
  "total_weight": 41988300037286,
  "feature_weight": { "messaging": 39100000000000 },
  "feature_ready_milli": { "messaging": 931 },
  "version_weight": [ { "version": "1.1.0", "weight": 39100000000000 } ],
  "unknown_weight": 2888300037286,
  "resolved_reps": 4,
  "total_reps": 6
}
```
Weight, not peer count: finality needs 67% of delegated weight, so a feature
activated below that wedges the network. `feature_ready_milli` is per-thousand
(the 90% gate reads as `>= 900`). `unknown_weight` is weight this node cannot
attribute to any advertising peer — **count it as not ready**; the mapping is
representative → directory registration → peer → advertised features, and every
link is best-effort.
## Operations

Three endpoints, three different questions. Confusing them is itself an
operational risk, so the semantics are stated precisely.

**`/metrics` is not served on this API.** It lives on a separate operator
listener (`--metrics-addr`, default `127.0.0.1:9095`), which also serves
`/health` and `/ready`. It is an unauthenticated firehose of network-wide state
and a cheap amplification target; a public node has no reason to serve it to
strangers. Operators who need remote scraping bind that listener to a private
interface.

### GET /health — liveness

**Question: is this process alive and are its internal loops running?**

Deliberately independent of peers and of consensus. A supervisor that restarts a
node for being isolated, or for waiting on quorum, turns a network problem into
a fleet-wide crash loop — so neither condition appears here.

`200` when live, `503` when not. Checks: `serving`, `sampler_alive`,
`store_readable`.

```bash
curl https://ldn.core.test.network/health
```
```json
{
  "status": "ok",
  "ok": true,
  "version": "xe/6f2e635",
  "network_id": "testnet-f1215c",
  "node_id": "12D3KooWJg4PQYGSfNCupBWZdEWbKj7pgdp5MmmUXbPdBcp6YDtT",
  "uptime_seconds": 86412.5,
  "checks": [
    { "name": "serving",        "ok": true, "evaluated": true, "detail": "HTTP handler reached" },
    { "name": "sampler_alive",  "ok": true, "evaluated": true, "detail": "sample 4s old" },
    { "name": "store_readable", "ok": true, "evaluated": true }
  ],
  "note": "liveness only: ... a node with zero delegated vote weight finalizes nothing and still reports healthy here. Use /ready for that."
}
```

> **`/health` being green means almost nothing about the network,** which is why
> the response says so in its own body. Zero total delegated vote weight is this
> system's worst state: blocks still commit, gossip converges, peers stay
> connected, block count climbs — and nothing ever finalizes, so every account's
> spendable balance is empty while its balance looks normal. Liveness is green
> throughout. `/ready` is the endpoint that catches it.

### GET /ready — readiness

**Question: can this node serve a correct answer?**

`200` when ready, `503` when not, with the same JSON body either way. Safe for a
load balancer to drain on. **Never wire a supervisor restart to it:** during a
network-wide quorum incident every node reports not-ready, and restarting them
all makes it strictly worse.

| Check | Passes when |
|---|---|
| `live` | Liveness passes |
| `sample_present` | An observability sample exists |
| `sample_fresh` | The newest sample is under 3 sample intervals old |
| `peers` | Connected peers ≥ `--ready-min-peers` (default 1) |
| `synced` | A sync round completed within `SyncStaleThreshold` (default 180s), **or** the operator declared the node standalone with `-ready-min-peers=0` and it has no peers |
| `delegated_weight` | Total delegated vote weight > 0 |
| `quorum_reachable` | No unfinalized backlog, **or** voting weight ≥ 67% of delegated weight |
| `finality_advancing` | No unfinalized backlog, **or** the final-height watermark moved within `--ready-finality-stall` (default 90s) |

**Every check answers in every state.** `evaluated` is `true` on all of them by
construction, and the field exists so that a future check which genuinely cannot
answer must say so out loud rather than quietly returning a pass — an unchecked
invariant that looks identical to a passed one is how a gate fails open. The
metric `xe_ready_check_evaluated` alerts on it.

Two of these deserve their reasoning stated, because the obvious formulation of
each fails open:

- **`quorum_reachable`** asks *"is finality blocked for want of participation?"*,
  not *"what is the live quorum margin?"*. The second question is unanswerable on
  a quiet network and would have to be skipped — and a skip that reads as a pass,
  on the one check that catches the project's top fear, is the worst possible
  outcome. So a quiet network passes on **direct evidence** (nothing is waiting to
  finalize), and a network with a backlog and no voting representatives **fails**.
- **`synced`** has no warm-up exemption. A node that has not reconciled with any
  peer is not ready, because holding traffic back during initial sync is the
  entire purpose of a readiness gate.

```bash
curl -s https://ldn.core.test.network/ready | jq '.status, (.checks[] | select(.ok == false))'
```
```json
{
  "status": "not_ready",
  "ready": false,
  "checks": [
    { "name": "live",             "ok": true,  "evaluated": true },
    { "name": "sample_present",   "ok": true,  "evaluated": true },
    { "name": "sample_fresh",     "ok": true,  "evaluated": true },
    { "name": "peers",            "ok": true,  "evaluated": true, "detail": "4 connected" },
    { "name": "synced",           "ok": true,  "evaluated": true, "detail": "last sync 7s ago" },
    { "name": "delegated_weight", "ok": false, "evaluated": true,
      "detail": "total delegated vote weight is ZERO — no block on this network can ever finalize; spendable balances will read empty for every account. See runbook: quorum loss." },
    { "name": "quorum_reachable", "ok": false, "evaluated": true, "detail": "no delegated weight to reach quorum with" },
    { "name": "finality_advancing", "ok": true, "evaluated": true, "detail": "no unfinalized backlog" }
  ],
  "peer_count": 4,
  "delegated_weight_micro_xe": 0,
  "active_representative_weight_micro_xe": 0,
  "representatives": 0,
  "active_representatives": 0,
  "quorum_margin_ratio": -0.67,
  "finality_stall_seconds": 0,
  "finality_advances": 0,
  "unfinalized_positions": 0,
  "conflicts_open": 0,
  "frontier_fingerprint": "cd21a6ef3809af88",
  "sample_age_seconds": 4.79
}
```

**Fails closed.** A handler with no observability source wired in answers `503`,
never `200`. A node that has never produced a sample answers `503`. "No data" is
never "ready".

### GET /metrics — Prometheus exposition (ops listener only)

Served at `--metrics-addr` (default `127.0.0.1:9095`), which also carries
`/health` and `/ready`. Set `--metrics-addr=""` to disable it entirely.

Exports the Go runtime and process collectors, the libp2p collectors, and the
`xe_*` series below. Series names and labels are stable; **every one is a
network-wide aggregate.** No metric carries an account address, a representative
address, a block hash, a peer id or a key as a label — `/metrics` is an operator
endpoint that may end up scraped over a shared network, and per-account labels
would be both a privacy leak and unbounded cardinality.

| Metric | Type | Meaning |
|---|---|---|
| `xe_build_info{version,network_id,role}` | gauge | Always 1; identity labels |
| `xe_healthy` / `xe_ready` | gauge | 1/0, matching `/health` and `/ready` |
| `xe_ready_check{check}` | gauge | 1 pass / 0 fail per readiness check |
| `xe_ready_check_evaluated{check}` | gauge | 1 when the check could be assessed |
| `xe_sample_age_seconds` | gauge | Age of the newest sample; **recomputed at scrape time**, so a wedged sampler shows as a climbing value rather than a frozen dashboard |
| `xe_delegated_weight_micro_xe` | gauge | Total delegated vote weight. **Zero means finality is dead** |
| `xe_delegated_weight_ratio` | gauge | Delegated weight ÷ circulating XE supply |
| `xe_representatives_total` / `xe_active_representatives_total` | gauge | Representatives holding weight vs observed voting |
| `xe_active_representative_weight_micro_xe` | gauge | Weight held by representatives that are actually voting |
| `xe_quorum_margin_ratio` | gauge | `active ÷ total − 0.67`. Below 0 finality halts — 67% is the only quorum |
| `xe_finality_stall_seconds` | gauge | Seconds since the watermark advanced, while a backlog exists |
| `xe_finality_latency_seconds` | histogram | Block timestamp → finalization |
| `xe_finalizations_total` | counter | Blocks finalized since start |
| `xe_finality_advances_total` | counter | Final-height watermark advances since start, read straight off the ledger's own counter rather than re-derived. Flat forever means nothing is finalizing |
| `xe_unfinalized_positions` / `xe_final_height_sum` | gauge | Finalization backlog and watermark total |
| `xe_conflicts_open` | gauge | Unresolved conflicts |
| `xe_delegation_underflows` | gauge | Vote-weight underflows; any non-zero value is a correctness fault |
| `xe_ineligible_weight_micro_xe` | gauge | Weight the representative-eligibility policy holds out of the quorum denominator. Zero when unrestricted |
| `xe_rep_eligibility_restricted` | gauge | 1 when a `sys.representatives` allowlist is actually in force |
| `xe_rep_eligibility_failed_open` | gauge | 1 when a published allowlist matched **zero** delegated weight and is being ignored — the policy is not being enforced |
| `xe_accounts_total` / `xe_blocks_total` / `xe_pending_sends` | gauge | Ledger size |
| `xe_supply_micro_units{asset}` | gauge | Circulating supply (`observed` = balances plus in-flight sends), from the `GET /supply` auditor — not a second derivation |
| `xe_supply_conserved{asset}` | gauge | 1 when this node's supply identity balances, 0 when it does not. Zero is a supply-conservation breach |
| `xe_supply_discrepancy_micro_units{asset}` | gauge | Signed `accounted − created`. Zero iff conserved |
| `xe_frontier_fingerprint` | gauge | Numeric projection of the sorted `account:frontier:block_count` digest. Equal across agreeing nodes; this is the documented parity gate, **not** block count |
| `xe_store_size_bytes` | gauge | Data directory size |
| `xe_peer_count` | gauge | Connected libp2p peers |
| `xe_quarantined_blocks` / `xe_blocks_quarantined_total` | gauge / counter | Sync quarantine. There is no fork machinery, so this is how a chain split first appears |
| `xe_sync_rounds_total{result}` | counter | Outbound sync rounds by outcome |
| `xe_votes_ingested_total{result}` | counter | Votes received by outcome |
| `xe_blocks_added_total{source}` | counter | Blocks accepted by ingress path |
| `xe_dropped_blocks_total` | counter | Blocks shed from a full gossip receive channel |
| `xe_certificate_valid` | gauge | 1 when this node holds a valid unexpired performance certificate |

Alert rules, an Alertmanager configuration, a Grafana dashboard and a compose
file are committed under `deploy/monitoring/`.

---

## Accounts

### GET /accounts
All known accounts. Query: `?offset=N&limit=M`. Returns an array of account summaries.
```bash
curl "https://ldn.core.test.network/accounts?limit=2"
```
```json
[
  {
    "address": "dcb8ed55384fca757b4d70aa46f472014a581ddff941671cf6a679a04caa8df8",
    "balance": 181469175,
    "balances": { "XE": 300000000, "XUSD": 181469175 },
    "block_count": 7,
    "frontier": "915f95f2f5cbc698ddc03e0736ef678c329bf510d2237f6180d384d78ae8e474",
    "last_block_timestamp": 1781799124233261067
  }
]
```
> `balance` is the legacy single-asset field; prefer `balances`.

### GET /accounts/{address}/balance
Per-asset balance for one account. Path: `address`.
```bash
curl https://ldn.core.test.network/accounts/0813c29...a33f/balance
```
```json
{
  "address": "dcb8ed55384fca757b4d70aa46f472014a581ddff941671cf6a679a04caa8df8",
  "balances":  { "XE": 300000000, "XUSD": 181469175 },
  "spendable": { "XE": 300000000, "XUSD": 181469175 },
  "final_height": 7
}
```
> `balances` includes unfinalized inflows; **`spendable` counts only finalized (irreversible) funds — treat it as the settlement figure**. `final_height` is the account's finalized-block watermark.
> Errors: `400 missing address`.

### GET /accounts/{address}/chain
Full block chain for an account, oldest first. Path: `address`. Query: `?offset=N&limit=M`.
```bash
curl "https://ldn.core.test.network/accounts/0813c29...a33f/chain?limit=1"
```
```json
{
  "address": "dcb8ed55384fca757b4d70aa46f472014a581ddff941671cf6a679a04caa8df8",
  "total": 7,
  "blocks": [
    {
      "type": "receive",
      "account": "dcb8ed55...8df8",
      "previous": "0",
      "pub_key": "c388b82f...9566",
      "balance": 100000000,
      "timestamp": 1781799001430387098,
      "asset": "XUSD",
      "representative": "e04689f4...c11d",
      "source": "050b7ff5...96963",
      "signature": "cb42918d...4b60b",
      "hash": "ab9952aa...87bfd4",
      "pow_nonce": 4609682588916829384,
      "finalized": true
    }
  ]
}
```
> Each block carries an added `"finalized"` boolean. `total` is the full chain length (so a client can tell a complete chain from page 1 of N). The first block (`"previous": "0"`) is the only one carrying `pub_key` — that is where the account publishes the key every later block on the chain is verified against. Errors: `400 missing address`.

### GET /accounts/{address}/keyset
Multisig keyset for an account, if any. Path: `address`.
```bash
curl https://ldn.core.test.network/accounts/<msig-addr>/keyset
```
```json
{ "keys": ["<pubkey1>", "<pubkey2>", "<pubkey3>"], "threshold": 2 }
```
> `keys` are raw ed25519 **public keys**, not addresses. A multisig account's
> address is the digest of this keyset, which is why such an account never
> declares a block `pub_key`. Errors: `400 missing address`,
> `404 not a multisig account`.

### GET /accounts/{address}/reputation
On-chain reputation aggregate from lease activity. Path: `address`. Eventually consistent (may briefly differ across nodes after a settle propagates).
```json
{
  "version": 1,
  "leases_accepted_as_provider": 12,
  "leases_settled_as_provider": 11,
  "lease_hours_settled_as_provider": 264,
  "leases_unfulfilled_as_provider": 0,
  "leases_accepted_as_consumer": 3,
  "leases_settled_as_consumer": 3,
  "leases_cancelled_as_consumer": 0,
  "lease_hours_settled_as_consumer": 72,
  "leases_unfulfilled_as_consumer": 0,
  "first_activity_at": 1781700000000000000,
  "last_activity_at": 1781800000000000000
}
```
> Errors: `400 missing address`, `404 no reputation activity`.

### GET /reputation
Reputation aggregates for every known account, keyed by address. Query: `?offset=N&limit=M`. Same eventual-consistency caveat.
```json
{ "<address>": { "version": 1, "leases_settled_as_provider": 11 } }
```

### GET /frontiers
Frontier (head block hash) for every account. Query: `?offset=N&limit=M`.
```bash
curl "https://ldn.core.test.network/frontiers?limit=1"
```
```json
[
  {
    "account": "0142c30f...6e9b",
    "frontier": "a7a4e300...dd73",
    "block_type": "receive",
    "timestamp": 1781792493171566846,
    "block_count": 8,
    "representative": "e04689f4...c11d"
  }
]
```

---

## Supply

### GET /supply
Aggregate supply for every asset, with **both sides of the conservation identity**, so a
client can check it in one request rather than re-deriving it from `/accounts`,
`/pending`, `/leases` and every account chain.

Per asset, in micro-units:

```
balances + in_flight + locked_stake + burned + escrow_burned + stake_forfeited
  == genesis + minted + emitted
```

XE is created only by the genesis block and by `lease_settle` emission, and destroyed
only by `burn` blocks. XUSD is created only by an authorized `mint`, and destroyed only
when a lease's escrow is burnt (at settle, or at escrow expiry) or a provider's
stake is forfeited by absence. Everything else — send, receive, `lease_cancel`,
`lease_force_settle`, `multisig_*` — is supply-neutral. `locked_stake` is the one term a
naive `balances + pending` sum misses: a provider's stake leaves balances at
`lease_accept` and is held on the lease record until settle, invisible to both.

```bash
curl https://ldn.core.test.network/supply
```
```json
{
  "genesis_supply": 42000000000000,
  "assets": {
    "XE": {
      "genesis": 42000000000000, "minted": 0, "emitted": 0, "created": 42000000000000,
      "burned": 1, "escrow_burned": 0, "stake_forfeited": 0, "destroyed": 1,
      "locked_stake": 0,
      "balances": 41999999996993, "in_flight": 3006, "observed": 41999999999999,
      "accounted": 42000000000000, "discrepancy": 0, "conserved": true
    },
    "XUSD": { "genesis": 0, "minted": 3625000000, "...": "..." }
  },
  "accounts": 56, "blocks": 433, "leases": 0, "pending": 3,
  "conserved": true, "notes": [],
  "stable": true, "attempts": 1,
  "computed_at": 1787089898490676837, "duration_ms": 4
}
```

- `genesis_supply` — the XE total this build enforces as an exact equality on every
  genesis block it loads. **This endpoint is the authority for that figure**; clients
  should read it here rather than hardcoding a copy.
- `conserved` — the AND over every asset, and `false` whenever any term could not be
  computed. It never reports `true` on incomplete data.
- `notes` — every reason the report is not clean (an unplaceable stake, an unsupported
  asset, an arithmetic overflow). Empty on a healthy network.
- `stable` — whether the frontier set was identical before and after the walk. `false`
  means **retry**, not "pass": the terms and the balances came from different instants.
- The response is **aggregate-only** — no address and no per-account amount — so it
  discloses strictly less than the already-public `GET /accounts`.

The walk is cached briefly, so `computed_at` may trail the request by a second or two.

---

## Pending sends

### GET /pending
All pending (sent but not yet received) sends across accounts. Query: `?offset=N&limit=M`. Each entry is enriched with the send block's `Timestamp`.
```bash
curl "https://ldn.core.test.network/pending?limit=2"
```
```json
[
  {
    "SendHash": "0099bb98...5d99",
    "Source": "5a598c38...b56d",
    "Destination": "334457d5...e80f",
    "Amount": 411203,
    "Asset": "XUSD",
    "Timestamp": 1781794221361820882
  }
]
```

### GET /pending/{address}
Pending sends destined for one account. Path: `address`. (Entries here are raw `PendingSend` with no `Timestamp` field.)
```json
{
  "address": "334457d5...e80f",
  "pending": [
    { "SendHash": "0099bb98...5d99", "Source": "5a598c38...b56d", "Destination": "334457d5...e80f", "Amount": 411203, "Asset": "XUSD" }
  ]
}
```
> Errors: `400 missing address`.

---

## Blocks

### GET /blocks/recent
The most recent blocks across the whole lattice, newest first. Returns an array of block objects (see the Block reference below).

Params:
- `limit` — how many blocks to return. Default 100, max 1000.
- `since` — unix **nanosecond** timestamp; returns only blocks strictly newer than it. A window with no blocks returns `[]`. Non-numeric values are a 400.

`since` is applied first, then `limit` truncates the result. Both operate over the newest 1000 blocks (the `maxPageLimit` ceiling), so a window holding more than 1000 blocks — sustained throughput above ~3.3 blocks/s over a 5-minute window — is truncated to the newest 1000.

The node rebuilds this list at most once per second and serves all callers from that snapshot, so results may be up to 1s stale.

### GET /blocks/{hash}
Block by hash. Path: `hash` (64 hex). Returns the block plus a `"finalized"` boolean.
```json
{ "type": "send", "account": "f6c78b...bb04", "previous": "3f560e...ec0b", "balance": 96088705, "timestamp": 1781801279942067170, "asset": "XUSD", "destination": "47815b...6f77", "amount": 1, "signature": "36a5c9...1001", "hash": "a1d201...2a13", "pow_nonce": 10051993738983095315, "finalized": false }
```
> Errors: `400 missing hash`, `404 block not found`.

### POST /blocks/{send,receive,lease,lease_accept,lease_settle,lease_cancel,lease_force_settle,multisig_open,multisig_update,burn,mint}
Submit a **pre-signed, pre-PoW'd** block. The request body is a single **Block object** (see reference). The path determines the expected `type`; a mismatch is rejected. Success is `201` echoing the stored block. A rejected block returns the reason plus a stable machine-readable `retryable` flag: a **deterministically invalid** block (bad signature/PoW, structural or value validation) returns `400 {"error":"block rejected: <reason>","retryable":false}`; a **transient** failure — a dependency not yet synced on this node, e.g. a receive submitted before its source send, or a frontier race — returns `503 {"error":"block rejected: <reason>","retryable":true}`, signalling the same block may be retried once the dependency lands. Branch on the `retryable` field, not the prose. An empty or type-mismatched body returns `400 block type mismatch`.

Typical send submission:
```bash
curl -X POST https://ldn.core.test.network/blocks/send \
  -H 'Content-Type: application/json' \
  -d '{
    "type": "send",
    "account": "5a598c38...b56d",
    "previous": "0099bb98...5d99",
    "balance": 99000000,
    "timestamp": 1781802000000000000,
    "asset": "XUSD",
    "destination": "334457d5...e80f",
    "amount": 1000000,
    "representative": "e04689f4...c11d",
    "signature": "<hex sig>",
    "hash": "<64 hex>",
    "pow_nonce": 1234567890
  }'
```
Response `201`: the same block object echoed back.

The same account's **first** block additionally declares `pub_key` (see below):
```bash
curl -X POST https://ldn.core.test.network/blocks/receive \
  -H 'Content-Type: application/json' \
  -d '{
    "type": "receive",
    "account": "5a598c38...b56d",
    "previous": "0",
    "pub_key": "<64 hex ed25519 public key deriving the account above>",
    "balance": 100000000,
    "timestamp": 1781802000000000000,
    "asset": "XUSD",
    "source": "0099bb98...5d99",
    "signature": "<hex sig>",
    "hash": "<64 hex>",
    "pow_nonce": 1234567890
  }'
```

#### `pub_key`: the opening-block key declaration

Because `account` is `sha256("xe/account/v1" || pubkey)` rather than the key
itself, a chain has to publish its key once so later blocks can be verified
against it. That happens on the **first** block:

- **Required** when `previous == "0"` on a single-key chain, whatever the block
  type (`receive`, `send`, `mint`, `burn`, …). The node checks
  `sha256("xe/account/v1" || pub_key) == account` and rejects a mismatch as
  `pub_key does not derive account address` (deterministic → `retryable:false`).
  Omitting it is `open block must declare pub_key`.
- **Forbidden** on every later block (`non-open block must not declare pub_key`).
  The node has already stored the key; accepting a redeclaration would be a
  silent credential swap.
- **Forbidden** on any block carrying `signatures` (multisig) — the keyset is
  the credential, and the multisig address already commits to it.

`pub_key` is bound into the block **hash**, and therefore into the signature, so
a relay cannot add, strip, or swap it in transit. It is appended after the
canonical block bytes as a tagged, length-prefixed section:

```
sha256( network_id || canonical_block_bytes || aux )

aux = u64be(len("xe/block/pubkey/v1")) || "xe/block/pubkey/v1"
   || u64be(len(pub_key_hex))          || pub_key_hex        # ASCII hex, 64 bytes
```

The lengths frame the ASCII hex string, not the decoded key. `aux` is empty when
no key is declared, so a non-opening block hashes exactly as it did before.
Reference implementations: `core.MarshalBlockAux` (Go),
`web/assets/xe-block.js` `marshalBlockAux` (JS).

**Notes per type:**
- `send` — `destination`, `amount`, `asset`; optional `memo` (≤64 bytes, UTF-8).
- `receive` — `source` (hash of the send being received), `asset`.
- `lease` — consumer-signed; `vcpus`, `memory_mb`, `disk_gb`, `duration` (secs), `access_pub_key`.
- `lease_accept` — provider-signed; carries `certificate_hash`, `attestations`, and the locked emission params `locked_r` / `locked_payout_cap` / `locked_twap_milli`.
- `lease_settle` / `lease_force_settle` — carry `attestations`.
- `multisig_open` / `multisig_update` — carry `keyset` and `signatures` (one per signer).
- `burn` — **XE only** (enforced by the ledger validator); optional `memo`.
- `mint` — **XUSD, authorized minter only** (`sys.minter`); rejected otherwise. `sys.minter.keys` holds account **addresses**, matched against the block's `account` (unlike `sys.timekeepers` / `sys.oracle` / `sys.dao_keyset`, which hold verifying keys matched against signatures).

### Block object reference (the POST `/blocks/*` body)
| Field | Type | Notes |
|---|---|---|
| `type` | string | one of `send,receive,lease,lease_accept,lease_settle,lease_cancel,lease_force_settle,multisig_open,multisig_update,burn,mint,genesis` |
| `account` | string | account **address**, 64 hex — `sha256("xe/account/v1" \|\| pubkey)`, or a multisig keyset digest. **Not** a public key |
| `previous` | string | prev block hash; `"0"` for first block |
| `pub_key` | string | account's ed25519 **public key**, 64 hex. **Required** iff `previous == "0"` on a single-key chain; **forbidden** on every other block and on all multisig blocks |
| `balance` | uint64 | balance **after** this block (micro-units) |
| `timestamp` | int64 | unix nanos |
| `asset` | string | `"XE"` / `"XUSD"` |
| `representative` | string | delegate **address** (optional) — vote weight is keyed by address, not key |
| `destination`,`amount` | string,uint64 | send |
| `source` | string | receive (send hash) |
| `vcpus`,`memory_mb`,`disk_gb`,`duration`,`access_pub_key` | uint64.../string | lease |
| `memo` | string | send/burn only, ≤64 bytes UTF-8 |
| `keyset` | object | multisig (`{keys:[],threshold:N}`) |
| `signatures` | array | multisig (`[{public_key,signature}]`) |
| `signature` | string | single-key ed25519 sig (hex) |
| `hash` | string | SHA-256 of canonical block bytes |
| `pow_nonce` | uint64 | anti-spam PoW (excluded from hash) |
| `attestations` | array | timekeeper attestations on accept/settle |
| `certificate_hash` | string | required on lease_accept |
| `locked_r`,`locked_payout_cap`,`locked_twap_milli` | uint64 | locked emission params on lease_accept |
| `lease_min_duration_secs`,`lease_settle_grace_ns`,`lease_force_settle_gap_ns`,`lease_escrow_expiry_ns`,`lease_archive_gap_ns`,`max_attestation_skew_ns` | uint64/int64 | **genesis block only** |

---

## PoW

Proof-of-work is solved **client-side**. The old `POST /pow` endpoint — which ground nonces on the node's CPU for any 64-hex hash, an offload/DoS oracle usable to bill block *and* chat PoW to the victim — is removed. To solve: compute the 8-byte unkeyed blake2b digest of `nonce_LE(8 bytes) || hash(32 bytes)`, read it as a big-endian uint64, and search for a nonce where the value is `>=` the difficulty. Difficulties are advertised by `GET /node` as hex strings: `pow_difficulty` (block submission) and `chat_pow_difficulty` (chat envelopes, solved over the envelope `id`). The web UI ships a reference implementation in `web/assets/blake2b.js` + `web/assets/pow.js`.

---

## Conflicts & delegation

### GET /conflicts
All open conflicts (forks awaiting representative-weighted resolution). Query: `?offset=N&limit=M`.
```json
[
  {
    "account_address": "1ce5074e...b528",
    "previous_hash": "1cf819b4...3236",
    "block_hashes": ["74e73dbb...a292", "3777188c...96c2"],
    "detected_at": "2026-06-18T16:46:49.440901357Z",
    "weight_snapshot": { "594c300c...aa84": 8400000000000, "...": 8388300047361 },
    "total_weight": 41988300047361
  }
]
```

### GET /conflicts/{account}
Open conflicts for a single account. Path: `account`. Returns an array (same shape). Errors: `400 missing account`.

### GET /delegation
Representative vote weights in **micro-XE**, split by eligibility for the
quorum denominator. No params.
```json
{
  "weights": {
    "594c300c...aa84": 8400000000000,
    "e04689f4...c11d": 8388300037286
  },
  "total_weight": 41988300037286,
  "ineligible_weights": {},
  "ineligible_weight": 0,
  "eligibility_restricted": false,
  "eligibility_failed_open": false
}
```
> Keys of `weights` are representative **addresses**, not public keys — a vote
> carries the representative's public key (so gossip can verify it statelessly),
> but weight is delegated to and tallied against the derived address.

| Field | Meaning |
|---|---|
| `weights` / `total_weight` | Weight that COUNTS toward quorum. `total_weight` **is** the quorum denominator, and every finality threshold on the network is a fraction of it. |
| `ineligible_weights` / `ineligible_weight` | Weight the `sys.representatives` policy excludes from quorum. Empty and zero when no policy is published. Watch it, but it costs the network nothing while it sits here. |
| `eligibility_restricted` | Whether an allowlist is actually in force. |
| `eligibility_failed_open` | An allowlist **is** published but is being IGNORED because it matches zero delegated weight. Should always be `false`; `true` means the published allowlist is wrong. |

`sys.representatives` on the state chain decides the split. Absent, or
`{"mode":"open"}`, means every representative counts — the default. An allowlist,
`{"mode":"allowlist","addresses":["<64-hex address>", ...]}`, counts only the
listed addresses: their weight is the denominator, and only they may vote.
`sys.*` keys can never be deleted, which is why `"open"` exists — it is the only
way to lift an allowlist once one has been published.

---

## Compute providers & certificates

### GET /providers
Advertised compute providers and their current utilization. No params. `account`
is the provider's **address** — the value you put in a lease block's
`destination` and look up with `GET /certificate/{provider}`.
```json
[
  { "account": "df280688...b750", "vcpus": 4, "memory_mb": 8192, "disk_gb": 50, "max_concurrent_leases": 5, "used_vcpus": 0, "used_memory_mb": 0, "used_disk_gb": 0, "active_leases": 0, "total_leases": 0, "timestamp": 1781858883888389215 }
]
```
`used_*` and `active_leases` count only leases the provider has **accepted** and
not yet finished. A lease still in `created` is a request, not a reservation, and
holds nothing — whether a provider can take it is decided at accept time.

### GET /certificate
This node's performance certificate (only meaningful in provider mode). No params.
```json
{
  "provider": "<account>", "seed": "<hex>", "workload_version": 1, "iterations": 1000000,
  "work_proof": "<hex>", "score": 1234.5,
  "start_attestation_root": "<hex>", "end_attestation_root": "<hex>",
  "start_median": 1781800000000000000, "end_median": 1781800600000000000,
  "issued_at": 1781800600000000000, "expires_at": 1781887000000000000,
  "price_multiplier_milli": 1000, "signature": "<hex>", "hash": "<hex>"
}
```
> Errors: `404 no performance certificate`.

### GET /certificate/{provider}
The provider's current **unexpired** performance certificate — what a consumer quotes and writes a lease against. Path: `provider` (account). Same body as above. Expired certificates are never returned here even though the node retains them, because a lease written against one is rejected by the ledger. Errors: `400 missing provider address`, `404 no certificate for provider`.

### GET /certificate/hash/{hash}
A retained performance certificate by its own hash, **including expired ones**. Path: `hash` (certificate hash). Same body as above.

Lease blocks pin the hash of the certificate that was current when they were written, and the ledger validates them against the block's timestamp — so a node must keep serving those certificates long after they expire. Use this to check that the certificate backing historical lease blocks is still held after a provider has rotated. Errors: `400 missing certificate hash`, `404 no certificate with that hash`.

---

## Leases

### GET /leases
All leases. Query: `?state=created|accepted|settled|cancelled|unfulfilled|expired` (optional filter), `?offset=N&limit=M`. Returns an array of lease objects.
```bash
curl "https://ldn.core.test.network/leases?state=accepted&limit=10"
```
Lease object:
```json
{
  "lease_hash": "<hash>", "state": "accepted", "consumer": "<account>", "provider": "<account>",
  "vcpus": 4, "memory_mb": 8192, "disk_gb": 50, "duration": 3600, "access_pub_key": "<hex>",
  "cost": 1500000, "stake": 150000, "start_time": 1781800000000000000,
  "certificate_hash": "<hash>", "settled": false,
  "locked_r": 2000, "locked_payout_cap": 0, "locked_twap_milli": 0
}
```
> Invalid `state` → `400 invalid state: must be one of created, accepted, settled, cancelled, unfulfilled`.

### GET /leases/{hash}
Lease by hash. Path: `hash`. Errors: `400 missing hash`, `404 lease not found`.

### POST /lease/request  — operator only
End-to-end lease request: the node builds, signs and PoWs the lease block from the operator's wallet. **Requires `Authorization: Bearer <XE_API_ADMIN_TOKEN>`.**
```bash
curl -X POST https://localhost:8080/lease/request \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"vcpus":4,"memory_mb":8192,"disk_gb":50,"duration":3600,"access_pub_key":"<hex>"}'
```
Request body: `vcpus`, `memory_mb`, `disk_gb` (uint64; at least one ≥1 required), `duration` (uint64 secs, **required**), `access_pub_key` (optional). Response `201`:
```json
{ "lease_hash": "<hash>" }
```
> Errors: `403 operator endpoint disabled: no admin token configured (set XE_API_ADMIN_TOKEN)`, `401 invalid or missing admin token`, `400 at least one resource required (vcpus, memory_mb, disk_gb)`, `400 duration required`.

---

## VMs & tunnels

### GET /vms
All VMs running on this node (provider mode). No params. Array of VM info:
```json
[ { "lease_hash": "<hash>", "status": "running", "resources": { "vcpus": 4, "memory_mb": 8192, "disk_gb": 50 }, "credentials": { "username": "xe", "password": "<pw>" }, "created_at": 1781800000000000000 } ]
```

### GET /vms/{lease}
VM info for a single lease. Path: `lease`. Errors: `400 missing lease hash`, `404 vm not found`.

### POST /tunnel/{leaseHash}/tcp
Open a raw bidirectional **TCP tunnel** into a lease's VM. The HTTP connection is **hijacked**: after a `200 OK` the node streams raw bytes both ways. Path: `leaseHash`. Header `X-Signature` required — a hex ed25519 signature of the lease hash by the lease's `access_pub_key`.
> Errors: `400 missing/invalid lease hash`, `401 missing X-Signature header`, `403 lease has no access key` / `signature verification failed`, `404 lease not found`, `410 lease settled`, `502 tunnel error: <msg>`, `500 hijacking not supported`.

---

## State chain (DAO / consensus KV)

### GET /statechain/tip
Latest state-chain block. No params. Errors: `404 no tip`.
```json
{
  "index": 0, "prev_hash": "0000...0000",
  "ops": [ { "action": "set", "key": "sys.network_id", "value": "testnet-84ec09" } ],
  "signatures": [], "hash": "b9237c0c...821b", "timestamp": 0
}
```

### GET /statechain/blocks
Range of state-chain blocks. Query: `?start=N` (default 0), `?limit=M` (default 100, max 1000).
```json
{ "blocks": [ { "index": 0, "prev_hash": "0000...0000", "ops": [], "hash": "...", "timestamp": 0 } ], "block_count": 1 }
```

### GET /statechain/blocks/{index}
State-chain block by index. Path: `index` (uint). Errors: `400 invalid index`, `404 block not found`.

### GET /statechain/kv
All state-chain KV entries, or a prefix subset. Query: `?prefix=epoch.` (optional), `?offset=N&limit=M`.
```bash
curl "https://ldn.core.test.network/statechain/kv?prefix=sys.&limit=3"
```
```json
{
  "sys.dao_keyset": { "keys": ["6304...93fb","7b29...3b53","979e...0bff"], "threshold": 2 },
  "sys.minter":     { "keys": ["8493...4d64"] }
}
```

### GET /statechain/kv/{key...}
A single KV entry by full key (the `{key...}` segment captures slashes/dots). Path: `key`.
```bash
curl https://ldn.core.test.network/statechain/kv/sys.network_id
```
```json
{ "key": "sys.network_id", "value": "testnet-84ec09" }
```
> Errors: `400 missing key`, `404 key not found`.

### GET /statechain/keyset
The DAO keyset (M-of-N timekeepers). No params. Errors: `404 keyset not found`.
```json
{ "keys": ["6304...93fb","7b29...3b53","979e...0bff"], "threshold": 2 }
```

### POST /statechain/blocks
Submit a signed state-chain block. Body: a state-chain Block (`index`, `prev_hash`, `ops:[{action,key,value}]`, `signatures:[{public_key,signature}]`, `hash`, `timestamp`). Success `201` echoes the block; rejection → `400 block rejected: <reason>`.

---

## Attestation

### POST /attestation/request
Ask this node (as a timekeeper) to attest a lease's timing.
```bash
curl -X POST https://ldn.core.test.network/attestation/request \
  -H 'Content-Type: application/json' -d '{"lease_hash":"<hash>"}'
```
Response `200`:
```json
{ "public_key": "<timekeeper pubkey>", "timestamp": 1781800000000000000, "signature": "<hex>" }
```
> `public_key` is a raw ed25519 **public key**, matched against the
> `sys.timekeepers` key list on the state chain — timekeeper identity is a key,
> not an account address. Errors: `400 invalid request body`,
> `400 lease_hash required`, `400 <attestation error>`.

---

## Directory (account → libp2p peer)

### GET /directory
All directory registrations. Query: `?offset=N&limit=M`.
```json
[ { "account": "594c300c...aa84", "pub_key": "8c1f52ab...9d31", "node_peer": "12D3KooWSrn...o6V6", "timestamp": 1781858573805587707, "signature": "216cc6d2...2b0c" } ]
```

### GET /directory/{account}
Directory entry for an account. Path: `account` (an **address**). Errors: `400 missing account`, `404 account not found in directory`.

### POST /directory/register
Register (or refresh) your own account → peer mapping. Body: a signed `Registration` (`account`, `pub_key`, `node_peer`, `timestamp`, `signature`). Response `200 {"ok":true}`. Errors: `400 invalid request body` / signature-validation error. CLI: `xe directory register [--watch]`.

`pub_key` is **required**: `account` is an address, so the record no
longer carries a key that can verify its own signature, and the directory is a
stateless ingress that must not consult the ledger (a chat-only account may have
no chain at all). The record therefore self-certifies — the node checks
`sha256("xe/account/v1" || pub_key) == account` **before** verifying the
signature (`registration key: public key does not derive account …`), and the key
is framed into the signed canonical bytes so it cannot be swapped in transit.
Omitting it is `missing pub_key`.

Signing payload (all fields length-prefixed with an 8-byte big-endian length):
```
"xe/directory-registration/v1\0"
  || f(network_id) || f(account) || f(pub_key) || f(node_peer) || f(decimal timestamp)
signature = ed25519(sha256(payload))
```
Reference implementations: `directory.NewRegistration` (Go),
`web/assets/directory-registration.js` `buildRegistrationJson` (JS).

> **Registrations expire after 30 minutes and nothing refreshes them for you.**
> The node's directory TTL is `MsgTTL`, which is unset and so falls back to the
> 30-minute default, and `RegisterAccount` is only ever called from this
> endpoint. Nodes re-announce their own account; a wallet or client account does
> not. Once the entry lapses, `POST /chat/send` to that account fails with
> `404 recipient not found in directory` — so any client that wants to stay
> reachable must re-register on a timer well inside the window.
> `xe directory register --watch` is that timer: it stays resident and
> re-registers every 20 minutes (two thirds of the TTL).

---

## Chat (P2P direct messaging)

### POST /chat/send
Send a signed chat envelope. CLI: `xe chat send <to-address> <message>` builds,
signs and PoW-solves the envelope and prints its `id`; an unregistered
recipient exits non-zero with the node's `404 recipient not found in directory`.
```bash
curl -X POST https://ldn.core.test.network/chat/send \
  -H 'Content-Type: application/json' \
  -d '{"from":"<address>","pub_key":"<64 hex>","to":"<address>","message":"hello","timestamp":1781800000000000000,"signature":"<hex>","pow_nonce":123}'
```
Body fields: `from` (required, an **address**), `pub_key` (required, the sender's ed25519 **public key**), `to` (required, an **address**), `message`, `timestamp` (nanos), `signature` (required, over the envelope id), `pow_nonce` (required when the node's `chat_pow_difficulty` > 0 — solved over the envelope `id` at that difficulty, see the PoW section). The envelope `timestamp` must be within ±5 minutes of the node's clock, and each envelope `id` is accepted at most once (replay dedup). Response `200 {"ok":true}`. Errors: `400 missing 'to' field`, `400 chat send requires a signed envelope (from + signature)`, `400 invalid request body`, `400 invalid envelope: missing required fields`, `400 invalid envelope: insufficient proof of work`, `400 invalid envelope: envelope timestamp outside freshness window`, `400 duplicate envelope`.

`pub_key` is **required**, for the same reason as on a directory
registration: `from` is an address and chat ingress is stateless. The node checks
that the key derives `from` before verifying the signature. The key is framed
into the canonical bytes the envelope `id` is computed from, and the `id` is both
the signed message and the PoW target — so the declared key is covered by the
signature *and* by the work:

```
id = sha256( f(from) || f(pub_key) || f(to) || f(message) || u64be(timestamp) )
```
where `f(x)` is a 4-byte big-endian length followed by the UTF-8 bytes of `x`.
Reference implementations: `chat.ComputeEnvelopeID` (Go),
`web/assets/chat-envelope.js` `computeEnvelopeID` (JS).

### GET /chat/auth/challenge
Issue a short-lived, single-use challenge to sign for a chat read. No params.
Returns `{"challenge": "<hex>", "expires_at": <unix nanos>}`. The challenge is
HMAC-bound to the issuing node and valid for 120s, so fetch it from the same node
you are about to read from.

### GET /chat/messages
Fetch chat messages for an account. Reading an account's history requires an
**ownership proof**.

Query: `account` (**required**), `pub_key` (**required**), `challenge`
(**required**), `sig` (**required**), `since` (optional, unix nanos, default 0).
Returns an array of envelopes. CLI: `xe chat read [--since <unix-ns>] [--follow]
[--json]` does the challenge → sign → fetch round trip for the loaded wallet;
`--follow` polls with a fresh challenge each time, `--json` prints one envelope
object per line.

`pub_key` is the account's **verifying key**, and is required for the same reason
as on a directory registration: `account` is an address and cannot verify
its own signature. The node checks the key derives the account before checking
the signature.

Build the proof by signing the challenge, domain-separated so a signature made
anywhere else can never be replayed here:

```
sign_target = sha256( "xe/chat-read-auth/v1\0" || challenge_bytes )
sig         = ed25519(sign_target)
```

where `challenge_bytes` is the hex-decoded `challenge`. Each challenge is
single-use — a replay returns `403 challenge already used`.

Errors: `400 missing account parameter`;
`401 chat read requires an ownership proof (pub_key + challenge + sig)`;
`403` for `malformed challenge`, `challenge not issued by this node`,
`challenge expired`, `challenge already used`, or
`ownership proof key: public key does not derive account …`.

### GET /chat/contacts
The distinct accounts an account has exchanged messages with — the other party
of every envelope stored under it, in both directions, deduplicated and sorted,
never the account itself. Reading it requires the same **ownership proof** as
`GET /chat/messages`.

Query: `account` (**required** for the per-account form), `pub_key`
(**required**), `challenge` (**required**), `sig` (**required**). Returns an
array of account strings.

**Omitting `account` requests the node-wide list of every account with a
message stored on this node, which is operator-only** and requires the admin
bearer token, exactly like the `GET /chat/events` firehose; without one
configured it returns `403 operator endpoint disabled: no admin token configured
(set XE_API_ADMIN_TOKEN)`, and a missing or wrong bearer returns
`401 invalid or missing admin token`.

Errors: the proof errors listed under `GET /chat/messages`.

### GET /chat/events
Server-Sent Events stream of incoming chat. `Content-Type: text/event-stream`; each event is `data: <envelope json>\n\n`. Query: `account` (optional) filters to envelopes where `from==account || to==account`.

A named `account` requires the same ownership proof as `GET /chat/messages`
(`pub_key`, `challenge`, `sig` — carried as query params because `EventSource`
cannot set headers). **Omitting `account` requests the unfiltered firehose of
every message on the node, which is operator-only** and requires the admin bearer
token; without one configured it returns `403 operator endpoint disabled: no
admin token configured (set XE_API_ADMIN_TOKEN)`.

Errors: `500 streaming not supported`, plus the proof errors listed under
`GET /chat/messages`.
> On connect the handler immediately flushes an SSE comment (`: connected`) so the response headers and `text/event-stream` content-type reach the client before any message arrives — this lets `EventSource.onopen` fire and lets the reverse proxy disable response buffering — then sends a `: ping` comment every 20s to keep idle connections alive and detect dead peers.

---

## Out of scope (separate services, own APIs)

The faucet, oracle, and explorer are separate services with their own small HTTP surfaces — documented separately. This reference covers the **core node** API only.
