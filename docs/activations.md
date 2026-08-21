# Feature activations — operator procedure

**Audience: anyone running an XE node, including operators the foundation does
not control.** This is the procedure for a coordinated protocol activation, and
the contract the network makes with you about upgrades. Read it before you run a
node on a network you care about.

---

## What this is, in one paragraph

XE has no hard-fork machinery and never will. Instead, a feature that changes
what nodes accept is compiled into the binary **disabled**, and a DAO-signed
state-chain record turns it on at a point every node computes identically from
the chain itself. There is no flag day decided by wall-clock on your machine, no
coordinated restart, and no wipe. If you are running a build that implements the
feature, you flip with everyone else. If you are not, your node **tells you so,
loudly, before the deadline** — and after it, governance can disconnect you
rather than leave you serving stale reads to your users.

---

## The registry

One state-chain key, `sys.activations`, written only by a DAO-multisig block:

```json
{
  "features": {
    "messaging": { "at_index": 41000, "not_before_ns": 1793558400000000000 }
  }
}
```

A feature is **active** when the state chain's tip satisfies **both** terms:

```
active(f)  ⟺  tip.index ≥ at_index  ∧  tip.timestamp ≥ not_before_ns
```

Either term may be `0`, meaning "no constraint from this term"; at least one must
be set. Both are read from the converged state chain — **never from your node's
clock, config or peer set**. Both are monotone, so an activation is
one-directional: once a feature is live it stays live.

Three consequences worth internalising:

1. **The flip is anchored to a block, not to a moment.** A feature goes live at
   the first state-chain block that satisfies both terms. On a chain that is
   quiet — no oracle epochs, no governance traffic — nothing happens until
   someone publishes a block. The DAO therefore publishes a **heartbeat block**
   at the activation time as part of the procedure below. This is deliberate:
   anchoring to an observable block is what makes every node flip at the *same*
   point rather than at the same *time* on differently-skewed clocks.
2. **"Never" is absence, not a sentinel.** A feature that is not in the registry
   is not activated and never has been. `sys.*` keys can be added by DAO block
   but can never be deleted, so nothing is seeded speculatively — a mainnet
   genesis ships without `sys.activations` at all.
3. **There is no de-activation path, by design.** A reversible consensus switch
   is a second, worse consensus surface. The only reverse is an emergency
   major-version bump and a coordinated restart, which is a hard fork and is
   documented as one.

### What the chain enforces

| Rule | Enforced | Why |
|---|---|---|
| Schema, name charset, feature cap | yes | bounds a governance blob that every validation reads |
| **Non-retroactive** — a new or rescheduled trigger must be in the future on both terms, relative to the block carrying it | yes | a trigger that lands already-fired activates with zero warning |
| **Frozen once fired** — an active feature's trigger cannot be moved | yes | moving it would retroactively change the validity of blocks already on the chain |
| **No removal** — a feature present in the registry stays present | yes | removal is de-activation by another name |
| Rescheduling a *pending* trigger, earlier or later, while it stays in the future | allowed | nothing has been validated under it yet |
| **Minimum lead time (14 days)** | **no — procedure only** | see below |

The 14-day lead is **not** a validity rule. It protects operators from surprise,
not the chain from an adversary: the only party who can write this key is the
DAO, so encoding the lead as consensus buys nothing against the only party able
to break it, while permanently foreclosing an emergency activation. It is
enforced by the procedure below and by the readiness gate, and a node logs a
warning when a record lands with less than 14 days of lead.

---

## What your node tells you

`GET /network/activations`

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

**`unsupported_active` is the field to alert on.** Non-empty means the chain has
activated something this build cannot enforce: blocks belonging to that feature
will be refused by your node and the account chains carrying them will stall on
it, while upgraded peers carry on. Your node is not corrupt and its funds are
safe — it is *behind*, and it will recover on its own once you upgrade, because
a refusal of this kind is classified as transient and never poisons the block.

`unsupported_pending` is the same warning delivered *before* the deadline. That
is the one you want to see.

The same lines appear in the log, printed on every state-chain movement when the
text changes, with the active-but-unsupported warning repeating every five
minutes so it cannot scroll away:

```
activation: feature messaging scheduled (at statechain index 41000, not before 2026-11-01T00:00:00Z); this build does NOT implement it — UPGRADE REQUIRED
CRITICAL: this node cannot enforce active network feature(s) [messaging] — it is validating DIFFERENTLY from upgraded peers. Upgrade now; ...
```

---

## Readiness — the number the DAO signs against

`GET /network/readiness`

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

Readiness is measured in **delegated vote weight**, not peer count. Finality
needs 67% of delegated weight; activating a feature that more than a third of
weight cannot validate wedges the network rather than forking it — safer, but
still a total outage for the feature. `feature_ready_milli` is per-thousand, so
the gate reads as `≥ 900`.

`unknown_weight` is weight this node cannot attribute to any advertising peer —
an unregistered representative, a peer not currently connected, one that never
completed a handshake. **Count it as not ready.** Mapping is
representative → directory registration → peer → advertised features, and every
link is best-effort.

Features are advertised in the netcheck handshake and derived from the compiled-in
registry, never from configuration, so a node cannot claim readiness it does not
have.

---

## The procedure, per activation

| When | Step |
|---|---|
| **T−45d** | **Release.** Publish the binary containing the dark feature. Release notes state *what* activates, the *earliest possible* trigger, and that not upgrading will eventually disconnect you. Announce on the status page, the docs site, and the node-operator channel. |
| **T−45d → T−14d** | **Signalling soak.** Operators upgrade at leisure; both versions interoperate. `/network/readiness` is published continuously. Foundation-run nodes upgrade **first** and are counted separately, so foundation weight is never mistaken for community readiness. |
| **T−14d** | **DAO signs the activation op**, once readiness has been **≥ 90% for 7 consecutive days**. 90% against a 67% quorum leaves a 23-point margin, so the feature cannot wedge on quorum even if a chunk of signalling weight drops offline at the trigger. The op names the exact `at_index` and `not_before_ns`. Every node — upgraded or not — stores it. |
| **T−14d → T** | **Freeze.** No other consensus-affecting release. Run the full harness battery against a rehearsal network that performs the same activation end to end, **including a deliberately un-upgraded node**: verify it stalls safely (never accepts wrong state), that upgraded nodes converge, and that frontier fingerprints stay N/N across the boundary. |
| **T** | **Activation.** The DAO publishes a heartbeat state-chain block at the activation moment (see "anchored to a block" above). Upgraded nodes flip in lockstep. Monitor `/conflicts`, frontier parity and finality latency continuously for 24h. |
| **T+7d** | **Evict.** The DAO raises `sys.min_protocol_version`. Stale nodes are cleanly disconnected instead of sitting half-synced. |

### Rehearse first

Run `scripts/test-830-activations` — it stands up a real five-node network,
publishes a DAO activation for a feature no binary implements, crosses the
trigger, and asserts frontier parity, zero conflicts and no restarts. Then
rehearse on the testnet using the reserved feature `noop`, which gates nothing
by construction. **Every network should activate `noop` once before it ever
activates anything real.**

---

## `sys.min_protocol_version`

A DAO-signed, monotonically-rising floor: `"1.2.0"`. A peer advertising a lower
protocol version is refused at the netcheck handshake, in addition to the
existing ±2-minor drift rule.

It exists because the drift rule alone is circular — enforcing an upgrade with
it requires everyone to have upgraded first. The floor is enforced immediately
by whoever *has* upgraded, and it takes effect on a running node with no restart.

`NetcheckVersion` is the **protocol** version: it moves only on a deliberate wire
or consensus change, in its own commit, with a changelog entry. It is not the
release version (`main.version`, set by ldflags, free to move every build), and a
CI test fails if it changes without a deliberate edit.

---

## If you are running an un-upgraded node

- Your funds are safe. Your node refuses what it cannot validate; it never
  accepts wrong state.
- Account chains carrying blocks of the new feature will **stall** on your node.
  Because the refusal is classified as transient rather than terminal, nothing is
  permanently blocklisted: your node picks the chain back up on its own once you
  upgrade.
- You will be disconnected at T+7d when the floor rises. That is intentional —
  a half-synced node serving stale balances to its users is worse than an
  offline one.
- The fix is always the same: install the current release and restart.
