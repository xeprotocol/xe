<p align="center">
  <img src="logo.svg" width="96" height="103" alt="XE">
</p>

<h1 align="center">XE</h1>

<p align="center">
  A decentralized compute &amp; networking platform.<br>
  Lease real VMs from strangers, pay with a stablecoin, settle on a ledger with no fees and no miners.
</p>

<p align="center">
  <a href="https://test.network">test.network</a> ·
  <a href="https://test.network/docs">docs</a> ·
  <a href="https://test.network/bounty">bug bounty</a>
</p>

---

> ### ⚠️ Work in progress
>
> XE is pre-1.0 and runs on a **public testnet only**. This source tree is
> published so you can read it, build it, run a node and break it — not because
> it is finished.
>
> - **Not every command in this README works right now.** The network is under
>   active development and pieces of it go up and down. Where something is
>   currently unavailable, it says so below.
> - **There is no backward compatibility.** Protocol changes land by wiping the
>   testnet and re-bootstrapping. Your balances, accounts and history are
>   discarded when that happens, on purpose and without warning.
> - **XE has no monetary value.** Testnet coins are for testing.
> - The current network is **`testnet-0001`**.

## What XE is

Consumers pay **XUSD** (a stablecoin) to lease real VMs from providers.
Providers earn newly minted **XE** when a lease settles — that settlement is the
only way XE is created after genesis. Around that sit signed peer-to-peer
messaging, an account directory, SSH into leased VMs over the p2p network, and
DAO-multisig governance.

The ledger is a **lattice**: every account owns its own signed chain, and a
transfer is two blocks — a `send` on the sender's chain, a `receive` on the
recipient's. Chains advance in parallel, so there is no global block race, no
mempool and no miners. Blocks finalize through representative voting: converge,
commit-lock, then an irrevocable final vote at ≥67% of delegated weight.

Two coins, one ledger:

| | XE | XUSD |
|---|---|---|
| Role | native coin, consensus weight, provider earnings | stablecoin, pays for compute |
| Supply | 42,000,000 at genesis + lease emission | minted by the `sys.minter` set (faucet/bridge) |
| Votes | yes — delegated XE is the only vote weight | never |
| Fees | zero | zero |

Both use 6 decimal places, and every amount on the wire is an integer count of
**micro-units** (1 XE = 1,000,000 micro-units).

## What works today

Honest status against the live `testnet-0001`, as of this release:

| Area | Status |
|---|---|
| Build the binary, run a node, sync the chain | ✅ works |
| Wallets, addresses, keys (`xe wallet …`) | ✅ works |
| Send / receive / balances, XE and XUSD | ✅ works |
| Burn XE | ✅ works |
| Explorer + wallet web UI embedded in the node | ✅ works |
| REST API and SSE streams | ✅ works |
| Signed p2p chat | ✅ works, end-to-end payload encryption is not done |
| **Faucet (`xe faucet`)** | ❌ **currently offline** — the service was not redeployed after the last testnet wipe and is still bound to the previous network. Until it is fixed there is no way to obtain XUSD on the testnet. |
| **Leasing a VM, `xe lease` / `xe ssh`** | ❌ **no providers are online** — the two testnet providers were retired, so `xe providers` returns an empty list and a lease has nobody to accept it. |
| GPU leasing | 🚧 not implemented |
| Proof of uptime | 🚧 design stage |
| Key rotation, dispute arbitration | 🚧 design stage |

Anything marked ❌ or 🚧 is genuinely not usable today. The commands exist and
will run — they will just fail, or wait forever for a counterparty that is not
there.

## Build

You need Go — the exact toolchain is pinned in [`.go-version`](.go-version).

```sh
git clone https://github.com/xeprotocol/xe && cd xe
make build          # produces ./xe
```

Builds are reproducible: pinned toolchain, `-trimpath`, `-buildvcs=false`,
`CGO_ENABLED=0`. `make dist` cross-compiles every published platform with a
`SHA256SUMS`; `make verify-repro` builds the same commit twice and asserts the
binaries are byte-identical.

One binary does everything. `./xe --help` lists the subcommands; `xe node` runs
the daemon, everything else is a client that talks to a node's HTTP API.

## Hello world

The shortest path from nothing to a transfer: two wallets, fund one, send to the
other. Point the client at a public node and keep each wallet in its own file.

```sh
export XE_NODE=https://ldn.core.test.network
```

**1. Create two wallets.**

```sh
XE_WALLET=~/.xe/alice.seed ./xe wallet create
XE_WALLET=~/.xe/bob.seed   ./xe wallet create
```

```
Wallet created!
  Address:    7d27d0a34cc2a5cd08f65905a983fabec1a517baf6d3cdab0a921256ecb9af57
  Public key: 665b50f96f8a4a86e1940386cce7fa1c0592c8eba9524fe9d579254fc341f02b
  File:       /home/you/.xe/alice.seed
```

The **address** is what you hand out. It is `sha256("xe/account/v1" ‖ pubkey)`,
not the public key itself: identity and credential are separate, so a key can be
rotated without the account changing. The seed file is the account — back it up,
and note that anyone holding it holds the funds.

**2. Fund Alice from the faucet.** The faucet grants 100 XUSD per address per
rolling 24 hours.

```sh
XE_WALLET=~/.xe/alice.seed ./xe faucet
XE_WALLET=~/.xe/alice.seed ./xe receive
```

> **This step does not work right now.** The faucet service is offline for
> `testnet-0001` and returns `error: faucet: failed to send grant`, because it
> was never redeployed after the last wipe. Everything below it needs
> funds, so until the faucet is back the rest of this walkthrough cannot be
> completed on the live network. It is left here because it is the intended
> path, not because it currently runs.

Note the two steps: a grant is an ordinary `send` from the minter, and it sits
as **pending** until you claim it with `receive`. That is the lattice — nothing
lands in your account without a block signed by you.

**3. Check the balance.**

```sh
XE_WALLET=~/.xe/alice.seed ./xe wallet balance
```

**4. Send Bob 25 XUSD** — using Bob's address from step 1.

```sh
XE_WALLET=~/.xe/alice.seed ./xe send \
  4feede759012ae67f4d4636322485f04e7d995525c6ce171da2601fdbe2e2a76 \
  25 --asset XUSD --memo "hello world"
```

**5. Bob receives it.**

```sh
XE_WALLET=~/.xe/bob.seed ./xe receive
XE_WALLET=~/.xe/bob.seed ./xe wallet balance
```

Both sides settle in a few seconds, and neither paid a fee.

**6. Look at it from outside.** Every account is public:

```sh
curl -s $XE_NODE/accounts/<address>/balance
curl -s $XE_NODE/accounts/<address>/chain
```

Or open the explorer and wallet UI that ship inside the node itself — run
`xe node --ui` and visit `http://127.0.0.1:8000`.

## Run a node

Full instructions, including verifying a downloaded binary and the packaging
(systemd unit, Dockerfile) in [`deploy/`](deploy/), are in
[`docs/run-a-node.md`](docs/run-a-node.md). The short version, joining the live
network:

```sh
./xe node \
  --data /var/lib/xe/data \
  --genesis-dir ./genesis/testnet-0001 \
  --dial /ip4/45.77.226.208/tcp/9000/p2p/12D3KooWJg4PQYGSfNCupBWZdEWbKj7pgdp5MmmUXbPdBcp6YDtT,/ip4/144.202.4.117/tcp/9000/p2p/12D3KooWEqv1BRZkSntgcgbrJh7bobFRSkBdRupubvNZLEx8hZLA \
  --port 9000 --api --api-port 8080
```

A node's identity is its **genesis, not its binary**. A binary built from a
clean checkout embeds a placeholder genesis that no live network uses, which is
why `--genesis-dir` exists. Confirm what you are about to join before you join
it:

```sh
./xe verify-genesis --genesis-dir ./genesis/testnet-0001
```

### Network parameters — `testnet-0001`

| Parameter | Value |
|---|---|
| `network_id` | `testnet-0001` |
| ledger genesis hash | `e813eefe3b61cfa6bb4c78c747417f4c7f38cde127fb04d62ded967af7d1ed68` |
| statechain genesis hash | `419460291afa7405e462d44b696f8284da1655634ead62196e50e09234733a29` |
| genesis bundle | [`genesis/testnet-0001/`](genesis/testnet-0001) |
| bootstrap (London) | `/ip4/45.77.226.208/tcp/9000/p2p/12D3KooWJg4PQYGSfNCupBWZdEWbKj7pgdp5MmmUXbPdBcp6YDtT` |
| bootstrap (Frankfurt) | `/ip4/144.202.4.117/tcp/9000/p2p/12D3KooWEqv1BRZkSntgcgbrJh7bobFRSkBdRupubvNZLEx8hZLA` |
| bootstrap (New York) | `/ip4/192.248.176.245/tcp/9000/p2p/12D3KooWEbQ5zDvSz6kKE5ppzwBXKRFsnZbHNjRx94QZFaPeGA4e` |

There is no ambient peer discovery: the DHT only resolves peer IDs you already
know and mDNS reaches your LAN, so the bootstrap list you configure *is* your
node's view of the network. Use more than one.

Public API endpoints, if you would rather not run anything:
`https://ldn.core.test.network`, `https://ffm.core.test.network`,
`https://nyc.core.test.network`.

## Repository layout

| Path | What |
|---|---|
| `core/` | the lattice ledger — blocks, validation, crypto, PoW, voting, quorum |
| `statechain/` | linear DAO-multisig governance chain and epoch records |
| `net/` | libp2p transport, gossip, frontier sync, peer admission |
| `node/` | composition — wires store, ledger, host, gossip, sync, voting |
| `api/` | HTTP REST + SSE API ([`docs/api.md`](docs/api.md)) |
| `chat/`, `directory/` | signed messaging and the account directory |
| `vm/`, `perf/` | VM provisioning and benchmark certificates |
| `store/` | storage behind one interface — in-memory or BadgerDB |
| `web/` | the explorer and wallet UI embedded in the binary, no build step |
| `cmd/xe/` | the single binary: node daemon and CLI |
| `deploy/` | systemd unit, Dockerfile, env example |
| `genesis/` | published genesis bundles, one directory per network |

This is the source the testnet runs, with the development test suites and
internal operational tooling removed. Development happens in a private
repository; this tree is the published release of it.

## Found a bug?

Please report it. There is a paid bug bounty — currently **Phase 1:
transactions & running a node**, which is exactly the surface this README walks
you through.

- Read the scope and reward tiers: **[test.network/bounty](https://test.network/bounty)**
- File it as an issue on this repository
- **Critical or severe findings** — anything risking funds or the network — go
  privately to `security@xe.network` first, not a public issue.

## Docs

- [test.network/docs](https://test.network/docs) — architecture, API, CLI, consensus, tokenomics
- [`docs/api.md`](docs/api.md) — the REST + SSE API, canonical
- [`docs/run-a-node.md`](docs/run-a-node.md) — obtain, verify and run a node
- [`docs/emission-formula.md`](docs/emission-formula.md) — how XE emission is computed

## License

[GNU General Public License v3.0](LICENSE).

You may use, study, modify and redistribute this software. If you distribute it,
or a modified version of it, you must do so under the same licence and make the
corresponding source available. There is no warranty.

```
Copyright (C) 2026 XE Protocol

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <https://www.gnu.org/licenses/>.
```
