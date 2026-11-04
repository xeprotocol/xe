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
> - The current network is **`testnet-0005`**.

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
| Supply | 42,000,000 at genesis + lease emission | permissioned mint by the `sys.minter` set (a bridge; none is deployed today) |
| Votes | yes — delegated XE is the only vote weight | never |
| Fees | zero | zero |

Both use 6 decimal places, and every amount on the wire is an integer count of
**micro-units** (1 XE = 1,000,000 micro-units).

## What works today

Honest status against the live `testnet-0005`, as of this release:

| Area | Status |
|---|---|
| Build the binary, run a node, sync the chain | ✅ works |
| Wallets, addresses, keys (`xe wallet …`) | ✅ works |
| Send / receive / balances, XE and XUSD | ✅ works |
| Burn XE | ✅ works |
| Explorer + wallet web UI embedded in the node | ✅ works |
| REST API and SSE streams | ✅ works |
| Signed p2p chat | ✅ works, end-to-end payload encryption is not done |
| **Faucet (`xe faucet`)** | ✅ works — grants **1,000 XE** per address per rolling 24 hours, from a funded wallet. |
| **Leasing a VM, `xe lease` / `xe ssh`** | Requires XUSD and an available provider; check current provider advertisements with the command below. |
| GPU leasing | 🚧 not implemented |
| Proof of uptime | 🚧 design stage |
| Key rotation, dispute arbitration | 🚧 design stage |

Areas marked 🚧 are incomplete. Provider availability changes independently of
this release. After [building](#build), check the public node:

```sh
XE_NODE=https://ldn.core.test.network ./xe providers
```

A provider advertisement alone does not establish that lease acceptance, VM
provisioning or SSH works end to end.

## Build

Prerequisites: **Git**, **make**, **curl** and **Go 1.25 or newer**. Install a
prebuilt Go toolchain, then use it to compile XE. If `go version` already reports
Go 1.25 or newer, skip the Go installation steps for your OS.

On macOS, Git and make are provided by the Command Line Tools; curl is included
with macOS. Install the tools if needed:

```sh
xcode-select --install
```

Download the macOS `.pkg` from [Go downloads](https://go.dev/dl/): choose
`darwin-arm64` for Apple Silicon or `darwin-amd64` for Intel. Run the installer,
open a new terminal so its PATH change takes effect, and check `go version`.

On Ubuntu, install Git, make and curl:

```sh
sudo apt-get update
sudo apt-get install -y git make curl
```

Clone the source:

```sh
git clone https://github.com/xeprotocol/xe && cd xe
```

If Go is missing on Ubuntu, run the following from this checkout to install the
prebuilt version in [`.go-version`](.go-version). These commands expect
`/usr/local/go` to be absent; for replacing an existing installation, follow the
[official installation instructions](https://go.dev/doc/install).

```sh
case "$(uname -m)" in
  x86_64)  go_arch=amd64 ;;
  aarch64) go_arch=arm64 ;;
  *) echo "Use Go downloads for this architecture"; exit 1 ;;
esac
go_archive="go$(cat .go-version).linux-${go_arch}.tar.gz"
go_download=$(mktemp -d)
curl -fL "https://go.dev/dl/$go_archive" -o "$go_download/$go_archive"
test ! -e /usr/local/go && sudo tar -C /usr/local -xzf "$go_download/$go_archive"
export PATH="/usr/local/go/bin:$PATH"
go version
```

Add `export PATH="/usr/local/go/bin:$PATH"` to `~/.profile` to make the Ubuntu
PATH setting available in future login shells.

On either OS, select the exact Go version for this shell and build XE. Go
downloads that toolchain if needed; no version manager is required:

```sh
export GOTOOLCHAIN="go$(cat .go-version)"
go version          # should match .go-version (currently go1.25.0)
make build          # produces ./xe
```

`make build` uses the selected Go toolchain; `.go-version` alone does not select
or install it. The `GOTOOLCHAIN` setting above pins this build to the release
toolchain. All builds use `-trimpath`, `-buildvcs=false` and `CGO_ENABLED=0`.

Run the release and reproducibility commands on Linux; they require
`sha256sum` and GNU `stat`, provided by Ubuntu's `coreutils` package.
`make dist` explicitly selects the pinned toolchain and cross-compiles every
published platform with a `SHA256SUMS`; `make verify-repro` uses the same pin to
build the same commit twice and assert that the binaries are byte-identical.

One binary does everything. `./xe --help` lists the subcommands; `./xe node` runs
the daemon, everything else is a client that talks to a node's HTTP API.
Run the commands below from this checkout, in the same shell. The build does
not install `xe` on your PATH.

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

Recovery phrase:

  1. <word 1> ... 24. <word 24>
```

The actual output contains 24 numbered BIP39 words and backup instructions.
Write them down before using the wallet. The phrase is your only backup unless
you keep the hex seed separately. Anyone with the backup controls the wallet.
XE uses BIP39 + SLIP-0010 ed25519 at `m/44'/1'/account'` (default account 0;
coin type 1 is provisional). Import accepts 12, 15, 18, 21 or 24 words.

`./xe wallet restore [--account N] [--passphrase]` reads words from stdin.
`--passphrase` opts into a separate hidden BIP39 passphrase prompt, never argv.
Creation asks twice and writes no files if the entries differ. Restore asks once;
check the printed address.
It is never stored; a wrong passphrase opens a different, empty account.
`./xe wallet phrase` displays the stored words only if the address recorded in
`alice.phrase` matches the seed's address. A missing or mismatched address refuses
reveal and directs you to the hex seed backup. The phrase file contains the words,
`account: N` and `address: <64 hex>` on separate lines. It and the unchanged
`alice.seed` file both use mode 0600. Create and restore refuse to overwrite a
stray phrase file, even if the seed is missing.
Wallets made before v2 restore from their hex seed, not their old words.
See [recovery phrase v2](docs/recovery-phrase.md) for storage and browser flows.

The **address** is what you hand out. It is `sha256("xe/account/v1" ‖ pubkey)`,
not the public key itself: identity and credential are separate, so a key can be
rotated without the account changing. The seed file is the account — back it up,
and note that anyone holding it holds the funds.

Save Bob's actual `Address:` value from his wallet output for the commands
below. Run this and paste that address at the prompt, then press Enter:

```sh
printf "Bob's address: "
read -r BOB_ADDRESS
```

**2. Fund Alice from the faucet.** The faucet grants 1,000 XE per address per
rolling 24 hours.

```sh
XE_WALLET=~/.xe/alice.seed ./xe faucet
XE_WALLET=~/.xe/alice.seed ./xe receive
```

Note the two steps: a grant is an ordinary `send` from the faucet's own wallet,
and it sits as **pending** until you claim it with `receive`. That is the lattice — nothing
lands in your account without a block signed by you.

**3. Check the balance.**

```sh
XE_WALLET=~/.xe/alice.seed ./xe wallet balance
```

**4. Send Bob 0.5 XE** using the address saved in step 1.

```sh
XE_WALLET=~/.xe/alice.seed ./xe send \
  "$BOB_ADDRESS" 25 --asset XE --memo "hello world"
```

**5. Bob receives it.**

```sh
XE_WALLET=~/.xe/bob.seed ./xe receive
XE_WALLET=~/.xe/bob.seed ./xe wallet balance
```

Both sides settle in a few seconds, and neither paid a fee.

**6. Say hello.** Chat is off-chain and free. Bob registers so the network
knows which node he listens on, Alice sends, Bob reads:

```sh
XE_WALLET=~/.xe/bob.seed   ./xe directory register
XE_WALLET=~/.xe/alice.seed ./xe chat send \
  "$BOB_ADDRESS" "hello bob"
XE_WALLET=~/.xe/bob.seed   ./xe chat read
```

Registrations lapse after 30 minutes; `xe directory register --watch` stays
resident and keeps one alive, and `xe chat read --follow --json` streams new
messages one JSON object per line for a program on the other end.

**7. Look at it from outside.** Every account is public. For Bob:

```sh
curl -fsS "$XE_NODE/accounts/$BOB_ADDRESS/balance"
curl -fsS "$XE_NODE/accounts/$BOB_ADDRESS/chain"
```

To use the embedded explorer and wallet UI, add `--ui` to the complete node
command in [Run a node](#run-a-node), then visit `http://127.0.0.1:8000`.
`XE_NODE` selects the HTTP API for client commands; it does not configure a
local node's genesis or bootstrap peers.

## Run a node

Full instructions, including verifying a downloaded binary and the packaging
(systemd unit, Dockerfile) in [`deploy/`](deploy/), are in
[`docs/run-a-node.md`](docs/run-a-node.md). The quickstart below runs a syncing
node as your regular user on macOS or Linux.

A node's network identity comes from its **genesis, not its binary**. A clean
checkout embeds a placeholder genesis that no live network uses.
`--genesis-dir` selects the published `ledger-genesis.json` and
`statechain-genesis.json` for the network you want to join. Verify the bundle
before starting the node, and compare its hashes with the table below:

```sh
./xe verify-genesis --genesis-dir ./genesis/testnet-0005 \
  --expect-network-id testnet-0005
```

`--data` stores persistent node state and identity. The node creates the
user-owned directory below; reuse it when restarting on the same network. After
a testnet wipe, use the new genesis bundle and a separate data directory for
that network. System-wide paths such as `/var/lib/xe/data` require administrator
ownership setup, covered in the [service installation guide](deploy/README.md).

Start the node after verification succeeds:

```sh
./xe node \
  --data "$HOME/.xe/testnet-0005" \
  --genesis-dir ./genesis/testnet-0005 \
  --dial /ip4/45.77.226.208/tcp/9000/p2p/12D3KooWJg4PQYGSfNCupBWZdEWbKj7pgdp5MmmUXbPdBcp6YDtT,/ip4/144.202.4.117/tcp/9000/p2p/12D3KooWEqv1BRZkSntgcgbrJh7bobFRSkBdRupubvNZLEx8hZLA \
  --port 9000 --api --api-port 8080
```

Keep it running and, from another terminal, check the local node:

```sh
curl -fsS http://127.0.0.1:8080/node
```

Confirm `network_id` is `testnet-0005` and `peer_count` becomes greater than
zero. The API listens on loopback by default; adding `--ui` also serves the
explorer and wallet at `http://127.0.0.1:8000`.

### Network parameters — `testnet-0005`

| Parameter | Value |
|---|---|
| `network_id` | `testnet-0005` |
| ledger genesis hash | `3ff640410d7879821b544d09545dcfb8e96fe4fc717634e8bff4e53cacd1e150` |
| statechain genesis hash | `d01aabc1a29dc64bc6bbc30031a716cd2e0ceb867e5479953cd5ad22c8f296d6` |
| genesis bundle | [`genesis/testnet-0005/`](genesis/testnet-0005) |
| bootstrap (London) | `/ip4/45.77.226.208/tcp/9000/p2p/12D3KooWJg4PQYGSfNCupBWZdEWbKj7pgdp5MmmUXbPdBcp6YDtT` |
| bootstrap (Frankfurt) | `/ip4/192.248.176.245/tcp/9000/p2p/12D3KooWEbQ5zDvSz6kKE5ppzwBXKRFsnZbHNjRx94QZFaPeGA4e` |
| bootstrap (New York) | `/ip4/144.202.4.117/tcp/9000/p2p/12D3KooWEqv1BRZkSntgcgbrJh7bobFRSkBdRupubvNZLEx8hZLA` |

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
