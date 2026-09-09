# Run a node

How to obtain, verify and run an XE node.

> **STATUS: work in progress.** The network values on this page are real and
> verified against the live `testnet-0003` — a node built from this tree and
> started with them joins the network and syncs. What is *not* settled is
> everything around them: no release has been tagged yet, so the "From a
> release" section below describes a flow that has no published artifacts to
> point at, and the testnet is wiped whenever the protocol changes, which
> retires the genesis bundle and network id named here.

---

## 1. Network parameters

A node's identity is its **genesis**, not its binary. Two values identify a
network and both are published:

| Parameter | Value |
|---|---|
| `network_id` | `testnet-0003` |
| statechain genesis hash | `5ea4cf0ee4c919c54af9476a93fe748fe87babf1432a8a53393d2f73cc6873e9` |
| ledger genesis hash | `946597b85290426dfab812778387b93b2b3a41291ebceaac02ca0bbb0e3791ab` |
| genesis bundle | [`genesis/testnet-0003/`](../genesis/testnet-0003) |
| bootstrap multiaddrs | see the table below |

| Node | API | p2p multiaddr |
|---|---|---|
| London | `https://ldn.core.test.network` | `/ip4/45.77.226.208/tcp/9000/p2p/12D3KooWJg4PQYGSfNCupBWZdEWbKj7pgdp5MmmUXbPdBcp6YDtT` |
| Frankfurt | `https://ffm.core.test.network` | `/ip4/192.248.176.245/tcp/9000/p2p/12D3KooWEbQ5zDvSz6kKE5ppzwBXKRFsnZbHNjRx94QZFaPeGA4e` |
| New York | `https://nyc.core.test.network` | `/ip4/144.202.4.117/tcp/9000/p2p/12D3KooWEqv1BRZkSntgcgbrJh7bobFRSkBdRupubvNZLEx8hZLA` |

Each row pairs a hostname with the address it actually resolves to. The previous
table had Frankfurt and New York the wrong way round against DNS: `ffm` resolves
to `192.248.176.245` and `nyc` to `144.202.4.117`. The IP-to-peer-id pairs were
right, so a copy-pasted `--dial` still worked — but building a dial string by
pairing a hostname with the peer id on its row produced two wrong peer ids, and
a wrong peer id is rejected outright rather than merely misrouted.

Peer ids are derived from each node's key and change if that key is regenerated,
so treat this table as a starting point and confirm against the node itself:

```sh
curl -s https://ldn.core.test.network/node | jq -r .id
```

Bootstrap multiaddrs look like:

```
/ip4/203.0.113.10/tcp/9000/p2p/12D3KooW...
```

**There is no ambient peer discovery today.** The DHT resolves peer IDs that are
already known and mDNS only reaches the local broadcast domain, so the
bootstrap list you configure *is* your node's view of the network. Use more than
one.

## 2. Get a binary

### From a release

> **No release has been tagged yet**, so there is nothing to download and this
> section describes the intended flow rather than one you can run today. Build
> [from source](#from-source) instead.

```sh
VERSION=v0.0.0         # the tag, once releases exist
OS=linux ARCH=amd64
gh release download "$VERSION" -R xeprotocol/xe -p 'xe_*' -p 'SHA256SUMS*'
```

Verify it, in three commands, before running anything:

```sh
# 1. integrity
sha256sum -c SHA256SUMS --ignore-missing

# 2. origin — Sigstore keyless: no key to trust, the identity is the workflow
cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature SHA256SUMS.sig \
  --certificate-identity-regexp '^https://github.com/xeprotocol/xe/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS

# 3. build provenance
gh attestation verify "xe_${VERSION}_${OS}_${ARCH}" --repo xeprotocol/xe
```

### From source

Prerequisites: **Go 1.25+**, **Git** and **make**. `make` drives the build and is
not installed on a clean Ubuntu image, so install it first or the very first
build command fails:

```sh
sudo apt-get install -y make    # Debian/Ubuntu
```

```sh
git clone https://github.com/xeprotocol/xe && cd xe
make build          # produces ./xe
```

Builds are reproducible: pinned toolchain (`.go-version`), `-trimpath`,
`-buildvcs=false`, `CGO_ENABLED=0`. To confirm a published checksum yourself:

```sh
git checkout "$VERSION"
make dist VERSION="$VERSION"
sha256sum -c SHA256SUMS --ignore-missing   # against the release's file
```

`make verify-repro` builds twice locally with a cleared build cache and asserts
the two binaries are byte-identical.

## 3. Confirm which chain the binary will start from

```sh
./xe verify-genesis --genesis-dir ./genesis/testnet-0003
```

```
network_id                testnet-0003
statechain genesis hash   5ea4cf0ee4c919c54af9476a93fe748fe87babf1432a8a53393d2f73cc6873e9
ledger genesis hash       946597b85290426dfab812778387b93b2b3a41291ebceaac02ca0bbb0e3791ab
ledger genesis treasury   0b102ffe934b5177e32a4439d8434ad7b11fc541cb73dd57a07591a23f83078b
genesis representative    set
source                    runtime (--genesis-dir/--genesis)
```

Run it bare — `./xe verify-genesis`, no flags — and it prints the genesis
compiled into the binary instead. That one is a **placeholder**
(`network_id = "testnet"`) which no live network uses: a clean checkout embeds
it deliberately, and it is why `--genesis-dir` exists.

Machine-checkable form, for scripts and CI:

```sh
./xe verify-genesis --genesis-dir ./genesis/testnet-0003 \
  --expect-network-id testnet-0003 \
  --expect-statechain-hash 5ea4cf0ee4c919c54af9476a93fe748fe87babf1432a8a53393d2f73cc6873e9
echo $?   # non-zero on any mismatch
```

## 4. Run

```sh
mkdir -p /var/lib/xe/data /etc/xe/genesis
cp genesis/testnet-0003/*.json /etc/xe/genesis/

./xe node \
  --data /var/lib/xe/data \
  --genesis-dir /etc/xe/genesis \
  --dial /ip4/45.77.226.208/tcp/9000/p2p/12D3KooWJg4PQYGSfNCupBWZdEWbKj7pgdp5MmmUXbPdBcp6YDtT,/ip4/144.202.4.117/tcp/9000/p2p/12D3KooWEqv1BRZkSntgcgbrJh7bobFRSkBdRupubvNZLEx8hZLA \
  --port 9000 \
  --api --api-bind 127.0.0.1 --api-port 8080
```

Genesis flags:

| Flag | Meaning |
|---|---|
| `--genesis-dir <dir>` | Directory holding `ledger-genesis.json` and `statechain-genesis.json`. The usual choice. |
| `--genesis <file>` | The ledger genesis alone. Must be paired with `--statechain-genesis`. |
| `--statechain-genesis <file>` | The statechain genesis alone. Must be paired with `--genesis`. |

Also worth knowing:

| Flag | Meaning |
|---|---|
| `--disable-mdns` | Turns off mDNS LAN discovery. Peers found that way are whatever else happens to be on your broadcast domain — harmless at home, wrong on a shared or hosted network. |

Omitting all three runs the genesis compiled into the binary.

Check it came up on the right network:

```sh
curl -s localhost:8080/node | jq '{network_id, peer_count, block_count, version}'
```

`peer_count` should be non-zero within a minute or two. `block_count` climbing
means sync is working.

## 5. Packaging

- **systemd** — [`deploy/xe-node.service`](../deploy/xe-node.service) plus
  [`deploy/xe-node.env.example`](../deploy/xe-node.env.example).
- **Docker** — [`deploy/Dockerfile`](../deploy/Dockerfile).

Both are documented in [`deploy/README.md`](../deploy/README.md).

## 6. Networking requirements

| | |
|---|---|
| Inbound | TCP `9000` (or your `--port`) must be reachable for this node to serve sync and be dialled. |
| Outbound | TCP to every bootstrap multiaddr. |
| IPv6 | Not supported — the node listens on `/ip4/0.0.0.0/tcp/<port>` only. |
| NAT | Not traversed automatically. A node behind NAT follows the chain over its outbound connections but is undiscoverable and cannot serve sync. Forward the port. |

## 7. Troubleshooting

### `CANNOT JOIN NETWORK` in the logs

```
=====================================================================
CANNOT JOIN NETWORK — no peers, 3 handshake(s) rejected, 0 aborted
=====================================================================
  this node is on   network_id="testnet" genesis=65c52970...
  peer 12*AbCdEf reported  network_id="testnet-f1215c" genesis=8ea8e950...
  rejection reason   network_id mismatch: peer is on ...
```

The node is on a different network from its bootstraps. Almost always this
means the genesis was not supplied: compare `xe verify-genesis` against the
table in §1 and start again with `--genesis-dir`.

If the peer line instead says *"every peer closed the handshake before
identifying itself"*, the remote rejected **us** and hung up — same diagnosis,
seen from the other end. Peers ban a mismatching node for 10 minutes, so
correct the genesis and expect a delay before reconnection.

### `genesis mismatch: this data dir belongs to a different network`

The data directory was bootstrapped under a different genesis. Point the node
at the matching genesis, or delete the data dir to start fresh on this network.
The node refuses to start rather than replay one network's ledger under
another's identity.

### No peers and no rejections

Nothing answered at all. Check the bootstrap multiaddrs, then outbound
firewalling. Failed dials are logged individually by the bootstrap watchdog.

---

## Re-bootstrap checklist

The testnet is wiped whenever the protocol changes, and every value on this
page changes with it. After a wipe:

1. Generate the genesis pair with the genesis generators. **The ledger genesis
   must set a `representative`** — without one, total delegated vote weight
   starts at zero, nothing ever finalizes, and every health check still reports
   green.
2. Record `network_id` and both genesis hashes
   (`xe verify-genesis --genesis-dir`).
3. Publish the two genesis files as a `genesis/<network-id>/` directory in the
   public source release, and update the table in section 1 with their hashes.
4. Start the bootstrap nodes; collect their multiaddrs from
   `curl -s <host>/node | jq -r .id` plus their public address and port.
5. Re-key and re-fund the faucet against the new network. A wipe re-generates
   the network, so the faucet's account no longer exists on it: generate a new
   wallet key on the faucet host (`xe-faucet -genkey`), send it a float from a
   funded account, and set `XE_FAUCET_REPRESENTATIVE` to that account's
   representative so the float's vote weight stays where it was. This step has
   been missed before, which leaves the testnet with no way to obtain XE at
   all — and the faucet will say so on `/health` (`status: degraded`) rather
   than reporting itself healthy.
6. Tag a release so published binaries embed nothing surprising, and fill in
   `VERSION` in section 2.
7. Mirror the new values onto test.network.
