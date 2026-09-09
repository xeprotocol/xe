# testnet-0001

The published genesis bundle for the `testnet-0001` network. A node's identity
is its genesis, not its binary — point a node at this directory and it joins
this network:

```sh
xe node --genesis-dir ./genesis/testnet-0001 --data ./data \
  --dial /ip4/45.77.226.208/tcp/9000/p2p/12D3KooWJg4PQYGSfNCupBWZdEWbKj7pgdp5MmmUXbPdBcp6YDtT
```

| | |
|---|---|
| `network_id` | `testnet-0001` |
| ledger genesis hash | `e813eefe3b61cfa6bb4c78c747417f4c7f38cde127fb04d62ded967af7d1ed68` |
| statechain genesis hash | `419460291afa7405e462d44b696f8284da1655634ead62196e50e09234733a29` |
| treasury | `a26d59a9a174474a3169178342de6fc017d40ff0ec632b2e87368d69dffb17dd` |
| genesis supply | 42,000,000 XE |

Check what you are about to join before you join it:

```sh
xe verify-genesis --genesis-dir ./genesis/testnet-0001 \
  --expect-network-id testnet-0001 \
  --expect-statechain-hash 419460291afa7405e462d44b696f8284da1655634ead62196e50e09234733a29
```

Both files are public artifacts: signed blocks containing public keys, account
addresses and the governance keysets they establish. No private material.

**These files are retired by a testnet wipe.** When the protocol changes the
network is re-bootstrapped under a new id and a new bundle is published beside
this one; the old network stops existing. See
[`docs/run-a-node.md`](../../docs/run-a-node.md).
