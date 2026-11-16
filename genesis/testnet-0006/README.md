# testnet-0006

The published genesis bundle for the `testnet-0006` network. A node's identity
is its genesis, not its binary. Point a node at this directory and it joins
this network:

```sh
xe node --genesis-dir ./genesis/testnet-0006 --data ./data \
  --dial /ip4/45.77.226.208/tcp/9000/p2p/12D3KooWJg4PQYGSfNCupBWZdEWbKj7pgdp5MmmUXbPdBcp6YDtT
```

| | |
|---|---|
| `network_id` | `testnet-0006` |
| ledger genesis hash | `65d9070a304303350cfd4f6a17a23efb4831894f61bc983805011e10e1b6fc82` |
| statechain genesis hash | `59b9875cd2f0e51d736c5be424012ab4abaf0ad38d69b5b22e942405132c284a` |
| treasury | `26065e94862df490fedf6b6832bbf586ec86a662b8a9218e07cda55e492b19fe` |
| genesis supply | 42,000,000 XE |

Check what you are about to join before you join it:

```sh
xe verify-genesis --genesis-dir ./genesis/testnet-0006 \
  --expect-network-id testnet-0006 \
  --expect-statechain-hash 59b9875cd2f0e51d736c5be424012ab4abaf0ad38d69b5b22e942405132c284a
```

Both files are public artifacts: signed blocks containing public keys, account
addresses and the governance keysets they establish. No private material.

**These files are retired by a testnet wipe.** When the protocol changes the
network is re-bootstrapped under a new id and a new bundle is published beside
this one; the old network stops existing. See
[`docs/run-a-node.md`](../../docs/run-a-node.md).
