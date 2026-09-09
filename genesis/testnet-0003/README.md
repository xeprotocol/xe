# testnet-0003

The published genesis bundle for the `testnet-0003` network. A node's identity
is its genesis, not its binary — point a node at this directory and it joins
this network:

```sh
xe node --genesis-dir ./genesis/testnet-0003 --data ./data \
  --dial /ip4/45.77.226.208/tcp/9000/p2p/12D3KooWJg4PQYGSfNCupBWZdEWbKj7pgdp5MmmUXbPdBcp6YDtT
```

| | |
|---|---|
| `network_id` | `testnet-0003` |
| ledger genesis hash | `946597b85290426dfab812778387b93b2b3a41291ebceaac02ca0bbb0e3791ab` |
| statechain genesis hash | `5ea4cf0ee4c919c54af9476a93fe748fe87babf1432a8a53393d2f73cc6873e9` |
| treasury | `0b102ffe934b5177e32a4439d8434ad7b11fc541cb73dd57a07591a23f83078b` |
| genesis supply | 42,000,000 XE |

Check what you are about to join before you join it:

```sh
xe verify-genesis --genesis-dir ./genesis/testnet-0003 \
  --expect-network-id testnet-0003 \
  --expect-statechain-hash 5ea4cf0ee4c919c54af9476a93fe748fe87babf1432a8a53393d2f73cc6873e9
```

Both files are public artifacts: signed blocks containing public keys, account
addresses and the governance keysets they establish. No private material.

**These files are retired by a testnet wipe.** When the protocol changes the
network is re-bootstrapped under a new id and a new bundle is published beside
this one; the old network stops existing. See
[`docs/run-a-node.md`](../../docs/run-a-node.md).
