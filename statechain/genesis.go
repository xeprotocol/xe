package statechain

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
)

//go:embed genesis.json
var embeddedGenesisJSON []byte

// genesisOverride holds a runtime-supplied statechain genesis (#733, #839).
// Nil means "use the embedded genesis.json", so a plain `go build` still
// produces a binary bound to the committed network. Atomic for the same
// reason as core.genesisOverride: the in-process test harness builds several
// nodes in one process.
var genesisOverride atomic.Pointer[[]byte]

// SetGenesisJSON overrides the embedded statechain genesis with
// runtime-supplied JSON, after validating it. MUST be called before any Chain
// or Node is created — the statechain genesis carries sys.network_id, which is
// bound into every block hash and can never change once a data dir exists.
func SetGenesisJSON(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("genesis: empty genesis document")
	}
	if _, err := ParseGenesis(data); err != nil {
		return err
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	genesisOverride.Store(&cp)
	return nil
}

// ClearGenesisOverride restores the embedded genesis. Test helper.
func ClearGenesisOverride() {
	genesisOverride.Store(nil)
}

// GenesisJSON returns the raw statechain genesis document this process is
// running with — the runtime override when installed, otherwise the embed.
func GenesisJSON() []byte {
	if p := genesisOverride.Load(); p != nil {
		out := make([]byte, len(*p))
		copy(out, *p)
		return out
	}
	out := make([]byte, len(embeddedGenesisJSON))
	copy(out, embeddedGenesisJSON)
	return out
}

// EmbeddedGenesisJSON returns the compiled-in statechain genesis, ignoring any
// runtime override.
func EmbeddedGenesisJSON() []byte {
	out := make([]byte, len(embeddedGenesisJSON))
	copy(out, embeddedGenesisJSON)
	return out
}

// LoadGenesis parses and validates this process's statechain genesis — the
// runtime override when set (--statechain-genesis), otherwise the embedded
// genesis.json.
func LoadGenesis() (*Block, error) {
	return ParseGenesis(GenesisJSON())
}

// ParseGenesis parses and validates a genesis block from JSON bytes.
// Used by LoadGenesis, SetGenesisJSON and tests (custom genesis).
func ParseGenesis(data []byte) (*Block, error) {
	var b Block
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse genesis: %w", err)
	}
	if err := ValidateGenesis(&b); err != nil {
		return nil, err
	}
	return &b, nil
}

// ValidateGenesis checks that a genesis block is well-formed.
func ValidateGenesis(b *Block) error {
	if b.Index != 0 {
		return fmt.Errorf("genesis: index must be 0, got %d", b.Index)
	}
	if b.PrevHash != "0000000000000000000000000000000000000000000000000000000000000000" {
		return fmt.Errorf("genesis: prev_hash must be 64 zero chars")
	}
	if len(b.Ops) == 0 {
		return fmt.Errorf("genesis: must have at least one op")
	}

	// Verify hash matches canonical encoding
	expected, err := HashBlock(b)
	if err != nil {
		return fmt.Errorf("genesis: %w", err)
	}
	if b.Hash != expected {
		return fmt.Errorf("genesis: hash mismatch: got %s, want %s", b.Hash, expected)
	}

	// Verify that sys.dao_keyset is set by the genesis ops
	kv := NewKVStore()
	kv.ApplyOps(b.Ops)
	keyset, err := kv.DAOKeyset()
	if err != nil {
		return fmt.Errorf("genesis: %w", err)
	}

	if err := validateGenesisOracleScope(b, kv); err != nil {
		return fmt.Errorf("genesis: %w", err)
	}

	// Verify signatures if present. The genesis must be signed by the
	// keyset it establishes (self-certifying). Unsigned genesis blocks
	// are only allowed in tests via GenerateTestGenesis.
	if len(b.Signatures) > 0 {
		if err := verifyMultisig(b, keyset); err != nil {
			return fmt.Errorf("genesis: %w", err)
		}
	}

	return nil
}

// validateGenesisOracleScope refuses a genesis that seeds oracle-scoped records
// (epoch.*) which no sys.oracle governs.
//
// Both protections on those records live INSIDE the `oracleConfig != nil &&
// opsMatchPrefix(...)` branch of AddBlock (chain.go): the write-once check that
// stops an epoch being rewritten, and the guard that stops a DAO block writing
// the oracle's prefix. A record outside any oracle's allowed_prefix falls into
// the DAO branch, where neither runs — so a DAO-threshold block can create and
// silently overwrite it, and epoch values feed lease_accept's locked emission
// params (#501). Seed the oracle that governs the record, or seed neither
// (epic #828, invariant K2). The thin Testnet(1) profile seeds neither (#834).
func validateGenesisOracleScope(b *Block, kv *KVStore) error {
	// The prefix the epoch record namespace lives under. Independent of any
	// oracle's configured allowed_prefix — the point of this check is that the
	// two must agree.
	const epochPrefix = "epoch."

	governed := ""
	// A malformed sys.oracle leaves oracle nil, which fails closed below.
	if oracle, err := kv.OracleConfig(); err == nil && oracle != nil {
		governed = oracle.AllowedPrefix
	}
	for _, op := range b.Ops {
		if op.Action != ActionSet || !strings.HasPrefix(op.Key, epochPrefix) {
			continue
		}
		if governed != "" && strings.HasPrefix(op.Key, governed) {
			continue
		}
		return fmt.Errorf("op %q is not governed by any sys.oracle allowed_prefix (%q): the epoch write-once and DAO-prefix guards both sit inside chain.go's oracleConfig branch, so a DAO block could overwrite it — seed a matching sys.oracle alongside, or seed neither", op.Key, governed)
	}
	return nil
}

// GenerateTestGenesis creates a genesis block with the given keyset.
// For use in tests only.
func GenerateTestGenesis(keys []string, threshold int) (*Block, error) {
	keyset := DAOKeyset{
		Keys:      keys,
		Threshold: threshold,
	}
	keysetJSON, err := json.Marshal(keyset)
	if err != nil {
		return nil, err
	}

	phaseJSON, err := json.Marshal(uint8(1))
	if err != nil {
		return nil, err
	}

	b := &Block{
		Index:    0,
		PrevHash: "0000000000000000000000000000000000000000000000000000000000000000",
		Ops: []Op{
			{
				Action: ActionSet,
				Key:    "sys.dao_keyset",
				Value:  keysetJSON,
			},
			{
				Action: ActionSet,
				Key:    "sys.phase",
				Value:  phaseJSON,
			},
		},
		Signatures: []BlockSignature{},
		Timestamp:  0,
	}

	hash, err := HashBlock(b)
	if err != nil {
		return nil, err
	}
	b.Hash = hash

	return b, nil
}

// NetworkIDFromGenesis returns the sys.network_id value set by the genesis
// block's ops, or "" when absent. The network id is bound into every block
// hash, so it can never change after genesis — reading it straight from the
// embedded genesis lets a booting node know its identity BEFORE the
// statechain replay rebuilds the KV. Waiting for replay left the node
// answering netcheck with an empty network_id for the whole replay window,
// and every peer that completed a handshake in that window banned it for
// 10 minutes (#652, the second #637 mechanism).
func NetworkIDFromGenesis(b *Block) string {
	if b == nil {
		return ""
	}
	for _, op := range b.Ops {
		if op.Action == "set" && op.Key == "sys.network_id" {
			var id string
			if json.Unmarshal(op.Value, &id) == nil {
				return id
			}
		}
	}
	return ""
}
