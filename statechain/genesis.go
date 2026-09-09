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

var genesisOverride atomic.Pointer[[]byte]

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

func ClearGenesisOverride() {
	genesisOverride.Store(nil)
}

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

func EmbeddedGenesisJSON() []byte {
	out := make([]byte, len(embeddedGenesisJSON))
	copy(out, embeddedGenesisJSON)
	return out
}

func LoadGenesis() (*Block, error) {
	return ParseGenesis(GenesisJSON())
}

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

	expected, err := HashBlock(b)
	if err != nil {
		return fmt.Errorf("genesis: %w", err)
	}
	if b.Hash != expected {
		return fmt.Errorf("genesis: hash mismatch: got %s, want %s", b.Hash, expected)
	}

	kv := NewKVStore()
	kv.ApplyOps(b.Ops)
	keyset, err := kv.DAOKeyset()
	if err != nil {
		return fmt.Errorf("genesis: %w", err)
	}

	if err := validateGenesisOracleScope(b, kv); err != nil {
		return fmt.Errorf("genesis: %w", err)
	}

	if len(b.Signatures) > 0 {
		if err := verifyMultisig(b, keyset); err != nil {
			return fmt.Errorf("genesis: %w", err)
		}
	}

	return nil
}

func validateGenesisOracleScope(b *Block, kv *KVStore) error {

	const epochPrefix = "epoch."

	governed := ""

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
