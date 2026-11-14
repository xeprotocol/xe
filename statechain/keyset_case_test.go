package statechain

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

type memStore struct {
	mu     sync.Mutex
	blocks []*Block
}

func newMemStore() *memStore {
	return &memStore{blocks: make([]*Block, 0)}
}

func (m *memStore) PutStateBlock(block *Block) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blocks = append(m.blocks, block)
	return nil
}

func (m *memStore) GetStateBlock(index uint64) (*Block, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, b := range m.blocks {
		if b.Index == index {
			return b, nil
		}
	}
	return nil, nil
}

func (m *memStore) GetStateTip() (*Block, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.blocks) == 0 {
		return nil, nil
	}
	return m.blocks[len(m.blocks)-1], nil
}

func (m *memStore) GetStateBlockRange(start, count uint64) ([]*Block, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Block
	for _, b := range m.blocks {
		if b.Index >= start && uint64(len(out)) < count {
			out = append(out, b)
		}
	}
	return out, nil
}

func (m *memStore) StateBlockCount() (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return uint64(len(m.blocks)), nil
}

func testKey(seedByte byte) (ed25519.PrivateKey, string) {
	var seed [32]byte
	for i := range seed {
		seed[i] = seedByte
	}
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	return priv, hex.EncodeToString(pub)
}

func toMixedCase(s string) string {
	b := []byte(s)
	for i := range b {
		if i%2 == 0 && b[i] >= 'a' && b[i] <= 'f' {
			b[i] = b[i] - 'a' + 'A'
		}
	}
	return string(b)
}

func TestValidateOp_KeysetCaseNormalization(t *testing.T) {
	_, k1 := testKey(1)
	_, k2 := testKey(2)
	k1Upper := strings.ToUpper(k1)
	k1Mixed := toMixedCase(k1)

	tests := []struct {
		name         string
		key          string
		payload      any
		wantErr      bool
		errSubstring string
	}{
		// sys.dao_keyset
		{
			name:    "dao_keyset distinct keys valid",
			key:     "sys.dao_keyset",
			payload: DAOKeyset{Keys: []string{k1, k2}, Threshold: 2},
			wantErr: false,
		},
		{
			name:         "dao_keyset exact duplicate rejected",
			key:          "sys.dao_keyset",
			payload:      DAOKeyset{Keys: []string{k1, k1}, Threshold: 2},
			wantErr:      true,
			errSubstring: "duplicate",
		},
		{
			name:         "dao_keyset upper duplicate rejected",
			key:          "sys.dao_keyset",
			payload:      DAOKeyset{Keys: []string{k1, k1Upper}, Threshold: 2},
			wantErr:      true,
			errSubstring: "duplicate",
		},
		{
			name:         "dao_keyset mixed duplicate rejected",
			key:          "sys.dao_keyset",
			payload:      DAOKeyset{Keys: []string{k1, k1Mixed}, Threshold: 2},
			wantErr:      true,
			errSubstring: "duplicate",
		},
		// sys.oracle
		{
			name: "oracle distinct keys valid",
			key:  "sys.oracle",
			payload: OracleConfig{
				Keys:          []string{k1, k2},
				Threshold:     2,
				AllowedPrefix: "epoch.",
			},
			wantErr: false,
		},
		{
			name: "oracle exact duplicate rejected",
			key:  "sys.oracle",
			payload: OracleConfig{
				Keys:          []string{k1, k1},
				Threshold:     2,
				AllowedPrefix: "epoch.",
			},
			wantErr:      true,
			errSubstring: "duplicate",
		},
		{
			name: "oracle upper duplicate rejected",
			key:  "sys.oracle",
			payload: OracleConfig{
				Keys:          []string{k1, k1Upper},
				Threshold:     2,
				AllowedPrefix: "epoch.",
			},
			wantErr:      true,
			errSubstring: "duplicate",
		},
		{
			name: "oracle mixed duplicate rejected",
			key:  "sys.oracle",
			payload: OracleConfig{
				Keys:          []string{k1, k1Mixed},
				Threshold:     2,
				AllowedPrefix: "epoch.",
			},
			wantErr:      true,
			errSubstring: "duplicate",
		},
		// sys.minter
		{
			name: "minter distinct keys valid",
			key:  "sys.minter",
			payload: struct {
				Keys []string `json:"keys"`
			}{Keys: []string{k1, k2}},
			wantErr: false,
		},
		{
			name: "minter exact duplicate rejected",
			key:  "sys.minter",
			payload: struct {
				Keys []string `json:"keys"`
			}{Keys: []string{k1, k1}},
			wantErr:      true,
			errSubstring: "duplicate",
		},
		{
			name: "minter upper duplicate rejected",
			key:  "sys.minter",
			payload: struct {
				Keys []string `json:"keys"`
			}{Keys: []string{k1, k1Upper}},
			wantErr:      true,
			errSubstring: "duplicate",
		},
		{
			name: "minter mixed duplicate rejected",
			key:  "sys.minter",
			payload: struct {
				Keys []string `json:"keys"`
			}{Keys: []string{k1, k1Mixed}},
			wantErr:      true,
			errSubstring: "duplicate",
		},
		// sys.timekeepers
		{
			name: "timekeepers distinct keys valid",
			key:  "sys.timekeepers",
			payload: struct {
				Keys      []string `json:"keys"`
				Threshold int      `json:"threshold"`
			}{Keys: []string{k1, k2}, Threshold: 2},
			wantErr: false,
		},
		{
			name: "timekeepers exact duplicate rejected",
			key:  "sys.timekeepers",
			payload: struct {
				Keys      []string `json:"keys"`
				Threshold int      `json:"threshold"`
			}{Keys: []string{k1, k1}, Threshold: 2},
			wantErr:      true,
			errSubstring: "duplicate",
		},
		{
			name: "timekeepers upper duplicate rejected",
			key:  "sys.timekeepers",
			payload: struct {
				Keys      []string `json:"keys"`
				Threshold int      `json:"threshold"`
			}{Keys: []string{k1, k1Upper}, Threshold: 2},
			wantErr:      true,
			errSubstring: "duplicate",
		},
		{
			name: "timekeepers mixed duplicate rejected",
			key:  "sys.timekeepers",
			payload: struct {
				Keys      []string `json:"keys"`
				Threshold int      `json:"threshold"`
			}{Keys: []string{k1, k1Mixed}, Threshold: 2},
			wantErr:      true,
			errSubstring: "duplicate",
		},
		{
			name: "timekeepers invalid hex rejected",
			key:  "sys.timekeepers",
			payload: struct {
				Keys      []string `json:"keys"`
				Threshold int      `json:"threshold"`
			}{Keys: []string{strings.Repeat("g", 64), k2}, Threshold: 2},
			wantErr:      true,
			errSubstring: "invalid hex",
		},
		// sys.representatives
		{
			name: "representatives allowlist distinct valid",
			key:  "sys.representatives",
			payload: RepresentativeConfig{
				Mode:      RepModeAllowlist,
				Addresses: []string{k1, k2},
			},
			wantErr: false,
		},
		{
			name: "representatives allowlist exact duplicate rejected",
			key:  "sys.representatives",
			payload: RepresentativeConfig{
				Mode:      RepModeAllowlist,
				Addresses: []string{k1, k1},
			},
			wantErr:      true,
			errSubstring: "duplicate",
		},
		{
			name: "representatives allowlist upper duplicate rejected",
			key:  "sys.representatives",
			payload: RepresentativeConfig{
				Mode:      RepModeAllowlist,
				Addresses: []string{k1, k1Upper},
			},
			wantErr:      true,
			errSubstring: "duplicate",
		},
		{
			name: "representatives allowlist mixed duplicate rejected",
			key:  "sys.representatives",
			payload: RepresentativeConfig{
				Mode:      RepModeAllowlist,
				Addresses: []string{k1, k1Mixed},
			},
			wantErr:      true,
			errSubstring: "duplicate",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.payload)
			if err != nil {
				t.Fatalf("marshal error: %v", err)
			}
			op := Op{
				Action: ActionSet,
				Key:    tc.key,
				Value:  raw,
			}
			err = ValidateOp(op)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errSubstring)
				}
				if !strings.Contains(err.Error(), tc.errSubstring) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.errSubstring)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestAddBlock_RejectCaseVariantInDAOBlock(t *testing.T) {
	priv1, k1 := testKey(1)
	priv2, k2 := testKey(2)
	_, k3 := testKey(3)
	k3Upper := strings.ToUpper(k3)

	genesisOps := []Op{
		{
			Action: ActionSet,
			Key:    "sys.dao_keyset",
			Value:  mustMarshal(DAOKeyset{Keys: []string{k1, k2}, Threshold: 2}),
		},
		{
			Action: ActionSet,
			Key:    "sys.phase",
			Value:  mustMarshal(uint8(1)),
		},
	}

	genBlock := &Block{
		Index:      0,
		PrevHash:   "0000000000000000000000000000000000000000000000000000000000000000",
		Ops:        genesisOps,
		Signatures: []BlockSignature{},
		Timestamp:  1000,
	}
	var err error
	genBlock.Hash, err = HashBlock(genBlock)
	if err != nil {
		t.Fatalf("genesis HashBlock: %v", err)
	}

	chain, err := NewChain(newMemStore(), genBlock)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}

	t.Run("reject dao_keyset case variant update", func(t *testing.T) {
		b := &Block{
			Index:    1,
			PrevHash: genBlock.Hash,
			Ops: []Op{
				{
					Action: ActionSet,
					Key:    "sys.dao_keyset",
					Value:  mustMarshal(DAOKeyset{Keys: []string{k3, k3Upper}, Threshold: 2}),
				},
			},
			Timestamp: 2000,
		}
		b.Hash, err = HashBlock(b)
		if err != nil {
			t.Fatalf("HashBlock: %v", err)
		}
		sig1, _ := SignBlock(b, priv1)
		sig2, _ := SignBlock(b, priv2)
		b.Signatures = []BlockSignature{sig1, sig2}

		err = chain.AddBlock(b)
		if err == nil {
			t.Fatal("expected AddBlock to reject dao_keyset case variant update")
		}
		if !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("expected duplicate error, got: %v", err)
		}
	})

	t.Run("reject oracle case variant update", func(t *testing.T) {
		b := &Block{
			Index:    1,
			PrevHash: genBlock.Hash,
			Ops: []Op{
				{
					Action: ActionSet,
					Key:    "sys.oracle",
					Value: mustMarshal(OracleConfig{
						Keys:          []string{k3, k3Upper},
						Threshold:     2,
						AllowedPrefix: "epoch.",
					}),
				},
			},
			Timestamp: 2000,
		}
		b.Hash, err = HashBlock(b)
		if err != nil {
			t.Fatalf("HashBlock: %v", err)
		}
		sig1, _ := SignBlock(b, priv1)
		sig2, _ := SignBlock(b, priv2)
		b.Signatures = []BlockSignature{sig1, sig2}

		err = chain.AddBlock(b)
		if err == nil {
			t.Fatal("expected AddBlock to reject oracle case variant update")
		}
		if !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("expected duplicate error, got: %v", err)
		}
	})
}

func TestAddBlock_MultisigDefenseInDepth(t *testing.T) {
	priv1, k1 := testKey(1)
	priv2, k2 := testKey(2)
	k1Upper := strings.ToUpper(k1)

	t.Run("dao multisig bypass rejected even with mixed genesis keyset", func(t *testing.T) {
		genBlock := &Block{
			Index:    0,
			PrevHash: "0000000000000000000000000000000000000000000000000000000000000000",
			Ops: []Op{
				{
					Action: ActionSet,
					Key:    "sys.dao_keyset",
					Value:  mustMarshal(DAOKeyset{Keys: []string{k1, k1Upper}, Threshold: 2}),
				},
				{
					Action: ActionSet,
					Key:    "sys.phase",
					Value:  mustMarshal(uint8(1)),
				},
			},
			Signatures: []BlockSignature{},
			Timestamp:  1000,
		}
		var err error
		genBlock.Hash, err = HashBlock(genBlock)
		if err != nil {
			t.Fatalf("HashBlock: %v", err)
		}

		chain, err := NewChain(newMemStore(), genBlock)
		if err != nil {
			t.Fatalf("NewChain: %v", err)
		}

		b := &Block{
			Index:    1,
			PrevHash: genBlock.Hash,
			Ops: []Op{
				{
					Action: ActionSet,
					Key:    "app.config",
					Value:  json.RawMessage(`{"enabled":true}`),
				},
			},
			Timestamp: 2000,
		}
		b.Hash, err = HashBlock(b)
		if err != nil {
			t.Fatalf("HashBlock: %v", err)
		}

		sigLower, err := SignBlock(b, priv1)
		if err != nil {
			t.Fatalf("SignBlock lower: %v", err)
		}
		sigUpper := BlockSignature{
			PublicKey: k1Upper,
			Sig:       sigLower.Sig,
		}

		b.Signatures = []BlockSignature{sigLower, sigUpper}
		err = chain.AddBlock(b)
		if err == nil {
			t.Fatal("expected AddBlock to reject block signed twice by same key")
		}
		if !strings.Contains(err.Error(), "duplicate signer") {
			t.Fatalf("expected duplicate signer error, got: %v", err)
		}
	})

	t.Run("honest dao multisig accepts mixed-case signatures", func(t *testing.T) {
		genBlock := &Block{
			Index:    0,
			PrevHash: "0000000000000000000000000000000000000000000000000000000000000000",
			Ops: []Op{
				{
					Action: ActionSet,
					Key:    "sys.dao_keyset",
					Value:  mustMarshal(DAOKeyset{Keys: []string{k1, k2}, Threshold: 2}),
				},
				{
					Action: ActionSet,
					Key:    "sys.phase",
					Value:  mustMarshal(uint8(1)),
				},
			},
			Signatures: []BlockSignature{},
			Timestamp:  1000,
		}
		var err error
		genBlock.Hash, err = HashBlock(genBlock)
		if err != nil {
			t.Fatalf("HashBlock: %v", err)
		}

		chain, err := NewChain(newMemStore(), genBlock)
		if err != nil {
			t.Fatalf("NewChain: %v", err)
		}

		b := &Block{
			Index:    1,
			PrevHash: genBlock.Hash,
			Ops: []Op{
				{
					Action: ActionSet,
					Key:    "app.config",
					Value:  json.RawMessage(`{"enabled":true}`),
				},
			},
			Timestamp: 2000,
		}
		b.Hash, err = HashBlock(b)
		if err != nil {
			t.Fatalf("HashBlock: %v", err)
		}

		sig1, _ := SignBlock(b, priv1)
		sig1.PublicKey = strings.ToUpper(sig1.PublicKey)
		sig2, _ := SignBlock(b, priv2)

		b.Signatures = []BlockSignature{sig1, sig2}
		err = chain.AddBlock(b)
		if err != nil {
			t.Fatalf("AddBlock should succeed with honest mixed-case signatures: %v", err)
		}
	})

	t.Run("oracle multisig bypass rejected even with mixed oracle keyset", func(t *testing.T) {
		genBlock := &Block{
			Index:    0,
			PrevHash: "0000000000000000000000000000000000000000000000000000000000000000",
			Ops: []Op{
				{
					Action: ActionSet,
					Key:    "sys.dao_keyset",
					Value:  mustMarshal(DAOKeyset{Keys: []string{k1, k2}, Threshold: 2}),
				},
				{
					Action: ActionSet,
					Key:    "sys.oracle",
					Value: mustMarshal(OracleConfig{
						Keys:          []string{k1, k1Upper},
						Threshold:     2,
						AllowedPrefix: "epoch.",
					}),
				},
				{
					Action: ActionSet,
					Key:    "sys.phase",
					Value:  mustMarshal(uint8(1)),
				},
			},
			Signatures: []BlockSignature{},
			Timestamp:  1000,
		}
		var err error
		genBlock.Hash, err = HashBlock(genBlock)
		if err != nil {
			t.Fatalf("HashBlock: %v", err)
		}

		chain, err := NewChain(newMemStore(), genBlock)
		if err != nil {
			t.Fatalf("NewChain: %v", err)
		}

		ev := EpochValue{
			Epoch:       1,
			StartNS:     1000,
			EndNS:       2000,
			RVolume:     200,
			RPriceFloor: 100,
			REffective:  200,
			RSource:     "volume",
			Phase:       1,
		}

		b := &Block{
			Index:    1,
			PrevHash: genBlock.Hash,
			Ops: []Op{
				{
					Action: ActionSet,
					Key:    "epoch.1",
					Value:  mustMarshal(ev),
				},
			},
			Timestamp: 2000,
		}
		b.Hash, err = HashBlock(b)
		if err != nil {
			t.Fatalf("HashBlock: %v", err)
		}

		sigLower, err := SignBlock(b, priv1)
		if err != nil {
			t.Fatalf("SignBlock: %v", err)
		}
		sigUpper := BlockSignature{
			PublicKey: k1Upper,
			Sig:       sigLower.Sig,
		}

		b.Signatures = []BlockSignature{sigLower, sigUpper}
		err = chain.AddBlock(b)
		if err == nil {
			t.Fatal("expected AddBlock to reject oracle block signed twice by same key")
		}
		if !strings.Contains(err.Error(), "duplicate signer") {
			t.Fatalf("expected duplicate signer error, got: %v", err)
		}
	})

	t.Run("honest oracle multisig accepts mixed-case signatures", func(t *testing.T) {
		genBlock := &Block{
			Index:    0,
			PrevHash: "0000000000000000000000000000000000000000000000000000000000000000",
			Ops: []Op{
				{
					Action: ActionSet,
					Key:    "sys.dao_keyset",
					Value:  mustMarshal(DAOKeyset{Keys: []string{k1, k2}, Threshold: 2}),
				},
				{
					Action: ActionSet,
					Key:    "sys.oracle",
					Value: mustMarshal(OracleConfig{
						Keys:          []string{k1, k2},
						Threshold:     2,
						AllowedPrefix: "epoch.",
					}),
				},
				{
					Action: ActionSet,
					Key:    "sys.phase",
					Value:  mustMarshal(uint8(1)),
				},
			},
			Signatures: []BlockSignature{},
			Timestamp:  1000,
		}
		var err error
		genBlock.Hash, err = HashBlock(genBlock)
		if err != nil {
			t.Fatalf("HashBlock: %v", err)
		}

		chain, err := NewChain(newMemStore(), genBlock)
		if err != nil {
			t.Fatalf("NewChain: %v", err)
		}

		ev := EpochValue{
			Epoch:       1,
			StartNS:     1000,
			EndNS:       2000,
			RVolume:     200,
			RPriceFloor: 100,
			REffective:  200,
			RSource:     "volume",
			Phase:       1,
		}

		b := &Block{
			Index:    1,
			PrevHash: genBlock.Hash,
			Ops: []Op{
				{
					Action: ActionSet,
					Key:    "epoch.1",
					Value:  mustMarshal(ev),
				},
			},
			Timestamp: 2000,
		}
		b.Hash, err = HashBlock(b)
		if err != nil {
			t.Fatalf("HashBlock: %v", err)
		}

		sig1, _ := SignBlock(b, priv1)
		sig1.PublicKey = strings.ToUpper(sig1.PublicKey)
		sig2, _ := SignBlock(b, priv2)

		b.Signatures = []BlockSignature{sig1, sig2}
		err = chain.AddBlock(b)
		if err != nil {
			t.Fatalf("AddBlock should succeed with honest oracle mixed-case signatures: %v", err)
		}
	})
}

func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
