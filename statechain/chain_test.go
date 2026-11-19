package statechain

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

type testMemStore struct {
	mu     sync.Mutex
	blocks map[uint64]*Block
	tip    *Block
}

func newTestMemStore() *testMemStore {
	return &testMemStore{blocks: make(map[uint64]*Block)}
}

func (s *testMemStore) PutStateBlock(b *Block) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blocks[b.Index] = b
	if s.tip == nil || b.Index >= s.tip.Index {
		s.tip = b
	}
	return nil
}

func (s *testMemStore) GetStateBlock(index uint64) (*Block, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.blocks[index]
	if !ok {
		return nil, fmt.Errorf("block %d not found", index)
	}
	return b, nil
}

func (s *testMemStore) GetStateTip() (*Block, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tip, nil
}

func (s *testMemStore) GetStateBlockRange(start, count uint64) ([]*Block, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var res []*Block
	for i := start; i < start+count; i++ {
		b, ok := s.blocks[i]
		if !ok {
			break
		}
		res = append(res, b)
	}
	return res, nil
}

func (s *testMemStore) StateBlockCount() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return uint64(len(s.blocks)), nil
}

func buildTestBlock(t *testing.T, index uint64, prevHash string, ts int64, ops []Op) *Block {
	t.Helper()
	b := &Block{
		Index:      index,
		PrevHash:   prevHash,
		Timestamp:  ts,
		Ops:        ops,
		Signatures: []BlockSignature{},
	}
	h, err := HashBlock(b)
	if err != nil {
		t.Fatalf("HashBlock failed: %v", err)
	}
	b.Hash = h
	return b
}

func signTestBlock(t *testing.T, b *Block, priv ed25519.PrivateKey) BlockSignature {
	t.Helper()
	sig, err := SignBlock(b, priv)
	if err != nil {
		t.Fatalf("SignBlock failed: %v", err)
	}
	return sig
}

func TestVerifyMultisig_CaseSensitivityAndDeduplication(t *testing.T) {
	d1Priv, d1PubLower, d1PubUpper := generateMixedCaseHexKey(t)
	d2Priv, d2PubLower, d2PubUpper := generateMixedCaseHexKey(t)
	_, otherPub, _ := generateMixedCaseHexKey(t)

	keyset := &DAOKeyset{
		Keys:      []string{d1PubLower, d2PubLower},
		Threshold: 2,
	}

	ts := time.Now().Unix()

	t.Run("accept valid 2-of-2 multisig with mixed case public keys", func(t *testing.T) {
		b := buildTestBlock(t, 1, "0000000000000000000000000000000000000000000000000000000000000000", ts, []Op{})
		sig1 := signTestBlock(t, b, d1Priv)
		sig1.PublicKey = d1PubUpper // Uppercase in signature vs lowercase in keyset

		sig2 := signTestBlock(t, b, d2Priv) // Lowercase in signature vs lowercase in keyset

		b.Signatures = []BlockSignature{sig1, sig2}
		if err := verifyMultisig(b, keyset); err != nil {
			t.Fatalf("expected signatures to verify: %v", err)
		}
	})

	t.Run("reject duplicate signer using lowercase and uppercase forms of same key", func(t *testing.T) {
		b := buildTestBlock(t, 1, "0000000000000000000000000000000000000000000000000000000000000000", ts, []Op{})
		sig1 := signTestBlock(t, b, d1Priv)
		sig1.PublicKey = d1PubLower

		sig2 := signTestBlock(t, b, d1Priv)
		sig2.PublicKey = d1PubUpper // Same private key, uppercase public key string

		b.Signatures = []BlockSignature{sig1, sig2}
		err := verifyMultisig(b, keyset)
		if err == nil {
			t.Fatal("expected verifyMultisig to reject duplicate signer with different casing")
		}
		if !strings.Contains(err.Error(), "duplicate signer") {
			t.Fatalf("expected 'duplicate signer' error, got: %v", err)
		}
	})

	t.Run("reject duplicate signer using exact same public key string", func(t *testing.T) {
		b := buildTestBlock(t, 1, "0000000000000000000000000000000000000000000000000000000000000000", ts, []Op{})
		sig1 := signTestBlock(t, b, d1Priv)
		b.Signatures = []BlockSignature{sig1, sig1}

		err := verifyMultisig(b, keyset)
		if err == nil {
			t.Fatal("expected verifyMultisig to reject identical duplicate signer")
		}
		if !strings.Contains(err.Error(), "duplicate signer") {
			t.Fatalf("expected 'duplicate signer' error, got: %v", err)
		}
	})

	t.Run("reject signer not in keyset", func(t *testing.T) {
		b := buildTestBlock(t, 1, "0000000000000000000000000000000000000000000000000000000000000000", ts, []Op{})
		sig1 := signTestBlock(t, b, d1Priv)
		sigOther := BlockSignature{
			PublicKey: otherPub,
			Sig:       hex.EncodeToString(make([]byte, 64)),
		}
		b.Signatures = []BlockSignature{sig1, sigOther}

		err := verifyMultisig(b, keyset)
		if err == nil {
			t.Fatal("expected verifyMultisig to reject non-keyset signer")
		}
		if !strings.Contains(err.Error(), "not in keyset") {
			t.Fatalf("expected 'not in keyset' error, got: %v", err)
		}
	})

	t.Run("reject insufficient signatures", func(t *testing.T) {
		b := buildTestBlock(t, 1, "0000000000000000000000000000000000000000000000000000000000000000", ts, []Op{})
		sig1 := signTestBlock(t, b, d1Priv)
		b.Signatures = []BlockSignature{sig1}

		err := verifyMultisig(b, keyset)
		if err == nil {
			t.Fatal("expected verifyMultisig to reject insufficient signatures")
		}
		if !strings.Contains(err.Error(), "insufficient signatures") {
			t.Fatalf("expected 'insufficient signatures' error, got: %v", err)
		}
	})

	t.Run("keyset with uppercase matches lowercase signature", func(t *testing.T) {
		upperKeyset := &DAOKeyset{
			Keys:      []string{d1PubUpper, d2PubUpper},
			Threshold: 2,
		}
		b := buildTestBlock(t, 1, "0000000000000000000000000000000000000000000000000000000000000000", ts, []Op{})
		sig1 := signTestBlock(t, b, d1Priv) // lowercase
		sig2 := signTestBlock(t, b, d2Priv) // lowercase
		b.Signatures = []BlockSignature{sig1, sig2}

		if err := verifyMultisig(b, upperKeyset); err != nil {
			t.Fatalf("expected uppercase keyset to verify lowercase signatures: %v", err)
		}
	})
}

func TestVerifyOracleMultisig_CaseSensitivityAndDeduplication(t *testing.T) {
	o1Priv, o1PubLower, o1PubUpper := generateMixedCaseHexKey(t)
	o2Priv, _, o2PubUpper := generateMixedCaseHexKey(t)

	oracleConfig := &OracleConfig{
		Keys:          []string{o1PubLower, o2PubUpper},
		Threshold:     2,
		AllowedPrefix: "epoch.",
	}

	ts := time.Now().Unix()

	t.Run("accept valid oracle multisig with case differences", func(t *testing.T) {
		b := buildTestBlock(t, 1, "0000000000000000000000000000000000000000000000000000000000000000", ts, []Op{})
		sig1 := signTestBlock(t, b, o1Priv)
		sig1.PublicKey = o1PubUpper // Uppercase in signature vs lowercase in config

		sig2 := signTestBlock(t, b, o2Priv) // Lowercase in signature vs uppercase in config

		b.Signatures = []BlockSignature{sig1, sig2}
		if err := verifyOracleMultisig(b, oracleConfig); err != nil {
			t.Fatalf("expected oracle signatures to verify: %v", err)
		}
	})

	t.Run("reject duplicate oracle signer using different cases [K, UPPER(K)]", func(t *testing.T) {
		b := buildTestBlock(t, 1, "0000000000000000000000000000000000000000000000000000000000000000", ts, []Op{})
		sig1 := signTestBlock(t, b, o1Priv)
		sig1.PublicKey = o1PubLower

		sig2 := signTestBlock(t, b, o1Priv)
		sig2.PublicKey = o1PubUpper

		b.Signatures = []BlockSignature{sig1, sig2}
		err := verifyOracleMultisig(b, oracleConfig)
		if err == nil {
			t.Fatal("expected verifyOracleMultisig to reject duplicate signer with case difference")
		}
		if !strings.Contains(err.Error(), "duplicate signer") {
			t.Fatalf("expected 'duplicate signer' error, got: %v", err)
		}
	})
}

func TestValidateGenesis_CaseInsensitiveDuplicates(t *testing.T) {
	_, kLower, kUpper := generateMixedCaseHexKey(t)
	_, d2, _ := generateMixedCaseHexKey(t)

	t.Run("reject genesis with [K, UPPER(K)] dao_keyset", func(t *testing.T) {
		raw, _ := json.Marshal(DAOKeyset{
			Keys:      []string{kLower, kUpper},
			Threshold: 2,
		})
		b := &Block{
			Index:    0,
			PrevHash: "0000000000000000000000000000000000000000000000000000000000000000",
			Ops: []Op{
				{Action: ActionSet, Key: "sys.dao_keyset", Value: raw},
			},
			Signatures: []BlockSignature{},
			Timestamp:  0,
		}
		h, _ := HashBlock(b)
		b.Hash = h

		err := ValidateGenesis(b)
		if err == nil {
			t.Fatal("expected ValidateGenesis to reject duplicate keys in dao_keyset")
		}
		if !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("expected 'duplicate' in error, got: %v", err)
		}
	})

	t.Run("accept valid genesis", func(t *testing.T) {
		b, err := GenerateTestGenesis([]string{kLower, d2}, 2)
		if err != nil {
			t.Fatalf("GenerateTestGenesis failed: %v", err)
		}
		if err := ValidateGenesis(b); err != nil {
			t.Fatalf("ValidateGenesis failed on valid genesis: %v", err)
		}
	})
}

// TestH1_PlantAndExploitPrevention explicitly reproduces the exploit from Issue #363
// and verifies that the plant block is rejected, preventing 1 key from satisfying 2-of-2.
func TestH1_PlantAndExploitPrevention(t *testing.T) {
	d1Priv, d1Pub := generateTestHexKey(t)
	d2Priv, d2Pub := generateTestHexKey(t)
	_, d3Pub := generateTestHexKey(t)

	genesis, err := GenerateTestGenesis([]string{d1Pub, d2Pub, d3Pub}, 2)
	if err != nil {
		t.Fatalf("GenerateTestGenesis: %v", err)
	}

	chain, err := NewChain(newTestMemStore(), genesis)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}

	// Attacker generates key K and computes uppercase form
	_, kPub, kUpper := generateMixedCaseHexKey(t)

	ts := time.Now().Unix()

	// Attacker attempts to plant [K, UPPER(K)] threshold 2
	keysetRaw, err := json.Marshal(DAOKeyset{
		Keys:      []string{kPub, kUpper},
		Threshold: 2,
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	plant := buildTestBlock(t, 1, genesis.Hash, ts, []Op{
		{Action: ActionSet, Key: "sys.dao_keyset", Value: keysetRaw},
	})
	plant.Signatures = []BlockSignature{
		signTestBlock(t, plant, d1Priv),
		signTestBlock(t, plant, d2Priv),
	}

	// The plant block MUST be rejected by chain.AddBlock
	err = chain.AddBlock(plant)
	if err == nil {
		t.Fatal("SECURITY VULNERABILITY: Plant block with [K, UPPER(K)] was ACCEPTED! Expected rejection.")
	}

	if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected rejection reason to cite duplicate key, got: %v", err)
	}

	// Verify that DAOKeyset on chain remains unchanged
	currentKS := chain.DAOKeyset()
	if len(currentKS.Keys) != 3 || currentKS.Threshold != 2 {
		t.Fatalf("expected DAO keyset to remain at genesis 3 keys, got %v", currentKS)
	}
}
