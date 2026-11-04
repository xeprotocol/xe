package statechain

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
)

type testSigner struct {
	priv ed25519.PrivateKey
	pub  string
}

func newTestSigner(t *testing.T) testSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519 gen: %v", err)
	}
	return testSigner{
		priv: priv,
		pub:  hex.EncodeToString(pub),
	}
}

func signBlock(t *testing.T, b *Block, signers ...testSigner) {
	t.Helper()
	hash, err := HashBlock(b)
	if err != nil {
		t.Fatalf("hash block: %v", err)
	}
	b.Hash = hash
	hashBytes, err := core.DecodeHash(hash)
	if err != nil {
		t.Fatalf("decode hash: %v", err)
	}
	b.Signatures = nil
	for _, s := range signers {
		sig := ed25519.Sign(s.priv, hashBytes)
		b.Signatures = append(b.Signatures, BlockSignature{
			PublicKey: s.pub,
			Sig:       hex.EncodeToString(sig),
		})
	}
}

type memStore struct {
	blocks map[uint64]*Block
	tip    *Block
}

func newMemStore() *memStore {
	return &memStore{blocks: make(map[uint64]*Block)}
}

func (m *memStore) PutStateBlock(block *Block) error {
	cp := *block
	m.blocks[block.Index] = &cp
	m.tip = &cp
	return nil
}

func (m *memStore) GetStateBlock(index uint64) (*Block, error) {
	b, ok := m.blocks[index]
	if !ok {
		return nil, ErrGap
	}
	return b, nil
}

func (m *memStore) GetStateTip() (*Block, error) {
	return m.tip, nil
}

func (m *memStore) GetStateBlockRange(start, count uint64) ([]*Block, error) {
	var res []*Block
	for i := start; i < start+count; i++ {
		b, ok := m.blocks[i]
		if !ok {
			break
		}
		res = append(res, b)
	}
	return res, nil
}

func (m *memStore) StateBlockCount() (uint64, error) {
	return uint64(len(m.blocks)), nil
}

func TestFutureTimestampSkewRejected(t *testing.T) {
	daoKey1 := newTestSigner(t)
	daoKey2 := newTestSigner(t)
	oracleKey := newTestSigner(t)

	keysetJSON, _ := json.Marshal(DAOKeyset{
		Keys:      []string{daoKey1.pub, daoKey2.pub},
		Threshold: 2,
	})
	oracleJSON, _ := json.Marshal(OracleConfig{
		Keys:          []string{oracleKey.pub},
		Threshold:     1,
		AllowedPrefix: "epoch.",
	})

	now := core.Now().UnixNano()
	genesis := &Block{
		Index:     0,
		PrevHash:  "0000000000000000000000000000000000000000000000000000000000000000",
		Timestamp: now,
		Ops: []Op{
			{Action: ActionSet, Key: "sys.dao_keyset", Value: keysetJSON},
			{Action: ActionSet, Key: "sys.oracle", Value: oracleJSON},
		},
	}
	signBlock(t, genesis, daoKey1, daoKey2)

	store := newMemStore()
	chain, err := NewChain(store, genesis)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}

	// 1. Block timestamped way in the future (e.g. now + 1 year) must be rejected
	farFutureBlock := &Block{
		Index:     1,
		PrevHash:  genesis.Hash,
		Timestamp: now + int64(365*24*time.Hour),
		Ops: []Op{
			{Action: ActionSet, Key: "some.key", Value: json.RawMessage(`"val"`)},
		},
	}
	signBlock(t, farFutureBlock, daoKey1, daoKey2)

	err = chain.AddBlock(farFutureBlock)
	if err == nil {
		t.Fatal("expected error for far future timestamp, got nil")
	}
	if !strings.Contains(err.Error(), "too far in future") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// 2. Block timestamped beyond MaxBlockFutureSkew (e.g. + 15 minutes) must be rejected
	moderateFutureBlock := &Block{
		Index:     1,
		PrevHash:  genesis.Hash,
		Timestamp: now + int64(MaxBlockFutureSkew+5*time.Minute),
		Ops: []Op{
			{Action: ActionSet, Key: "some.key", Value: json.RawMessage(`"val"`)},
		},
	}
	signBlock(t, moderateFutureBlock, daoKey1, daoKey2)

	err = chain.AddBlock(moderateFutureBlock)
	if err == nil {
		t.Fatal("expected error for future skew, got nil")
	}

	// 3. Block within allowable skew (e.g. + 1 second) must be accepted
	validBlock := &Block{
		Index:     1,
		PrevHash:  genesis.Hash,
		Timestamp: now + int64(time.Second),
		Ops: []Op{
			{Action: ActionSet, Key: "some.key", Value: json.RawMessage(`"val"`)},
		},
	}
	signBlock(t, validBlock, daoKey1, daoKey2)

	if err := chain.AddBlock(validBlock); err != nil {
		t.Fatalf("expected valid block to be accepted, got: %v", err)
	}
}

func TestOracleCannotActivateFeatures(t *testing.T) {
	daoKey1 := newTestSigner(t)
	daoKey2 := newTestSigner(t)
	oracleKey := newTestSigner(t)

	keysetJSON, _ := json.Marshal(DAOKeyset{
		Keys:      []string{daoKey1.pub, daoKey2.pub},
		Threshold: 2,
	})
	oracleJSON, _ := json.Marshal(OracleConfig{
		Keys:          []string{oracleKey.pub},
		Threshold:     1,
		AllowedPrefix: "epoch.",
	})

	now := core.Now().UnixNano()
	activationsJSON, _ := json.Marshal(Activations{
		Features: map[string]ActivationRecord{
			"feat_index": {
				AtIndex:     2,
				NotBeforeNS: 0,
			},
		},
	})

	genesis := &Block{
		Index:     0,
		PrevHash:  "0000000000000000000000000000000000000000000000000000000000000000",
		Timestamp: now,
		Ops: []Op{
			{Action: ActionSet, Key: "sys.dao_keyset", Value: keysetJSON},
			{Action: ActionSet, Key: "sys.oracle", Value: oracleJSON},
			{Action: ActionSet, Key: "sys.activations", Value: activationsJSON},
		},
	}
	signBlock(t, genesis, daoKey1, daoKey2)

	store := newMemStore()
	chain, err := NewChain(store, genesis)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}

	// Block 1: Oracle sets epoch 1 (does not activate feat_index, which is at_index=2)
	epochVal1, _ := json.Marshal(EpochValue{
		Epoch:        1,
		StartNS:      now,
		EndNS:        now + int64(time.Hour),
		TWAPMilliUSD: 1000,
		TWAVMilliUSD: 1000,
		RVolume:      1000,
		RPriceFloor:  1000,
		REffective:   1000,
		RSource:      "tied",
		Phase:        1,
		PayoutCap:    1500,
	})

	b1 := &Block{
		Index:     1,
		PrevHash:  genesis.Hash,
		Timestamp: now + int64(time.Second),
		Ops: []Op{
			{Action: ActionSet, Key: "epoch.1", Value: epochVal1},
		},
	}
	signBlock(t, b1, oracleKey)

	if err := chain.AddBlock(b1); err != nil {
		t.Fatalf("expected b1 to be accepted: %v", err)
	}
	if chain.FeatureActive("feat_index") {
		t.Fatal("feat_index should not be active at index 1")
	}

	// Block 2: Oracle attempts to publish epoch 2, which would cross at_index=2 and activate feat_index
	epochVal2, _ := json.Marshal(EpochValue{
		Epoch:        2,
		StartNS:      now + int64(time.Hour),
		EndNS:        now + int64(2*time.Hour),
		TWAPMilliUSD: 1000,
		TWAVMilliUSD: 1000,
		RVolume:      1000,
		RPriceFloor:  1000,
		REffective:   1000,
		RSource:      "tied",
		Phase:        1,
		PayoutCap:    1500,
	})

	b2Oracle := &Block{
		Index:     2,
		PrevHash:  b1.Hash,
		Timestamp: now + int64(2*time.Second),
		Ops: []Op{
			{Action: ActionSet, Key: "epoch.2", Value: epochVal2},
		},
	}
	signBlock(t, b2Oracle, oracleKey)

	err = chain.AddBlock(b2Oracle)
	if err == nil {
		t.Fatal("expected oracle block activating feature to be rejected")
	}
	if !strings.Contains(err.Error(), "oracle block cannot activate feature") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// Block 2 by DAO (2-of-3 threshold) is allowed to advance and activate the feature
	b2DAO := &Block{
		Index:     2,
		PrevHash:  b1.Hash,
		Timestamp: now + int64(2*time.Second),
		Ops: []Op{
			{Action: ActionSet, Key: "dao.config", Value: json.RawMessage(`"ok"`)},
		},
	}
	signBlock(t, b2DAO, daoKey1, daoKey2)

	if err := chain.AddBlock(b2DAO); err != nil {
		t.Fatalf("expected DAO block to be accepted: %v", err)
	}
	if !chain.FeatureActive("feat_index") {
		t.Fatal("feat_index should now be active after DAO block 2")
	}
}
