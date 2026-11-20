package statechain

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testStore struct {
	mu     sync.RWMutex
	blocks map[uint64]*Block
}

func newTestStore() *testStore {
	return &testStore{blocks: make(map[uint64]*Block)}
}

func (s *testStore) PutStateBlock(block *Block) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blocks[block.Index] = block
	return nil
}

func (s *testStore) GetStateBlock(index uint64) (*Block, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.blocks[index], nil
}

func (s *testStore) GetStateTip() (*Block, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var tip *Block
	for _, b := range s.blocks {
		if tip == nil || b.Index > tip.Index {
			tip = b
		}
	}
	return tip, nil
}

func (s *testStore) GetStateBlockRange(start, count uint64) ([]*Block, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Block
	for i := start; i < start+count; i++ {
		if b, ok := s.blocks[i]; ok {
			out = append(out, b)
		}
	}
	return out, nil
}

func (s *testStore) StateBlockCount() (uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return uint64(len(s.blocks)), nil
}

func setupTestChain(t *testing.T) (*Chain, *testStore, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	pub1, priv1, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey 1: %v", err)
	}
	pub2, priv2, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey 2: %v", err)
	}

	k1 := hex.EncodeToString(pub1)
	k2 := hex.EncodeToString(pub2)

	genesis, err := GenerateTestGenesis([]string{k1, k2}, 2)
	if err != nil {
		t.Fatalf("GenerateTestGenesis: %v", err)
	}

	st := newTestStore()
	chain, err := NewChain(st, genesis)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}

	return chain, st, priv1, priv2
}

func createSignedBlock(t *testing.T, index uint64, prevHash string, key string, val string, timestamp int64, priv1, priv2 ed25519.PrivateKey) *Block {
	t.Helper()
	b := &Block{
		Index:    index,
		PrevHash: prevHash,
		Ops: []Op{
			{
				Action: ActionSet,
				Key:    key,
				Value:  []byte(fmt.Sprintf("%q", val)),
			},
		},
		Timestamp: timestamp,
	}

	h, err := HashBlock(b)
	if err != nil {
		t.Fatalf("HashBlock: %v", err)
	}
	b.Hash = h

	sig1, err := SignBlock(b, priv1)
	if err != nil {
		t.Fatalf("SignBlock 1: %v", err)
	}
	sig2, err := SignBlock(b, priv2)
	if err != nil {
		t.Fatalf("SignBlock 2: %v", err)
	}
	b.Signatures = []BlockSignature{sig1, sig2}
	return b
}

func TestGetBlocksAndBlockCount(t *testing.T) {
	chain, _, priv1, priv2 := setupTestChain(t)

	// BlockCount with genesis only
	count, err := chain.BlockCount()
	if err != nil {
		t.Fatalf("BlockCount: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected BlockCount=1, got %d", count)
	}

	// GetBlock(0) returns genesis
	b0, err := chain.GetBlock(0)
	if err != nil {
		t.Fatalf("GetBlock(0): %v", err)
	}
	if b0 == nil || b0.Index != 0 {
		t.Fatalf("unexpected genesis block: %+v", b0)
	}

	// GetBlocks with limit 0
	bEmpty, err := chain.GetBlocks(0, 0)
	if err != nil {
		t.Fatalf("GetBlocks(0, 0): %v", err)
	}
	if len(bEmpty) != 0 {
		t.Fatalf("expected 0 blocks, got %d", len(bEmpty))
	}

	// GetBlocks(0, 1) returns genesis
	bGen, err := chain.GetBlocks(0, 1)
	if err != nil {
		t.Fatalf("GetBlocks(0, 1): %v", err)
	}
	if len(bGen) != 1 || bGen[0].Index != 0 {
		t.Fatalf("expected 1 block (index 0), got %v", bGen)
	}

	// Add block 1
	b1 := createSignedBlock(t, 1, chain.Tip().Hash, "kv.1", "val1", 100, priv1, priv2)
	if err := chain.AddBlock(b1); err != nil {
		t.Fatalf("AddBlock 1: %v", err)
	}

	// Add block 2
	b2 := createSignedBlock(t, 2, chain.Tip().Hash, "kv.2", "val2", 200, priv1, priv2)
	if err := chain.AddBlock(b2); err != nil {
		t.Fatalf("AddBlock 2: %v", err)
	}

	// BlockCount now 3
	count, err = chain.BlockCount()
	if err != nil {
		t.Fatalf("BlockCount: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected BlockCount=3, got %d", count)
	}

	// GetBlocks(0, 3) returns [genesis, b1, b2]
	all, err := chain.GetBlocks(0, 3)
	if err != nil {
		t.Fatalf("GetBlocks(0, 3): %v", err)
	}
	if len(all) != 3 || all[0].Index != 0 || all[1].Index != 1 || all[2].Index != 2 {
		t.Fatalf("unexpected range output: %+v", all)
	}

	// GetBlocks(1, 2) returns [b1, b2]
	stored, err := chain.GetBlocks(1, 2)
	if err != nil {
		t.Fatalf("GetBlocks(1, 2): %v", err)
	}
	if len(stored) != 2 || stored[0].Index != 1 || stored[1].Index != 2 {
		t.Fatalf("unexpected stored range: %+v", stored)
	}
}

func TestAddBlockFailFast(t *testing.T) {
	chain, _, _, _ := setupTestChain(t)

	// nil block
	if err := chain.AddBlock(nil); err == nil {
		t.Fatal("expected error on AddBlock(nil), got nil")
	}

	// block with invalid hash
	bogus := &Block{
		Index:     1,
		PrevHash:  chain.Tip().Hash,
		Ops:       []Op{{Action: ActionSet, Key: "kv.bogus", Value: []byte(`"val"`)}},
		Hash:      "deadbeef00000000000000000000000000000000000000000000000000000000",
		Timestamp: 100,
	}
	if err := chain.AddBlock(bogus); err == nil {
		t.Fatal("expected error on invalid hash, got nil")
	}
}

func TestConcurrentGetBlocksAndAddBlock(t *testing.T) {
	chain, _, priv1, priv2 := setupTestChain(t)

	// Pre-seed 50 blocks
	for i := uint64(1); i <= 50; i++ {
		b := createSignedBlock(t, i, chain.Tip().Hash, fmt.Sprintf("seed.%d", i), "data", int64(i*10), priv1, priv2)
		if err := chain.AddBlock(b); err != nil {
			t.Fatalf("pre-seed block %d: %v", i, err)
		}
	}

	const readerCount = 8
	var stop atomic.Bool
	var wg sync.WaitGroup

	// Launch concurrent readers querying GetBlocks, GetBlock, and BlockCount
	for r := 0; r < readerCount; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				_, _ = chain.GetBlocks(0, 50)
				_, _ = chain.GetBlocks(1, 20)
				_, _ = chain.GetBlock(0)
				_, _ = chain.GetBlock(10)
				_, _ = chain.BlockCount()
			}
		}()
	}

	// Concurrently add next 50 blocks
	for i := uint64(51); i <= 100; i++ {
		b := createSignedBlock(t, i, chain.Tip().Hash, fmt.Sprintf("dyn.%d", i), "dyndata", int64(i*10), priv1, priv2)
		if err := chain.AddBlock(b); err != nil {
			stop.Store(true)
			t.Fatalf("concurrent AddBlock %d: %v", i, err)
		}
	}

	stop.Store(true)
	wg.Wait()

	if tip := chain.Tip(); tip.Index != 100 {
		t.Fatalf("expected tip index 100, got %d", tip.Index)
	}
}

func TestConcurrentKVReadAndAddBlock(t *testing.T) {
	chain, _, priv1, priv2 := setupTestChain(t)

	const readerCount = 6
	var stop atomic.Bool
	var wg sync.WaitGroup

	for r := 0; r < readerCount; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				_ = chain.Tip()
				_ = chain.GetAllKV()
				_, _ = chain.GetKV("sys.phase")
				_ = chain.GetKVByPrefix("sys.")
				_ = chain.DAOKeyset()
				_ = chain.Phase()
				_ = chain.Activations()
				_ = chain.FeatureActive("some_feature")
			}
		}()
	}

	for i := uint64(1); i <= 50; i++ {
		b := createSignedBlock(t, i, chain.Tip().Hash, fmt.Sprintf("k.%d", i), "v", int64(i*10), priv1, priv2)
		if err := chain.AddBlock(b); err != nil {
			stop.Store(true)
			t.Fatalf("AddBlock %d: %v", i, err)
		}
		time.Sleep(100 * time.Microsecond)
	}

	stop.Store(true)
	wg.Wait()

	if chain.Tip().Index != 50 {
		t.Fatalf("expected tip 50, got %d", chain.Tip().Index)
	}
}
