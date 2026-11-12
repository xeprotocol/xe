package node

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func setupTestNode(t *testing.T) (*Node, *core.KeyPair, map[string]*core.CertificateInfo) {
	t.Helper()
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	certs := make(map[string]*core.CertificateInfo)
	mem := store.NewMemStore()
	ledger := core.NewLedger(mem, core.LedgerConfig{
		Difficulty:      0,
		TimestampWindow: 0,
		CertificateLookupFn: func(hash string) *core.CertificateInfo {
			return certs[hash]
		},
	})

	n := &Node{
		KeyPair: kp,
		Ledger:  ledger,
		store:   mem,
		ctx:     context.Background(),
	}

	return n, kp, certs
}

func TestCreateLeaseBlock_ReturnsLeaseHash(t *testing.T) {
	n, kp, certs := setupTestNode(t)
	myAddr := kp.Address()

	provider, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate provider key: %v", err)
	}

	accessKey := hex.EncodeToString(make([]byte, 32))
	certHash := "1111111111111111111111111111111111111111111111111111111111111111"
	certs[certHash] = &core.CertificateInfo{
		Provider:             provider.Address(),
		ExpiresAt:            time.Now().Add(7 * 24 * time.Hour).UnixNano(),
		PriceMultiplierMilli: 1000,
	}

	// 1. Account not open yet -> returns error
	_, err = n.CreateLeaseBlock(provider.Address(), 1, 1024, 10, 3600, 40000, accessKey, certHash)
	if err == nil {
		t.Fatalf("expected error when account is not open")
	}

	// 2. Open account with seed funds
	seed := &core.Block{
		Type:      core.BlockMint,
		Account:   myAddr,
		Previous:  "0",
		Balance:   1_000_000,
		Amount:    1_000_000,
		Timestamp: time.Now().UnixNano(),
		Asset:     "XUSD",
	}
	if err := core.SignBlock(seed, kp); err != nil {
		t.Fatalf("sign seed: %v", err)
	}
	if err := n.Ledger.SeedAssetForTesting(seed); err != nil {
		t.Fatalf("seed asset: %v", err)
	}

	// 3. Insufficient balance test
	_, err = n.CreateLeaseBlock(provider.Address(), 1, 1024, 10, 3600, 5_000_000, accessKey, certHash)
	if err == nil {
		t.Fatalf("expected error for insufficient balance")
	}

	// 4. Successful CreateLeaseBlock
	const cost = 40_000
	leaseHash, err := n.CreateLeaseBlock(provider.Address(), 1, 1024, 10, 3600, cost, accessKey, certHash)
	if err != nil {
		t.Fatalf("CreateLeaseBlock failed: %v", err)
	}
	if leaseHash == "" {
		t.Fatalf("expected non-empty leaseHash")
	}

	// Verify the block corresponding to leaseHash is indeed the lease block
	chain := n.Ledger.GetChain(myAddr)
	if len(chain) < 2 {
		t.Fatalf("expected at least 2 blocks in chain, got %d", len(chain))
	}
	leaseBlock := chain[len(chain)-1]
	if leaseBlock.Hash != leaseHash {
		t.Fatalf("expected leaseHash %s to match block hash %s", leaseHash, leaseBlock.Hash)
	}
	if leaseBlock.Type != core.BlockLease {
		t.Fatalf("expected block type %s, got %s", core.BlockLease, leaseBlock.Type)
	}

	// 5. Append another block to chain (e.g. Send block) to simulate a concurrent transaction
	recipient, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate recipient: %v", err)
	}
	sendBlock := &core.Block{
		Type:        core.BlockSend,
		Account:     myAddr,
		Previous:    leaseBlock.Hash,
		Balance:     leaseBlock.Balance - 1000,
		Amount:      1000,
		Destination: recipient.Address(),
		Timestamp:   time.Now().UnixNano(),
		Asset:       "XUSD",
	}
	if err := core.SignBlock(sendBlock, kp); err != nil {
		t.Fatalf("sign send block: %v", err)
	}
	if err := n.Ledger.AddBlock(sendBlock); err != nil {
		t.Fatalf("add send block: %v", err)
	}

	// Now chain tail is sendBlock.Hash, but leaseHash returned previously was leaseBlock.Hash!
	newTail := n.Ledger.GetChain(myAddr)
	tailBlock := newTail[len(newTail)-1]
	if tailBlock.Hash == leaseHash {
		t.Fatalf("tail block hash should differ from lease block hash")
	}
	if tailBlock.Type != core.BlockSend {
		t.Fatalf("tail block should be send block, got %s", tailBlock.Type)
	}
}

func TestCreateLeaseBlock_ConcurrentUniqueness(t *testing.T) {
	n, kp, certs := setupTestNode(t)
	myAddr := kp.Address()

	provider, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate provider key: %v", err)
	}

	accessKey := hex.EncodeToString(make([]byte, 32))
	certHash := "2222222222222222222222222222222222222222222222222222222222222222"
	certs[certHash] = &core.CertificateInfo{
		Provider:             provider.Address(),
		ExpiresAt:            time.Now().Add(7 * 24 * time.Hour).UnixNano(),
		PriceMultiplierMilli: 1000,
	}

	// Fund account with ample XUSD
	seed := &core.Block{
		Type:      core.BlockMint,
		Account:   myAddr,
		Previous:  "0",
		Balance:   100_000_000,
		Amount:    100_000_000,
		Timestamp: time.Now().UnixNano(),
		Asset:     "XUSD",
	}
	if err := core.SignBlock(seed, kp); err != nil {
		t.Fatalf("sign seed: %v", err)
	}
	if err := n.Ledger.SeedAssetForTesting(seed); err != nil {
		t.Fatalf("seed asset: %v", err)
	}

	cost, err := core.LeaseCost(1, 1024, 10, 3600, 1000)
	if err != nil {
		t.Fatalf("LeaseCost: %v", err)
	}

	const numLeases = 20
	hashes := make([]string, numLeases)
	errs := make([]error, numLeases)

	// Run concurrent lease creations
	done := make(chan int, numLeases)
	for i := 0; i < numLeases; i++ {
		go func(idx int) {
			h, err := n.CreateLeaseBlock(provider.Address(), 1, 1024, 10, 3600, cost, accessKey, certHash)
			hashes[idx] = h
			errs[idx] = err
			done <- idx
		}(i)
	}

	for i := 0; i < numLeases; i++ {
		<-done
	}

	seen := make(map[string]bool)
	for i := 0; i < numLeases; i++ {
		if errs[i] != nil {
			t.Fatalf("lease %d failed: %v", i, errs[i])
		}
		if hashes[i] == "" {
			t.Fatalf("lease %d returned empty hash", i)
		}
		if seen[hashes[i]] {
			t.Fatalf("duplicate lease hash returned: %s", hashes[i])
		}
		seen[hashes[i]] = true

		blk, err := n.store.GetBlock(hashes[i])
		if err != nil || blk == nil {
			t.Fatalf("block %s not found in store: %v", hashes[i], err)
		}
		if blk.Type != core.BlockLease {
			t.Fatalf("expected block type %s, got %s for hash %s", core.BlockLease, blk.Type, hashes[i])
		}
	}
}
