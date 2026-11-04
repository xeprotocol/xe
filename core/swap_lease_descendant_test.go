package core_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func TestSwapBlock_UnwindLeaseDescendant(t *testing.T) {
	core.SetNetworkID("")
	ms := store.NewMemStore()

	certHash := strings.Repeat("ab", 32)
	provider, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen provider: %v", err)
	}

	l := core.NewLedger(ms, core.LedgerConfig{
		Difficulty:      0,
		TimestampWindow: 0,
		CertificateLookupFn: func(hash string) *core.CertificateInfo {
			if hash != certHash {
				return nil
			}
			return &core.CertificateInfo{
				Provider:             provider.Address(),
				PriceMultiplierMilli: 1000,
			}
		},
	})

	owner, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen owner: %v", err)
	}
	payee, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen payee: %v", err)
	}

	const fundAmount = 1_000_000_000
	open := &core.Block{
		Type:           core.BlockMint,
		Account:        owner.Address(),
		Previous:       "0",
		Balance:        fundAmount,
		Amount:         fundAmount,
		Timestamp:      core.Now().UnixNano(),
		Asset:          "XUSD",
		PubKey:         owner.PubKeyHex(),
		Representative: owner.Address(),
	}
	if err := core.SignBlock(open, owner); err != nil {
		t.Fatalf("sign open: %v", err)
	}
	if err := l.MintForTesting(open); err != nil {
		t.Fatalf("mint open: %v", err)
	}
	if err := ms.SetFinalHeight(owner.Address(), 1); err != nil {
		t.Fatalf("finalize open: %v", err)
	}

	// 1. sendA: send 1 XUSD
	sendAmt := uint64(1)
	sendA := &core.Block{
		Type:        core.BlockSend,
		Account:     owner.Address(),
		Previous:    open.Hash,
		Balance:     fundAmount - sendAmt,
		Amount:      sendAmt,
		Timestamp:   core.Now().UnixNano(),
		Asset:       "XUSD",
		Destination: payee.Address(),
	}
	if err := core.SignBlock(sendA, owner); err != nil {
		t.Fatalf("sign send A: %v", err)
	}
	if err := l.AddBlock(sendA); err != nil {
		t.Fatalf("add send A: %v", err)
	}

	// 2. lease descendant chained on sendA
	cost, err := core.LeaseCost(1, 0, 0, 60, 1000)
	if err != nil {
		t.Fatalf("lease cost: %v", err)
	}
	xusdAfterSend := fundAmount - sendAmt
	lease := &core.Block{
		Type:            core.BlockLease,
		Account:         owner.Address(),
		Previous:        sendA.Hash,
		Balance:         xusdAfterSend - cost,
		Amount:          cost,
		Timestamp:       core.Now().UnixNano(),
		Asset:           "XUSD",
		Destination:     provider.Address(),
		CertificateHash: certHash,
		VCPUs:           1,
		Duration:        60,
	}
	if err := core.SignBlock(lease, owner); err != nil {
		t.Fatalf("sign lease: %v", err)
	}
	if err := l.AddBlock(lease); err != nil {
		t.Fatalf("add lease: %v", err)
	}

	// Verify chain has [open, sendA, lease]
	chain := l.GetChain(owner.Address())
	if len(chain) != 3 {
		t.Fatalf("expected 3 blocks on chain, got %d", len(chain))
	}

	// 3. sendB: contested send conflicting with sendA (both previous == open.Hash)
	sendB := &core.Block{
		Type:        core.BlockSend,
		Account:     owner.Address(),
		Previous:    open.Hash,
		Balance:     fundAmount - 2,
		Amount:      2,
		Timestamp:   core.Now().UnixNano(),
		Asset:       "XUSD",
		Destination: payee.Address(),
	}
	if err := core.SignBlock(sendB, owner); err != nil {
		t.Fatalf("sign send B: %v", err)
	}
	if err := l.AddBlock(sendB); err != nil {
		t.Fatalf("stage send B: %v", err)
	}

	conflict := l.GetConflict(owner.Address(), open.Hash)
	if conflict == nil {
		t.Fatalf("expected conflict between send A and send B")
	}

	// 4. SwapBlock: replace sendA (and unwind lease descendant) with sendB
	swapErr := l.SwapBlock(owner.Address(), sendA.Hash, sendB.Hash, sendB)
	if swapErr != nil {
		t.Fatalf("SwapBlock failed to unwind lease descendant: %v", swapErr)
	}

	// 5. Verify post-swap state:
	newChain := l.GetChain(owner.Address())
	if len(newChain) != 2 {
		t.Fatalf("expected 2 blocks on chain after swap, got %d", len(newChain))
	}
	if newChain[1].Hash != sendB.Hash {
		t.Fatalf("expected sendB (%s) at height 2, got %s", sendB.Hash, newChain[1].Hash)
	}

	// Replaced lease should be deleted
	deletedLease, _ := ms.GetLease(lease.Hash)
	if deletedLease != nil {
		t.Fatalf("expected lease to be deleted from store after unwind")
	}

	// Account balance should match sendB balance
	bal := l.GetAssetBalances(owner.Address())["XUSD"]
	if bal != fundAmount-2 {
		t.Fatalf("expected balance %d, got %d", fundAmount-2, bal)
	}
}

func TestSwapBlock_UnsupportedDescendantWrapsWinnerValidation(t *testing.T) {
	core.SetNetworkID("")
	ms := store.NewMemStore()
	l := core.NewLedger(ms, core.LedgerConfig{Difficulty: 0, TimestampWindow: 0})

	owner, _ := core.GenerateKeyPair()
	payee, _ := core.GenerateKeyPair()

	const fundAmount = 1000
	open := &core.Block{
		Type:           core.BlockMint,
		Account:        owner.Address(),
		Previous:       "0",
		Balance:        fundAmount,
		Amount:         fundAmount,
		Timestamp:      core.Now().UnixNano(),
		Asset:          "XE",
		PubKey:         owner.PubKeyHex(),
		Representative: owner.Address(),
	}
	_ = core.SignBlock(open, owner)
	_ = l.SeedAssetForTesting(open)
	_ = ms.SetFinalHeight(owner.Address(), 1)

	sendA := &core.Block{
		Type:        core.BlockSend,
		Account:     owner.Address(),
		Previous:    open.Hash,
		Balance:     fundAmount - 10,
		Amount:      10,
		Timestamp:   core.Now().UnixNano(),
		Asset:       "XE",
		Destination: payee.Address(),
	}
	_ = core.SignBlock(sendA, owner)
	_ = l.AddBlock(sendA)

	// Add an un-unwindable descendant (e.g. BlockMultisigUpdate)
	badDesc := &core.Block{
		Type:      core.BlockMultisigUpdate,
		Account:   owner.Address(),
		Previous:  sendA.Hash,
		Balance:   fundAmount - 10,
		Timestamp: core.Now().UnixNano(),
		Asset:     "XE",
	}
	_ = core.SignBlock(badDesc, owner)
	// Inject directly to test SwapBlock error handling
	chain, _ := ms.GetAccountChain(owner.Address())
	chain.Blocks = append(chain.Blocks, badDesc)
	_ = ms.PutAccountChain(owner.Address(), chain)

	sendB := &core.Block{
		Type:        core.BlockSend,
		Account:     owner.Address(),
		Previous:    open.Hash,
		Balance:     fundAmount - 20,
		Amount:      20,
		Timestamp:   core.Now().UnixNano(),
		Asset:       "XE",
		Destination: payee.Address(),
	}
	_ = core.SignBlock(sendB, owner)

	swapErr := l.SwapBlock(owner.Address(), sendA.Hash, sendB.Hash, sendB)
	if swapErr == nil {
		t.Fatalf("expected SwapBlock to fail on multisig_update descendant")
	}
	if !errors.Is(swapErr, core.ErrWinnerFullValidation) {
		t.Fatalf("expected error to satisfy errors.Is(ErrWinnerFullValidation), got: %v", swapErr)
	}
}
