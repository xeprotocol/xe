package core_test

import (
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

// TestSwapBlock_UnwindLeaseDescendant verifies that SwapBlock can unwind a descendant
// BlockLease when replacing an unfinalized send block on an account chain.
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
		Asset:          "XCU",
		PubKey:         owner.PubKeyHex(),
		Representative: owner.Address(),
	}
	if err := core.SignBlock(open, owner); err != nil {
		t.Fatalf("sign open: %v", err)
	}
	if err := l.SeedAssetForTesting(open); err != nil {
		t.Fatalf("seed open: %v", err)
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
		Asset:       "XCU",
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
		Asset:           "XCU",
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
		Asset:       "XCU",
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
	bal := l.GetAssetBalances(owner.Address())["XCU"]
	if bal != fundAmount-2 {
		t.Fatalf("expected balance %d, got %d", fundAmount-2, bal)
	}
}

// TestSwapBlock_UnwindMultisigOpenDescendant verifies that SwapBlock can unwind a descendant
// BlockMultisigOpen when replacing an unfinalized block on an account chain.
func TestSwapBlock_UnwindMultisigOpenDescendant(t *testing.T) {
	core.SetNetworkID("")
	ms := store.NewMemStore()
	l := core.NewLedger(ms, core.LedgerConfig{Difficulty: 0, TimestampWindow: 0})

	k1, _ := core.GenerateKeyPair()
	k2, _ := core.GenerateKeyPair()
	payee, _ := core.GenerateKeyPair()

	keyset := &core.Keyset{
		Threshold: 2,
		Keys:      []string{k1.PubKeyHex(), k2.PubKeyHex()},
	}

	owner, _ := core.GenerateKeyPair()
	const fundAmount = 1000
	open := &core.Block{
		Type:           core.BlockMint,
		Account:        owner.Address(),
		Previous:       "0",
		Balance:        fundAmount,
		Amount:         fundAmount,
		Timestamp:      time.Now().UnixNano(),
		Asset:          "XE",
		PubKey:         owner.PubKeyHex(),
		Representative: owner.Address(),
	}
	_ = core.SignBlock(open, owner)
	if err := l.SeedAssetForTesting(open); err != nil {
		t.Fatalf("seed open: %v", err)
	}
	_ = ms.SetFinalHeight(owner.Address(), 1)

	// sendA
	sendA := &core.Block{
		Type:        core.BlockSend,
		Account:     owner.Address(),
		Previous:    open.Hash,
		Balance:     fundAmount - 10,
		Amount:      10,
		Timestamp:   time.Now().UnixNano() + 1,
		Asset:       "XE",
		Destination: payee.Address(),
	}
	_ = core.SignBlock(sendA, owner)
	if err := l.AddBlock(sendA); err != nil {
		t.Fatalf("add send A: %v", err)
	}

	// MultisigOpen descendant chained on sendA (injected directly to test unwind planning)
	msOpen := &core.Block{
		Type:      core.BlockMultisigOpen,
		Account:   owner.Address(),
		Previous:  sendA.Hash,
		Balance:   fundAmount - 10,
		Timestamp: time.Now().UnixNano() + 2,
		Asset:     "XE",
		MSKeyset:  keyset,
	}
	_ = core.SignBlock(msOpen, owner)
	chain, _ := ms.GetAccountChain(owner.Address())
	chain.Blocks = append(chain.Blocks, msOpen)
	_ = ms.PutAccountChain(owner.Address(), chain)
	_ = ms.PutBlock(msOpen)

	// sendB conflicting with sendA
	sendB := &core.Block{
		Type:        core.BlockSend,
		Account:     owner.Address(),
		Previous:    open.Hash,
		Balance:     fundAmount - 20,
		Amount:      20,
		Timestamp:   time.Now().UnixNano() + 3,
		Asset:       "XE",
		Destination: payee.Address(),
	}
	_ = core.SignBlock(sendB, owner)

	// SwapBlock should unwind msOpen descendant without error
	if err := l.SwapBlock(owner.Address(), sendA.Hash, sendB.Hash, sendB); err != nil {
		t.Fatalf("SwapBlock failed to unwind multisig_open descendant: %v", err)
	}

	newChain := l.GetChain(owner.Address())
	if len(newChain) != 2 {
		t.Fatalf("expected 2 blocks on chain after swap, got %d", len(newChain))
	}
	if newChain[1].Hash != sendB.Hash {
		t.Fatalf("expected sendB at height 2, got %s", newChain[1].Hash)
	}
}

// TestCascadeRollback_UnwindCounterpartyLeaseDescendant verifies that planRollbackFrom
// cascades properly across counterparties with lease descendants.
func TestCascadeRollback_UnwindCounterpartyLeaseDescendant(t *testing.T) {
	core.SetNetworkID("")
	ms := store.NewMemStore()

	certHash := strings.Repeat("cd", 32)
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

	sender, _ := core.GenerateKeyPair()
	recipient, _ := core.GenerateKeyPair()
	altPayee, _ := core.GenerateKeyPair()

	const fundAmount = 1_000_000_000
	// Sender open
	sOpen := &core.Block{
		Type:           core.BlockMint,
		Account:        sender.Address(),
		Previous:       "0",
		Balance:        fundAmount,
		Amount:         fundAmount,
		Timestamp:      time.Now().UnixNano(),
		Asset:          "XCU",
		PubKey:         sender.PubKeyHex(),
		Representative: sender.Address(),
	}
	_ = core.SignBlock(sOpen, sender)
	if err := l.SeedAssetForTesting(sOpen); err != nil {
		t.Fatalf("seed sOpen: %v", err)
	}
	_ = ms.SetFinalHeight(sender.Address(), 1)

	// Send S1 from sender to recipient
	sendAmt := uint64(500_000_000)
	s1 := &core.Block{
		Type:        core.BlockSend,
		Account:     sender.Address(),
		Previous:    sOpen.Hash,
		Balance:     fundAmount - sendAmt,
		Amount:      sendAmt,
		Timestamp:   time.Now().UnixNano() + 1,
		Asset:       "XCU",
		Destination: recipient.Address(),
	}
	_ = core.SignBlock(s1, sender)
	if err := l.AddBlock(s1); err != nil {
		t.Fatalf("add s1: %v", err)
	}

	// Recipient receives S1 as R1
	r1 := &core.Block{
		Type:           core.BlockReceive,
		Account:        recipient.Address(),
		Previous:       "0",
		Balance:        sendAmt,
		Timestamp:      time.Now().UnixNano() + 2,
		Asset:          "XCU",
		Source:         s1.Hash,
		PubKey:         recipient.PubKeyHex(),
		Representative: recipient.Address(),
	}
	_ = core.SignBlock(r1, recipient)
	if err := l.AddBlock(r1); err != nil {
		t.Fatalf("add r1: %v", err)
	}

	// Recipient creates a compute lease descendant chained on R1
	cost, err := core.LeaseCost(1, 0, 0, 60, 1000)
	if err != nil {
		t.Fatalf("lease cost: %v", err)
	}
	recLease := &core.Block{
		Type:            core.BlockLease,
		Account:         recipient.Address(),
		Previous:        r1.Hash,
		Balance:         sendAmt - cost,
		Amount:          cost,
		Timestamp:       time.Now().UnixNano() + 3,
		Asset:           "XCU",
		Destination:     provider.Address(),
		CertificateHash: certHash,
		VCPUs:           1,
		Duration:        60,
	}
	_ = core.SignBlock(recLease, recipient)
	if err := l.AddBlock(recLease); err != nil {
		t.Fatalf("add recLease: %v", err)
	}

	// Competing block W on sender replacing S1
	w := &core.Block{
		Type:        core.BlockSend,
		Account:     sender.Address(),
		Previous:    sOpen.Hash,
		Balance:     fundAmount - 100,
		Amount:      100,
		Timestamp:   time.Now().UnixNano() + 4,
		Asset:       "XCU",
		Destination: altPayee.Address(),
	}
	_ = core.SignBlock(w, sender)
	if err := l.AddBlock(w); err != nil {
		t.Fatalf("stage w: %v", err)
	}

	// Swap S1 -> W on sender (should cascade rollback recipient's lease and receive)
	if err := l.SwapBlock(sender.Address(), s1.Hash, w.Hash, w); err != nil {
		t.Fatalf("SwapBlock with cascade lease descendant failed: %v", err)
	}

	// Verify recipient chain is unwound to empty (deleted account)
	recChain := l.GetChain(recipient.Address())
	if len(recChain) != 0 {
		t.Fatalf("expected recipient chain to be unwound to empty, got %d blocks", len(recChain))
	}

	// Verify recipient lease is deleted
	deletedLease, _ := ms.GetLease(recLease.Hash)
	if deletedLease != nil {
		t.Fatalf("expected recipient lease to be deleted after cascade rollback")
	}
}
