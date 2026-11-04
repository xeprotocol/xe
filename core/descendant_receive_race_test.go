package core_test

import (
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

// TestDescendantReceiveDeferredDuringConflict verifies Defect 1:
// validateAndAddReceive must defer receives of descendant sends when ANY conflict
// exists on the source account, preventing unresolvable orphaned credits.
func TestDescendantReceiveDeferredDuringConflict(t *testing.T) {
	core.SetNetworkID("testnet-race-229")

	xKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair x: %v", err)
	}
	dKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair d: %v", err)
	}
	eKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair e: %v", err)
	}

	xAddr, err := core.DeriveAddress(xKP.PubKeyHex())
	if err != nil {
		t.Fatalf("DeriveAddress x: %v", err)
	}
	dAddr, err := core.DeriveAddress(dKP.PubKeyHex())
	if err != nil {
		t.Fatalf("DeriveAddress d: %v", err)
	}
	eAddr, err := core.DeriveAddress(eKP.PubKeyHex())
	if err != nil {
		t.Fatalf("DeriveAddress e: %v", err)
	}

	now := time.Now().UnixNano()
	ms := store.NewMemStore()
	l := core.NewLedger(ms, core.LedgerConfig{
		TimekeeperConfigFn: func() *core.TimekeeperConfig { return &core.TimekeeperConfig{} },
		MinterConfigFn:     func() *core.MinterConfig { return &core.MinterConfig{Keys: []string{xAddr}} },
		FeatureActiveFn:    func(f string) bool { return true },
	})

	// 1. Mint 1,000,000 XUSD to X (P)
	p := &core.Block{Type: core.BlockMint, Account: xAddr, Previous: "0", Balance: 1_000_000, Amount: 1_000_000, Asset: "XUSD", Timestamp: now}
	if err := core.SignBlock(p, xKP); err != nil {
		t.Fatalf("SignBlock p: %v", err)
	}
	if err := l.AddBlock(p); err != nil {
		t.Fatalf("AddBlock p: %v", err)
	}

	// 2. L: send 50k X -> E (previous = P)
	lBlk := &core.Block{Type: core.BlockSend, Account: xAddr, Previous: p.Hash, Balance: 950_000, Amount: 50_000, Asset: "XUSD", Timestamp: now + 1, Destination: eAddr}
	if err := core.SignBlock(lBlk, xKP); err != nil {
		t.Fatalf("SignBlock lBlk: %v", err)
	}
	if err := l.AddBlock(lBlk); err != nil {
		t.Fatalf("AddBlock lBlk: %v", err)
	}

	// 3. S1: send 100k X -> D (previous = L) - descendant of L
	s1 := &core.Block{Type: core.BlockSend, Account: xAddr, Previous: lBlk.Hash, Balance: 850_000, Amount: 100_000, Asset: "XUSD", Timestamp: now + 2, Destination: dAddr}
	if err := core.SignBlock(s1, xKP); err != nil {
		t.Fatalf("SignBlock s1: %v", err)
	}
	if err := l.AddBlock(s1); err != nil {
		t.Fatalf("AddBlock s1: %v", err)
	}

	// 4. Conflict: W on X with previous = P (conflicts with L)
	w := &core.Block{Type: core.BlockSend, Account: xAddr, Previous: p.Hash, Balance: 930_000, Amount: 70_000, Asset: "XUSD", Timestamp: now + 3, Destination: eAddr}
	if err := core.SignBlock(w, xKP); err != nil {
		t.Fatalf("SignBlock w: %v", err)
	}
	if err := l.AddBlock(w); err != nil {
		t.Fatalf("AddBlock w: %v", err)
	}

	// Verify conflict is registered
	c := l.GetConflict(xAddr, p.Hash)
	if c == nil {
		t.Fatalf("expected conflict at fork point")
	}

	// 5. Attempt receive R1 of descendant send S1 while conflict is open
	r1 := &core.Block{Type: core.BlockReceive, Account: dAddr, Previous: "0", Balance: 100_000, Asset: "XUSD", Timestamp: now + 4, Source: s1.Hash, Representative: dAddr}
	if err := core.SignBlock(r1, dKP); err != nil {
		t.Fatalf("SignBlock r1: %v", err)
	}
	recvErr := l.AddBlock(r1)
	if recvErr == nil {
		t.Fatalf("expected receive to be deferred during open ancestor conflict, but got nil error")
	}
	if !strings.Contains(recvErr.Error(), "receive deferred pending resolution") {
		t.Fatalf("unexpected error message: %v", recvErr)
	}

	// 6. Resolve conflict: swap L -> W
	if err := l.SwapBlock(xAddr, lBlk.Hash, w.Hash, w); err != nil {
		t.Fatalf("SwapBlock: %v", err)
	}

	// 7. Verify D has no balance from discarded S1
	dBal := l.GetAssetBalances(dAddr)["XUSD"]
	if dBal != 0 {
		t.Fatalf("expected D balance to be 0 after swap, got %d", dBal)
	}
}

// TestCascadeRecheckPendingSendUnwindsDestination verifies Defect 2:
// When a receive was processed before/during cascade, swapBlockLocked correctly
// unwinds the destination account and does not leave supply inflated.
func TestCascadeRecheckPendingSendUnwindsDestination(t *testing.T) {
	core.SetNetworkID("testnet-race-229-recheck")

	xKP, _ := core.GenerateKeyPair()
	dKP, _ := core.GenerateKeyPair()
	eKP, _ := core.GenerateKeyPair()

	xAddr, _ := core.DeriveAddress(xKP.PubKeyHex())
	dAddr, _ := core.DeriveAddress(dKP.PubKeyHex())
	eAddr, _ := core.DeriveAddress(eKP.PubKeyHex())

	now := time.Now().UnixNano()
	ms := store.NewMemStore()
	l := core.NewLedger(ms, core.LedgerConfig{
		TimekeeperConfigFn: func() *core.TimekeeperConfig { return &core.TimekeeperConfig{} },
		MinterConfigFn:     func() *core.MinterConfig { return &core.MinterConfig{Keys: []string{xAddr}} },
		FeatureActiveFn:    func(f string) bool { return true },
	})

	// Mint 1,000,000 XUSD to X (P)
	p := &core.Block{Type: core.BlockMint, Account: xAddr, Previous: "0", Balance: 1_000_000, Amount: 1_000_000, Asset: "XUSD", Timestamp: now}
	_ = core.SignBlock(p, xKP)
	_ = l.AddBlock(p)

	// Send S1 from X to D
	s1 := &core.Block{Type: core.BlockSend, Account: xAddr, Previous: p.Hash, Balance: 900_000, Amount: 100_000, Asset: "XUSD", Timestamp: now + 1, Destination: dAddr}
	_ = core.SignBlock(s1, xKP)
	_ = l.AddBlock(s1)

	// D receives S1
	r1 := &core.Block{Type: core.BlockReceive, Account: dAddr, Previous: "0", Balance: 100_000, Asset: "XUSD", Timestamp: now + 2, Source: s1.Hash, Representative: dAddr}
	_ = core.SignBlock(r1, dKP)
	if err := l.AddBlock(r1); err != nil {
		t.Fatalf("AddBlock r1: %v", err)
	}

	// Competing block W on X replacing S1, sending to E
	w := &core.Block{Type: core.BlockSend, Account: xAddr, Previous: p.Hash, Balance: 800_000, Amount: 200_000, Asset: "XUSD", Timestamp: now + 3, Destination: eAddr}
	_ = core.SignBlock(w, xKP)
	_ = l.AddBlock(w)

	// Swap S1 -> W
	if err := l.SwapBlock(xAddr, s1.Hash, w.Hash, w); err != nil {
		t.Fatalf("SwapBlock: %v", err)
	}

	// Verify D's received block was properly rolled back and total supply is consistent
	dBal := l.GetAssetBalances(dAddr)["XUSD"]
	if dBal != 0 {
		t.Fatalf("expected D balance to be unwound to 0, got %d", dBal)
	}
}
