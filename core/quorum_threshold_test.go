package core_test

import (
	"strings"
	"testing"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

// TestQuorum_NoSubstitutionWithoutThreshold asserts that if the 67% winner
// is unpromotable (fails full validation), conflict resolution WITHHOLDS finality
// and NEVER substitutes a candidate that has not reached the 67% threshold.
func TestQuorum_NoSubstitutionWithoutThreshold(t *testing.T) {
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

	// Honest sendA: 1 XUSD to payee
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

	// Decoy block: staged conflict on open.Hash with 0 resources (fails full validation on SwapBlock)
	decoy := &core.Block{
		Type:            core.BlockLease,
		Account:         owner.Address(),
		Previous:        open.Hash,
		Balance:         fundAmount - 1000,
		Amount:          1000,
		Timestamp:       core.Now().UnixNano(),
		Asset:           "XUSD",
		Destination:     provider.Address(),
		CertificateHash: certHash,
		VCPUs:           0,
		MemoryMB:        0,
		DiskGB:          0,
		Duration:        60,
	}
	if err := core.SignBlock(decoy, owner); err != nil {
		t.Fatalf("sign decoy: %v", err)
	}
	if err := l.AddBlock(decoy); err != nil {
		t.Fatalf("stage decoy: %v", err)
	}

	c := l.GetConflict(owner.Address(), open.Hash)
	if c == nil {
		t.Fatalf("expected conflict record")
	}
	c.TotalWeight = 100
	if err := ms.SaveConflict(c); err != nil {
		t.Fatalf("save conflict: %v", err)
	}

	// Decoy holds 67% vote weight. Honest sendA only holds 10% vote weight.
	if err := ms.PutVote(&core.Vote{
		RepPubKey:       "aa" + decoy.Hash[2:],
		BlockHash:       decoy.Hash,
		ConflictAccount: owner.Address(),
		ConflictPrev:    open.Hash,
		Timestamp:       core.Now().UnixNano(),
		Final:           true,
		Weight:          67,
	}); err != nil {
		t.Fatalf("put decoy vote: %v", err)
	}
	if err := ms.PutVote(&core.Vote{
		RepPubKey:       "bb" + sendA.Hash[2:],
		BlockHash:       sendA.Hash,
		ConflictAccount: owner.Address(),
		ConflictPrev:    open.Hash,
		Timestamp:       core.Now().UnixNano(),
		Final:           true,
		Weight:          10,
	}); err != nil {
		t.Fatalf("put send vote: %v", err)
	}

	qm := core.NewQuorumManager(ms, ms, ms, l)

	// First tally: decoy fails validation and is quarantined
	qm.Retally(owner.Address(), open.Hash)
	if l.IsFinalized(owner.Address(), decoy.Hash) {
		t.Fatalf("decoy should not be finalized")
	}

	// Second tally: decoy is unpromotable. sendA MUST NOT be substituted because it only has 10% weight.
	qm.Retally(owner.Address(), open.Hash)
	if l.IsFinalized(owner.Address(), sendA.Hash) {
		t.Fatalf("FATAL: sendA was finalized despite only holding 10%% of vote weight! Quorum invariant violated!")
	}
	if l.IsFinalized(owner.Address(), decoy.Hash) {
		t.Fatalf("decoy was finalized")
	}

	// Height must stay at 1 (open block)
	if h := l.FinalHeight(owner.Address()); h != 1 {
		t.Fatalf("expected final height to remain at 1, got %d", h)
	}
}

func TestQuorum_LegitimateWinnerFinalized(t *testing.T) {
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

	c := l.GetConflict(owner.Address(), open.Hash)
	if c == nil {
		// Single block on frontier, not a conflict yet. Create a conflicting sendB.
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
		_ = l.AddBlock(sendB)
		c = l.GetConflict(owner.Address(), open.Hash)
	}
	c.TotalWeight = 100
	_ = ms.SaveConflict(c)

	// SendA receives 67% of vote weight
	_ = ms.PutVote(&core.Vote{
		RepPubKey:       "aa" + sendA.Hash[2:],
		BlockHash:       sendA.Hash,
		ConflictAccount: owner.Address(),
		ConflictPrev:    open.Hash,
		Timestamp:       core.Now().UnixNano(),
		Final:           true,
		Weight:          67,
	})

	qm := core.NewQuorumManager(ms, ms, ms, l)
	qm.Retally(owner.Address(), open.Hash)

	if !l.IsFinalized(owner.Address(), sendA.Hash) {
		t.Fatalf("expected sendA to be finalized when holding 67%% of vote weight")
	}
	if h := l.FinalHeight(owner.Address()); h != 2 {
		t.Fatalf("expected final height to advance to 2, got %d", h)
	}
}
