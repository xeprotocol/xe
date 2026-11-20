package core_test

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func signVote(t *testing.T, v *core.Vote, kp *core.KeyPair) {
	t.Helper()
	if err := core.SignVote(v, kp); err != nil {
		t.Fatalf("SignVote: %v", err)
	}
}

// TestSnapshotWeightZero_StallResolved verifies issue #527:
// When a representative holding >33% of the snapshot weight drops to live weight 0
// after conflict detection, its vote is accepted at its snapshot weight so the conflict
// can reach quorum and resolve rather than freezing the victim account permanently.
func TestSnapshotWeightZero_StallResolved(t *testing.T) {
	core.SetNetworkID("")
	ms := store.NewMemStore()
	l := core.NewLedger(ms, core.LedgerConfig{Difficulty: 0, TimestampWindow: 0})
	vm := core.NewVoteManager(ms, nil, l)
	qm := core.NewQuorumManager(ms, ms, ms, l)
	vm.SetQuorumManager(qm)

	repA, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen repA: %v", err)
	}
	repB, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen repB: %v", err)
	}
	repC, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen repC: %v", err)
	}
	victim, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen victim: %v", err)
	}
	payee, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen payee: %v", err)
	}

	// 1. Fund representatives with initial balances and self-delegation:
	// RA = 100_000_000, RB = 60_000_000, RC = 60_000_000.
	now := time.Now().UnixNano()
	initRep := func(kp *core.KeyPair, amount uint64) *core.Block {
		b := &core.Block{
			Type:           core.BlockMint,
			Account:        kp.Address(),
			Previous:       "0",
			Balance:        amount,
			Amount:         amount,
			Timestamp:      now,
			Asset:          "XE",
			PubKey:         kp.PubKeyHex(),
			Representative: kp.Address(),
		}
		if err := core.SignBlock(b, kp); err != nil {
			t.Fatalf("sign rep mint: %v", err)
		}
		if err := l.SeedAssetForTesting(b); err != nil {
			t.Fatalf("seed rep mint: %v", err)
		}
		if err := ms.SetFinalHeight(kp.Address(), 1); err != nil {
			t.Fatalf("finalize rep mint: %v", err)
		}
		return b
	}

	openRA := initRep(repA, 100_000_000_000_000)
	initRep(repB, 60_000_000_000_000)
	initRep(repC, 60_000_000_000_000)

	// 2. Fund victim account V (1000 XE)
	openV := &core.Block{
		Type:           core.BlockMint,
		Account:        victim.Address(),
		Previous:       "0",
		Balance:        1000,
		Amount:         1000,
		Timestamp:      now,
		Asset:          "XE",
		PubKey:         victim.PubKeyHex(),
		Representative: victim.Address(),
	}
	if err := core.SignBlock(openV, victim); err != nil {
		t.Fatalf("sign openV: %v", err)
	}
	if err := l.SeedAssetForTesting(openV); err != nil {
		t.Fatalf("seed openV: %v", err)
	}
	if err := ms.SetFinalHeight(victim.Address(), 1); err != nil {
		t.Fatalf("finalize openV: %v", err)
	}

	// 3. Create a conflict on victim account V: S1 and S2 (both Previous == openV.Hash)
	s1 := &core.Block{
		Type:        core.BlockSend,
		Account:     victim.Address(),
		Previous:    openV.Hash,
		Balance:     900,
		Amount:      100,
		Timestamp:   now + 1,
		Asset:       "XE",
		Destination: payee.Address(),
	}
	if err := core.SignBlock(s1, victim); err != nil {
		t.Fatalf("sign s1: %v", err)
	}
	if err := l.AddBlock(s1); err != nil {
		t.Fatalf("add s1: %v", err)
	}

	s2 := &core.Block{
		Type:        core.BlockSend,
		Account:     victim.Address(),
		Previous:    openV.Hash,
		Balance:     800,
		Amount:      200,
		Timestamp:   now + 2,
		Asset:       "XE",
		Destination: payee.Address(),
	}
	if err := core.SignBlock(s2, victim); err != nil {
		t.Fatalf("sign s2: %v", err)
	}
	if err := l.AddBlock(s2); err != nil {
		t.Fatalf("stage s2: %v", err)
	}

	conflict := l.GetConflict(victim.Address(), openV.Hash)
	if conflict == nil {
		t.Fatalf("expected conflict on victim account")
	}

	// Verify RA holds >33% of the snapshot weight
	snapTotal := conflict.TotalWeight
	snapRA := conflict.WeightSnapshot[repA.Address()]
	if snapRA != 100_000_000_000_000 {
		t.Fatalf("expected repA snapshot weight 100_000_000_000_000, got %d", snapRA)
	}
	if float64(snapRA)/float64(snapTotal) < 0.33 {
		t.Fatalf("expected repA to hold >33%% of snapshot weight")
	}

	// 4. Now simulate repA moving all its funds away to fresh account, dropping live weight to 0
	drainBlock := &core.Block{
		Type:        core.BlockSend,
		Account:     repA.Address(),
		Previous:    openRA.Hash,
		Balance:     0,
		Amount:      100_000_000_000_000,
		Timestamp:   now + 3,
		Asset:       "XE",
		Destination: payee.Address(),
	}
	if err := core.SignBlock(drainBlock, repA); err != nil {
		t.Fatalf("sign drainBlock: %v", err)
	}
	if err := l.AddBlock(drainBlock); err != nil {
		t.Fatalf("add drainBlock: %v", err)
	}

	liveWeightRA := l.GetVoteWeight(repA.Address())
	if liveWeightRA.Sign() != 0 {
		t.Fatalf("expected repA live weight to be 0, got %v", liveWeightRA)
	}

	// 5. RepB and RepC cast final votes for S1 (sum = 120M / 220M ≈ 54.5%, <67%)
	voteB := &core.Vote{
		RepPubKey:       repB.PubKeyHex(),
		BlockHash:       s1.Hash,
		ConflictAccount: victim.Address(),
		ConflictPrev:    openV.Hash,
		Timestamp:       core.Now().UnixNano(),
		Final:           true,
	}
	signVote(t, voteB, repB)
	if err := vm.ReceiveVote(voteB); err != nil {
		t.Fatalf("ReceiveVote repB: %v", err)
	}

	voteC := &core.Vote{
		RepPubKey:       repC.PubKeyHex(),
		BlockHash:       s1.Hash,
		ConflictAccount: victim.Address(),
		ConflictPrev:    openV.Hash,
		Timestamp:       core.Now().UnixNano(),
		Final:           true,
	}
	signVote(t, voteC, repC)
	if err := vm.ReceiveVote(voteC); err != nil {
		t.Fatalf("ReceiveVote repC: %v", err)
	}

	// Check that S1 has not yet finalized (only 54.5% of weight)
	if l.IsFinalized(victim.Address(), s1.Hash) {
		t.Fatalf("s1 finalized prematurely without repA vote")
	}

	// 6. Now repA casts its vote for S1 despite its LIVE weight being 0:
	// Prior to fix, ValidateVote returned "representative ... has zero vote weight",
	// freezing the account forever.
	voteA := &core.Vote{
		RepPubKey:       repA.PubKeyHex(),
		BlockHash:       s1.Hash,
		ConflictAccount: victim.Address(),
		ConflictPrev:    openV.Hash,
		Timestamp:       core.Now().UnixNano(),
		Final:           true,
	}
	signVote(t, voteA, repA)

	if err := vm.ValidateVote(voteA); err != nil {
		t.Fatalf("ValidateVote failed for snapshot-weighted representative: %v", err)
	}

	if err := vm.ReceiveVote(voteA); err != nil {
		t.Fatalf("ReceiveVote failed for repA: %v", err)
	}

	// 7. Verify quorum reached and conflict resolved: S1 is finalized at height 2!
	if !l.IsFinalized(victim.Address(), s1.Hash) {
		t.Fatalf("expected s1 to be finalized after repA vote was accepted")
	}
	if h := l.FinalHeight(victim.Address()); h != 2 {
		t.Fatalf("expected final height 2, got %d", h)
	}

	// Verify conflict record is cleaned up
	if c := l.GetConflict(victim.Address(), openV.Hash); c != nil {
		t.Fatalf("expected conflict record to be cleaned up after resolution")
	}
}

// TestSnapshotWeightZero_ZeroWeightWithoutSnapshotRejected verifies that a representative
// with live weight 0 that was NOT part of the conflict snapshot is still rejected.
func TestSnapshotWeightZero_ZeroWeightWithoutSnapshotRejected(t *testing.T) {
	core.SetNetworkID("")
	ms := store.NewMemStore()
	l := core.NewLedger(ms, core.LedgerConfig{Difficulty: 0, TimestampWindow: 0})
	vm := core.NewVoteManager(ms, nil, l)

	zeroRep, _ := core.GenerateKeyPair()
	v := &core.Vote{
		RepPubKey:       zeroRep.PubKeyHex(),
		BlockHash:       hex.EncodeToString(make([]byte, 32)),
		ConflictAccount: hex.EncodeToString(make([]byte, 32)),
		ConflictPrev:    "0",
		Timestamp:       core.Now().UnixNano(),
		Final:           true,
	}
	signVote(t, v, zeroRep)

	err := vm.ValidateVote(v)
	if err == nil {
		t.Fatalf("expected ValidateVote to reject zero weight representative not in snapshot")
	}
}
