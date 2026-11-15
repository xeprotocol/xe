package core_test

import (
	"crypto/ed25519"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func signTestVote(t *testing.T, kp *core.KeyPair, v *core.Vote) {
	t.Helper()
	v.Signature = nil
	raw, err := core.EncodeVote(v)
	if err != nil {
		t.Fatalf("EncodeVote: %v", err)
	}
	signingBytes := raw[:len(raw)-2]
	v.Signature = ed25519.Sign(kp.Private, signingBytes)
}

func setupFinalityTestEnv(t *testing.T, nowNanos *atomic.Int64) (*store.MemStore, *core.Ledger, *core.VoteManager, *core.QuorumManager, *core.KeyPair, *core.KeyPair, *core.Block, *core.Block) {
	t.Helper()

	honestSeed := make([]byte, ed25519.SeedSize)
	honestSeed[0] = 1
	honestRep := core.KeyPairFromSeed(honestSeed)

	attackerSeed := make([]byte, ed25519.SeedSize)
	attackerSeed[0] = 2
	attackerRep := core.KeyPairFromSeed(attackerSeed)

	genesis := &core.Block{
		Type:           core.BlockGenesis,
		Account:        honestRep.Address(),
		Previous:       "0",
		Balance:        core.GenesisSupply,
		Asset:          "XE",
		Representative: honestRep.Address(),
		Timestamp:      0,
	}
	core.MustSignBlock(genesis, honestRep)
	genesisBytes, err := json.Marshal(genesis)
	if err != nil {
		t.Fatalf("marshal genesis: %v", err)
	}
	if err := core.SetGenesisJSON(genesisBytes); err != nil {
		t.Fatalf("SetGenesisJSON: %v", err)
	}
	t.Cleanup(core.ClearGenesisOverride)

	mem := store.NewMemStore()
	ledger := core.NewLedger(mem, core.LedgerConfig{
		Difficulty:      0,
		TimestampWindow: int64(time.Hour),
	})
	vm := core.NewVoteManager(mem, honestRep, ledger)
	t.Cleanup(vm.Close)
	qm := core.NewQuorumManager(mem, mem, mem, ledger)
	vm.SetQuorumManager(qm)

	// Give attackerRep 1 micro-XE of finalized vote weight so it is a valid voter.
	sendToAttacker := &core.Block{
		Type:           core.BlockSend,
		Account:        honestRep.Address(),
		Previous:       genesis.Hash,
		Balance:        core.GenesisSupply - 1,
		Amount:         1,
		Asset:          "XE",
		Destination:    attackerRep.Address(),
		Representative: honestRep.Address(),
		Timestamp:      nowNanos.Load(),
	}
	core.MustSignBlock(sendToAttacker, honestRep)
	if err := ledger.AddBlock(sendToAttacker); err != nil {
		t.Fatalf("AddBlock(sendToAttacker): %v", err)
	}
	if err := mem.SetFinalHeight(honestRep.Address(), 2); err != nil {
		t.Fatalf("SetFinalHeight(honestRep, 2): %v", err)
	}
	if err := mem.SetBlockStatus(sendToAttacker.Hash, core.StatusFinalized); err != nil {
		t.Fatalf("SetBlockStatus(sendToAttacker): %v", err)
	}

	recvByAttacker := &core.Block{
		Type:           core.BlockReceive,
		Account:        attackerRep.Address(),
		Previous:       "0",
		Balance:        1,
		Amount:         1,
		Asset:          "XE",
		Source:         sendToAttacker.Hash,
		Representative: attackerRep.Address(),
		Timestamp:      nowNanos.Load(),
	}
	core.MustSignBlock(recvByAttacker, attackerRep)
	if err := ledger.AddBlock(recvByAttacker); err != nil {
		t.Fatalf("AddBlock(recvByAttacker): %v", err)
	}
	if err := mem.SetFinalHeight(attackerRep.Address(), 1); err != nil {
		t.Fatalf("SetFinalHeight(attackerRep, 1): %v", err)
	}
	if err := mem.SetBlockStatus(recvByAttacker.Hash, core.StatusFinalized); err != nil {
		t.Fatalf("SetBlockStatus(recvByAttacker): %v", err)
	}

	return mem, ledger, vm, qm, honestRep, attackerRep, genesis, sendToAttacker
}

func TestVoteManagerRejectsForeignBlockCandidate(t *testing.T) {
	var nowNanos atomic.Int64
	nowNanos.Store(time.Unix(1_700_000_000, 0).UnixNano())
	origNow := core.Now
	core.Now = func() time.Time { return time.Unix(0, nowNanos.Load()) }
	defer func() { core.Now = origNow }()

	mem, ledger, vm, _, honestRep, attackerRep, _, sendToAttacker := setupFinalityTestEnv(t, &nowNanos)

	chain := ledger.GetChain(attackerRep.Address())
	if len(chain) == 0 {
		t.Fatalf("attacker chain empty")
	}
	foreignBlock := chain[0]

	// Construct victimBlock at (honestRep.Address(), sendToAttacker.Hash) with hash > foreignBlock.Hash.
	var victimBlock *core.Block
	for offset := int64(1); offset < 10000; offset++ {
		candidate := &core.Block{
			Type:           core.BlockSend,
			Account:        honestRep.Address(),
			Previous:       sendToAttacker.Hash,
			Balance:        core.GenesisSupply - 2,
			Amount:         1,
			Asset:          "XE",
			Destination:    attackerRep.Address(),
			Representative: honestRep.Address(),
			Timestamp:      nowNanos.Load() + offset,
		}
		core.MustSignBlock(candidate, honestRep)
		if foreignBlock.Hash < candidate.Hash {
			victimBlock = candidate
			break
		}
	}
	if victimBlock == nil {
		t.Fatalf("failed to find victimBlock with hash > foreignBlock.Hash (%s)", foreignBlock.Hash)
	}

	if err := ledger.AddBlock(victimBlock); err != nil {
		t.Fatalf("AddBlock(victimBlock): %v", err)
	}
	vm.OnBlockAdded(victimBlock)

	// Attacker (1 micro-XE weight) attempts to poison (honestRep, sendToAttacker.Hash)
	// by voting for foreignBlock.Hash (which belongs to attackerRep's chain).
	poisonVote := &core.Vote{
		RepPubKey:       attackerRep.PubKeyHex(),
		BlockHash:       foreignBlock.Hash,
		ConflictAccount: honestRep.Address(),
		ConflictPrev:    sendToAttacker.Hash,
		Timestamp:       nowNanos.Load(),
		Final:           false,
		Weight:          1,
	}
	signTestVote(t, attackerRep, poisonVote)

	if err := vm.ReceiveVote(poisonVote); err == nil {
		t.Errorf("expected ReceiveVote to reject cross-position vote referencing foreign block %s, got nil", foreignBlock.Hash)
	}

	// Even if a cross-position vote was stored before the foreign block arrived,
	// VoteManager must ignore it when gathering candidates, tracking stability
	// window resets, computing converge weights, and locking FinalVoteStore.
	nowNanos.Add(int64(2 * time.Second))
	if err := mem.PutVote(poisonVote); err != nil {
		t.Fatalf("PutVote(poisonVote): %v", err)
	}
	vm.CastVote(honestRep.Address(), sendToAttacker.Hash, victimBlock.Hash)

	// Advance 1.1s more (3.1s total since victimBlock was first seen, <3s since poisonVote).
	// Because foreignBlock does not belong to (honestRep, sendToAttacker.Hash), it must
	// not have reset lockStabilityWindow at t+2s.
	nowNanos.Add(int64(1100 * time.Millisecond))
	vm.CastVote(honestRep.Address(), sendToAttacker.Hash, victimBlock.Hash)

	lockedHash, ok, err := mem.GetFinalVote(honestRep.Address(), sendToAttacker.Hash)
	if err != nil {
		t.Fatalf("GetFinalVote: %v", err)
	}
	if !ok {
		t.Fatalf("expected FinalVoteStore to have locked a candidate for (%s, %s)", honestRep.Address(), sendToAttacker.Hash)
	}
	if lockedHash != victimBlock.Hash {
		t.Fatalf("FinalVoteStore locked foreign block %s instead of legitimate block %s", lockedHash, victimBlock.Hash)
	}
	if !ledger.IsFinalized(honestRep.Address(), victimBlock.Hash) {
		t.Fatalf("expected victimBlock %s to finalize; FinalHeight=%d", victimBlock.Hash, ledger.FinalHeight(honestRep.Address()))
	}
}

func TestQuorumFinalTallyDoesNotRejectForeignBlockViaCrossPositionVote(t *testing.T) {
	var nowNanos atomic.Int64
	nowNanos.Store(time.Unix(1_700_000_000, 0).UnixNano())
	origNow := core.Now
	core.Now = func() time.Time { return time.Unix(0, nowNanos.Load()) }
	defer func() { core.Now = origNow }()

	mem, ledger, vm, qm, honestRep, attackerRep, _, sendToAttacker := setupFinalityTestEnv(t, &nowNanos)

	victimSeed := make([]byte, ed25519.SeedSize)
	victimSeed[0] = 3
	victimKP := core.KeyPairFromSeed(victimSeed)

	victimStaged := &core.Block{
		Type:           core.BlockReceive,
		Account:        victimKP.Address(),
		Previous:       "0",
		Balance:        1,
		Amount:         1,
		Asset:          "XE",
		Source:         sendToAttacker.Hash,
		Representative: honestRep.Address(),
		Timestamp:      nowNanos.Load(),
	}
	core.MustSignBlock(victimStaged, victimKP)
	if err := mem.SaveStagedBlock(victimStaged); err != nil {
		t.Fatalf("SaveStagedBlock: %v", err)
	}

	nextHonest := &core.Block{
		Type:           core.BlockSend,
		Account:        honestRep.Address(),
		Previous:       sendToAttacker.Hash,
		Balance:        core.GenesisSupply - 2,
		Amount:         1,
		Asset:          "XE",
		Destination:    attackerRep.Address(),
		Representative: honestRep.Address(),
		Timestamp:      nowNanos.Load() + 1,
	}
	core.MustSignBlock(nextHonest, honestRep)
	if err := ledger.AddBlock(nextHonest); err != nil {
		t.Fatalf("AddBlock(nextHonest): %v", err)
	}
	vm.OnBlockAdded(nextHonest)

	// Inject a cross-position vote on (honestRep, sendToAttacker.Hash) naming victimStaged.Hash.
	crossVote := &core.Vote{
		RepPubKey:       attackerRep.PubKeyHex(),
		BlockHash:       victimStaged.Hash,
		ConflictAccount: honestRep.Address(),
		ConflictPrev:    sendToAttacker.Hash,
		Timestamp:       nowNanos.Load(),
		Final:           false,
		Weight:          1,
	}
	signTestVote(t, attackerRep, crossVote)
	if err := mem.PutVote(crossVote); err != nil {
		t.Fatalf("PutVote(crossVote): %v", err)
	}

	nowNanos.Add(int64(4 * time.Second))
	vm.CastVote(honestRep.Address(), sendToAttacker.Hash, nextHonest.Hash)
	qm.Retally(honestRep.Address(), sendToAttacker.Hash)

	if !ledger.IsFinalized(honestRep.Address(), nextHonest.Hash) {
		t.Fatalf("expected nextHonest %s to finalize", nextHonest.Hash)
	}

	status, err := mem.GetBlockStatus(victimStaged.Hash)
	if err != nil {
		t.Fatalf("GetBlockStatus(victimStaged): %v", err)
	}
	if status == core.StatusRejected {
		t.Fatalf("cross-position vote caused unrelated block %s to be marked StatusRejected", victimStaged.Hash)
	}
	stagedAfter, err := mem.GetStagedBlock(victimStaged.Hash)
	if err != nil {
		t.Fatalf("GetStagedBlock(victimStaged): %v", err)
	}
	if stagedAfter == nil {
		t.Fatalf("cross-position vote caused unrelated staged block %s to be deleted", victimStaged.Hash)
	}
}
