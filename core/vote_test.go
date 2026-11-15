package core_test

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

type putCounter struct {
	core.VoteStore
	puts atomic.Int64
}

func (p *putCounter) Load() int64 {
	return p.puts.Load()
}

func (p *putCounter) PutVote(v *core.Vote) error {
	p.puts.Add(1)
	return p.VoteStore.PutVote(v)
}

func setupVoteMgr(t *testing.T) (*core.VoteManager, *store.MemStore, *putCounter) {
	t.Helper()
	ms := store.NewMemStore()
	ledger := core.NewLedger(ms, core.LedgerConfig{})
	local, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	counter := &putCounter{VoteStore: ms}
	vm := core.NewVoteManager(counter, local, ledger)
	return vm, ms, counter
}

func mustKey(t *testing.T) *core.KeyPair {
	t.Helper()
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func grantWeight(l *core.Ledger, rep string, w int64) {
	l.SetWeightForTest(rep, w)
}

func hexID(n uint64) string {
	var buf [32]byte
	buf[0] = 0xA5
	binary.BigEndian.PutUint64(buf[24:], n)
	return hex.EncodeToString(buf[:])
}

func signVote(kp *core.KeyPair, account, prev, block string, ts int64) (*core.Vote, error) {
	v := &core.Vote{
		RepPubKey:       kp.PubKeyHex(),
		BlockHash:       block,
		ConflictAccount: account,
		ConflictPrev:    prev,
		Timestamp:       ts,
		Final:           false,
	}
	sb, err := core.VoteSigningBytes(v)
	if err != nil {
		return nil, err
	}
	v.Signature = ed25519.Sign(kp.Private, sb)
	return v, nil
}

func signedVote(t *testing.T, kp *core.KeyPair, account, prev, block string) *core.Vote {
	t.Helper()
	v, err := signVote(kp, account, prev, block, core.Now().UnixNano())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func saveConflict(t *testing.T, ms *store.MemStore, account, prev, voter string, hashes ...string) {
	t.Helper()
	if err := ms.SaveConflict(&core.Conflict{
		AccountAddress: account,
		PreviousHash:   prev,
		BlockHashes:    hashes,
		DetectedAt:     core.Now(),
		WeightSnapshot: map[string]uint64{voter: 100},
		TotalWeight:    100,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestReceiveVoteAbsentConflictNeverPersists(t *testing.T) {
	vm, ms, puts := setupVoteMgr(t)
	voter := mustKey(t)
	grantWeight(vm.LedgerForTest(), voter.Address(), 100)
	grantWeight(vm.LedgerForTest(), vm.KeyPairForTest().Address(), 100)

	account := hexID(1)
	prev := hexID(2)
	block := hexID(3)
	v := signedVote(t, voter, account, prev, block)

	if err := vm.ReceiveVote(v); err != nil {
		t.Fatal(err)
	}
	again := signedVote(t, voter, account, prev, block)
	if err := vm.ReceiveVote(again); err != nil {
		t.Fatal(err)
	}

	if puts.Load() != 0 {
		t.Fatalf("PutVote calls = %d, want 0", puts.Load())
	}
	got, err := ms.GetVote(account, prev, voter.PubKeyHex())
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatal("absent conflict was written to the vote store")
	}
	if n := vm.ConflictLockCountForTest(); n != 0 {
		t.Fatalf("conflict locks = %d, want 0", n)
	}
	if n := vm.PendingConflictCountForTest(); n != 1 {
		t.Fatalf("pending conflicts = %d, want 1", n)
	}
	if votes := vm.PendingVotesForTest(account, prev); len(votes) != 1 {
		t.Fatalf("pending votes = %d, want 1 after same-rep refresh", len(votes))
	}
	if seen := vm.SeenCandidatesCountForTest(); seen != 0 {
		t.Fatalf("seenCandidates = %d, want 0", seen)
	}

	bad := signedVote(t, voter, account, hexID(4), block)
	bad.Signature[0] ^= 0xff
	if err := vm.ReceiveVote(bad); err == nil {
		t.Fatal("tampered signature was accepted")
	}
	if vm.PendingConflictCountForTest() != 1 {
		t.Fatal("invalid signature entered the pending buffer")
	}

	stranger := mustKey(t)
	unowned := signedVote(t, stranger, account, hexID(5), block)
	if err := vm.ReceiveVote(unowned); err == nil {
		t.Fatal("zero-weight representative was accepted")
	}
	if puts.Load() != 0 || vm.ConflictLockCountForTest() != 0 {
		t.Fatal("rejected vote touched the store or the conflict lock map")
	}
}

func TestReceiveVotePendingBufferIsGloballyBounded(t *testing.T) {
	vm, _, puts := setupVoteMgr(t)
	voter := mustKey(t)
	grantWeight(vm.LedgerForTest(), voter.Address(), 100)
	grantWeight(vm.LedgerForTest(), vm.KeyPairForTest().Address(), 100)

	account := hexID(10)
	block := hexID(11)

	for i := 1; i <= core.MaxPendingConflictsForTest; i++ {
		v := signedVote(t, voter, account, hexID(uint64(i)), block)
		if err := vm.ReceiveVote(v); err != nil {
			t.Fatalf("vote %d: %v", i, err)
		}
	}
	if n := vm.PendingConflictCountForTest(); n != core.MaxPendingConflictsForTest {
		t.Fatalf("pending conflicts = %d, want %d", n, core.MaxPendingConflictsForTest)
	}

	// Refreshing the oldest key must not pin it.
	for n := 0; n < 20; n++ {
		v := signedVote(t, voter, account, hexID(1), block)
		if err := vm.ReceiveVote(v); err != nil {
			t.Fatal(err)
		}
	}
	if votes := vm.PendingVotesForTest(account, hexID(1)); len(votes) != 1 {
		t.Fatalf("refreshed key has %d votes, want 1", len(votes))
	}

	extra := signedVote(t, voter, account, hexID(uint64(core.MaxPendingConflictsForTest+1)), block)
	if err := vm.ReceiveVote(extra); err != nil {
		t.Fatal(err)
	}
	if n := vm.PendingConflictCountForTest(); n != core.MaxPendingConflictsForTest {
		t.Fatalf("after eviction pending conflicts = %d, want %d", n, core.MaxPendingConflictsForTest)
	}
	if vm.PendingVotesForTest(account, hexID(1)) != nil {
		t.Fatal("oldest conflict key survived a new insertion")
	}
	if vm.PendingVotesForTest(account, hexID(2)) == nil {
		t.Fatal("second-oldest key was evicted ahead of the oldest")
	}
	if vm.PendingVotesForTest(account, hexID(uint64(core.MaxPendingConflictsForTest+1))) == nil {
		t.Fatal("newest conflict key was not admitted")
	}
	if puts.Load() != 0 {
		t.Fatalf("flood issued %d PutVote calls", puts.Load())
	}
	if n := vm.ConflictLockCountForTest(); n != 0 {
		t.Fatalf("flood allocated %d conflict locks", n)
	}
	if seen := vm.SeenCandidatesCountForTest(); seen != 0 {
		t.Fatalf("flood grew seenCandidates to %d", seen)
	}
}

func TestReceiveVotePerConflictCap(t *testing.T) {
	vm, _, puts := setupVoteMgr(t)
	account := hexID(20)
	prev := hexID(21)
	block := hexID(22)

	var reps []*core.KeyPair
	for i := 0; i < core.MaxPendingVotesPerConflictForTest+1; i++ {
		kp := mustKey(t)
		grantWeight(vm.LedgerForTest(), kp.Address(), 50)
		reps = append(reps, kp)
		v := signedVote(t, kp, account, prev, block)
		if err := vm.ReceiveVote(v); err != nil {
			t.Fatal(err)
		}
	}
	// Same representative refreshing must not consume another slot.
	for n := 0; n < 30; n++ {
		v := signedVote(t, reps[0], account, prev, block)
		if err := vm.ReceiveVote(v); err != nil {
			t.Fatal(err)
		}
	}

	votes := vm.PendingVotesForTest(account, prev)
	if len(votes) != core.MaxPendingVotesPerConflictForTest {
		t.Fatalf("pending votes = %d, want %d", len(votes), core.MaxPendingVotesPerConflictForTest)
	}
	last := reps[len(reps)-1].PubKeyHex()
	for _, v := range votes {
		if v.RepPubKey == last {
			t.Fatal("vote past the per-conflict cap was retained")
		}
	}
	found := false
	for _, v := range votes {
		if v.RepPubKey == reps[0].PubKeyHex() {
			found = true
		}
	}
	if !found {
		t.Fatal("first representative was evicted by its own refreshes")
	}
	if vm.PendingConflictCountForTest() != 1 {
		t.Fatal("per-conflict cap grew the conflict-key map")
	}
	if puts.Load() != 0 || vm.ConflictLockCountForTest() != 0 {
		t.Fatal("capped pending votes touched the store or allocated a lock")
	}
}

func TestReceiveVoteReplayWhenConflictArrives(t *testing.T) {
	t.Run("on conflict", func(t *testing.T) {
		vm, ms, puts := setupVoteMgr(t)
		voter := mustKey(t)
		grantWeight(vm.LedgerForTest(), voter.Address(), 100)

		account := hexID(30)
		prev := hexID(31)
		block := hexID(32)
		decoyPrev := hexID(33)
		v := signedVote(t, voter, account, prev, block)
		decoy := signedVote(t, voter, account, decoyPrev, block)
		if err := vm.ReceiveVote(v); err != nil {
			t.Fatal(err)
		}
		if err := vm.ReceiveVote(decoy); err != nil {
			t.Fatal(err)
		}

		saveConflict(t, ms, account, prev, voter.Address(), block, hexID(34))
		vm.OnConflict(core.Conflict{
			AccountAddress: account,
			PreviousHash:   prev,
			BlockHashes:    []string{block, hexID(34)},
		})

		got, err := ms.GetVote(account, prev, voter.PubKeyHex())
		if err != nil {
			t.Fatal(err)
		}
		if got == nil {
			t.Fatal("buffered vote was not replayed")
		}
		if got.BlockHash != block || got.Weight != 100 {
			t.Fatalf("replayed vote = hash %s weight %d", got.BlockHash, got.Weight)
		}
		decoyStored, err := ms.GetVote(account, decoyPrev, voter.PubKeyHex())
		if err != nil {
			t.Fatal(err)
		}
		if decoyStored != nil {
			t.Fatal("unrelated pending vote was written during replay")
		}
		if vm.PendingVotesForTest(account, prev) != nil {
			t.Fatal("replayed conflict is still buffered")
		}
		if vm.PendingVotesForTest(account, decoyPrev) == nil {
			t.Fatal("unrelated pending vote was dropped")
		}
		if puts.Load() != 1 {
			t.Fatalf("PutVote calls = %d, want 1", puts.Load())
		}
		if n := vm.ConflictLockCountForTest(); n != 1 {
			t.Fatalf("conflict locks = %d, want 1 real conflict", n)
		}
	})

	t.Run("later vote flushes earlier buffer", func(t *testing.T) {
		vm, ms, puts := setupVoteMgr(t)
		first := mustKey(t)
		second := mustKey(t)
		grantWeight(vm.LedgerForTest(), first.Address(), 100)
		grantWeight(vm.LedgerForTest(), second.Address(), 100)

		account := hexID(40)
		prev := hexID(41)
		block := hexID(42)
		early := signedVote(t, first, account, prev, block)
		if err := vm.ReceiveVote(early); err != nil {
			t.Fatal(err)
		}
		saveConflict(t, ms, account, prev, first.Address(), block, hexID(43))
		c, err := ms.GetConflict(account, prev)
		if err != nil {
			t.Fatal(err)
		}
		c.WeightSnapshot[second.Address()] = 100
		if err := ms.SaveConflict(c); err != nil {
			t.Fatal(err)
		}

		late := signedVote(t, second, account, prev, block)
		if err := vm.ReceiveVote(late); err != nil {
			t.Fatal(err)
		}
		for _, kp := range []*core.KeyPair{first, second} {
			got, err := ms.GetVote(account, prev, kp.PubKeyHex())
			if err != nil {
				t.Fatal(err)
			}
			if got == nil {
				t.Fatalf("vote from %s was not stored", kp.Address()[:8])
			}
		}
		if vm.PendingVotesForTest(account, prev) != nil {
			t.Fatal("buffer survived the direct-path flush")
		}
		if puts.Load() != 2 {
			t.Fatalf("PutVote calls = %d, want 2", puts.Load())
		}
	})

	t.Run("stale buffered vote is dropped on replay", func(t *testing.T) {
		vm, ms, puts := setupVoteMgr(t)
		voter := mustKey(t)
		grantWeight(vm.LedgerForTest(), voter.Address(), 100)

		start := time.Unix(1_700_000_000, 0)
		prevNow := core.Now
		core.Now = func() time.Time { return start }
		t.Cleanup(func() { core.Now = prevNow })

		account := hexID(50)
		prev := hexID(51)
		block := hexID(52)
		v := signedVote(t, voter, account, prev, block)
		if err := vm.ReceiveVote(v); err != nil {
			t.Fatal(err)
		}

		core.Now = func() time.Time { return start.Add(6 * time.Minute) }
		saveConflict(t, ms, account, prev, voter.Address(), block, hexID(53))
		vm.OnConflict(core.Conflict{
			AccountAddress: account,
			PreviousHash:   prev,
			BlockHashes:    []string{block, hexID(53)},
		})
		got, err := ms.GetVote(account, prev, voter.PubKeyHex())
		if err != nil {
			t.Fatal(err)
		}
		if got != nil {
			t.Fatal("expired buffered vote was persisted")
		}
		if vm.PendingVotesForTest(account, prev) != nil {
			t.Fatal("expired vote remained buffered")
		}
		if puts.Load() != 0 {
			t.Fatalf("PutVote calls = %d, want 0", puts.Load())
		}
	})

	t.Run("conflict already present", func(t *testing.T) {
		vm, ms, puts := setupVoteMgr(t)
		voter := mustKey(t)
		grantWeight(vm.LedgerForTest(), voter.Address(), 100)
		account := hexID(60)
		prev := hexID(61)
		block := hexID(62)
		saveConflict(t, ms, account, prev, voter.Address(), block, hexID(63))

		v := signedVote(t, voter, account, prev, block)
		if err := vm.ReceiveVote(v); err != nil {
			t.Fatal(err)
		}
		got, err := ms.GetVote(account, prev, voter.PubKeyHex())
		if err != nil {
			t.Fatal(err)
		}
		if got == nil || got.BlockHash != block {
			t.Fatal("vote for a live conflict was not stored")
		}
		if vm.PendingConflictCountForTest() != 0 {
			t.Fatal("live conflict was buffered")
		}
		if puts.Load() != 1 {
			t.Fatalf("PutVote calls = %d, want 1", puts.Load())
		}
		if n := vm.ConflictLockCountForTest(); n != 1 {
			t.Fatalf("conflict locks = %d, want 1", n)
		}
	})
}

func TestReceiveVoteConcurrentFlood(t *testing.T) {
	vm, _, puts := setupVoteMgr(t)
	voter := mustKey(t)
	grantWeight(vm.LedgerForTest(), voter.Address(), 100)
	grantWeight(vm.LedgerForTest(), vm.KeyPairForTest().Address(), 100)

	const workers = 32
	const each = 40
	var wg sync.WaitGroup
	errCh := make(chan error, workers*each)
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			for k := 0; k < each; k++ {
				id := uint64(w*each + k + 1)
				v, err := signVote(voter, hexID(id), hexID(id+1_000_000), hexID(9), core.Now().UnixNano())
				if err != nil {
					errCh <- err
					return
				}
				if err := vm.ReceiveVote(v); err != nil {
					errCh <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
	if puts.Load() != 0 {
		t.Fatalf("concurrent flood issued %d PutVote calls", puts.Load())
	}
	if n := vm.ConflictLockCountForTest(); n != 0 {
		t.Fatalf("concurrent flood allocated %d conflict locks", n)
	}
	if n := vm.PendingConflictCountForTest(); n > core.MaxPendingConflictsForTest {
		t.Fatalf("pending conflicts = %d, ceiling is %d", n, core.MaxPendingConflictsForTest)
	}
}
