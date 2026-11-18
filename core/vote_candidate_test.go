package core_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func makeTestKP() *core.KeyPair {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return &core.KeyPair{Public: pub, Private: priv}
}

func signTestVote(t *testing.T, repKp *core.KeyPair, blockHash, account, prev string, final bool) *core.Vote {
	t.Helper()
	rep, _ := hex.DecodeString(repKp.PubKeyHex())
	bh, _ := hex.DecodeString(blockHash)
	acc, _ := hex.DecodeString(account)
	var pr []byte
	if prev == "0" {
		pr = make([]byte, 32)
	} else {
		pr, _ = hex.DecodeString(prev)
	}
	ts := time.Now().UnixNano()
	var tsBytes [8]byte
	binary.BigEndian.PutUint64(tsBytes[:], uint64(ts))
	var buf bytes.Buffer
	buf.WriteByte(0x02) // voteVersionByte
	buf.Write(rep)
	buf.Write(bh)
	buf.Write(acc)
	buf.Write(pr)
	buf.Write(tsBytes[:])
	if final {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	sig := ed25519.Sign(repKp.Private, buf.Bytes())
	return &core.Vote{
		RepPubKey:       repKp.PubKeyHex(),
		BlockHash:       blockHash,
		ConflictAccount: account,
		ConflictPrev:    prev,
		Timestamp:       ts,
		Final:           final,
		Signature:       sig,
	}
}

func fundTestRep(t *testing.T, l *core.Ledger, kp *core.KeyPair, amount uint64) {
	t.Helper()
	b := &core.Block{
		Type:           core.BlockMint,
		Account:        kp.Address(),
		Previous:       "0",
		Balance:        amount,
		Amount:         amount,
		Timestamp:      time.Now().UnixNano(),
		Asset:          "XE",
		PubKey:         kp.PubKeyHex(),
		Representative: kp.Address(),
	}
	if err := core.SignBlock(b, kp); err != nil {
		t.Fatalf("fund sign: %v", err)
	}
	if err := l.SeedAssetForTesting(b); err != nil {
		t.Fatalf("fund seed: %v", err)
	}
}

func TestReceiveVoteNonCandidateRejected(t *testing.T) {
	ms := store.NewMemStore()
	l := core.NewLedger(ms, core.LedgerConfig{})
	vm := core.NewVoteManager(ms, nil, l)
	repKp := makeTestKP()
	fundTestRep(t, l, repKp, 1_000_000)

	account := strings.Repeat("1", 64)
	prev := strings.Repeat("2", 64)
	candA := strings.Repeat("a", 64)
	candB := strings.Repeat("b", 64)
	nonCand := strings.Repeat("c", 64)

	// Save conflict record
	c := core.NewConflict(account, prev, candA, candB)
	if err := ms.SaveConflict(c); err != nil {
		t.Fatalf("SaveConflict: %v", err)
	}

	vote := signTestVote(t, repKp, nonCand, account, prev, true)
	err := vm.ReceiveVote(vote)
	if err == nil {
		t.Fatal("expected ReceiveVote for non-candidate hash to be rejected, got nil")
	}
	if !strings.Contains(err.Error(), "not a candidate in conflict") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestReceiveVoteBufferedBeforeConflictRecorded(t *testing.T) {
	ms := store.NewMemStore()
	l := core.NewLedger(ms, core.LedgerConfig{})
	vm := core.NewVoteManager(ms, nil, l)
	repKp := makeTestKP()
	fundTestRep(t, l, repKp, 1_000_000)

	account := strings.Repeat("1", 64)
	prev := strings.Repeat("2", 64)
	candA := strings.Repeat("a", 64)
	candB := strings.Repeat("b", 64)

	// 1. Vote for candA arrives BEFORE conflict is recorded
	vote := signTestVote(t, repKp, candA, account, prev, true)
	err := vm.ReceiveVote(vote)
	if err != nil {
		t.Fatalf("expected vote arriving before block to be buffered without error, got: %v", err)
	}

	// Verify not yet stored in vote store
	stored, _ := ms.GetVote(account, prev, repKp.PubKeyHex())
	if stored != nil {
		t.Fatal("vote should not be stored in VoteStore before conflict is recorded")
	}

	// 2. Conflict arrives
	c := core.NewConflict(account, prev, candA, candB)
	if err := ms.SaveConflict(c); err != nil {
		t.Fatalf("SaveConflict: %v", err)
	}
	vm.OnConflict(*c)

	// 3. Verify vote is now flushed and stored
	stored, err = ms.GetVote(account, prev, repKp.PubKeyHex())
	if err != nil || stored == nil {
		t.Fatalf("expected buffered vote to be flushed and stored, got stored=%v, err=%v", stored, err)
	}
	if stored.BlockHash != candA {
		t.Fatalf("expected stored vote to have block hash %s, got %s", candA, stored.BlockHash)
	}
}

func TestReceiveVoteVoteBurnAvoidedOnDroppedSibling(t *testing.T) {
	ms := store.NewMemStore()
	l := core.NewLedger(ms, core.LedgerConfig{})
	vm := core.NewVoteManager(ms, nil, l)
	repKp := makeTestKP()
	fundTestRep(t, l, repKp, 1_000_000)

	account := strings.Repeat("1", 64)
	prev := strings.Repeat("2", 64)

	cand1 := strings.Repeat("a", 64)
	cand2 := strings.Repeat("b", 64)
	droppedS11 := strings.Repeat("f", 64)

	// 1. Final vote for dropped 11th sibling arrives when conflict == nil
	vote11 := signTestVote(t, repKp, droppedS11, account, prev, true)
	err := vm.ReceiveVote(vote11)
	if err != nil {
		t.Fatalf("ReceiveVote before conflict: expected nil, got %v", err)
	}

	// 2. Conflict record arrives containing cand1 and cand2 (droppedS11 was rejected/not recorded)
	c := core.NewConflict(account, prev, cand1, cand2)
	if err := ms.SaveConflict(c); err != nil {
		t.Fatalf("SaveConflict: %v", err)
	}
	vm.OnConflict(*c)

	// Verify droppedS11 was NOT stored because it's not in conflict.BlockHashes
	stored, _ := ms.GetVote(account, prev, repKp.PubKeyHex())
	if stored != nil {
		t.Fatalf("dropped sibling vote should not be stored, but found: %+v", stored)
	}

	// 3. Rep later casts final vote for held candidate cand2
	vote2 := signTestVote(t, repKp, cand2, account, prev, true)
	err = vm.ReceiveVote(vote2)
	if err != nil {
		t.Fatalf("ReceiveVote for valid candidate cand2 failed: %v", err)
	}

	// Verify cand2 IS stored
	stored, err = ms.GetVote(account, prev, repKp.PubKeyHex())
	if err != nil || stored == nil {
		t.Fatalf("expected vote for cand2 to be stored, got stored=%v, err=%v", stored, err)
	}
	if stored.BlockHash != cand2 {
		t.Fatalf("expected stored vote for cand2, got %s", stored.BlockHash)
	}
}
