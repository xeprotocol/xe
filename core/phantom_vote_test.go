package core_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"

	. "github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func phantomVoteSigningBytes(v *Vote) ([]byte, error) {
	repB, err := hex.DecodeString(v.RepPubKey)
	if err != nil || len(repB) != 32 {
		return nil, err
	}
	blkB, err := hex.DecodeString(v.BlockHash)
	if err != nil || len(blkB) != 32 {
		return nil, err
	}
	acctB, err := hex.DecodeString(v.ConflictAccount)
	if err != nil || len(acctB) != 32 {
		return nil, err
	}
	var prevB []byte
	if v.ConflictPrev == "0" {
		prevB = make([]byte, 32)
	} else {
		prevB, err = hex.DecodeString(v.ConflictPrev)
		if err != nil || len(prevB) != 32 {
			return nil, err
		}
	}
	var buf []byte
	buf = append(buf, 0x02)
	buf = append(buf, repB...)
	buf = append(buf, blkB...)
	buf = append(buf, acctB...)
	buf = append(buf, prevB...)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(v.Timestamp))
	buf = append(buf, ts[:]...)
	if v.Final {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	return buf, nil
}

func phantomRandHex(t *testing.T) string {
	t.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b[:])
}

// TestTrackB_PhantomVotes verifies that votes for nonexistent conflicts
// are rejected at ingress and never stored in the persistent vote store (#532).
func TestTrackB_PhantomVotes(t *testing.T) {
	repA, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("repA: %v", err)
	}
	funder, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("funder: %v", err)
	}
	st := store.NewMemStore()
	led := NewLedger(st, LedgerConfig{Difficulty: 0, TimestampWindow: 0})

	now := time.Now().UnixNano()
	mint := &Block{
		Type: BlockMint, Asset: "XE", Account: funder.Address(),
		Previous: "0", Balance: 100_000_000_000_000, Amount: 100_000_000_000_000,
		Representative: repA.Address(), Timestamp: now,
	}
	if err := SignBlock(mint, funder); err != nil {
		t.Fatalf("sign mint: %v", err)
	}
	if err := led.SeedAssetForTesting(mint); err != nil {
		t.Fatalf("seed mint: %v", err)
	}

	vm := NewVoteManager(st, nil, led)
	qm := NewQuorumManager(st, st, st, led)
	vm.SetQuorumManager(qm)

	// 1. Submit 200 votes for random nonexistent (account, prev, block) pairs
	var sampleKeys [][2]string
	for i := 0; i < 200; i++ {
		acct := phantomRandHex(t)
		prev := phantomRandHex(t)
		blk := phantomRandHex(t)

		v := &Vote{
			RepPubKey:       repA.PubKeyHex(),
			BlockHash:       blk,
			ConflictAccount: acct,
			ConflictPrev:    prev,
			Timestamp:       time.Now().UnixNano(),
			Final:           true,
		}
		sb, err := phantomVoteSigningBytes(v)
		if err != nil {
			t.Fatalf("signing bytes: %v", err)
		}
		v.Signature = ed25519.Sign(repA.Private, sb)
		if !VerifyVoteSignature(v) {
			t.Fatalf("signature verify failed")
		}

		err = vm.ReceiveVote(v)
		if err == nil {
			t.Fatalf("expected phantom vote %d to be rejected, but ReceiveVote returned nil", i)
		}

		if i < 10 {
			sampleKeys = append(sampleKeys, [2]string{acct, prev})
		}
	}

	// 2. Ensure none of the sample phantom keys were persisted in the vote store
	for _, k := range sampleKeys {
		vs, err := st.GetVotesByConflict(k[0], k[1])
		if err != nil {
			t.Fatalf("GetVotesByConflict: %v", err)
		}
		if len(vs) != 0 {
			t.Fatalf("phantom vote for %s|%s stored in vote store (got %d entries, want 0)", k[0][:8], k[1][:8], len(vs))
		}
		if led.GetConflict(k[0], k[1]) != nil {
			t.Fatalf("unexpected conflict record found for phantom key")
		}
	}

	// 3. Verify that under a real conflict, valid votes are accepted and stored
	victim, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("victim: %v", err)
	}
	dest, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("dest: %v", err)
	}
	victimMint := &Block{
		Type: BlockMint, Asset: "XE", Account: victim.Address(),
		Previous: "0", Balance: 1000, Amount: 1000,
		Representative: victim.Address(), Timestamp: now,
	}
	if err := SignBlock(victimMint, victim); err != nil {
		t.Fatalf("sign victim mint: %v", err)
	}
	if err := led.SeedAssetForTesting(victimMint); err != nil {
		t.Fatalf("seed victim mint: %v", err)
	}

	s1 := &Block{
		Type: BlockSend, Asset: "XE", Account: victim.Address(),
		Previous: victimMint.Hash, Balance: 990, Amount: 10,
		Destination: dest.Address(), Timestamp: now + int64(10*time.Second),
	}
	if err := SignBlock(s1, victim); err != nil {
		t.Fatalf("sign s1: %v", err)
	}
	if err := led.AddBlock(s1); err != nil {
		t.Fatalf("add s1: %v", err)
	}

	s2 := &Block{
		Type: BlockSend, Asset: "XE", Account: victim.Address(),
		Previous: victimMint.Hash, Balance: 980, Amount: 20,
		Destination: repA.Address(), Timestamp: now + int64(11*time.Second),
	}
	if err := SignBlock(s2, victim); err != nil {
		t.Fatalf("sign s2: %v", err)
	}
	if err := led.AddBlock(s2); err != nil {
		t.Fatalf("add s2: %v", err)
	}

	c := led.GetConflict(victim.Address(), victimMint.Hash)
	if c == nil {
		t.Fatalf("expected conflict record after s2")
	}

	// Under this real conflict, a vote for a candidate block hash is accepted and stored
	validVote := &Vote{
		RepPubKey:       repA.PubKeyHex(),
		BlockHash:       s1.Hash,
		ConflictAccount: victim.Address(),
		ConflictPrev:    victimMint.Hash,
		Timestamp:       time.Now().UnixNano(),
		Final:           false,
	}
	sb, err := phantomVoteSigningBytes(validVote)
	if err != nil {
		t.Fatalf("signing bytes: %v", err)
	}
	validVote.Signature = ed25519.Sign(repA.Private, sb)
	if err := vm.ReceiveVote(validVote); err != nil {
		t.Fatalf("valid vote under real conflict rejected: %v", err)
	}

	vs, err := st.GetVotesByConflict(victim.Address(), victimMint.Hash)
	if err != nil || len(vs) != 1 {
		t.Fatalf("expected 1 stored vote under real conflict, got %d (err: %v)", len(vs), err)
	}
}
