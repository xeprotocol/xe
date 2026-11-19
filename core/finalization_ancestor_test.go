package core_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

type c2Node struct {
	l  *core.Ledger
	ms *store.MemStore
	vm *core.VoteManager
	qm *core.QuorumManager
}

func newC2Node(t *testing.T) *c2Node {
	t.Helper()
	ms := store.NewMemStore()
	l := core.NewLedger(ms, core.LedgerConfig{Difficulty: 0, TimestampWindow: 0})
	vm := core.NewVoteManager(ms, nil, l)
	qm := core.NewQuorumManager(ms, ms, ms, l)
	vm.SetQuorumManager(qm)
	return &c2Node{l: l, ms: ms, vm: vm, qm: qm}
}

func c2Key(t *testing.T) *core.KeyPair {
	t.Helper()
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return kp
}

func c2FundAt(t *testing.T, l *core.Ledger, kp *core.KeyPair, amount uint64, repAddr string, ts int64) *core.Block {
	t.Helper()
	b := &core.Block{
		Type:           core.BlockMint,
		Account:        kp.Address(),
		Previous:       "0",
		Balance:        amount,
		Amount:         amount,
		Timestamp:      ts,
		Asset:          "XE",
		PubKey:         kp.PubKeyHex(),
		Representative: repAddr,
	}
	if err := core.SignBlock(b, kp); err != nil {
		t.Fatalf("fund sign: %v", err)
	}
	if err := l.SeedAssetForTesting(b); err != nil {
		t.Fatalf("fund %s: %v", kp.Address()[:12], err)
	}
	return b
}

func c2Send(t *testing.T, kp *core.KeyPair, previous string, balance, amount uint64, dest string, ts int64) *core.Block {
	t.Helper()
	b := &core.Block{
		Type:        core.BlockSend,
		Account:     kp.Address(),
		Previous:    previous,
		Balance:     balance,
		Amount:      amount,
		Timestamp:   ts,
		Asset:       "XE",
		Destination: dest,
	}
	if err := core.SignBlock(b, kp); err != nil {
		t.Fatalf("send sign: %v", err)
	}
	return b
}

func c2SignVote(t *testing.T, repKp *core.KeyPair, blockHash, account, prev string, final bool) *core.Vote {
	t.Helper()
	rep, _ := hex.DecodeString(repKp.PubKeyHex())
	bh, _ := hex.DecodeString(blockHash)
	acc, _ := hex.DecodeString(account)
	var pv []byte
	if prev == "0" {
		pv = make([]byte, 32)
	} else {
		pv, _ = hex.DecodeString(prev)
	}
	v := &core.Vote{
		RepPubKey:       repKp.PubKeyHex(),
		BlockHash:       blockHash,
		ConflictAccount: account,
		ConflictPrev:    prev,
		Timestamp:       core.Now().UnixNano(),
		Final:           final,
	}
	var buf bytes.Buffer
	buf.WriteByte(0x02)
	buf.Write(rep)
	buf.Write(bh)
	buf.Write(acc)
	buf.Write(pv)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(v.Timestamp))
	buf.Write(ts[:])
	if final {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	v.Signature = ed25519.Sign(repKp.Private, buf.Bytes())
	return v
}

func c2RecvFinal(t *testing.T, n *c2Node, repKp *core.KeyPair, blockHash, account, prev string) {
	t.Helper()
	v := c2SignVote(t, repKp, blockHash, account, prev, true)
	if err := n.vm.ReceiveVote(v); err != nil {
		t.Fatalf("ReceiveVote %s: %v", blockHash[:12], err)
	}
}

func TestDescendantCannotImplicitlyFinalizeUnfinalizedAncestor(t *testing.T) {
	rep1, rep2 := c2Key(t), c2Key(t)
	d1, d2, v := c2Key(t), c2Key(t), c2Key(t)

	n1 := newC2Node(t)
	n2 := newC2Node(t)

	fundTs := core.Now().UnixNano()
	var seedV1 *core.Block
	for _, nd := range []*c2Node{n1, n2} {
		c2FundAt(t, nd.l, d1, 60_000_000_000_000, rep1.Address(), fundTs)
		c2FundAt(t, nd.l, d2, 40_000_000_000_000, rep2.Address(), fundTs)
		sv := c2FundAt(t, nd.l, v, 10_000_000_000_000, rep1.Address(), fundTs)
		if nd == n1 {
			seedV1 = sv
		}
	}

	ts := core.Now().UnixNano() + 1_000_000

	// Create fork pair A4 vs B4 at (v, seed).
	a4 := c2Send(t, v, seedV1.Hash, 9_000_000_000_000, 1_000_000_000_000, c2Key(t).Address(), ts)
	var b4 *core.Block
	for delta := uint64(0); delta < 100_000; delta++ {
		cand := c2Send(t, v, seedV1.Hash, 10_000_000_000_000-(1_000_000_000_000+delta), 1_000_000_000_000+delta, c2Key(t).Address(), ts)
		if cand.Hash < a4.Hash {
			b4 = cand
			break
		}
	}
	if b4 == nil {
		t.Fatalf("could not grind B4 < A4")
	}

	// A5 extends A4
	a5 := c2Send(t, v, a4.Hash, 8_000_000_000_000, 1_000_000_000_000, c2Key(t).Address(), ts+1_000_000)

	// Node 1 receives A4 and A5
	if err := n1.l.AddBlock(a4); err != nil {
		t.Fatalf("n1 add a4: %v", err)
	}
	if err := n1.l.AddBlock(a5); err != nil {
		t.Fatalf("n1 add a5: %v", err)
	}

	// Reps send final votes for A5 at position (v, A4)
	c2RecvFinal(t, n1, rep1, a5.Hash, v.Address(), a4.Hash)
	c2RecvFinal(t, n1, rep2, a5.Hash, v.Address(), a4.Hash)
	n1.qm.Retally(v.Address(), a4.Hash)

	// CRITICAL FIX CHECK:
	// A5 must NOT be finalized, and A4 must NOT be implicitly finalized!
	if n1.l.IsFinalized(v.Address(), a4.Hash) {
		t.Fatalf("BUG: A4 was implicitly finalized via A5 without winning its own position election!")
	}
	if n1.l.IsFinalized(v.Address(), a5.Hash) {
		t.Fatalf("BUG: A5 was finalized even though its predecessor A4 is not finalized!")
	}
	if fh := n1.l.FinalHeight(v.Address()); fh > 1 {
		t.Fatalf("BUG: FinalHeight advanced past unfinalized predecessor: got %d, want 1", fh)
	}

	// Now B4 arrives at Node 1. Because A4 is NOT finalized, B4 must NOT be rejected as
	// "conflicts with finalized block"!
	if err := n1.l.AddBlock(b4); err != nil {
		t.Fatalf("n1 must accept B4 as conflict, got error: %v", err)
	}

	// Node 2 receives A4 and B4, forms conflict at (v, seed)
	if err := n2.l.AddBlock(a4); err != nil {
		t.Fatalf("n2 add a4: %v", err)
	}
	if err := n2.l.AddBlock(b4); err != nil {
		t.Fatalf("n2 add b4: %v", err)
	}

	// Reps vote for B4 at position (v, seed) on both nodes (honest lowest-hash pick B4 < A4)
	for _, nd := range []*c2Node{n1, n2} {
		c2RecvFinal(t, nd, rep1, b4.Hash, v.Address(), seedV1.Hash)
		c2RecvFinal(t, nd, rep2, b4.Hash, v.Address(), seedV1.Hash)
		nd.qm.Retally(v.Address(), seedV1.Hash)

		if !nd.l.IsFinalized(v.Address(), b4.Hash) {
			t.Fatalf("B4 must be finalized at position (v, seed)")
		}
		if nd.l.IsFinalized(v.Address(), a4.Hash) {
			t.Fatalf("A4 must NOT be finalized")
		}
	}

	// Both nodes converged on B4, preventing the split!
}

func TestSequentialFinalizationPreserved(t *testing.T) {
	rep1, rep2 := c2Key(t), c2Key(t)
	d1, d2, v := c2Key(t), c2Key(t), c2Key(t)

	n := newC2Node(t)
	fundTs := core.Now().UnixNano()
	c2FundAt(t, n.l, d1, 60_000_000_000_000, rep1.Address(), fundTs)
	c2FundAt(t, n.l, d2, 40_000_000_000_000, rep2.Address(), fundTs)
	seed := c2FundAt(t, n.l, v, 10_000_000_000_000, rep1.Address(), fundTs)

	ts := core.Now().UnixNano() + 1_000_000
	b1 := c2Send(t, v, seed.Hash, 9_000_000_000_000, 1_000_000_000_000, c2Key(t).Address(), ts)
	b2 := c2Send(t, v, b1.Hash, 8_000_000_000_000, 1_000_000_000_000, c2Key(t).Address(), ts+1_000_000)

	if err := n.l.AddBlock(b1); err != nil {
		t.Fatalf("add b1: %v", err)
	}
	if err := n.l.AddBlock(b2); err != nil {
		t.Fatalf("add b2: %v", err)
	}

	// First finalize b1 at position (v, seed.Hash)
	c2RecvFinal(t, n, rep1, b1.Hash, v.Address(), seed.Hash)
	c2RecvFinal(t, n, rep2, b1.Hash, v.Address(), seed.Hash)
	n.qm.Retally(v.Address(), seed.Hash)

	if !n.l.IsFinalized(v.Address(), b1.Hash) {
		t.Fatalf("b1 should be finalized")
	}
	if n.l.FinalHeight(v.Address()) != 2 {
		t.Fatalf("final height after b1: got %d, want 2", n.l.FinalHeight(v.Address()))
	}

	// Now finalize b2 at position (v, b1.Hash)
	c2RecvFinal(t, n, rep1, b2.Hash, v.Address(), b1.Hash)
	c2RecvFinal(t, n, rep2, b2.Hash, v.Address(), b1.Hash)
	n.qm.Retally(v.Address(), b1.Hash)

	if !n.l.IsFinalized(v.Address(), b2.Hash) {
		t.Fatalf("b2 should be finalized")
	}
	if n.l.FinalHeight(v.Address()) != 3 {
		t.Fatalf("final height after b2: got %d, want 3", n.l.FinalHeight(v.Address()))
	}
}
