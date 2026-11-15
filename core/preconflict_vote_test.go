package core_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

type c1Node struct {
	l  *core.Ledger
	ms *store.MemStore
	vm *core.VoteManager
	qm *core.QuorumManager
}

func newC1Node(t *testing.T) *c1Node {
	t.Helper()
	core.SetNetworkID("")
	ms := store.NewMemStore()
	l := core.NewLedger(ms, core.LedgerConfig{Difficulty: 0, TimestampWindow: 0})
	vm := core.NewVoteManager(ms, nil, l)
	qm := core.NewQuorumManager(ms, ms, ms, l)
	vm.SetQuorumManager(qm)
	l.SetConflictCallback(vm.OnConflict)
	return &c1Node{l: l, ms: ms, vm: vm, qm: qm}
}

func c1Key(t *testing.T) *core.KeyPair {
	t.Helper()
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return kp
}

func c1FundAt(t *testing.T, l *core.Ledger, kp *core.KeyPair, amount uint64, repAddr string, ts int64) *core.Block {
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

func c1Fund(t *testing.T, l *core.Ledger, kp *core.KeyPair, amount uint64, repAddr string) *core.Block {
	t.Helper()
	return c1FundAt(t, l, kp, amount, repAddr, core.Now().UnixNano())
}

func c1SignSend(t *testing.T, kp *core.KeyPair, previous string, balance, amount uint64, dest string, ts int64) *core.Block {
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

func c1SignVote(t *testing.T, repKp *core.KeyPair, blockHash, account, prev string, final bool) *core.Vote {
	t.Helper()
	rep, err := hex.DecodeString(repKp.PubKeyHex())
	if err != nil || len(rep) != 32 {
		t.Fatalf("rep decode: %v", err)
	}
	bh, err := hex.DecodeString(blockHash)
	if err != nil || len(bh) != 32 {
		t.Fatalf("blockhash decode: %v", err)
	}
	acc, err := hex.DecodeString(account)
	if err != nil || len(acc) != 32 {
		t.Fatalf("account decode: %v", err)
	}
	var pv []byte
	if prev == "0" {
		pv = make([]byte, 32)
	} else {
		pv, err = hex.DecodeString(prev)
		if err != nil || len(pv) != 32 {
			t.Fatalf("prev decode: %v", err)
		}
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

func c1Weight(t *testing.T, l *core.Ledger, addr string) uint64 {
	t.Helper()
	w := l.GetVoteWeight(addr)
	if !w.IsUint64() {
		t.Fatalf("weight %s does not fit uint64: %s", addr[:12], w.String())
	}
	return w.Uint64()
}

func c1FmtXE(u uint64) string { return fmt.Sprintf("%d", u) }

func TestStalePreConflictFinalVoteCannotClearQuorum(t *testing.T) {
	n := newC1Node(t)
	l, ms, vm, qm := n.l, n.ms, n.vm, n.qm

	repA, repB := c1Key(t), c1Key(t)
	addrA, addrB := repA.Address(), repB.Address()
	dA := c1Key(t) // attacker delegator
	dB := c1Key(t) // honest delegator
	v := c1Key(t)  // victim/fork account
	sink := c1Key(t)

	seedDA := c1Fund(t, l, dA, 100_000_000_000_000, addrA)
	c1Fund(t, l, dB, 30_000_000_000_000, addrB)
	seedV := c1Fund(t, l, v, 10_000_000_000_000, addrB)
	ts := core.Now().UnixNano() + 1_000_000

	if got := c1Weight(t, l, addrA); got != 100_000_000_000_000 {
		t.Fatalf("setup: repA weight = %s, want 100e12", c1FmtXE(got))
	}

	// Two conflicting sends. v2 signed offline before either is published.
	v1 := c1SignSend(t, v, seedV.Hash, 9_000_000_000_000, 1_000_000_000_000, c1Key(t).Address(), ts)
	v2 := c1SignSend(t, v, seedV.Hash, 9_000_000_000_000, 1_000_000_000_000, c1Key(t).Address(), ts)
	if v1.Hash == v2.Hash {
		t.Fatalf("setup: fork hashes collided")
	}

	// (1) PRE-CONFLICT final vote from repA for v2. No conflict exists yet.
	if err := vm.ReceiveVote(c1SignVote(t, repA, v2.Hash, v.Address(), seedV.Hash, true)); err != nil {
		t.Fatalf("pre-conflict ReceiveVote: %v", err)
	}

	// (2) SHED: dA sends entire balance away.
	shed := c1SignSend(t, dA, seedDA.Hash, 0, 100_000_000_000_000, sink.Address(), ts)
	if err := l.AddBlock(shed); err != nil {
		t.Fatalf("shed send: %v", err)
	}
	if got := c1Weight(t, l, addrA); got != 0 {
		t.Fatalf("after shed: repA weight = %s, want 0", c1FmtXE(got))
	}

	// (3) FORK publishes: v1 on chain, v2 staged + conflict record.
	if err := l.AddBlock(v1); err != nil {
		t.Fatalf("add v1: %v", err)
	}
	if err := l.AddBlock(v2); err != nil {
		t.Fatalf("add v2 (conflict): %v", err)
	}
	c := l.GetConflict(v.Address(), seedV.Hash)
	if c == nil {
		t.Fatalf("no conflict record after v2")
	}
	if _, ok := c.WeightSnapshot[addrA]; ok {
		t.Fatalf("snapshot still contains repA")
	}

	// (4) TALLY: retally must NOT finalize v2 with repA's stale vote
	qm.Retally(v.Address(), seedV.Hash)
	if l.IsFinalized(v.Address(), v2.Hash) {
		t.Fatalf("V2 was finalized by stale vote from repA which holds 0 weight in snapshot")
	}
	if got := l.FinalHeight(v.Address()); got == 2 {
		t.Fatalf("final height advanced to 2 via stale pre-conflict vote")
	}

	// CONTROL: verify that post-conflict zero-weight final vote is rejected
	w := c1Key(t)
	seedW := c1Fund(t, l, w, 10_000_000_000_000, addrB)
	ts2 := core.Now().UnixNano() + 1_000_000
	w1 := c1SignSend(t, w, seedW.Hash, 9_000_000_000_000, 1_000_000_000_000, c1Key(t).Address(), ts2)
	w2 := c1SignSend(t, w, seedW.Hash, 9_000_000_000_000, 1_000_000_000_000, c1Key(t).Address(), ts2)
	if err := l.AddBlock(w1); err != nil {
		t.Fatalf("control add w1: %v", err)
	}
	if err := l.AddBlock(w2); err != nil {
		t.Fatalf("control add w2: %v", err)
	}
	err := vm.ReceiveVote(c1SignVote(t, repA, w2.Hash, w.Address(), seedW.Hash, true))
	if err == nil {
		t.Fatalf("control: post-conflict zero-weight final vote was ACCEPTED (expected rejection)")
	}
	if got, _ := ms.GetVote(w.Address(), seedW.Hash, repA.PubKeyHex()); got != nil {
		t.Fatalf("control: post-conflict zero-weight vote was stored")
	}
}
