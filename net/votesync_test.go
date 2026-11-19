package net

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func signTestVote(t *testing.T, v *core.Vote, kp *core.KeyPair) {
	t.Helper()
	v.Signature = nil
	encoded, err := core.EncodeVote(v)
	if err != nil {
		t.Fatalf("EncodeVote: %v", err)
	}
	v.Signature = ed25519.Sign(kp.Private, encoded[:len(encoded)-2])
}

func newTestPair(t *testing.T) (host.Host, *Messenger, host.Host, *Messenger) {
	t.Helper()
	h1, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("libp2p.New h1: %v", err)
	}
	t.Cleanup(func() { _ = h1.Close() })

	h2, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("libp2p.New h2: %v", err)
	}
	t.Cleanup(func() { _ = h2.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h1.Connect(ctx, peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()}); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	return h1, NewMessenger(h1, nil), h2, NewMessenger(h2, nil)
}

func TestPullVotesRejectsCrossPositionAndDeduplicatesResponses(t *testing.T) {
	_, mClient, hServer, mServer := newTestPair(t)

	targetAcc := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	targetPrev := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	otherAcc := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	repPub := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	blkHash := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

	validVote := &core.Vote{
		ConflictAccount: targetAcc,
		ConflictPrev:    targetPrev,
		BlockHash:       blkHash,
		RepPubKey:       repPub,
		Final:           true,
	}
	crossAccountVote := &core.Vote{
		ConflictAccount: otherAcc,
		ConflictPrev:    targetPrev,
		BlockHash:       blkHash,
		RepPubKey:       repPub,
		Final:           true,
	}
	crossPrevVote := &core.Vote{
		ConflictAccount: targetAcc,
		ConflictPrev:    "0",
		BlockHash:       blkHash,
		RepPubKey:       repPub,
		Final:           true,
	}

	mServer.Handle(VoteRequestMsgType, func(_ peer.ID, _ json.RawMessage) (json.RawMessage, error) {
		votes := []*core.Vote{nil, crossAccountVote, crossPrevVote}
		for i := 0; i < 50; i++ {
			votes = append(votes, validVote)
		}
		return json.Marshal(&VoteResponse{Votes: votes})
	})

	var calls atomic.Int32
	got := PullVotes(context.Background(), mClient, []peer.ID{hServer.ID()}, targetAcc, targetPrev, func(v *core.Vote) error {
		calls.Add(1)
		if v.ConflictAccount != targetAcc || v.ConflictPrev != targetPrev {
			t.Errorf("cross-position vote reached ingest callback: %+v", v)
		}
		return nil
	})

	if got != 1 || calls.Load() != 1 {
		t.Fatalf("PullVotes got=%d ingestCalls=%d, want 1 and 1", got, calls.Load())
	}
}

func TestPullVotesForgedPeerCannotPoisonHonestPeer(t *testing.T) {
	hClient, mClient, hEvil, mEvil := newTestPair(t)
	hHonest, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("libp2p.New hHonest: %v", err)
	}
	t.Cleanup(func() { _ = hHonest.Close() })
	mHonest := NewMessenger(hHonest, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := hClient.Connect(ctx, peer.AddrInfo{ID: hHonest.ID(), Addrs: hHonest.Addrs()}); err != nil {
		t.Fatalf("Connect honest: %v", err)
	}

	repKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	targetAcc := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	targetPrev := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	blkHash := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

	honestVote := &core.Vote{
		ConflictAccount: targetAcc,
		ConflictPrev:    targetPrev,
		BlockHash:       blkHash,
		RepPubKey:       repKP.PubKeyHex(),
		Timestamp:       core.Now().UnixNano(),
		Final:           true,
	}
	signTestVote(t, honestVote, repKP)

	forgedVote := *honestVote
	forgedVote.Signature = make([]byte, ed25519.SignatureSize)

	mEvil.Handle(VoteRequestMsgType, func(_ peer.ID, _ json.RawMessage) (json.RawMessage, error) {
		return json.Marshal(&VoteResponse{Votes: []*core.Vote{&forgedVote}})
	})
	mHonest.Handle(VoteRequestMsgType, func(_ peer.ID, _ json.RawMessage) (json.RawMessage, error) {
		return json.Marshal(&VoteResponse{Votes: []*core.Vote{honestVote, honestVote}})
	})

	var accepted atomic.Int32
	got := PullVotes(context.Background(), mClient, []peer.ID{hEvil.ID(), hHonest.ID()}, targetAcc, targetPrev, func(v *core.Vote) error {
		if !core.VerifyVoteSignature(v) {
			return context.Canceled
		}
		accepted.Add(1)
		return nil
	})
	if got != 1 || accepted.Load() != 1 {
		t.Fatalf("Byzantine peer poisoned dedup set: got=%d accepted=%d, want 1 and 1", got, accepted.Load())
	}
}

type syncCountingStore struct {
	*store.MemStore
	syncs  atomic.Int32
	writes atomic.Int32
}

func (s *syncCountingStore) Sync() error {
	s.syncs.Add(1)
	return nil
}

func (s *syncCountingStore) PutVote(v *core.Vote) error {
	s.writes.Add(1)
	return s.MemStore.PutVote(v)
}

func TestReceiveVoteIgnoresDuplicateNonFinalVotesWithoutResettingBackoff(t *testing.T) {
	st := &syncCountingStore{MemStore: store.NewMemStore()}
	localKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair local: %v", err)
	}
	peerKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair peer: %v", err)
	}

	genesis, err := core.LoadGenesisBlock()
	if err != nil {
		t.Fatalf("LoadGenesisBlock: %v", err)
	}
	if err := st.PutBlock(genesis); err != nil {
		t.Fatalf("PutBlock genesis: %v", err)
	}
	// Split stake across localKP and peerKP so both have positive vote weight.
	sendBlk := &core.Block{
		Type:           core.BlockSend,
		Account:        genesis.Account,
		Previous:       genesis.Hash,
		Balance:        genesis.Balance - 1_000_000,
		Amount:         1_000_000,
		Destination:    peerKP.Address(),
		Representative: localKP.Address(),
		Timestamp:      genesis.Timestamp + 1,
		Asset:          "XE",
	}
	sendHash, err := core.HashBlock(sendBlk)
	if err != nil {
		t.Fatalf("HashBlock send: %v", err)
	}
	sendBlk.Hash = sendHash
	recvBlk := &core.Block{
		Type:           core.BlockReceive,
		Account:        peerKP.Address(),
		Previous:       "0",
		Balance:        1_000_000,
		Amount:         1_000_000,
		Source:         sendBlk.Hash,
		Representative: peerKP.Address(),
		Timestamp:      genesis.Timestamp + 2,
		Asset:          "XE",
	}
	if err := core.SignBlock(recvBlk, peerKP); err != nil {
		t.Fatalf("SignBlock recv: %v", err)
	}
	_ = st.PutBlock(sendBlk)
	_ = st.PutBlock(recvBlk)
	_ = st.PutAccountChain(genesis.Account, &core.AccountChain{Blocks: []*core.Block{genesis, sendBlk}})
	_ = st.PutFrontier(genesis.Account, sendBlk.Hash)
	_ = st.PutDelegation(genesis.Account, localKP.Address())
	_ = st.PutAccountChain(peerKP.Address(), &core.AccountChain{Blocks: []*core.Block{recvBlk}})
	_ = st.PutFrontier(peerKP.Address(), recvBlk.Hash)
	_ = st.PutDelegation(peerKP.Address(), peerKP.Address())

	ledger := core.NewLedger(st, core.LedgerConfig{})
	if w := ledger.GetVoteWeight(peerKP.Address()); w.Cmp(big.NewInt(0)) <= 0 {
		t.Fatalf("expected positive peer vote weight, got %v", w)
	}

	conflictAcc := genesis.Account
	conflictPrev := sendBlk.Hash
	candA := "1111111111111111111111111111111111111111111111111111111111111111"
	candB := "2222222222222222222222222222222222222222222222222222222222222222"
	if err := st.SaveConflict(&core.Conflict{
		AccountAddress: conflictAcc,
		PreviousHash:   conflictPrev,
		BlockHashes:    []string{candA, candB},
		DetectedAt:     core.Now(),
	}); err != nil {
		t.Fatalf("SaveConflict: %v", err)
	}

	// Seed localKP's locked final vote so castVoteLocked guards re-emission via 15s revoteBackoff + Sync().
	localFinal := &core.Vote{
		ConflictAccount: conflictAcc,
		ConflictPrev:    conflictPrev,
		BlockHash:       candA,
		RepPubKey:       localKP.PubKeyHex(),
		Timestamp:       core.Now().UnixNano(),
		Final:           true,
	}
	signTestVote(t, localFinal, localKP)
	_ = st.MemStore.PutVote(localFinal)

	vm := core.NewVoteManager(st, localKP, ledger)
	var emitted atomic.Int32
	vm.VoteEmitter = func(*core.Vote) { emitted.Add(1) }

	// 1. First non-final vote from peerKP is novel: stores vote and triggers initial final-vote re-affirm + Sync().
	convergeVote := &core.Vote{
		ConflictAccount: conflictAcc,
		ConflictPrev:    conflictPrev,
		BlockHash:       candA,
		RepPubKey:       peerKP.PubKeyHex(),
		Timestamp:       core.Now().UnixNano(),
		Final:           false,
	}
	signTestVote(t, convergeVote, peerKP)
	if err := vm.ReceiveVote(convergeVote); err != nil {
		t.Fatalf("first converge vote failed: %v", err)
	}
	if emitted.Load() != 1 || st.syncs.Load() != 1 || st.writes.Load() != 1 {
		t.Fatalf("after 1st converge vote: emitted=%d syncs=%d writes=%d, want 1, 1, 1",
			emitted.Load(), st.syncs.Load(), st.writes.Load())
	}

	// 2. Replaying duplicate non-final votes for the same BlockHash must NOT rewrite storage or reset revoteBackoff.
	for i := 0; i < 5; i++ {
		replay := *convergeVote
		replay.Timestamp = core.Now().UnixNano() + int64(i+1)
		signTestVote(t, &replay, peerKP)
		if err := vm.ReceiveVote(&replay); err != nil {
			t.Fatalf("duplicate converge replay %d failed: %v", i, err)
		}
	}
	if emitted.Load() != 1 || st.syncs.Load() != 1 || st.writes.Load() != 1 {
		t.Fatalf("duplicate non-final replays reset revoteBackoff: emitted=%d syncs=%d writes=%d, want 1, 1, 1",
			emitted.Load(), st.syncs.Load(), st.writes.Load())
	}

	// 3. Upgrading to Final=true is a real state transition and must be stored and trigger re-affirm.
	finalVote := &core.Vote{
		ConflictAccount: conflictAcc,
		ConflictPrev:    conflictPrev,
		BlockHash:       candA,
		RepPubKey:       peerKP.PubKeyHex(),
		Timestamp:       core.Now().UnixNano() + 100,
		Final:           true,
	}
	signTestVote(t, finalVote, peerKP)
	if err := vm.ReceiveVote(finalVote); err != nil {
		t.Fatalf("upgrade to final vote failed: %v", err)
	}
	if emitted.Load() != 2 || st.syncs.Load() != 2 || st.writes.Load() != 2 {
		t.Fatalf("after final upgrade: emitted=%d syncs=%d writes=%d, want 2, 2, 2",
			emitted.Load(), st.syncs.Load(), st.writes.Load())
	}
}

func TestPullBlocksRejectsForgedHashBeforeIngest(t *testing.T) {
	_, mClient, hServer, mServer := newTestPair(t)

	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	realBlk := &core.Block{
		Type:           core.BlockGenesis,
		Account:        kp.Address(),
		Previous:       "0",
		Balance:        500,
		Representative: kp.Address(),
		Timestamp:      core.Now().UnixNano(),
		Asset:          "XE",
	}
	if err := core.SignBlock(realBlk, kp); err != nil {
		t.Fatalf("SignBlock: %v", err)
	}
	wantHash := realBlk.Hash

	forged := *realBlk
	forged.Balance = 999_999_999

	var ingested int
	mServer.Handle(BlockRequestMsgType, func(_ peer.ID, _ json.RawMessage) (json.RawMessage, error) {
		return json.Marshal(&BlockResponse{Blocks: []*core.Block{&forged}})
	})
	pulled := PullBlocks(context.Background(), mClient, []peer.ID{hServer.ID()}, []string{wantHash}, func(b *core.Block) error {
		ingested++
		return nil
	})
	if pulled != 0 || ingested != 0 {
		t.Fatalf("forged block must be rejected before ingest: pulled=%d ingested=%d", pulled, ingested)
	}

	unwantedBlk := &core.Block{
		Type:           core.BlockGenesis,
		Account:        kp.Address(),
		Previous:       "0",
		Balance:        123,
		Representative: kp.Address(),
		Timestamp:      core.Now().UnixNano() + 1,
		Asset:          "XE",
	}
	if err := core.SignBlock(unwantedBlk, kp); err != nil {
		t.Fatalf("SignBlock unwanted: %v", err)
	}

	// Server prepends both an unsolicited block and a forged copy before the genuine block when len(remaining)==1.
	mServer.Handle(BlockRequestMsgType, func(_ peer.ID, _ json.RawMessage) (json.RawMessage, error) {
		return json.Marshal(&BlockResponse{Blocks: []*core.Block{unwantedBlk, &forged, realBlk, realBlk}})
	})
	pulled = PullBlocks(context.Background(), mClient, []peer.ID{hServer.ID()}, []string{wantHash}, func(b *core.Block) error {
		ingested++
		return nil
	})
	if pulled != 1 || ingested != 1 {
		t.Fatalf("valid block after unwanted+forged prefix must be pulled once: pulled=%d ingested=%d", pulled, ingested)
	}
}
