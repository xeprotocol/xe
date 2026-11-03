package net

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func TestSyncRequestAbove1MiBWith10kFrontiersRoundTrips(t *testing.T) {
	serverStore := store.NewMemStore()
	clientStore := store.NewMemStore()

	serverLedger := core.NewLedger(serverStore, core.LedgerConfig{Difficulty: 0})
	clientLedger := core.NewLedger(clientStore, core.LedgerConfig{Difficulty: 0})

	// Populate 9,000 synthetic 64-hex frontier entries in clientStore (> 1.2 MiB JSON payload,
	// well past the old 1 MiB / 7,825-entry truncation boundary).
	for i := 0; i < 9000; i++ {
		acct := fmt.Sprintf("%064x", i+1)
		hash := fmt.Sprintf("%064x", i+100000)
		_ = clientStore.PutFrontier(acct, hash)
	}

	// Add a real block on serverLedger that clientLedger is missing.
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	mint := &core.Block{
		Type:           core.BlockMint,
		Account:        kp.Address(),
		Previous:       "0",
		Balance:        5000,
		Amount:         5000,
		Asset:          "XUSD",
		Representative: kp.Address(),
		Timestamp:      core.Now().UnixNano(),
		PubKey:         kp.PubKeyHex(),
	}
	mint.Hash = mint.ComputeHash()
	if err := kp.SignBlock(mint); err != nil {
		t.Fatalf("SignBlock: %v", err)
	}
	if err := serverLedger.SeedAssetForTesting(mint); err != nil {
		t.Fatalf("SeedAssetForTesting: %v", err)
	}

	hServer, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer hServer.Close()

	hClient, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer hClient.Close()

	serverTracker := newSyncTracker()
	hServer.SetStreamHandler(syncProtocol, func(s network.Stream) {
		defer s.Close()
		handleSyncStream(s, serverLedger, serverTracker)
	})

	pi := peer.AddrInfo{ID: hServer.ID(), Addrs: hServer.Addrs()}
	if err := hClient.Connect(context.Background(), pi); err != nil {
		t.Fatal(err)
	}

	clientTracker := newSyncTracker()
	if err := requestSync(hClient, hServer.ID(), clientLedger, newBlockQuarantine(), clientTracker); err != nil {
		t.Fatalf("requestSync with >1 MiB frontiers map failed: %v", err)
	}

	if got := clientLedger.GetBlock(mint.Hash); got == nil {
		t.Fatalf("expected clientLedger to receive missing block %s across >1 MiB sync request", mint.Hash)
	}
}

func TestSyncTruncatedRequestReturnsExplicitErrorInsteadOfFalseSuccess(t *testing.T) {
	serverLedger := core.NewLedger(store.NewMemStore(), core.LedgerConfig{Difficulty: 0})
	clientLedger := core.NewLedger(store.NewMemStore(), core.LedgerConfig{Difficulty: 0})

	hServer, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer hServer.Close()

	hClient, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer hClient.Close()

	// 1. Verify handleSyncStream responds with SyncResponse.Error on truncated JSON.
	hServer.SetStreamHandler(syncProtocol, func(s network.Stream) {
		defer s.Close()
		handleSyncStream(s, serverLedger, newSyncTracker())
	})

	pi := peer.AddrInfo{ID: hServer.ID(), Addrs: hServer.Addrs()}
	if err := hClient.Connect(context.Background(), pi); err != nil {
		t.Fatal(err)
	}

	s, err := hClient.NewStream(context.Background(), hServer.ID(), syncProtocol)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.Write([]byte(`{"frontiers":{"abcd":`))
	_ = s.CloseWrite()

	var resp SyncResponse
	if err := json.NewDecoder(s).Decode(&resp); err != nil {
		t.Fatalf("expected explicit error SyncResponse on truncated request, got decode err: %v", err)
	}
	_ = s.Close()
	if !strings.Contains(resp.Error, "decode request") {
		t.Fatalf("expected SyncResponse.Error to mention decode request, got %q", resp.Error)
	}

	// 2. Verify requestSync returns an error if the server closes the stream without any response.
	hServer.SetStreamHandler(syncProtocol, func(s network.Stream) {
		_ = s.Close()
	})
	if err := requestSync(hClient, hServer.ID(), clientLedger, newBlockQuarantine(), newSyncTracker()); err == nil {
		t.Fatalf("expected requestSync to return an error on empty premature EOF")
	}
}

func TestSyncAppliesDeepDependencyChainBeyond10PassesInReverseOrder(t *testing.T) {
	serverStore := store.NewMemStore()
	clientStore := store.NewMemStore()

	serverLedger := core.NewLedger(serverStore, core.LedgerConfig{Difficulty: 0})
	clientLedger := core.NewLedger(clientStore, core.LedgerConfig{Difficulty: 0})

	// Build a 30-hop cross-account dependency chain (60 blocks):
	// KP_0 mints XUSD -> sends to KP_1 -> KP_1 receives -> sends to KP_2 -> ... -> KP_29 receives.
	// Under the old 10-pass cap, reverse order could apply at most 11 hops per round.
	const hops = 30
	kps := make([]*core.KeyPair, hops)
	for i := 0; i < hops; i++ {
		kp, err := core.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		kps[i] = kp
	}

	baseTS := core.Now().Add(-5 * time.Minute).UnixNano()
	var chainBlocks []*core.Block

	mint := &core.Block{
		Type:           core.BlockMint,
		Account:        kps[0].Address(),
		Previous:       "0",
		Balance:        100_000,
		Amount:         100_000,
		Asset:          "XUSD",
		Representative: kps[0].Address(),
		Timestamp:      baseTS,
		PubKey:         kps[0].PubKeyHex(),
	}
	mint.Hash = mint.ComputeHash()
	if err := kps[0].SignBlock(mint); err != nil {
		t.Fatal(err)
	}
	if err := serverLedger.SeedAssetForTesting(mint); err != nil {
		t.Fatalf("SeedAssetForTesting: %v", err)
	}
	chainBlocks = append(chainBlocks, mint)

	prevHash := mint.Hash
	bal := uint64(100_000)
	for i := 0; i < hops-1; i++ {
		sender := kps[i]
		receiver := kps[i+1]
		sendAmt := uint64(1000)
		bal -= sendAmt

		sendBlk := &core.Block{
			Type:           core.BlockSend,
			Account:        sender.Address(),
			Previous:       prevHash,
			Destination:    receiver.Address(),
			Balance:        bal,
			Amount:         sendAmt,
			Asset:          "XUSD",
			Representative: sender.Address(),
			Timestamp:      baseTS + int64((2*i+1)*int(time.Second)),
			PubKey:         sender.PubKeyHex(),
		}
		sendBlk.Hash = sendBlk.ComputeHash()
		if err := sender.SignBlock(sendBlk); err != nil {
			t.Fatal(err)
		}
		if err := serverLedger.AddSyncedBlock(sendBlk); err != nil {
			t.Fatalf("server AddSyncedBlock send %d: %v", i, err)
		}
		chainBlocks = append(chainBlocks, sendBlk)

		recvBlk := &core.Block{
			Type:           core.BlockReceive,
			Account:        receiver.Address(),
			Previous:       "0",
			Source:         sendBlk.Hash,
			Balance:        sendAmt,
			Amount:         sendAmt,
			Asset:          "XUSD",
			Representative: receiver.Address(),
			Timestamp:      baseTS + int64((2*i+2)*int(time.Second)),
			PubKey:         receiver.PubKeyHex(),
		}
		recvBlk.Hash = recvBlk.ComputeHash()
		if err := receiver.SignBlock(recvBlk); err != nil {
			t.Fatal(err)
		}
		if err := serverLedger.AddSyncedBlock(recvBlk); err != nil {
			t.Fatalf("server AddSyncedBlock recv %d: %v", i, err)
		}
		chainBlocks = append(chainBlocks, recvBlk)

		prevHash = recvBlk.Hash
		bal = sendAmt
	}

	// Reverse the blocks (worst-case chain_desc order) and serve them to clientLedger.
	reversed := make([]*core.Block, len(chainBlocks))
	for i := range chainBlocks {
		reversed[i] = chainBlocks[len(chainBlocks)-1-i]
	}

	hServer, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer hServer.Close()

	hClient, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer hClient.Close()

	hServer.SetStreamHandler(syncProtocol, func(s network.Stream) {
		defer s.Close()
		var req SyncRequest
		_ = json.NewDecoder(s).Decode(&req)
		_ = json.NewEncoder(s).Encode(&SyncResponse{
			Blocks:  reversed,
			HasMore: false,
		})
	})

	pi := peer.AddrInfo{ID: hServer.ID(), Addrs: hServer.Addrs()}
	if err := hClient.Connect(context.Background(), pi); err != nil {
		t.Fatal(err)
	}

	if err := requestSync(hClient, hServer.ID(), clientLedger, newBlockQuarantine(), newSyncTracker()); err != nil {
		t.Fatalf("requestSync failed: %v", err)
	}

	lastBlock := chainBlocks[len(chainBlocks)-1]
	if got := clientLedger.GetBlock(lastBlock.Hash); got == nil {
		t.Fatalf("expected all %d blocks in reverse-ordered 30-hop dependency chain to apply in 1 round, but leaf block %s was not applied", len(chainBlocks), lastBlock.Hash)
	}
}
