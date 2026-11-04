package net

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func TestEnqueueVoteNormalizesCaseVariants(t *testing.T) {
	ctx := context.Background()
	ch := make(chan *core.Vote, 8)
	seen := make(map[string]int64)
	now := time.Now().UnixNano()

	v1 := &core.Vote{
		RepPubKey:       strings.Repeat("ab", 32),
		BlockHash:       strings.Repeat("cd", 32),
		ConflictAccount: strings.Repeat("ef", 32),
		ConflictPrev:    "0",
		Final:           true,
	}
	if !enqueueVote(ctx, ch, seen, v1, now) {
		t.Fatal("expected first vote to be enqueued")
	}

	v2 := *v1
	v2.RepPubKey = strings.ToUpper(v1.RepPubKey)
	v2.BlockHash = strings.ToUpper(v1.BlockHash)
	if enqueueVote(ctx, ch, seen, &v2, now+10) {
		t.Fatal("expected case-variant duplicate vote within TTL to be deduplicated")
	}
}

func TestRequestSyncHandlesNilBlocksAndEmptyPagesWithoutPanic(t *testing.T) {
	ledger := core.NewLedger(store.NewMemStore(), core.LedgerConfig{})

	h1, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer h1.Close()

	h2, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer h2.Close()

	// Malicious peer sends [null] in Blocks followed by empty pages with HasMore=true
	h2.SetStreamHandler(syncProtocol, func(s network.Stream) {
		defer s.Close()
		var req SyncRequest
		_ = json.NewDecoder(s).Decode(&req)
		enc := json.NewEncoder(s)
		_ = enc.Encode(&SyncResponse{
			Blocks:  []*core.Block{nil},
			HasMore: true,
		})
		_ = enc.Encode(&SyncResponse{
			Blocks:  []*core.Block{},
			HasMore: true,
		})
	})

	pi := peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()}
	if err := h1.Connect(context.Background(), pi); err != nil {
		t.Fatal(err)
	}

	if err := requestSync(h1, h2.ID(), ledger, newBlockQuarantine(), newSyncTracker()); err != nil {
		t.Fatalf("requestSync returned unexpected error: %v", err)
	}
}
