package net

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/xeprotocol/xe/core"
)

const (
	// BlockRequestMsgType is the Messenger message type a node uses to ask a peer
	// for a specific block body by hash. (#540)
	BlockRequestMsgType = "block_request"

	// blockPullTimeout bounds a single targeted block pull from one peer.
	blockPullTimeout = 10 * time.Second

	// MaxBlockRequestHashes caps how many hashes one block_request may ask
	// for. The handler does a store lookup per hash and ~900 hashes fit in
	// the 64 KiB request cap, so an uncapped request was a cheap way to buy a
	// burst of disk reads (#840). Honest callers ask for the one or two
	// conflict siblings they are missing, so the cap is never reached in
	// normal operation. Excess hashes are ignored rather than rejected: a
	// truncated answer is still useful and the caller retries on the next
	// stale-conflict sweep.
	MaxBlockRequestHashes = 64
)

// BlockRequest asks a peer for the bodies of the named block hashes.
type BlockRequest struct {
	Hashes []string `json:"hashes"`
}

// BlockResponse returns the block bodies a peer holds for the requested hashes.
// Hashes the peer does not hold are simply omitted.
type BlockResponse struct {
	Blocks []*core.Block `json:"blocks"`
}

// SetupBlockSync wires targeted block-by-hash exchange over the Messenger so a
// node can actively pull a conflicting sibling's body that never reached it via
// gossip and that the frontier-sync server refuses to backfill (its
// anti-amplification guard skips unrecognised frontiers — see
// findMissingBlocksPaginated). Without both sibling bodies on a single node, an
// equivocated account cannot run weighted 2-block voting and stalls. (#540)
//
//   - provide(hash) returns the block this node holds for hash (chain or
//     conflict staging), or nil if it does not hold it.
//
// PullBlocks (below) drives the requesting side; its ingest callback is
// responsible for verification and insertion (typically Ledger.AddBlock), which
// routes a conflicting block into the conflict machinery.
//
// The pull is best-effort: a peer that does not answer or does not hold the body
// is skipped, and the periodic stale-conflict sweep retries on the next tick.
func SetupBlockSync(msg *Messenger, provide func(hash string) *core.Block) {
	msg.Handle(BlockRequestMsgType, func(_ peer.ID, payload json.RawMessage) (json.RawMessage, error) {
		var req BlockRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, err
		}
		hashes := req.Hashes
		if len(hashes) > MaxBlockRequestHashes {
			hashes = hashes[:MaxBlockRequestHashes]
		}
		var resp BlockResponse
		for _, h := range hashes {
			if b := provide(h); b != nil {
				resp.Blocks = append(resp.Blocks, b)
			}
		}
		return json.Marshal(&resp)
	})
}

// PullBlocks requests the named block bodies from the given peers until all are
// obtained (or peers are exhausted), ingesting each one. Best-effort and safe to
// call repeatedly: ingest is idempotent (a block already held is a no-op).
// Returns the number of blocks newly ingested. (#540)
func PullBlocks(ctx context.Context, msg *Messenger, peers []peer.ID, hashes []string, ingest func(*core.Block) error) int {
	want := make(map[string]bool, len(hashes))
	for _, h := range hashes {
		want[h] = true
	}
	if len(want) == 0 {
		return 0
	}

	pulled := 0
	for _, pid := range peers {
		if len(want) == 0 {
			break
		}
		remaining := make([]string, 0, len(want))
		for h := range want {
			remaining = append(remaining, h)
		}

		reqCtx, cancel := context.WithTimeout(ctx, blockPullTimeout)
		raw, err := msg.Request(reqCtx, pid, BlockRequestMsgType, &BlockRequest{Hashes: remaining})
		cancel()
		if err != nil {
			continue // peer unreachable or doesn't support the protocol; try the next
		}

		var resp BlockResponse
		if err := json.Unmarshal(raw, &resp); err != nil {
			continue
		}
		for _, b := range resp.Blocks {
			if b == nil || !want[b.Hash] {
				continue
			}
			if err := ingest(b); err != nil {
				log.Printf("blocksync: ingest pulled block %s from %s: %v",
					shortHash(b.Hash), pid.ShortString(), err)
				continue
			}
			delete(want, b.Hash)
			pulled++
		}
	}
	if pulled > 0 {
		log.Printf("blocksync: pulled %d conflicting block body(ies) by hash", pulled)
	}
	return pulled
}
