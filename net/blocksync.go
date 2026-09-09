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
	BlockRequestMsgType = "block_request"

	blockPullTimeout = 10 * time.Second

	MaxBlockRequestHashes = 64
)

type BlockRequest struct {
	Hashes []string `json:"hashes"`
}

type BlockResponse struct {
	Blocks []*core.Block `json:"blocks"`
}

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
			continue
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
