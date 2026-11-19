package net

import (
	"context"
	"encoding/json"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/logging"
)

const (
	VoteRequestMsgType = "vote_request"

	votePullTimeout = 10 * time.Second
)

type VoteRequest struct {
	Account  string `json:"account"`
	Previous string `json:"previous"`
}

type VoteResponse struct {
	Votes []*core.Vote `json:"votes"`
}

func SetupVoteSync(msg *Messenger, provide func(account, previous string) []*core.Vote) {
	msg.Handle(VoteRequestMsgType, func(_ peer.ID, payload json.RawMessage) (json.RawMessage, error) {
		var req VoteRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, err
		}
		if req.Account == "" {
			return json.Marshal(&VoteResponse{})
		}
		resp := VoteResponse{Votes: provide(req.Account, req.Previous)}
		return json.Marshal(&resp)
	})
}

func voteSyncDedupKey(v *core.Vote) string {
	finalFlag := "c"
	if v.Final {
		finalFlag = "f"
	}
	return v.RepPubKey + "|" + v.BlockHash + "|" + finalFlag
}

func PullVotes(ctx context.Context, msg *Messenger, peers []peer.ID, account, previous string, ingest func(*core.Vote) error) int {
	if account == "" || ingest == nil {
		return 0
	}
	ingested := 0
	seen := make(map[string]struct{})
	for _, pid := range peers {
		if ctx.Err() != nil {
			break
		}
		reqCtx, cancel := context.WithTimeout(ctx, votePullTimeout)
		raw, err := msg.Request(reqCtx, pid, VoteRequestMsgType, &VoteRequest{Account: account, Previous: previous})
		cancel()
		if err != nil {
			continue
		}
		var resp VoteResponse
		if err := json.Unmarshal(raw, &resp); err != nil {
			continue
		}
		for _, v := range resp.Votes {
			if v == nil || v.ConflictAccount != account || v.ConflictPrev != previous {
				continue
			}
			if v.RepPubKey == "" || v.BlockHash == "" {
				continue
			}
			key := voteSyncDedupKey(v)
			if _, dup := seen[key]; dup {
				continue
			}
			if err := ingest(v); err != nil {
				continue
			}
			seen[key] = struct{}{}
			ingested++
		}
	}
	if ingested > 0 {
		logging.Debugf("votesync: ingested %d vote(s) for %s|%s from peers", ingested, shortHash(account), shortHash(previous))
	}
	return ingested
}
