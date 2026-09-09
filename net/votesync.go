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
		resp := VoteResponse{Votes: provide(req.Account, req.Previous)}
		return json.Marshal(&resp)
	})
}

func PullVotes(ctx context.Context, msg *Messenger, peers []peer.ID, account, previous string, ingest func(*core.Vote) error) int {
	if account == "" {
		return 0
	}
	ingested := 0
	for _, pid := range peers {
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
			if v == nil {
				continue
			}
			if err := ingest(v); err != nil {
				continue
			}
			ingested++
		}
	}
	if ingested > 0 {
		logging.Debugf("votesync: ingested %d vote(s) for %s|%s from peers", ingested, shortHash(account), shortHash(previous))
	}
	return ingested
}
