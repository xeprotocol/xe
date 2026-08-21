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
	// VoteRequestMsgType is the Messenger message type a node uses to ask a peer
	// for its votes at a conflict position (account, previous). (#703)
	VoteRequestMsgType = "vote_request"

	// votePullTimeout bounds a single targeted vote pull from one peer.
	votePullTimeout = 10 * time.Second
)

// VoteRequest asks a peer for its votes at a conflict position.
type VoteRequest struct {
	Account  string `json:"account"`
	Previous string `json:"previous"`
}

// VoteResponse returns the votes a peer can offer for the requested position:
// its stored votes, plus a freshly-derived signed final vote when the peer has
// already finalized the child there (its stored votes may have been cleaned up).
type VoteResponse struct {
	Votes []*core.Vote `json:"votes"`
}

// SetupVoteSync wires targeted vote-by-position exchange over the Messenger so a
// lagging node can actively pull the final votes that resolve a conflict it is
// stuck on. The frontier-sync protocol carries block bodies but no finalization
// state, so a node that holds its own NON-FINAL losing fork at (account,
// previous) stages the network winner as a conflict it can never resolve: the
// network already finalized the winner and — after the post-finalization cleanup
// deleted every rep's stored vote — will not re-gossip those votes. Without the
// quorum of final votes the laggard cannot run the weight-gated tally, so it
// wedges on its losing fork and a cold-sync restart reconstructs the same fork
// (#406/#501/#703 class).
//
//   - provide(account, previous) returns the votes this node can offer for the
//     position (see Ledger/VoteManager.VotesForPosition): stored votes plus, when
//     this node has finalized the child there, a fresh signed final vote derived
//     from chain state — a sound commitment behind the rollback wall.
//
// PullVotes (below) drives the requesting side; its ingest callback verifies and
// records each vote (typically VoteManager.ReceiveVote), which re-drives the
// local weight-gated tally and, once a quorum of final votes lands, promotes the
// winner via the normal confirmConflict/swapBlockLocked reorg — whose finality
// wall is the safety backstop (a locally-finalized block is never reorged).
//
// The pull is best-effort: a peer that does not answer or holds nothing is
// skipped, and the periodic stale-conflict sweep retries on the next tick.
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

// PullVotes requests votes at (account, previous) from the given peers and
// ingests each one. Best-effort and safe to call repeatedly: ingest is idempotent
// (a vote already held / a final vote already recorded is a no-op). Returns the
// number of votes successfully ingested. (#703)
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
			continue // peer unreachable or doesn't support the protocol; try the next
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
				continue // invalid / not-applicable vote; skip
			}
			ingested++
		}
	}
	if ingested > 0 {
		logging.Debugf("votesync: ingested %d vote(s) for %s|%s from peers", ingested, shortHash(account), shortHash(previous))
	}
	return ingested
}
