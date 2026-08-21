package net

import (
	"bytes"
	"context"
	"encoding/json"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/directory"
	"github.com/xeprotocol/xe/logging"
	"github.com/xeprotocol/xe/perf"
	"github.com/xeprotocol/xe/statechain"
)

const (
	BlockTopic       = "xe/blocks"
	VoteTopic        = "xe/votes"
	MarketplaceTopic = "xe/marketplace"
	StateChainTopic  = "xe/statechain"
	DirectoryTopic   = "xe/directory"
	CertificateTopic = "xe/certificates"

	// MaxGossipMessageSize limits the size of individual gossip messages.
	// Raised to 256KB for state chain blocks which can carry large KV values.
	// Block lattice gossip pre-validates field lengths (hash=64, sig=128,
	// account=64 hex chars), so the larger limit doesn't weaken security.
	MaxGossipMessageSize = 262144
)

// maxSubscribedTopics bounds how many topics a peer may subscribe us to.
// Without a subscription filter any peer can push arbitrary topic strings into
// our subscription table; the allowlist means only XE's own topics exist and
// the limit is a second line of defence on the filter itself.
const maxSubscribedTopics = 16

// gossipOptions builds the full GossipSub option set: message size cap, topic
// validators, peer scoring, and a subscription allowlist. Validators are
// registered on the returned instance by the caller before topics are joined.
func gossipOptions(cfg GossipConfig) []pubsub.Option {
	inspect := cfg.ScoreInspect
	if inspect == nil {
		inspect = scoreInspector
	}
	inspectEvery := cfg.ScoreInspectInterval
	if inspectEvery <= 0 {
		inspectEvery = 5 * time.Minute
	}
	return []pubsub.Option{
		pubsub.WithMaxMessageSize(MaxGossipMessageSize),

		// Peer scoring (#840). See gossip_score.go for why each parameter is
		// what it is; the short version is that honest peers can never score
		// below zero and only the topic validators can drive a peer negative.
		pubsub.WithPeerScore(peerScoreParams(cfg), peerScoreThresholds()),
		pubsub.WithPeerScoreInspect(inspect, inspectEvery),

		// Only XE's own topics exist. A peer cannot subscribe this node to
		// arbitrary topic strings.
		pubsub.WithSubscriptionFilter(
			pubsub.WrapLimitSubscriptionFilter(
				pubsub.NewAllowlistSubscriptionFilter(gossipTopics()...),
				maxSubscribedTopics,
			),
		),

		// The validate queue is the buffer between the router and the
		// validator workers; a full queue DROPS messages, and a dropped final
		// vote permanently wedges a conflict (#565). The stock size is 32,
		// which is small once validators do real work, so raise it.
		pubsub.WithValidateQueueSize(512),
	}
}

// NewPubSub creates a GossipSub instance for the given host with message size
// limits, topic validators and peer scoring.
// Both Gossip (blocks) and VoteGossip (votes) should share the same PubSub.
func NewPubSub(ctx context.Context, h host.Host, cfg GossipConfig) (*pubsub.PubSub, error) {
	ps, err := pubsub.NewGossipSub(ctx, h, gossipOptions(cfg)...)
	if err != nil {
		return nil, err
	}
	// Validators must be registered before any topic is joined so that no
	// message can be relayed unvalidated during startup.
	if err := RegisterTopicValidators(ps, cfg); err != nil {
		return nil, err
	}
	return ps, nil
}

// Gossip manages GossipSub for block broadcasting.
type Gossip struct {
	ps    *pubsub.PubSub
	topic *pubsub.Topic
	sub   *pubsub.Subscription
}

// NewGossip sets up GossipSub and joins the block topic.
// If ps is nil, a new GossipSub instance is created (backward compat).
func NewGossip(ctx context.Context, h host.Host, ps ...*pubsub.PubSub) (*Gossip, error) {
	var p *pubsub.PubSub
	if len(ps) > 0 && ps[0] != nil {
		p = ps[0]
	} else {
		var err error
		p, err = NewPubSub(ctx, h, GossipConfig{})
		if err != nil {
			return nil, err
		}
	}

	topic, err := p.Join(BlockTopic)
	if err != nil {
		return nil, err
	}

	sub, err := topic.Subscribe()
	if err != nil {
		return nil, err
	}

	return &Gossip{ps: p, topic: topic, sub: sub}, nil
}

// PubSub returns the underlying PubSub instance for sharing with VoteGossip.
func (g *Gossip) PubSub() *pubsub.PubSub {
	return g.ps
}

// Publish broadcasts a block to all peers.
func (g *Gossip) Publish(ctx context.Context, b *core.Block) error {
	msg := BlockMsg{Block: b}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return g.topic.Publish(ctx, data)
}

// droppedBlocks counts blocks dropped from the gossip receive path because the
// 256-slot receive channel was full. Frontier-sync is the backstop, but a
// non-zero and rising count means the node is shedding gossiped blocks under
// sustained load and falling behind. (#731)
var droppedBlocks atomic.Uint64

// DroppedBlocks returns the total number of blocks dropped from the gossip
// receive path because the receive channel was full. (#731)
func DroppedBlocks() uint64 {
	return droppedBlocks.Load()
}

// recordDroppedBlock increments the dropped-block counter and returns the new
// running total, for inclusion in the drop-site log line. (#731)
func recordDroppedBlock() uint64 {
	return droppedBlocks.Add(1)
}

// Subscribe returns a channel that yields blocks received from peers.
func (g *Gossip) Subscribe(ctx context.Context) <-chan *core.Block {
	ch := make(chan *core.Block, 256)
	go func() {
		defer close(ch)
		for {
			msg, err := g.sub.Next(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				logging.Warnf("gossip recv error: %v", err)
				continue
			}

			var bm BlockMsg
			dec := json.NewDecoder(bytes.NewReader(msg.Data))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&bm); err != nil {
				logging.Warnf("gossip unmarshal error: %v", err)
				continue
			}
			if bm.Block == nil {
				continue
			}
			// Pre-validate required fields and expected lengths to reject
			// malformed blocks before expensive signature verification.
			// Hash and Account are 64 hex chars (32 bytes), Signature is
			// 128 hex chars (64-byte ed25519 signature).
			b := bm.Block
			if len(b.Hash) != 64 || len(b.Signature) != 128 || len(b.Account) != 64 {
				continue
			}

			select {
			case ch <- bm.Block:
			default:
				total := recordDroppedBlock()
				logging.Warnf("gossip: block channel full, dropping block %s (total dropped: %d)", shortHash(bm.Block.Hash), total)
			}
		}
	}()
	return ch
}

// VoteGossip manages GossipSub for vote broadcasting.
type VoteGossip struct {
	topic *pubsub.Topic
	sub   *pubsub.Subscription
}

// NewVoteGossip joins the vote topic on the given PubSub instance.
func NewVoteGossip(ps *pubsub.PubSub) (*VoteGossip, error) {
	topic, err := ps.Join(VoteTopic)
	if err != nil {
		return nil, err
	}
	sub, err := topic.Subscribe()
	if err != nil {
		return nil, err
	}
	return &VoteGossip{topic: topic, sub: sub}, nil
}

// Publish broadcasts a vote to all peers.
func (vg *VoteGossip) Publish(ctx context.Context, v *core.Vote) error {
	msg := VoteMsg{Vote: v}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return vg.topic.Publish(ctx, data)
}

// Subscribe returns a channel that yields votes received from peers.
func (vg *VoteGossip) Subscribe(ctx context.Context) <-chan *core.Vote {
	// Buffer sized for burst headroom. Converge votes take a non-blocking send
	// (dropped on overflow and re-driven by the sweep); final votes take a
	// blocking, ctx-guarded send below so they are never the casualties of
	// saturation — a final vote is emitted exactly once with no rebroadcast, so a
	// single drop permanently wedges a conflict. (#565)
	ch := make(chan *core.Vote, 1024)
	go func() {
		defer close(ch)
		// Per-subscription dedup of exact mesh-fanout duplicates: gossipsub may
		// deliver the same vote from several peers, and each duplicate would pay
		// the full O(N) consumer cost downstream. Drop exact repeats (same rep,
		// position, hash AND Final flag) seen within dedupTTL — by definition they
		// carry no new information. Final is in the key so a converge vote and the
		// later final vote from the same rep are distinct keys and both pass. The
		// map is owned solely by this goroutine, so no lock is needed. (#565)
		seen := make(map[string]int64)
		for {
			msg, err := vg.sub.Next(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				logging.Warnf("vote gossip recv error: %v", err)
				continue
			}

			var vm VoteMsg
			dec := json.NewDecoder(bytes.NewReader(msg.Data))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&vm); err != nil {
				logging.Warnf("vote gossip unmarshal error: %v", err)
				continue
			}
			if vm.Vote == nil {
				continue
			}
			// Pre-validate required fields and expected lengths to reject
			// malformed votes before expensive signature verification.
			// RepPubKey and BlockHash are 64 hex chars (32 bytes),
			// Signature is 64 raw bytes (ed25519).
			v := vm.Vote
			if len(v.RepPubKey) != 64 || len(v.BlockHash) != 64 || len(v.Signature) != 64 {
				continue
			}

			// Verify the signature, then dedup + priority-send. (#565, #570/H9)
			if !ingestVote(ctx, ch, seen, v, core.VerifyVoteSignature, time.Now().UnixNano()) {
				// forged, duplicate, dropped converge vote, or ctx cancelled
				if ctx.Err() != nil {
					return
				}
			}
		}
	}()
	return ch
}

// voteDedupTTL is the window within which an exact duplicate vote (same rep,
// position, block hash, and Final flag) is dropped before the channel — a
// mesh-fanout copy within this window carries no new information. (#565)
const voteDedupTTL = int64(200 * time.Millisecond)

// ingestVote runs the gossip-ingestion pipeline for one received vote:
// signature verification FIRST, then dedup + priority send. #570/H9: verifying
// before dedup means a forged vote (e.g. an attacker flooding Final=true votes
// for a victim rep with random signature bytes) is dropped before it can touch
// `seen`, so it can no longer evict/suppress the rep's genuine, finality-
// critical vote within the dedup TTL. verify is injectable for testing.
func ingestVote(ctx context.Context, ch chan<- *core.Vote, seen map[string]int64, v *core.Vote, verify func(*core.Vote) bool, now int64) bool {
	if !verify(v) {
		return false // forged signature — never reaches dedup state or the channel
	}
	return enqueueVote(ctx, ch, seen, v, now)
}

// enqueueVote applies gossip-ingestion dedup and the final-vote-priority send
// policy for a single received vote, and returns whether it was forwarded onto
// ch. `seen` (key -> first-seen unix nanos) is owned solely by the caller's
// Subscribe goroutine, so no lock is needed.
//
// Dedup keys on the vote's self-reported identity (rep, position, hash, Final)
// BEFORE signature verification (which happens downstream in ReceiveVote). That
// is safe: the only effect of a forged-identity collision is suppressing a
// genuine identical vote for at most voteDedupTTL, which self-heals via the 15s
// re-emit and the re-arm on the next genuine inbound vote. Final is part of the
// key so a converge vote and the later final vote from the same rep are distinct
// and both pass. (#565)
func enqueueVote(ctx context.Context, ch chan<- *core.Vote, seen map[string]int64, v *core.Vote, now int64) bool {
	finalByte := "c"
	if v.Final {
		finalByte = "f"
	}
	key := v.RepPubKey + "|" + v.ConflictAccount + "|" + v.ConflictPrev + "|" + v.BlockHash + "|" + finalByte
	if ts, ok := seen[key]; ok && now-ts < voteDedupTTL {
		return false // exact duplicate within the TTL
	}
	seen[key] = now
	// Opportunistic age-based GC keeps the map bounded under sustained distinct
	// votes.
	if len(seen) > 4096 {
		for k, ts := range seen {
			if now-ts >= voteDedupTTL {
				delete(seen, k)
			}
		}
	}

	if v.Final {
		// Final votes are finality-critical, rare, and emitted exactly once with
		// no rebroadcast — never drop one. Block (ctx-guarded) instead.
		select {
		case ch <- v:
			return true
		case <-ctx.Done():
			return false
		}
	}
	// Converge votes are re-driven by the sweep, so a non-blocking drop on a full
	// buffer is safe.
	select {
	case ch <- v:
		return true
	default:
		logging.Warnf("gossip: vote channel full, dropping CONVERGE vote from %s", shortHash(v.RepPubKey))
		return false
	}
}

// MarketplaceGossip manages GossipSub for marketplace message broadcasting.
type MarketplaceGossip struct {
	topic *pubsub.Topic
	sub   *pubsub.Subscription
}

// NewMarketplaceGossip joins the marketplace topic on the given PubSub instance.
func NewMarketplaceGossip(ps *pubsub.PubSub) (*MarketplaceGossip, error) {
	topic, err := ps.Join(MarketplaceTopic)
	if err != nil {
		return nil, err
	}
	sub, err := topic.Subscribe()
	if err != nil {
		return nil, err
	}
	return &MarketplaceGossip{topic: topic, sub: sub}, nil
}

// Publish broadcasts a marketplace message to all peers.
func (mg *MarketplaceGossip) Publish(ctx context.Context, msg *MarketplaceMsg) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return mg.topic.Publish(ctx, data)
}

// StateChainGossip manages GossipSub for state chain block broadcasting.
type StateChainGossip struct {
	topic *pubsub.Topic
	sub   *pubsub.Subscription
}

// NewStateChainGossip joins the state chain topic on the given PubSub instance.
func NewStateChainGossip(ps *pubsub.PubSub) (*StateChainGossip, error) {
	topic, err := ps.Join(StateChainTopic)
	if err != nil {
		return nil, err
	}
	sub, err := topic.Subscribe()
	if err != nil {
		return nil, err
	}
	return &StateChainGossip{topic: topic, sub: sub}, nil
}

// Publish broadcasts a state chain block to all peers.
func (sg *StateChainGossip) Publish(ctx context.Context, b *statechain.Block) error {
	msg := StateChainMsg{Block: b}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return sg.topic.Publish(ctx, data)
}

// Subscribe returns a channel that yields state chain blocks received from peers.
func (sg *StateChainGossip) Subscribe(ctx context.Context) <-chan *statechain.Block {
	ch := make(chan *statechain.Block, 16)
	go func() {
		defer close(ch)
		for {
			msg, err := sg.sub.Next(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				logging.Warnf("statechain gossip recv error: %v", err)
				continue
			}

			var scm StateChainMsg
			if err := json.Unmarshal(msg.Data, &scm); err != nil {
				logging.Warnf("statechain gossip unmarshal error: %v", err)
				continue
			}
			if scm.Block == nil {
				continue
			}
			// Pre-validate: hash must be 64 hex chars, at least one signature
			if len(scm.Block.Hash) != 64 || len(scm.Block.Signatures) == 0 {
				continue
			}

			select {
			case ch <- scm.Block:
			default:
				logging.Warnf("gossip: statechain channel full, dropping block %d", scm.Block.Index)
			}
		}
	}()
	return ch
}

// Subscribe returns a channel that yields marketplace messages received from peers.
func (mg *MarketplaceGossip) Subscribe(ctx context.Context) <-chan *MarketplaceMsg {
	ch := make(chan *MarketplaceMsg, 256)
	go func() {
		defer close(ch)
		for {
			msg, err := mg.sub.Next(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				logging.Warnf("marketplace gossip recv error: %v", err)
				continue
			}

			var mm MarketplaceMsg
			dec := json.NewDecoder(bytes.NewReader(msg.Data))
			if err := dec.Decode(&mm); err != nil {
				logging.Warnf("marketplace gossip unmarshal error: %v", err)
				continue
			}
			if mm.Type == "" {
				continue
			}

			select {
			case ch <- &mm:
			default:
				logging.Warnf("gossip: marketplace channel full, dropping message type=%s", mm.Type)
			}
		}
	}()
	return ch
}

// DirectoryGossip manages GossipSub for account directory registration broadcasting.
type DirectoryGossip struct {
	topic *pubsub.Topic
	sub   *pubsub.Subscription
}

// NewDirectoryGossip joins the directory topic on the given PubSub instance.
func NewDirectoryGossip(ps *pubsub.PubSub) (*DirectoryGossip, error) {
	topic, err := ps.Join(DirectoryTopic)
	if err != nil {
		return nil, err
	}
	sub, err := topic.Subscribe()
	if err != nil {
		return nil, err
	}
	return &DirectoryGossip{topic: topic, sub: sub}, nil
}

// Publish broadcasts an account registration to all peers.
func (dg *DirectoryGossip) Publish(ctx context.Context, reg *directory.Registration) error {
	data, err := json.Marshal(reg)
	if err != nil {
		return err
	}
	return dg.topic.Publish(ctx, data)
}

// Subscribe returns a channel that yields account registrations received from peers.
func (dg *DirectoryGossip) Subscribe(ctx context.Context) <-chan *directory.Registration {
	ch := make(chan *directory.Registration, 256)
	go func() {
		defer close(ch)
		for {
			msg, err := dg.sub.Next(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				logging.Warnf("directory gossip recv error: %v", err)
				continue
			}

			var reg directory.Registration
			if err := json.Unmarshal(msg.Data, &reg); err != nil {
				logging.Warnf("directory gossip unmarshal error: %v", err)
				continue
			}
			if reg.Account == "" || reg.Signature == "" {
				continue
			}

			select {
			case ch <- &reg:
			default:
				logging.Warnf("gossip: directory channel full, dropping registration for %s", shortHash(reg.Account))
			}
		}
	}()
	return ch
}

// CertificateGossip manages GossipSub for performance certificate broadcasting.
type CertificateGossip struct {
	topic *pubsub.Topic
	sub   *pubsub.Subscription
}

// NewCertificateGossip joins the certificate topic on the given PubSub instance.
func NewCertificateGossip(ps *pubsub.PubSub) (*CertificateGossip, error) {
	topic, err := ps.Join(CertificateTopic)
	if err != nil {
		return nil, err
	}
	sub, err := topic.Subscribe()
	if err != nil {
		return nil, err
	}
	return &CertificateGossip{topic: topic, sub: sub}, nil
}

// Publish broadcasts a performance certificate to all peers.
func (cg *CertificateGossip) Publish(ctx context.Context, cert *perf.Certificate) error {
	data, err := json.Marshal(cert)
	if err != nil {
		return err
	}
	return cg.topic.Publish(ctx, data)
}

// Subscribe returns a channel that yields certificates received from peers.
func (cg *CertificateGossip) Subscribe(ctx context.Context) <-chan *perf.Certificate {
	ch := make(chan *perf.Certificate, 64)
	go func() {
		defer close(ch)
		for {
			msg, err := cg.sub.Next(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				logging.Warnf("certificate gossip recv error: %v", err)
				continue
			}

			var cert perf.Certificate
			if err := json.Unmarshal(msg.Data, &cert); err != nil {
				continue
			}
			// Cheap shape check only; the real verification (hash, key
			// derivation, signature) is perf.VerifyCertificateContent in the
			// ingest path. ProviderPubKey is required since #829 — without it
			// the certificate carries no verifying key at all.
			if cert.Provider == "" || cert.ProviderPubKey == "" || cert.Hash == "" || cert.Signature == "" {
				continue
			}

			select {
			case ch <- &cert:
			default:
			}
		}
	}()
	return ch
}
