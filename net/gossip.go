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

	MaxGossipMessageSize = 262144
)

const maxSubscribedTopics = 16

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

		pubsub.WithPeerScore(peerScoreParams(cfg), peerScoreThresholds()),
		pubsub.WithPeerScoreInspect(inspect, inspectEvery),

		pubsub.WithSubscriptionFilter(
			pubsub.WrapLimitSubscriptionFilter(
				pubsub.NewAllowlistSubscriptionFilter(gossipTopics()...),
				maxSubscribedTopics,
			),
		),

		pubsub.WithValidateQueueSize(512),
	}
}

func NewPubSub(ctx context.Context, h host.Host, cfg GossipConfig) (*pubsub.PubSub, error) {
	ps, err := pubsub.NewGossipSub(ctx, h, gossipOptions(cfg)...)
	if err != nil {
		return nil, err
	}

	if err := RegisterTopicValidators(ps, cfg); err != nil {
		return nil, err
	}
	return ps, nil
}

type Gossip struct {
	ps    *pubsub.PubSub
	topic *pubsub.Topic
	sub   *pubsub.Subscription
}

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

func (g *Gossip) PubSub() *pubsub.PubSub {
	return g.ps
}

func (g *Gossip) Publish(ctx context.Context, b *core.Block) error {
	msg := BlockMsg{Block: b}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return g.topic.Publish(ctx, data)
}

var droppedBlocks atomic.Uint64

func DroppedBlocks() uint64 {
	return droppedBlocks.Load()
}

func recordDroppedBlock() uint64 {
	return droppedBlocks.Add(1)
}

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

type VoteGossip struct {
	topic *pubsub.Topic
	sub   *pubsub.Subscription
}

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

func (vg *VoteGossip) Publish(ctx context.Context, v *core.Vote) error {
	msg := VoteMsg{Vote: v}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return vg.topic.Publish(ctx, data)
}

func (vg *VoteGossip) Subscribe(ctx context.Context) <-chan *core.Vote {

	ch := make(chan *core.Vote, 1024)
	go func() {
		defer close(ch)

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

			v := vm.Vote
			if len(v.RepPubKey) != 64 || len(v.BlockHash) != 64 || len(v.Signature) != 64 {
				continue
			}

			if !ingestVote(ctx, ch, seen, v, core.VerifyVoteSignature, time.Now().UnixNano()) {

				if ctx.Err() != nil {
					return
				}
			}
		}
	}()
	return ch
}

const voteDedupTTL = int64(200 * time.Millisecond)

func ingestVote(ctx context.Context, ch chan<- *core.Vote, seen map[string]int64, v *core.Vote, verify func(*core.Vote) bool, now int64) bool {
	if !verify(v) {
		return false
	}
	return enqueueVote(ctx, ch, seen, v, now)
}

func enqueueVote(ctx context.Context, ch chan<- *core.Vote, seen map[string]int64, v *core.Vote, now int64) bool {
	finalByte := "c"
	if v.Final {
		finalByte = "f"
	}
	key := v.RepPubKey + "|" + v.ConflictAccount + "|" + v.ConflictPrev + "|" + v.BlockHash + "|" + finalByte
	if ts, ok := seen[key]; ok && now-ts < voteDedupTTL {
		return false
	}
	seen[key] = now

	if len(seen) > 4096 {
		for k, ts := range seen {
			if now-ts >= voteDedupTTL {
				delete(seen, k)
			}
		}
	}

	if v.Final {

		select {
		case ch <- v:
			return true
		case <-ctx.Done():
			return false
		}
	}

	select {
	case ch <- v:
		return true
	default:
		logging.Warnf("gossip: vote channel full, dropping CONVERGE vote from %s", shortHash(v.RepPubKey))
		return false
	}
}

type MarketplaceGossip struct {
	topic *pubsub.Topic
	sub   *pubsub.Subscription
}

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

func (mg *MarketplaceGossip) Publish(ctx context.Context, msg *MarketplaceMsg) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return mg.topic.Publish(ctx, data)
}

type StateChainGossip struct {
	topic *pubsub.Topic
	sub   *pubsub.Subscription
}

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

func (sg *StateChainGossip) Publish(ctx context.Context, b *statechain.Block) error {
	msg := StateChainMsg{Block: b}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return sg.topic.Publish(ctx, data)
}

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

type DirectoryGossip struct {
	topic *pubsub.Topic
	sub   *pubsub.Subscription
}

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

func (dg *DirectoryGossip) Publish(ctx context.Context, reg *directory.Registration) error {
	data, err := json.Marshal(reg)
	if err != nil {
		return err
	}
	return dg.topic.Publish(ctx, data)
}

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

type CertificateGossip struct {
	topic *pubsub.Topic
	sub   *pubsub.Subscription
}

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

func (cg *CertificateGossip) Publish(ctx context.Context, cert *perf.Certificate) error {
	data, err := json.Marshal(cert)
	if err != nil {
		return err
	}
	return cg.topic.Publish(ctx, data)
}

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
