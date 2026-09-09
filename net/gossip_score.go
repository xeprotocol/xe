package net

import (
	"log"
	"math"
	"net"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	scoreDecayInterval = 12 * time.Second

	scoreDecayToZero = 0.01

	scoreRetention = time.Hour

	gossipThreshold        = -100.0
	publishThreshold       = -200.0
	graylistThreshold      = -400.0
	acceptPXThreshold      = 100.0
	opportunisticGraftPeak = 5.0

	trustedPeerScore = 100000.0

	ipColocationThreshold = 8
	ipColocationWeight    = -20.0

	behaviourPenaltyWeight    = -10.0
	behaviourPenaltyThreshold = 6.0

	invalidMessageWeight = -25.0
)

func scoreDecay(halflife time.Duration) float64 {
	intervals := float64(halflife) / float64(scoreDecayInterval)
	if intervals <= 0 {
		return 0
	}
	return math.Pow(0.5, 1/intervals)
}

func topicScoreParams(weight float64) *pubsub.TopicScoreParams {
	return &pubsub.TopicScoreParams{
		TopicWeight: weight,

		TimeInMeshWeight:  0.02,
		TimeInMeshQuantum: scoreDecayInterval,
		TimeInMeshCap:     100,

		FirstMessageDeliveriesWeight: 0.5,
		FirstMessageDeliveriesDecay:  scoreDecay(10 * time.Minute),
		FirstMessageDeliveriesCap:    50,

		MeshMessageDeliveriesWeight:     0,
		MeshMessageDeliveriesDecay:      0,
		MeshMessageDeliveriesCap:        0,
		MeshMessageDeliveriesThreshold:  0,
		MeshMessageDeliveriesWindow:     0,
		MeshMessageDeliveriesActivation: 0,
		MeshFailurePenaltyWeight:        0,
		MeshFailurePenaltyDecay:         0,

		InvalidMessageDeliveriesWeight: invalidMessageWeight,
		InvalidMessageDeliveriesDecay:  scoreDecay(30 * time.Minute),
	}
}

func peerScoreParams(cfg GossipConfig) *pubsub.PeerScoreParams {
	trusted := cfg.Trusted
	return &pubsub.PeerScoreParams{
		Topics: map[string]*pubsub.TopicScoreParams{

			BlockTopic:      topicScoreParams(0.5),
			VoteTopic:       topicScoreParams(0.5),
			StateChainTopic: topicScoreParams(0.3),

			DirectoryTopic:   topicScoreParams(0.15),
			CertificateTopic: topicScoreParams(0.15),
			MarketplaceTopic: topicScoreParams(0.15),
		},

		TopicScoreCap: 50,

		AppSpecificScore: func(p peer.ID) float64 {
			if trusted != nil && trusted(p) {
				return trustedPeerScore
			}
			return 0
		},
		AppSpecificWeight: 1,

		IPColocationFactorWeight:    ipColocationWeight,
		IPColocationFactorThreshold: ipColocationThreshold,
		IPColocationFactorWhitelist: privateIPNets(),

		BehaviourPenaltyWeight:    behaviourPenaltyWeight,
		BehaviourPenaltyThreshold: behaviourPenaltyThreshold,
		BehaviourPenaltyDecay:     scoreDecay(10 * time.Minute),

		DecayInterval: scoreDecayInterval,
		DecayToZero:   scoreDecayToZero,
		RetainScore:   scoreRetention,
	}
}

func peerScoreThresholds() *pubsub.PeerScoreThresholds {
	return &pubsub.PeerScoreThresholds{
		GossipThreshold:             gossipThreshold,
		PublishThreshold:            publishThreshold,
		GraylistThreshold:           graylistThreshold,
		AcceptPXThreshold:           acceptPXThreshold,
		OpportunisticGraftThreshold: opportunisticGraftPeak,
	}
}

func privateIPNets() []*net.IPNet {
	cidrs := []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		nets = append(nets, n)
	}
	return nets
}

func scoreInspector(scores map[peer.ID]float64) {
	for p, s := range scores {
		if s < gossipThreshold {
			log.Printf("gossip: peer %s scored %.1f (gossip<%.0f publish<%.0f graylist<%.0f)",
				p.ShortString(), s, gossipThreshold, publishThreshold, graylistThreshold)
		}
	}
}
