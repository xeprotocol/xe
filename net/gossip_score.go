package net

import (
	"log"
	"math"
	"net"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/peer"
)

// GossipSub peer scoring (#840).
//
// Scoring is the mechanism that makes topic validators bite: a validator stops
// one message, scoring stops the peer that keeps sending them. It is also the
// single easiest way to partition an honest network — mis-tuned parameters
// silently graylist well-behaved peers and the network splits with nothing in
// the logs but a falling peer count. Every choice below is therefore biased
// towards liveness, and the properties that keep it safe are asserted in
// gossip_score_test.go:
//
//  1. An honest peer's score can never go negative. Every positive term is
//     opt-in (time in mesh, first deliveries) and every negative term requires
//     provable misbehaviour (invalid messages, router-level protocol abuse,
//     extreme IP colocation). A silent-but-honest peer scores exactly 0, which
//     is above every threshold.
//
//  2. P3 / P3b (mesh message deliveries, mesh failure penalty) are DISABLED.
//     This is the classic footgun and it is a bad fit for XE specifically: the
//     penalty punishes peers that deliver fewer than a threshold of mesh
//     messages per window, and XE's topics are low-rate and bursty (a handful
//     of blocks a minute; the statechain topic can be silent for hours). With
//     P3 on, a quiet topic drives every honest peer negative simultaneously.
//     Enabling it would need per-topic rate measurements from a live network
//     of realistic size, which does not exist yet (#450).
//
//  3. Operator-chosen bootstrap peers get a large positive application score,
//     so realistic penalty accumulation cannot graylist the links the operator
//     deliberately configured (see trustedPeerScore for the exact bound). That
//     is a trust decision, and the mirror of the eclipse defence in
//     netcheck.go: the operator's chosen peers are the ones an attacker must
//     not be able to squeeze out. An operator who no longer trusts a bootstrap
//     removes it from --dial.
//
// What actually stops a spammer is milder and faster than the graylist.
// GossipSub PRUNEs any mesh peer whose score is negative and will not GRAFT it
// back while it stays negative, and flood publishing is off, so a peer that has
// been pruned cannot inject into our mesh at all. Measured over real hosts in
// gossip_score_test.go, that costs a spammer its channel after about three
// rejected messages. The thresholds below are the deeper backstops: roughly six
// rejected messages inside the penalty half-life reach the graylist, and every
// penalty decays away on its own, so a node that was briefly broken recovers
// without operator action.

const (
	// scoreDecayInterval is how often score counters decay. Long relative to
	// libp2p defaults because XE's message rates are low; a short interval
	// with low traffic makes scores jittery.
	scoreDecayInterval = 12 * time.Second

	// scoreDecayToZero is the counter value below which a counter is treated
	// as zero.
	scoreDecayToZero = 0.01

	// scoreRetention is how long a disconnected peer's score is remembered.
	// Long enough that reconnecting does not launder a penalty, short enough
	// that a node that was briefly misconfigured recovers within an hour.
	scoreRetention = time.Hour

	// Score thresholds. All are wide: honest peers sit at >= 0.
	gossipThreshold        = -100.0
	publishThreshold       = -200.0
	graylistThreshold      = -400.0
	acceptPXThreshold      = 100.0
	opportunisticGraftPeak = 5.0

	// trustedPeerScore is the application-specific score given to
	// operator-chosen peers.
	//
	// Sized so that ordinary penalty accumulation cannot reach it: with the
	// weights below, graylisting a trusted peer needs roughly 48 rejected
	// messages on EVERY topic simultaneously, inside the 30-minute penalty
	// half-life. A bootstrap doing that is compromised or broken, not merely
	// unlucky, and even then it keeps its CONNECTION (it is unbannable and
	// connection-manager-protected), so frontier sync continues while gossip
	// processing degrades. It is deliberately finite rather than infinite: an
	// operator who no longer trusts a bootstrap removes it from --dial, but
	// the node should not be defenceless in the meantime.
	trustedPeerScore = 100000.0

	// ipColocationThreshold allows as many same-IP peers as the transport
	// layer's per-IP connection cap does (net/host.go, --max-conns-per-ip),
	// so the two limits agree instead of fighting.
	ipColocationThreshold = 8
	ipColocationWeight    = -20.0

	// Behaviour penalty (P7): router-level abuse such as re-grafting inside
	// the prune backoff or advertising IHAVE and never answering IWANT.
	behaviourPenaltyWeight    = -10.0
	behaviourPenaltyThreshold = 6.0

	// Invalid-message penalty (P4) per topic, before the topic weight. The
	// penalty is the SQUARE of the counter, so with the weights below a peer
	// needs ~6 rejected messages inside the half-life to be graylisted.
	invalidMessageWeight = -25.0
)

// scoreDecay returns the per-interval decay multiplier giving the requested
// half-life.
func scoreDecay(halflife time.Duration) float64 {
	intervals := float64(halflife) / float64(scoreDecayInterval)
	if intervals <= 0 {
		return 0
	}
	return math.Pow(0.5, 1/intervals)
}

// topicScoreParams builds the per-topic parameters. weight scales the whole
// topic's contribution; consensus topics carry more weight than advisory ones.
func topicScoreParams(weight float64) *pubsub.TopicScoreParams {
	return &pubsub.TopicScoreParams{
		TopicWeight: weight,

		// P1: time in mesh. A small, slowly-earned positive so that a
		// long-standing peer has a buffer against a single bad message.
		TimeInMeshWeight:  0.02,
		TimeInMeshQuantum: scoreDecayInterval,
		TimeInMeshCap:     100,

		// P2: first message deliveries. Rewards peers that bring us news
		// first, which is what a well-connected honest peer does.
		FirstMessageDeliveriesWeight: 0.5,
		FirstMessageDeliveriesDecay:  scoreDecay(10 * time.Minute),
		FirstMessageDeliveriesCap:    50,

		// P3 / P3b: DISABLED — see the note at the top of this file.
		MeshMessageDeliveriesWeight:     0,
		MeshMessageDeliveriesDecay:      0,
		MeshMessageDeliveriesCap:        0,
		MeshMessageDeliveriesThreshold:  0,
		MeshMessageDeliveriesWindow:     0,
		MeshMessageDeliveriesActivation: 0,
		MeshFailurePenaltyWeight:        0,
		MeshFailurePenaltyDecay:         0,

		// P4: invalid messages. This is the term the topic validators feed.
		InvalidMessageDeliveriesWeight: invalidMessageWeight,
		InvalidMessageDeliveriesDecay:  scoreDecay(30 * time.Minute),
	}
}

// peerScoreParams builds the whole-peer scoring parameters.
func peerScoreParams(cfg GossipConfig) *pubsub.PeerScoreParams {
	trusted := cfg.Trusted
	return &pubsub.PeerScoreParams{
		Topics: map[string]*pubsub.TopicScoreParams{
			// Consensus-carrying topics.
			BlockTopic:      topicScoreParams(0.5),
			VoteTopic:       topicScoreParams(0.5),
			StateChainTopic: topicScoreParams(0.3),
			// Advisory topics: misbehaviour still costs, but they carry less
			// of the peer's overall standing.
			DirectoryTopic:   topicScoreParams(0.15),
			CertificateTopic: topicScoreParams(0.15),
			MarketplaceTopic: topicScoreParams(0.15),
		},

		// Cap the total positive contribution from topics so a peer cannot
		// farm goodwill on a cheap topic and spend it misbehaving on blocks.
		TopicScoreCap: 50,

		// P5: application-specific score. Operator-chosen peers only.
		AppSpecificScore: func(p peer.ID) float64 {
			if trusted != nil && trusted(p) {
				return trustedPeerScore
			}
			return 0
		},
		AppSpecificWeight: 1,

		// P6: IP colocation. A Sybil running many identities from one host is
		// the cheapest attack there is; this makes it visible to scoring.
		// Loopback and private ranges are whitelisted so that multi-node test
		// networks, LAN deployments and NATed operators are unaffected — the
		// per-IP connection cap already bounds those.
		IPColocationFactorWeight:    ipColocationWeight,
		IPColocationFactorThreshold: ipColocationThreshold,
		IPColocationFactorWhitelist: privateIPNets(),

		// P7: router-level behaviour penalty.
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

// privateIPNets lists the ranges exempt from the IP-colocation penalty:
// loopback, RFC1918, IPv6 loopback, link-local and unique-local.
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

// scoreInspector logs peers whose score has fallen below the gossip threshold.
// Scoring failures are otherwise invisible — the symptom is a quietly shrinking
// mesh — and a public network has no operator watching every node.
func scoreInspector(scores map[peer.ID]float64) {
	for p, s := range scores {
		if s < gossipThreshold {
			log.Printf("gossip: peer %s scored %.1f (gossip<%.0f publish<%.0f graylist<%.0f)",
				p.ShortString(), s, gossipThreshold, publishThreshold, graylistThreshold)
		}
	}
}
