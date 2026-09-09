package net

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/directory"
	"github.com/xeprotocol/xe/perf"
)

type GossipConfig struct {
	Difficulty uint64

	Trusted func(peer.ID) bool

	ScoreInspect func(map[peer.ID]float64)

	ScoreInspectInterval time.Duration
}

func gossipTopics() []string {
	return []string{
		BlockTopic,
		VoteTopic,
		MarketplaceTopic,
		StateChainTopic,
		DirectoryTopic,
		CertificateTopic,
	}
}

func RegisterTopicValidators(ps *pubsub.PubSub, cfg GossipConfig) error {
	validators := map[string]pubsub.ValidatorEx{
		BlockTopic:       blockValidator(cfg),
		VoteTopic:        voteValidator(core.VerifyVoteSignature),
		StateChainTopic:  stateChainValidator(),
		DirectoryTopic:   directoryValidator(),
		CertificateTopic: certificateValidator(),
		MarketplaceTopic: marketplaceValidator(),
	}
	for topic, v := range validators {
		if err := ps.RegisterTopicValidator(topic, v); err != nil {
			return err
		}
	}
	return nil
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func blockValidator(cfg GossipConfig) pubsub.ValidatorEx {
	return func(_ context.Context, _ peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
		var bm BlockMsg
		if err := json.Unmarshal(msg.Data, &bm); err != nil {
			return pubsub.ValidationReject
		}
		b := bm.Block
		if b == nil {
			return pubsub.ValidationReject
		}
		if !isHex64(b.Hash) || !isHex64(b.Account) {
			return pubsub.ValidationReject
		}

		if len(b.Signature) != 128 && len(b.Signatures) == 0 {
			return pubsub.ValidationReject
		}

		expected, err := core.HashBlock(b)
		if err != nil || expected != b.Hash {
			return pubsub.ValidationIgnore
		}

		if cfg.Difficulty > 0 {
			hashBytes, err := hex.DecodeString(b.Hash)
			if err != nil {
				return pubsub.ValidationReject
			}
			if !core.ValidatePoW(hashBytes, b.PoWNonce, cfg.Difficulty) {
				return pubsub.ValidationReject
			}
		}

		return pubsub.ValidationAccept
	}
}

func voteValidator(verify func(*core.Vote) bool) pubsub.ValidatorEx {
	return func(_ context.Context, _ peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
		var vm VoteMsg
		if err := json.Unmarshal(msg.Data, &vm); err != nil {
			return pubsub.ValidationReject
		}
		v := vm.Vote
		if v == nil {
			return pubsub.ValidationReject
		}
		if !isHex64(v.RepPubKey) || !isHex64(v.BlockHash) {
			return pubsub.ValidationReject
		}
		if len(v.Signature) != 64 {
			return pubsub.ValidationReject
		}
		if !verify(v) {
			return pubsub.ValidationReject
		}
		return pubsub.ValidationAccept
	}
}

func stateChainValidator() pubsub.ValidatorEx {
	return func(_ context.Context, _ peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
		var scm StateChainMsg
		if err := json.Unmarshal(msg.Data, &scm); err != nil {
			return pubsub.ValidationReject
		}
		b := scm.Block
		if b == nil {
			return pubsub.ValidationReject
		}
		if !isHex64(b.Hash) {
			return pubsub.ValidationReject
		}
		if len(b.Signatures) == 0 {
			return pubsub.ValidationReject
		}
		return pubsub.ValidationAccept
	}
}

func directoryValidator() pubsub.ValidatorEx {
	return func(_ context.Context, _ peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
		var reg directory.Registration
		if err := json.Unmarshal(msg.Data, &reg); err != nil {
			return pubsub.ValidationReject
		}
		if reg.Account == "" || reg.PubKey == "" || reg.Signature == "" || reg.NodePeer == "" {
			return pubsub.ValidationReject
		}

		if err := directory.VerifyRegistration(&reg); err != nil {
			return pubsub.ValidationReject
		}
		return pubsub.ValidationAccept
	}
}

func certificateValidator() pubsub.ValidatorEx {
	return func(_ context.Context, _ peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
		var cert perf.Certificate
		if err := json.Unmarshal(msg.Data, &cert); err != nil {
			return pubsub.ValidationReject
		}
		if cert.Provider == "" || cert.ProviderPubKey == "" || cert.Hash == "" || cert.Signature == "" {
			return pubsub.ValidationReject
		}

		if err := perf.VerifyCertificateContent(&cert); err != nil {
			return pubsub.ValidationReject
		}
		return pubsub.ValidationAccept
	}
}

func marketplaceValidator() pubsub.ValidatorEx {
	return func(_ context.Context, _ peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
		var mm MarketplaceMsg
		if err := json.Unmarshal(msg.Data, &mm); err != nil {
			return pubsub.ValidationReject
		}
		switch mm.Type {
		case "advertisement":
			if mm.Ad == nil {
				return pubsub.ValidationReject
			}
			if err := VerifyAdvertisement(mm.Ad); err != nil {
				return pubsub.ValidationReject
			}
		case "request":
			if mm.Request == nil {
				return pubsub.ValidationReject
			}
			if err := VerifyRequest(mm.Request); err != nil {
				return pubsub.ValidationReject
			}
		case "offer":
			if mm.Offer == nil {
				return pubsub.ValidationReject
			}
			if err := VerifyOffer(mm.Offer); err != nil {
				return pubsub.ValidationReject
			}
		case "":
			return pubsub.ValidationReject
		default:
			return pubsub.ValidationIgnore
		}
		return pubsub.ValidationAccept
	}
}
