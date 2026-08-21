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

// Topic validators (#840).
//
// GossipSub relays a message to the mesh as soon as its validators accept it.
// Without validators, "accept" is unconditional: every field check in this
// package's Subscribe loops runs only after the message has already been
// forwarded to ~D=6 peers, so the network amplifies an attacker's garbage on
// the attacker's behalf and every node pays the parse cost. Validators are the
// only hook that halts propagation.
//
// # Strictness policy
//
// Validators are the propagation gate, not the acceptance gate, and the two
// want different strictness. XE has no fork machinery and no activation
// heights (see epic #828): a future protocol version cannot be negotiated, it
// just appears on the wire. If validators rejected anything they did not
// recognise, then the day a block gains a field, old nodes would both refuse
// to relay new-format messages AND charge the GossipSub P4 invalid-message
// penalty against the peers sending them — graylisting the new-version half of
// the network. The hardening would itself cause the partition it exists to
// prevent.
//
// So the split is:
//
//   - ValidationReject (message dropped, sender penalised) — wire-level
//     malformation that no version of this protocol could produce: undecodable
//     JSON, an absent payload object, identity fields of the wrong length, a
//     signature that does not verify under the key the payload itself names,
//     proof-of-work that does not meet the configured difficulty.
//
//   - ValidationIgnore (message dropped, sender NOT penalised) — anything a
//     legitimate future format could cause: a block whose recomputed hash does
//     not match (a canonical-encoding change lands here), a marketplace message
//     of an unknown type.
//
//   - Validators decode LENIENTLY. `DisallowUnknownFields` stays where it is,
//     in the Subscribe loops, so what this node ACCEPTS is unchanged; but an
//     unknown-field message is still relayed. Consensus forward-compatibility
//     is unchanged and still needs the activation machinery tracked in #828 W2.
//
// # The one forward-compatibility cost, stated plainly
//
// The block validator recomputes the hash, and it has to: without that, one
// solved proof-of-work nonce would launder unlimited distinct payloads through
// the PoW gate. The consequence is that a future change to the CANONICAL
// ENCODING (a new hashed field, a new block type carrying one) makes old nodes
// stop RELAYING new-format blocks, where today they would relay what they
// cannot themselves apply.
//
// That cost is bounded and is judged worth paying:
//
//   - The decision is Ignore, NOT Reject. No score penalty, so a
//     version-skewed peer is never graylisted and the peer graph does not
//     partition; a node that upgrades resumes relaying immediately.
//   - Ignore here is the propagation-layer counterpart of what the ledger now
//     does with the same situation. sys.activations (#830/#878) made "unknown
//     block type" and "not yet activated" RETRYABLE in core.IsRetryableError:
//     a stale node PARKS such a block and re-applies it once it upgrades or
//     once the activation lands, rather than quarantining it. Both layers say
//     the same thing — version skew is not misbehaviour, so it must cost the
//     sender nothing and must not be permanent. If either side is ever
//     tightened, the other has to move with it: a Reject here would penalise
//     peers for blocks the ledger deliberately parks, and a quarantine there
//     would strand blocks this layer deliberately declines to judge.
//   - An old node that stops relaying a new-format block still RECEIVES it,
//     through sync anti-entropy rather than the mesh, and parks it per the
//     above. Propagation degrades to the pull path for the upgrade window; it
//     does not stop.
//   - Fields that are not part of the canonical pre-image (and any additive
//     wire framing) still relay untouched.
//
// The real fix for hashed-format evolution is the activation machinery #828
// requires in the Genesis(1) binary; #830 landed its first half (a governed,
// ship-dark feature registry), and the encoding-versioning half is still open.
//
// # Self-certifying payloads (#829)
//
// An account address is sha256("xe/account/v1" || pubkey), so an address alone
// cannot check a signature. The off-chain payloads on these topics — directory
// registrations, performance certificates, marketplace ads/requests/offers —
// therefore carry the signer's public key bound into their own signed bytes,
// and their canonical verifiers call core.VerifyPayloadKey (key derives the
// claimed address) BEFORE verifying the signature. A signature that verifies
// under a key the sender chose proves nothing about the account it names.
//
// These validators delegate to those canonical verifiers rather than
// re-implementing any part of the check, which is the only way the ordering
// cannot drift. A payload carrying no key at all is Reject, not Ignore: since
// #829 required a network wipe, no peer on this network can be running a
// version that omits it.
//
// Deliberately NOT in the validators:
//
//   - Block signature verification. It is ~50 µs of ed25519 versus ~1 µs for
//     hash-plus-PoW, and under #829 the credential for an account is the key
//     the LEDGER stored, not a field of the block — a gossip-layer signature
//     check would either duplicate that lookup or silently drift from it. PoW
//     is the right gossip-layer gate: ~1 CPU-second per block for the attacker,
//     one blake2b for us, and no credential semantics at all.
//
//   - Freshness/expiry checks (certificates, registrations). Two honest nodes
//     with skewed clocks would disagree about relaying, which is a partition
//     risk for zero attacker cost. Expiry stays an acceptance-side decision.
//
//   - Statechain DAO threshold verification. It needs the live keyset, which a
//     node is still replaying at startup; rejecting during that window would
//     stop a booting node relaying governance blocks.

// GossipConfig carries the node-level policy the gossip layer needs.
type GossipConfig struct {
	// Difficulty is the block proof-of-work threshold, matching the value the
	// ledger validates with. Zero disables the PoW gate in the block
	// validator, exactly as it disables it in the ledger.
	Difficulty uint64

	// Trusted reports whether a peer is operator-chosen (a bootstrap). Trusted
	// peers receive a large positive application-specific score so peer
	// scoring can never graylist the links the operator picked. May be nil.
	Trusted func(peer.ID) bool

	// ScoreInspect, if non-nil, replaces the default score inspector (which
	// logs peers below the gossip threshold). Intended for metrics export and
	// for tests that need to observe scoring directly.
	ScoreInspect func(map[peer.ID]float64)

	// ScoreInspectInterval overrides how often the inspector runs. 0 =
	// default.
	ScoreInspectInterval time.Duration
}

// gossipTopics is the full set of topics this node participates in. Used both
// for validator registration and for the subscription allowlist.
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

// RegisterTopicValidators installs a validator on every gossip topic. It must
// be called before joining the topics.
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

// isHex64 reports whether s is exactly 32 bytes of lowercase-or-uppercase hex.
// Every identity field on the wire (account address, block hash, public key)
// is a 32-byte value; a field of any other length cannot be one.
func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// blockValidator gates the block topic on structural validity, hash
// consistency and proof-of-work — cheapest check first, and no ed25519.
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
		// A block is authenticated either by a single-key signature or by a
		// multisig signature set. Accepting both here is deliberate: the
		// Subscribe loop's single-key-only length check would otherwise stop
		// multisig blocks propagating at all, which they do today.
		if len(b.Signature) != 128 && len(b.Signatures) == 0 {
			return pubsub.ValidationReject
		}

		// Hash consistency. A mismatch is Ignore, not Reject: the canonical
		// encoding is exactly the thing a future version changes, and an old
		// node must not penalise a new one for it.
		expected, err := core.HashBlock(b)
		if err != nil || expected != b.Hash {
			return pubsub.ValidationIgnore
		}

		// Proof of work. The hash is now known to be the block's real hash, so
		// a failing nonce is unambiguous: this peer sent spam that cost it
		// nothing. Skipped when PoW is disabled, matching the ledger.
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

// voteValidator gates the vote topic on structure and signature. Votes are
// small, fixed-shape and self-certifying (the vote names the representative
// key it is signed by), so verifying here is both cheap and complete — and it
// is the same check ingestVote already applies, moved to where it can stop
// propagation rather than merely stopping local processing.
//
// verify is injected so tests can drive the validator without reaching into
// core's unexported vote signing bytes; production always passes
// core.VerifyVoteSignature.
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

// stateChainValidator gates the statechain topic on structure only. DAO
// threshold verification needs the live keyset and is left to the acceptance
// path: a node still replaying the statechain at startup would otherwise
// refuse to relay perfectly good governance blocks.
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

// directoryValidator gates the directory topic on the registration's own
// signature. Registrations are self-certifying and freely mintable, so an
// unverified one is pure amplification: without this, any keypair could have
// its junk fanned out network-wide.
func directoryValidator() pubsub.ValidatorEx {
	return func(_ context.Context, _ peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
		var reg directory.Registration
		if err := json.Unmarshal(msg.Data, &reg); err != nil {
			return pubsub.ValidationReject
		}
		if reg.Account == "" || reg.PubKey == "" || reg.Signature == "" || reg.NodePeer == "" {
			return pubsub.ValidationReject
		}
		// VerifyRegistration ties PubKey to the claimed address
		// (core.VerifyPayloadKey) BEFORE checking the signature — see the
		// self-certifying-payload note above. Do not inline a signature check
		// here; it would drop that ordering.
		if err := directory.VerifyRegistration(&reg); err != nil {
			return pubsub.ValidationReject
		}
		return pubsub.ValidationAccept
	}
}

// certificateValidator gates the certificate topic on content validity (hash
// and provider signature). Certificates are persisted on acceptance, so
// relaying unverified ones spends every peer's disk as well as its bandwidth.
// Expiry is deliberately not checked here — see the strictness policy above.
func certificateValidator() pubsub.ValidatorEx {
	return func(_ context.Context, _ peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
		var cert perf.Certificate
		if err := json.Unmarshal(msg.Data, &cert); err != nil {
			return pubsub.ValidationReject
		}
		if cert.Provider == "" || cert.ProviderPubKey == "" || cert.Hash == "" || cert.Signature == "" {
			return pubsub.ValidationReject
		}
		// VerifyCertificateContent recomputes the hash, ties ProviderPubKey to
		// the provider ADDRESS (core.VerifyPayloadKey) and only then checks the
		// signature (#829).
		if err := perf.VerifyCertificateContent(&cert); err != nil {
			return pubsub.ValidationReject
		}
		return pubsub.ValidationAccept
	}
}

// marketplaceValidator gates the marketplace topic on the signature carried by
// whichever payload the message declares. An unknown Type is Ignored rather
// than Rejected: a new message type is precisely the forward-compatible change
// this policy must not punish.
//
// The Verify* helpers are the canonical ones from marketplace_sign.go, which
// run core.VerifyPayloadKey before the signature check (#829). Calling them
// rather than re-implementing the check here is what keeps the ordering.
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
