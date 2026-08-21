package core

import (
	"fmt"
	"sort"
)

// ── Ship-dark validators (#830) ─────────────────────────────────────────────
//
// A "ship-dark" validator is the full, real validator for a block type that a
// LATER stage of the roadmap introduces, compiled into an EARLIER binary and
// refusing to run until the state chain says the feature is active. It is the
// enforcement half of sys.activations, and it is the half that cannot be
// retrofitted: governance records are forward-compatible already (an old node
// stores and relays a sys.* key it has never heard of), but a gate added after
// mainnet launch is a gate the already-deployed nodes do not have.
//
// HOW A FUTURE STAGE USES THIS
//
// The binary that introduces a type registers it here — one entry, no change
// to dispatchValidateAndAdd:
//
//	func init() {
//	    registerDarkValidator(BlockMessage, "messaging",
//	        func(l *Ledger, b *Block, skipTimestamp bool) error {
//	            return l.validateAndAddMessage(b)
//	        })
//	}
//
// Then the three states of the dispatch default case are:
//
//	type not registered   → errUnknownBlockType, exactly as before this change
//	registered, inactive  → errFeatureNotActivated (RETRYABLE — see below)
//	registered, active    → the real validator runs
//
// THE MAP IS EMPTY IN THE GENESIS(1) BINARY, AND THAT IS DELIBERATE.
//
// The twelve types that dispatchValidateAndAdd switches over are Genesis(1)
// consensus; none of them is gated. Gating an existing type would mean every
// network that wants it must SEED sys.activations at genesis — and a seeded
// sys.* key can never be deleted. It would also add a way for a live chain to
// LOSE functionality, which is a new failure mode for no gain: Genesis(1)
// scopes compute out economically instead (no sys.minter ⇒ no XUSD ⇒ a lease
// can never fund its escrow), with zero consensus-code risk. What ships here
// is the mechanism and its proof, not a speculative type.
//
// WHY THE GATE IS RETRYABLE AND NOT TERMINAL
//
// A node that has not yet synced the state chain past the activation point
// computes "inactive" for a block every other node accepts. That is transient,
// not deterministic, so it must never quarantine — IsRetryableError classifies
// both errFeatureNotActivated and the unknown-type error as retryable. C7 (the
// #673 lesson) says quarantine only on a failure that is identical on every
// node holding the dependencies; a verdict that depends on which binary and
// which state-chain height the node is running is precisely not that.

// FeatureNoop is a reserved feature name that gates nothing, ever. It exists
// so an activation can be rehearsed end to end — DAO signing, propagation,
// every node crossing the trigger, the operator comms — on a real network with
// no consensus consequence whatsoever. Genesis(1) rehearses with it; so does
// every network before a real activation.
const FeatureNoop = "noop"

// DarkValidateFunc is the signature of a gated type's validator. It matches the
// shape of the existing validateAndAddX methods so registering one is a
// one-line adaptation.
type DarkValidateFunc func(l *Ledger, b *Block, skipTimestamp bool) error

type darkValidator struct {
	feature  string
	validate DarkValidateFunc
}

// darkValidators maps a block type to the feature that must be active before
// this binary will validate it. EMPTY in the Genesis(1) binary — see the note
// above. Written only from package init functions, read-only thereafter, so no
// lock is needed and no runtime path can add a consensus rule.
var darkValidators = map[BlockType]darkValidator{}

// registerDarkValidator wires a gated block type to its feature. It is not
// exported: a consensus rule may only be added by editing this package and
// shipping a binary, never by configuration, an API call or a plugin.
func registerDarkValidator(t BlockType, feature string, fn DarkValidateFunc) {
	if feature == "" || fn == nil {
		panic("registerDarkValidator: feature and validator are required")
	}
	if _, dup := darkValidators[t]; dup {
		panic(fmt.Sprintf("registerDarkValidator: duplicate registration for block type %q", t))
	}
	darkValidators[t] = darkValidator{feature: feature, validate: fn}
}

// KnownFeatures lists the activation features this binary understands, sorted.
// A feature named on chain but absent from this list is one the node cannot
// enforce — the node warns loudly about those and governance evicts it via
// sys.min_protocol_version. This is what makes an un-upgraded node LOUD rather
// than silently wrong.
func KnownFeatures() []string {
	seen := map[string]bool{FeatureNoop: true}
	for _, dv := range darkValidators {
		seen[dv.feature] = true
	}
	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// KnownFeatureSet is KnownFeatures as a set, for callers rendering status.
func KnownFeatureSet() map[string]bool {
	set := make(map[string]bool)
	for _, f := range KnownFeatures() {
		set[f] = true
	}
	return set
}

// GatedBlockTypes lists the block types this binary gates behind a feature,
// with their feature names. Empty in the Genesis(1) binary.
func GatedBlockTypes() map[string]string {
	out := make(map[string]string, len(darkValidators))
	for t, dv := range darkValidators {
		out[string(t)] = dv.feature
	}
	return out
}

// FeatureActive reports whether an activation feature is active as of the
// state chain this ledger reads.
//
// Fail-CLOSED: with no reader wired (a bare ledger in a unit test, a node built
// without a state chain) nothing is ever active. The alternative — defaulting
// to active — would make a misconfigured node accept blocks the network
// rejects, which is the divergence this mechanism exists to prevent.
func (l *Ledger) FeatureActive(feature string) bool {
	if l.featureActiveFn == nil {
		return false
	}
	return l.featureActiveFn(feature)
}

// errFeatureNotActivatedFor builds the rejection for a registered-but-inactive
// type. The wording carries "not yet activated", which IsRetryableError keys
// on — the message IS the classification, so keep the phrase.
func errFeatureNotActivatedFor(t BlockType, feature string) error {
	return fmt.Errorf("block type %q requires feature %q: not yet activated (retry after statechain syncs)", t, feature)
}
