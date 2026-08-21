package statechain

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ── sys.activations — the on-chain feature activation registry (#830) ────────
//
// WHY THIS EXISTS
//
// XE has no fork machinery. `dispatchValidateAndAdd` (core/ledger.go) is a
// closed switch over the block types the running binary knows, and a rejected
// block at index N of an account chain means that node can never accept N+1 —
// in a lattice the divergence cascades. So introducing a block type, or any
// block field, is a hard fork: the only tool for one is a wipe, and a live
// mainnet cannot be wiped.
//
// The forward-compatible half of the fix already exists and always has:
// validateSysKeyValue has no default case and no allowlist, so a node ACCEPTS,
// STORES and RELAYS a DAO-signed sys.* key it has never heard of. Governance is
// forward-compatible by construction. The missing half is ENFORCEMENT, and
// enforcement lives in the binary — which is why the registry, the reader and
// the gate must ship in the Genesis(1) binary. Add them later and old nodes
// simply ignore the gate.
//
// THE TRIGGER
//
// A feature activates at the first point where the CONVERGED state chain
// satisfies both terms of its record:
//
//	Active(f) ⟺ tip.Index ≥ at_index ∧ tip.Timestamp ≥ not_before_ns
//
// Both terms read the state chain and nothing else — never the validating
// node's clock, config or peer set. That is the #501 invariant restated: a
// consensus-visible decision must be a pure function of chain content. Both
// terms are monotone (Index strictly increases; AddBlock rejects a block whose
// timestamp precedes the tip's), so their conjunction is monotone: once a
// feature is active it can never become inactive.
//
// Either term may be zero, meaning "this term imposes no constraint". A record
// with both terms zero is rejected — it would mean "active immediately", and
// activations are never retroactive.
//
// "Never activated" is expressed by ABSENCE from the registry, not by a
// sentinel value. That matters because of the sys.* asymmetry: a key can be
// added later by DAO block but can NEVER be deleted (ValidateOp rejects delete
// on any sys.* key). Absence is free and reversible; a seeded name is forever.
// For the same reason sys.activations is deliberately NOT seeded into any
// genesis: an absent key reads as an empty registry, which is exactly today's
// behaviour, and nothing is baked in that we might regret.
//
// WHAT IS *NOT* ENFORCED HERE, DELIBERATELY
//
// A minimum lead time (the epic suggests ~14 days) is NOT a validity rule. It
// protects operators from surprise, not the chain from an adversary — the only
// party who can write this key is the DAO, so a consensus rule buys nothing
// against the only party able to break it, while permanently foreclosing an
// emergency activation. The lead is enforced by the published operator
// procedure and the weight-readiness gate (docs/activations.md), and a node
// logs a loud warning when a record lands with less than RecommendedLeadNS of
// lead. Non-retroactivity and monotonicity ARE enforced, because those two
// change the validity of blocks that are already on the chain.

// ActivationsKey is the state-chain key holding the feature activation registry.
const ActivationsKey = "sys.activations"

// MinProtocolVersionKey is the state-chain key holding the governance-set
// minimum protocol version a peer must advertise to stay connected. It gives
// the DAO a lever to evict stale nodes without shipping a binary — the only
// other lever, the netcheck minor-drift rule, requires everyone to upgrade in
// order to enforce upgrading.
const MinProtocolVersionKey = "sys.min_protocol_version"

// MaxActivationFeatures bounds the registry so a single op cannot make every
// future validation walk an unbounded map.
const MaxActivationFeatures = 64

// RecommendedLeadNS is the lead time the operator procedure requires between a
// DAO activation op landing and the feature going live: 14 days. Advisory —
// see the note above on why this is not a validity rule.
const RecommendedLeadNS int64 = 14 * 24 * 60 * 60 * 1_000_000_000

// minSaneActivationNS rejects a not_before_ns that is obviously in the wrong
// unit. 1.6e18 ns is 2020-09-13; any real activation is far past it, and a
// seconds-valued timestamp is nine orders of magnitude below it. This catches
// the unit slip, not the schedule.
const minSaneActivationNS int64 = 1_600_000_000_000_000_000

// featureNameRegex constrains feature names to a conservative charset. Dots are
// excluded on purpose so a feature name can never be confused with a key path.
var featureNameRegex = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// ActivationRecord is the trigger for one feature. Both terms are floors on the
// state-chain tip and both must be met; zero means "no constraint from this
// term". At least one must be non-zero.
type ActivationRecord struct {
	// AtIndex is the state-chain index at or after which the feature is active.
	AtIndex uint64 `json:"at_index,omitempty"`
	// NotBeforeNS is the unix-nanosecond wall-clock floor, compared against the
	// state-chain TIP TIMESTAMP — never the local clock.
	NotBeforeNS int64 `json:"not_before_ns,omitempty"`
}

// ActiveAt reports whether the record's trigger is satisfied by a state chain
// whose tip is at (index, ns).
func (r ActivationRecord) ActiveAt(index uint64, ns int64) bool {
	return index >= r.AtIndex && ns >= r.NotBeforeNS
}

// Activations is the decoded value of sys.activations.
//
// It is an ENVELOPE around the feature map rather than a bare map so a later
// binary can add sibling fields without ambiguity. Decoding is deliberately
// LENIENT (no DisallowUnknownFields): a node must accept, store and relay a
// record written by a newer binary it does not fully understand — that
// property is the whole point of this mechanism, and rejecting on an unknown
// field would reintroduce the partition it exists to prevent.
//
// Trigger SEMANTICS are fixed as of the Genesis(1) binary. Adding a third
// trigger term for an existing feature would be a consensus change requiring a
// new binary, not a governance change — an old binary would evaluate the
// two terms it knows and activate at the wrong point.
type Activations struct {
	Features map[string]ActivationRecord `json:"features"`
}

// ParseActivations decodes a sys.activations value. A nil/empty value decodes
// to an empty registry rather than an error, so callers can treat "key absent"
// and "key present but empty" identically.
func ParseActivations(raw json.RawMessage) (*Activations, error) {
	a := &Activations{Features: map[string]ActivationRecord{}}
	if len(raw) == 0 {
		return a, nil
	}
	if err := json.Unmarshal(raw, a); err != nil {
		return nil, fmt.Errorf("invalid activations JSON: %w", err)
	}
	if a.Features == nil {
		a.Features = map[string]ActivationRecord{}
	}
	return a, nil
}

// Names returns the feature names in sorted order.
func (a *Activations) Names() []string {
	names := make([]string, 0, len(a.Features))
	for n := range a.Features {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ActiveAt reports whether feature is active on a chain whose tip is at
// (index, ns). An unregistered feature is never active.
func (a *Activations) ActiveAt(feature string, index uint64, ns int64) bool {
	if a == nil {
		return false
	}
	rec, ok := a.Features[feature]
	if !ok {
		return false
	}
	return rec.ActiveAt(index, ns)
}

// validateActivations is the static (prior-state-free) half of sys.activations
// validation, called from validateSysKeyValue.
func validateActivations(value json.RawMessage) error {
	a, err := ParseActivations(value)
	if err != nil {
		return err
	}
	if len(a.Features) > MaxActivationFeatures {
		return fmt.Errorf("activations: %d features exceeds maximum %d", len(a.Features), MaxActivationFeatures)
	}
	for name, rec := range a.Features {
		if !featureNameRegex.MatchString(name) {
			return fmt.Errorf("activations: feature name %q invalid (must match %s)", name, featureNameRegex)
		}
		if rec.AtIndex == 0 && rec.NotBeforeNS == 0 {
			return fmt.Errorf("activations: feature %q must set at_index or not_before_ns (both zero would mean active immediately)", name)
		}
		if rec.NotBeforeNS < 0 {
			return fmt.Errorf("activations: feature %q not_before_ns must not be negative", name)
		}
		if rec.NotBeforeNS != 0 && rec.NotBeforeNS < minSaneActivationNS {
			return fmt.Errorf("activations: feature %q not_before_ns %d is implausibly small — unix NANOSECONDS expected", name, rec.NotBeforeNS)
		}
	}
	return nil
}

// validateActivationsTransition enforces the two rules that protect blocks
// already on the chain, given the registry as of before b and the previous tip:
//
//  1. MONOTONIC — a feature is never removed, and once its trigger has fired
//     the record is frozen. Moving or clearing a fired trigger would retro-
//     actively invalidate blocks that were validated under it.
//  2. NON-RETROACTIVE — a new or rescheduled trigger must still be in the
//     future relative to the block that carries it, on BOTH terms. A record
//     that is already satisfied when it lands would activate a feature with no
//     warning at all, which is the failure this whole mechanism exists to
//     prevent.
//
// Rescheduling a trigger that has not yet fired — earlier or later, so long as
// it stays in the future — is permitted: nothing has been validated under it.
func validateActivationsTransition(kv *KVStore, tip *Block, b *Block, value json.RawMessage) error {
	next, err := ParseActivations(value)
	if err != nil {
		return err
	}

	var prev *Activations
	if raw, ok := kv.Get(ActivationsKey); ok {
		prev, err = ParseActivations(raw)
		if err != nil {
			// Unreadable prior state is not something a new op can repair.
			return fmt.Errorf("existing sys.activations unreadable: %w", err)
		}
	} else {
		prev = &Activations{Features: map[string]ActivationRecord{}}
	}

	var tipIndex uint64
	var tipNS int64
	if tip != nil {
		tipIndex, tipNS = tip.Index, tip.Timestamp
	}

	for name, oldRec := range prev.Features {
		newRec, ok := next.Features[name]
		if !ok {
			return fmt.Errorf("activations: feature %q cannot be removed (activations are one-directional)", name)
		}
		if oldRec.ActiveAt(tipIndex, tipNS) {
			if newRec != oldRec {
				return fmt.Errorf("activations: feature %q is already active; its trigger is frozen (at_index %d, not_before_ns %d)",
					name, oldRec.AtIndex, oldRec.NotBeforeNS)
			}
			continue
		}
		if newRec == oldRec {
			continue // unchanged pending record; already validated when written
		}
		if err := requireFuture(name, newRec, b); err != nil {
			return err
		}
	}

	for name, newRec := range next.Features {
		if _, existed := prev.Features[name]; existed {
			continue
		}
		if err := requireFuture(name, newRec, b); err != nil {
			return err
		}
	}
	return nil
}

// requireFuture rejects a trigger that is already satisfied at the block
// carrying it. Both terms are checked, so a past at_index paired with a future
// not_before_ns is refused too — it is never useful and always confusing.
func requireFuture(name string, rec ActivationRecord, b *Block) error {
	if b == nil {
		return nil
	}
	if rec.AtIndex != 0 && rec.AtIndex <= b.Index {
		return fmt.Errorf("activations: feature %q at_index %d is not in the future (this block is index %d)", name, rec.AtIndex, b.Index)
	}
	if rec.NotBeforeNS != 0 && rec.NotBeforeNS <= b.Timestamp {
		return fmt.Errorf("activations: feature %q not_before_ns %d is not in the future (this block is stamped %d)", name, rec.NotBeforeNS, b.Timestamp)
	}
	return nil
}

// ── sys.min_protocol_version ────────────────────────────────────────────────

var protocolVersionRegex = regexp.MustCompile(`^\d{1,4}\.\d{1,4}\.\d{1,4}$`)

func validateMinProtocolVersion(value json.RawMessage) error {
	var v string
	if err := json.Unmarshal(value, &v); err != nil {
		return fmt.Errorf("invalid min_protocol_version JSON (expected a string): %w", err)
	}
	if !protocolVersionRegex.MatchString(v) {
		return fmt.Errorf("min_protocol_version %q must be MAJOR.MINOR.PATCH", v)
	}
	return nil
}

// validateMinProtocolVersionTransition enforces monotonicity: the floor may
// only rise. A floor that could fall would let one DAO block re-admit every
// stale node the previous one evicted.
func validateMinProtocolVersionTransition(kv *KVStore, value json.RawMessage) error {
	raw, ok := kv.Get(MinProtocolVersionKey)
	if !ok {
		return nil
	}
	var oldV, newV string
	if err := json.Unmarshal(raw, &oldV); err != nil {
		return fmt.Errorf("existing sys.min_protocol_version unreadable: %w", err)
	}
	if err := json.Unmarshal(value, &newV); err != nil {
		return fmt.Errorf("incoming sys.min_protocol_version unreadable: %w", err)
	}
	if CompareProtocolVersion(newV, oldV) < 0 {
		return fmt.Errorf("sys.min_protocol_version %s → %s not permitted (the floor only rises)", oldV, newV)
	}
	return nil
}

// CompareProtocolVersion compares two MAJOR.MINOR.PATCH strings, returning
// -1, 0 or 1. An unparseable version sorts below a parseable one.
func CompareProtocolVersion(a, b string) int {
	av, aok := parseProtocolVersion(a)
	bv, bok := parseProtocolVersion(b)
	switch {
	case !aok && !bok:
		return 0
	case !aok:
		return -1
	case !bok:
		return 1
	}
	for i := 0; i < 3; i++ {
		if av[i] != bv[i] {
			if av[i] < bv[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func parseProtocolVersion(s string) ([3]int, bool) {
	var out [3]int
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// ── Chain accessors ─────────────────────────────────────────────────────────

// FeatureStatus is the observable state of one registered feature, rendered
// against the chain's current tip.
type FeatureStatus struct {
	Name        string `json:"name"`
	AtIndex     uint64 `json:"at_index,omitempty"`
	NotBeforeNS int64  `json:"not_before_ns,omitempty"`
	Active      bool   `json:"active"`
	// KnownToBinary is filled in by the caller that owns the binary's feature
	// list; the state chain has no opinion on what this build implements.
	KnownToBinary bool `json:"known_to_binary"`
}

// Activations returns the registry as of the current tip. A missing or
// unreadable key yields an empty registry — never an error — because every
// caller's correct response to "no registry" and "unreadable registry" is the
// same: nothing is activated.
func (c *Chain) Activations() *Activations {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.activationsLocked()
}

func (c *Chain) activationsLocked() *Activations {
	raw, ok := c.kv.Get(ActivationsKey)
	if !ok {
		return &Activations{Features: map[string]ActivationRecord{}}
	}
	a, err := ParseActivations(raw)
	if err != nil {
		return &Activations{Features: map[string]ActivationRecord{}}
	}
	return a
}

// FeatureActive reports whether feature is active as of this chain's tip.
//
// Registry and tip are read under ONE acquisition of the chain mutex: reading
// them separately could pair a newer registry with an older tip. Both are
// monotone so the mismatch could only ever be conservative, but a consensus
// gate should not rely on an argument that subtle.
func (c *Chain) FeatureActive(feature string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tip == nil {
		return false
	}
	return c.activationsLocked().ActiveAt(feature, c.tip.Index, c.tip.Timestamp)
}

// FeatureStatuses renders every registered feature against the current tip,
// marking which ones the caller's binary implements.
func (c *Chain) FeatureStatuses(known map[string]bool) []FeatureStatus {
	c.mu.Lock()
	a := c.activationsLocked()
	var idx uint64
	var ns int64
	if c.tip != nil {
		idx, ns = c.tip.Index, c.tip.Timestamp
	}
	c.mu.Unlock()

	out := make([]FeatureStatus, 0, len(a.Features))
	for _, name := range a.Names() {
		rec := a.Features[name]
		out = append(out, FeatureStatus{
			Name:          name,
			AtIndex:       rec.AtIndex,
			NotBeforeNS:   rec.NotBeforeNS,
			Active:        rec.ActiveAt(idx, ns),
			KnownToBinary: known[name],
		})
	}
	return out
}

// MinProtocolVersion returns the governance-set version floor, or "" when the
// key is absent or unreadable (no floor).
func (c *Chain) MinProtocolVersion() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	raw, ok := c.kv.Get(MinProtocolVersionKey)
	if !ok {
		return ""
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return ""
	}
	if !protocolVersionRegex.MatchString(v) {
		return ""
	}
	return v
}
