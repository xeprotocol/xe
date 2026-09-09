package statechain

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const ActivationsKey = "sys.activations"

const MinProtocolVersionKey = "sys.min_protocol_version"

const MaxActivationFeatures = 64

const RecommendedLeadNS int64 = 14 * 24 * 60 * 60 * 1_000_000_000

const minSaneActivationNS int64 = 1_600_000_000_000_000_000

var featureNameRegex = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

type ActivationRecord struct {
	AtIndex uint64 `json:"at_index,omitempty"`

	NotBeforeNS int64 `json:"not_before_ns,omitempty"`
}

func (r ActivationRecord) ActiveAt(index uint64, ns int64) bool {
	return index >= r.AtIndex && ns >= r.NotBeforeNS
}

type Activations struct {
	Features map[string]ActivationRecord `json:"features"`
}

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

func (a *Activations) Names() []string {
	names := make([]string, 0, len(a.Features))
	for n := range a.Features {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

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

func validateActivationsTransition(kv *KVStore, tip *Block, b *Block, value json.RawMessage) error {
	next, err := ParseActivations(value)
	if err != nil {
		return err
	}

	var prev *Activations
	if raw, ok := kv.Get(ActivationsKey); ok {
		prev, err = ParseActivations(raw)
		if err != nil {

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
			continue
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

type FeatureStatus struct {
	Name        string `json:"name"`
	AtIndex     uint64 `json:"at_index,omitempty"`
	NotBeforeNS int64  `json:"not_before_ns,omitempty"`
	Active      bool   `json:"active"`

	KnownToBinary bool `json:"known_to_binary"`
}

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

func (c *Chain) FeatureActive(feature string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tip == nil {
		return false
	}
	return c.activationsLocked().ActiveAt(feature, c.tip.Index, c.tip.Timestamp)
}

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
