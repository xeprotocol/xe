package core

import (
	"fmt"
	"sort"
)

const FeatureNoop = "noop"

type DarkValidateFunc func(l *Ledger, b *Block, skipTimestamp bool) error

type darkValidator struct {
	feature  string
	validate DarkValidateFunc
}

var darkValidators = map[BlockType]darkValidator{}

func registerDarkValidator(t BlockType, feature string, fn DarkValidateFunc) {
	if feature == "" || fn == nil {
		panic("registerDarkValidator: feature and validator are required")
	}
	if _, dup := darkValidators[t]; dup {
		panic(fmt.Sprintf("registerDarkValidator: duplicate registration for block type %q", t))
	}
	darkValidators[t] = darkValidator{feature: feature, validate: fn}
}

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

func KnownFeatureSet() map[string]bool {
	set := make(map[string]bool)
	for _, f := range KnownFeatures() {
		set[f] = true
	}
	return set
}

func GatedBlockTypes() map[string]string {
	out := make(map[string]string, len(darkValidators))
	for t, dv := range darkValidators {
		out[string(t)] = dv.feature
	}
	return out
}

func (l *Ledger) FeatureActive(feature string) bool {
	if l.featureActiveFn == nil {
		return false
	}
	return l.featureActiveFn(feature)
}

func errFeatureNotActivatedFor(t BlockType, feature string) error {
	return fmt.Errorf("block type %q requires feature %q: not yet activated (retry after statechain syncs)", t, feature)
}
