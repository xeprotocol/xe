package statechain

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

var validKeyRegex = regexp.MustCompile(`^[a-z0-9_.-]+$`)

type KVStore struct {
	data map[string]json.RawMessage
}

func NewKVStore() *KVStore {
	return &KVStore{data: make(map[string]json.RawMessage)}
}

func ValidateKey(key string) error {
	if len(key) == 0 {
		return fmt.Errorf("key is empty")
	}
	if len(key) > MaxKeyLength {
		return fmt.Errorf("key exceeds %d characters", MaxKeyLength)
	}
	if !validKeyRegex.MatchString(key) {
		return fmt.Errorf("key contains invalid characters (must be [a-z0-9_.-])")
	}
	return nil
}

func ValidateOp(op Op) error {
	if err := ValidateKey(op.Key); err != nil {
		return fmt.Errorf("op key %q: %w", op.Key, err)
	}
	switch op.Action {
	case ActionSet:
		if len(op.Value) == 0 {
			return fmt.Errorf("op key %q: set op must have a value", op.Key)
		}
		if len(op.Value) > MaxValueSize {
			return fmt.Errorf("op key %q: value exceeds %d bytes", op.Key, MaxValueSize)
		}
		if !json.Valid(op.Value) {
			return fmt.Errorf("op key %q: value is not valid JSON", op.Key)
		}
		if err := validateSysKeyValue(op.Key, op.Value); err != nil {
			return fmt.Errorf("op key %q: %w", op.Key, err)
		}
	case ActionDelete:
		if strings.HasPrefix(op.Key, "sys.") {
			return fmt.Errorf("op key %q: cannot delete sys.* keys", op.Key)
		}
	default:
		return fmt.Errorf("op key %q: unknown action %q", op.Key, op.Action)
	}
	return nil
}

// MinDAOThreshold is the minimum allowed DAO keyset threshold.
// Prevents single-signer takeover via threshold downgrade.
const MinDAOThreshold = 2

func validateSysKeyValue(key string, value json.RawMessage) error {
	switch key {
	case "sys.dao_keyset":
		var ks DAOKeyset
		if err := json.Unmarshal(value, &ks); err != nil {
			return fmt.Errorf("invalid dao_keyset JSON: %w", err)
		}
		if len(ks.Keys) == 0 {
			return fmt.Errorf("dao_keyset must have at least one key")
		}
		if ks.Threshold < MinDAOThreshold {
			return fmt.Errorf("dao_keyset threshold %d is below minimum %d", ks.Threshold, MinDAOThreshold)
		}
		if ks.Threshold > len(ks.Keys) {
			return fmt.Errorf("dao_keyset threshold %d exceeds key count %d", ks.Threshold, len(ks.Keys))
		}
		seen := make(map[string]bool, len(ks.Keys))
		for i, k := range ks.Keys {
			if len(k) != 64 {
				return fmt.Errorf("dao_keyset key[%d] invalid length: got %d, want 64 hex chars", i, len(k))
			}
			if _, err := hex.DecodeString(k); err != nil {
				return fmt.Errorf("dao_keyset key[%d] invalid hex: %w", i, err)
			}
			if seen[k] {
				return fmt.Errorf("dao_keyset key[%d] is a duplicate", i)
			}
			seen[k] = true
		}
	case "sys.timekeepers":
		var tk struct {
			Keys      []string `json:"keys"`
			Threshold int      `json:"threshold"`
		}
		if err := json.Unmarshal(value, &tk); err != nil {
			return fmt.Errorf("invalid timekeepers JSON: %w", err)
		}
		if len(tk.Keys) == 0 {
			return fmt.Errorf("timekeepers must have at least one key")
		}
		if tk.Threshold < 1 || tk.Threshold > len(tk.Keys) {
			return fmt.Errorf("timekeepers threshold %d invalid for %d keys", tk.Threshold, len(tk.Keys))
		}
		for i, k := range tk.Keys {
			if len(k) != 64 {
				return fmt.Errorf("timekeepers key[%d] invalid length: got %d, want 64 hex chars", i, len(k))
			}
		}
	case "sys.minter":
		// Accounts authorized to mint XUSD (faucet now, bridge later). Mirrors
		// the core.MinterConfig shape: {"keys": ["<64-hex pubkey>", ...]}.
		var mc struct {
			Keys []string `json:"keys"`
		}
		if err := json.Unmarshal(value, &mc); err != nil {
			return fmt.Errorf("invalid minter config JSON: %w", err)
		}
		if len(mc.Keys) == 0 {
			return fmt.Errorf("minter config must have at least one key")
		}
		seen := make(map[string]bool, len(mc.Keys))
		for i, k := range mc.Keys {
			if len(k) != 64 {
				return fmt.Errorf("minter key[%d] invalid length: got %d, want 64 hex chars", i, len(k))
			}
			if _, err := hex.DecodeString(k); err != nil {
				return fmt.Errorf("minter key[%d] invalid hex: %w", i, err)
			}
			if seen[k] {
				return fmt.Errorf("minter key[%d] is a duplicate", i)
			}
			seen[k] = true
		}
	case "sys.oracle":
		var oc OracleConfig
		if err := json.Unmarshal(value, &oc); err != nil {
			return fmt.Errorf("invalid oracle config JSON: %w", err)
		}
		if len(oc.Keys) == 0 {
			return fmt.Errorf("oracle config must have at least one key")
		}
		if oc.Threshold < 1 || oc.Threshold > len(oc.Keys) {
			return fmt.Errorf("oracle threshold %d invalid for %d keys", oc.Threshold, len(oc.Keys))
		}
		if len(oc.AllowedPrefix) == 0 {
			return fmt.Errorf("oracle allowed_prefix must not be empty")
		}
		seen := make(map[string]bool, len(oc.Keys))
		for i, k := range oc.Keys {
			if len(k) != 64 {
				return fmt.Errorf("oracle key[%d] invalid length: got %d, want 64 hex chars", i, len(k))
			}
			if _, err := hex.DecodeString(k); err != nil {
				return fmt.Errorf("oracle key[%d] invalid hex: %w", i, err)
			}
			if seen[k] {
				return fmt.Errorf("oracle key[%d] is a duplicate", i)
			}
			seen[k] = true
		}
	case "sys.phase":
		// Tokenomics v15 §C3: protocol phase ∈ {1, 2}. Set by DAO multisig.
		// Transition direction is enforced separately (validateTransition) since
		// this function has no access to the prior value.
		var phase uint8
		if err := json.Unmarshal(value, &phase); err != nil {
			return fmt.Errorf("invalid phase JSON: %w", err)
		}
		if phase != 1 && phase != 2 {
			return fmt.Errorf("phase %d invalid (must be 1 or 2)", phase)
		}
	case "sys.tokenomics":
		return validateTokenomicsConfig(value)
	case ActivationsKey:
		return validateActivations(value)
	case MinProtocolVersionKey:
		return validateMinProtocolVersion(value)
	case "sys.representatives":
		// Representative eligibility for the quorum denominator (#832).
		// {"mode":"open"} or {"mode":"allowlist","addresses":["<64-hex address>", ...]}.
		// Addresses are ACCOUNT ADDRESSES (the Representative field on blocks),
		// not verifying keys — since #829 those are different things.
		var rc RepresentativeConfig
		if err := json.Unmarshal(value, &rc); err != nil {
			return fmt.Errorf("invalid representatives config JSON: %w", err)
		}
		switch rc.Mode {
		case RepModeOpen:
			if len(rc.Addresses) != 0 {
				return fmt.Errorf("representatives mode %q must not carry addresses", rc.Mode)
			}
		case RepModeAllowlist:
			if len(rc.Addresses) == 0 {
				return fmt.Errorf("representatives allowlist must have at least one address")
			}
			if len(rc.Addresses) > MaxEligibleRepresentatives {
				return fmt.Errorf("representatives allowlist has %d addresses, maximum %d", len(rc.Addresses), MaxEligibleRepresentatives)
			}
			seen := make(map[string]bool, len(rc.Addresses))
			for i, a := range rc.Addresses {
				if len(a) != 64 {
					return fmt.Errorf("representatives address[%d] invalid length: got %d, want 64 hex chars", i, len(a))
				}
				if _, err := hex.DecodeString(a); err != nil {
					return fmt.Errorf("representatives address[%d] invalid hex: %w", i, err)
				}
				if seen[a] {
					return fmt.Errorf("representatives address[%d] is a duplicate", i)
				}
				seen[a] = true
			}
		default:
			// Fail closed on the SHAPE (an unrecognised mode is a typo, and a
			// typo in a consensus-weight policy must not be publishable), while
			// the ledger fails OPEN on an unusable policy it nonetheless finds
			// in the store — belt and braces in opposite directions on purpose.
			return fmt.Errorf("representatives mode %q unknown (want %q or %q)", rc.Mode, RepModeOpen, RepModeAllowlist)
		}
	}
	return nil
}

// Tokenomics sanity bounds (#435). Every R-scaled value must be within
// [1, 100000] — i.e. 0.001× to 100×, well outside any operating point
// envisioned in v15.
const (
	tokenomicsRMin uint64 = 1
	tokenomicsRMax uint64 = 100_000
)

// validateTokenomicsConfig enforces the v15 §C2 cross-field invariants on a
// candidate sys.tokenomics blob (#422/#435).
func validateTokenomicsConfig(value json.RawMessage) error {
	dec := json.NewDecoder(strings.NewReader(string(value)))
	dec.DisallowUnknownFields()
	var tc TokenomicsConfig
	if err := dec.Decode(&tc); err != nil {
		return fmt.Errorf("invalid tokenomics JSON: %w", err)
	}

	// R_volume curve.
	if tc.RFloor == 0 {
		return fmt.Errorf("tokenomics r_floor must be > 0")
	}
	if tc.RInit <= tc.RFloor {
		return fmt.Errorf("tokenomics r_init (%d) must be > r_floor (%d)", tc.RInit, tc.RFloor)
	}
	if tc.VHalf == 0 {
		return fmt.Errorf("tokenomics v_half must be > 0")
	}

	// R_price_floor tiers.
	if tc.PriceTier1 >= tc.PriceTier2 || tc.PriceTier2 >= tc.PriceTier3 {
		return fmt.Errorf("tokenomics price tiers must be strictly increasing (got %d, %d, %d)",
			tc.PriceTier1, tc.PriceTier2, tc.PriceTier3)
	}
	if tc.RPriceFloorTier1 < tc.RPriceFloorTier2 {
		return fmt.Errorf("tokenomics r_price_floor_tier_1 (%d) must be >= r_price_floor_tier_2 (%d)",
			tc.RPriceFloorTier1, tc.RPriceFloorTier2)
	}
	if tc.RPriceFloorTier2 < tc.RFloor {
		return fmt.Errorf("tokenomics r_price_floor_tier_2 (%d) must be >= r_floor (%d)",
			tc.RPriceFloorTier2, tc.RFloor)
	}

	// R_collusion.
	if tc.RCollusionFactorMilli == 0 || tc.RCollusionFactorMilli >= 1000 {
		return fmt.Errorf("tokenomics r_collusion_factor_milli (%d) must be in (0, 1000)",
			tc.RCollusionFactorMilli)
	}

	// Hermite payout cap.
	if tc.HermiteFDVMinUSD == 0 {
		return fmt.Errorf("tokenomics hermite_fdv_min_usd must be > 0")
	}
	if tc.HermiteFDVMinUSD >= tc.HermiteFDVMaxUSD {
		return fmt.Errorf("tokenomics hermite_fdv_min_usd (%d) must be < hermite_fdv_max_usd (%d)",
			tc.HermiteFDVMinUSD, tc.HermiteFDVMaxUSD)
	}
	if tc.HermiteFloorMilli == 0 {
		return fmt.Errorf("tokenomics hermite_floor_milli must be > 0")
	}
	if tc.HermiteCeilingMilli <= tc.HermiteFloorMilli {
		return fmt.Errorf("tokenomics hermite_ceiling_milli (%d) must be > hermite_floor_milli (%d)",
			tc.HermiteCeilingMilli, tc.HermiteFloorMilli)
	}

	// Sanity range on every R-scaled value.
	rChecks := []struct {
		name string
		v    uint64
	}{
		{"r_init", tc.RInit},
		{"r_floor", tc.RFloor},
		{"r_price_floor_tier_1", tc.RPriceFloorTier1},
		{"r_price_floor_tier_2", tc.RPriceFloorTier2},
		{"r_collusion_factor_milli", tc.RCollusionFactorMilli},
		{"hermite_ceiling_milli", tc.HermiteCeilingMilli},
		{"hermite_floor_milli", tc.HermiteFloorMilli},
	}
	for _, c := range rChecks {
		if c.v < tokenomicsRMin || c.v > tokenomicsRMax {
			return fmt.Errorf("tokenomics %s (%d) out of sane range [%d, %d]",
				c.name, c.v, tokenomicsRMin, tokenomicsRMax)
		}
	}

	return nil
}

// validateTransition enforces per-key transition rules that depend on the
// existing value. Called from Chain.AddBlock after static ValidateOp but
// before mutating state. Pure read; safe to call under the chain mutex.
//
// tip is the chain tip as of BEFORE this block (nil for a chain with no tip);
// b is the block carrying the op. sys.activations needs both: "already fired"
// is measured against the previous tip, "still in the future" against the
// incoming block (#830). Keys whose rules depend only on the prior value
// ignore them.
func validateTransition(kv *KVStore, tip *Block, b *Block, op Op) error {
	if op.Action != ActionSet {
		return nil
	}
	switch op.Key {
	case ActivationsKey:
		return validateActivationsTransition(kv, tip, b, op.Value)
	case MinProtocolVersionKey:
		return validateMinProtocolVersionTransition(kv, op.Value)
	case "sys.phase":
		old, ok := kv.Get("sys.phase")
		if !ok {
			// First-write (or pre-migration chain). Allow any valid value;
			// static validation has already constrained to {1, 2}.
			return nil
		}
		var oldPhase, newPhase uint8
		if err := json.Unmarshal(old, &oldPhase); err != nil {
			return fmt.Errorf("existing sys.phase unreadable: %w", err)
		}
		if err := json.Unmarshal(op.Value, &newPhase); err != nil {
			return fmt.Errorf("incoming sys.phase unreadable: %w", err)
		}
		if newPhase < oldPhase {
			return fmt.Errorf("sys.phase transition %d → %d not permitted (one-directional)", oldPhase, newPhase)
		}
	}
	return nil
}

// RCollusionFactorMilliDefault is the v15 §C2 safety margin (0.95 × 1000) used
// to validate the oracle's published R_collusion. When #422 lands and the
// factor moves to sys.tokenomics, the validator reads from there instead.
const RCollusionFactorMilliDefault = 950

// SMilliForPhase returns the phase-aware provider stable share (×1000).
// v15 §C3: P1 → 0, P2 → 300.
func SMilliForPhase(phase uint8) uint16 {
	if phase == 2 {
		return 300
	}
	return 0
}

// validateEpochValue checks that an epoch value is well-formed and consistent
// with current chain state. kv may be nil for pure schema validation (the
// phase cross-check is skipped in that case).
func validateEpochValue(value json.RawMessage, kv *KVStore) error {
	var ev EpochValue
	if err := json.Unmarshal(value, &ev); err != nil {
		return fmt.Errorf("invalid epoch JSON: %w", err)
	}
	if ev.EndNS <= ev.StartNS {
		return fmt.Errorf("epoch end_ns (%d) must be after start_ns (%d)", ev.EndNS, ev.StartNS)
	}

	if ev.Phase != 1 && ev.Phase != 2 {
		return fmt.Errorf("epoch phase must be 1 or 2, got %d", ev.Phase)
	}

	// PayoutCap is optional (zero = older epoch, ledger treats as no-op).
	// When present it must be within the chain-governed Hermite envelope if
	// sys.tokenomics is set, else within the v13 sanity range [1000, 2000].
	if ev.PayoutCap != 0 {
		lo, hi := uint64(1000), uint64(2000)
		if kv != nil {
			if tc, terr := kv.Tokenomics(); terr == nil && tc != nil {
				lo, hi = tc.HermiteFloorMilli, tc.HermiteCeilingMilli
			}
		}
		if ev.PayoutCap < lo || ev.PayoutCap > hi {
			return fmt.Errorf("epoch payout_cap (%d) out of range [%d, %d]", ev.PayoutCap, lo, hi)
		}
	}

	// v15 §C2: s_milli is phase-derived. The epoch must publish the phase
	// it computed against and the matching s.
	expectedS := SMilliForPhase(ev.Phase)
	if ev.SMilli != expectedS {
		return fmt.Errorf("epoch s_milli (%d) does not match phase %d (expected %d)", ev.SMilli, ev.Phase, expectedS)
	}

	// v15 §C2: R_collusion = factor × (1000 − s_milli) / twap_milli (×1000 scaled).
	// Verify the oracle's published value matches the deterministic formula.
	// Factor is read from sys.tokenomics when present, else the v15 §C2 default
	// constant. On pre-v15 epochs r_collusion is zero — accept those for
	// backward compat only when r_source isn't "collusion".
	factor := uint64(RCollusionFactorMilliDefault)
	if kv != nil {
		if tc, terr := kv.Tokenomics(); terr == nil && tc != nil {
			factor = tc.RCollusionFactorMilli
		}
	}
	expectedRCol := expectedRCollusion(ev.TWAPMilliUSD, uint64(ev.SMilli), factor)
	if ev.RCollusion != 0 && ev.RCollusion != expectedRCol {
		return fmt.Errorf("epoch r_collusion (%d) != expected %d (twap=%d, s=%d)",
			ev.RCollusion, expectedRCol, ev.TWAPMilliUSD, ev.SMilli)
	}

	// R_effective = min(max(R_volume, R_price_floor), R_collusion).
	// On pre-v15 epochs (RCollusion == 0) fall back to the v12 max-of-two rule.
	supportive := ev.RVolume
	if ev.RPriceFloor > supportive {
		supportive = ev.RPriceFloor
	}
	expectedR := supportive
	if ev.RCollusion != 0 && ev.RCollusion < supportive {
		expectedR = ev.RCollusion
	}
	if ev.REffective != expectedR {
		return fmt.Errorf("epoch r_effective (%d) != expected %d (r_vol=%d, r_pf=%d, r_col=%d)",
			ev.REffective, expectedR, ev.RVolume, ev.RPriceFloor, ev.RCollusion)
	}

	// R_source must name the term that bound R_effective.
	switch ev.RSource {
	case "volume":
		if ev.RVolume <= ev.RPriceFloor {
			return fmt.Errorf("r_source 'volume' but r_volume (%d) <= r_price_floor (%d)", ev.RVolume, ev.RPriceFloor)
		}
		if ev.RCollusion != 0 && ev.RCollusion < ev.RVolume {
			return fmt.Errorf("r_source 'volume' but r_collusion (%d) < r_volume (%d) — should be 'collusion'", ev.RCollusion, ev.RVolume)
		}
	case "price_floor":
		if ev.RPriceFloor <= ev.RVolume {
			return fmt.Errorf("r_source 'price_floor' but r_price_floor (%d) <= r_volume (%d)", ev.RPriceFloor, ev.RVolume)
		}
		if ev.RCollusion != 0 && ev.RCollusion < ev.RPriceFloor {
			return fmt.Errorf("r_source 'price_floor' but r_collusion (%d) < r_price_floor (%d) — should be 'collusion'", ev.RCollusion, ev.RPriceFloor)
		}
	case "tied":
		if ev.RVolume != ev.RPriceFloor {
			return fmt.Errorf("r_source 'tied' but r_volume (%d) != r_price_floor (%d)", ev.RVolume, ev.RPriceFloor)
		}
		if ev.RCollusion != 0 && ev.RCollusion < ev.RVolume {
			return fmt.Errorf("r_source 'tied' but r_collusion (%d) < supportive (%d) — should be 'collusion'", ev.RCollusion, ev.RVolume)
		}
	case "collusion":
		if ev.RCollusion == 0 {
			return fmt.Errorf("r_source 'collusion' but r_collusion is zero")
		}
		if ev.RCollusion >= supportive {
			return fmt.Errorf("r_source 'collusion' but r_collusion (%d) >= supportive max (%d)", ev.RCollusion, supportive)
		}
	default:
		return fmt.Errorf("epoch r_source must be 'volume', 'price_floor', 'tied', or 'collusion', got %q", ev.RSource)
	}

	// Cross-check: the oracle's claimed phase must match the chain's current
	// sys.phase. Without this, a buggy or compromised oracle could publish a
	// phase that diverges from governance state. kv == nil skips this check
	// (used by tests that validate the schema in isolation).
	if kv != nil {
		chainPhase, perr := kv.Phase()
		if perr == nil && chainPhase != ev.Phase {
			return fmt.Errorf("epoch phase (%d) does not match chain sys.phase (%d)", ev.Phase, chainPhase)
		}
	}

	return nil
}

// expectedRCollusion computes the canonical R_collusion using the supplied
// factor (×1000). Mirrors oracle/oracle.RCollusion exactly. Kept in the chain
// package to avoid a core→oracle import cycle. Caller passes the live
// sys.tokenomics factor or RCollusionFactorMilliDefault as a fallback. See
// "XE Token Economy Model" v15 §C2.
func expectedRCollusion(twapMilliUSD, sMilli, factorMilli uint64) uint64 {
	if twapMilliUSD == 0 {
		return 0 // matches the "older epoch / unknown" sentinel for validator purposes
	}
	if sMilli >= 1000 {
		return 0
	}
	if factorMilli == 0 {
		factorMilli = RCollusionFactorMilliDefault
	}
	return factorMilli * (1000 - sMilli) / twapMilliUSD
}

func (kv *KVStore) ApplyOps(ops []Op) {
	for _, op := range ops {
		switch op.Action {
		case ActionSet:
			kv.data[op.Key] = json.RawMessage(append([]byte(nil), op.Value...))
		case ActionDelete:
			delete(kv.data, op.Key)
		}
	}
}

func (kv *KVStore) Get(key string) (json.RawMessage, bool) {
	v, ok := kv.data[key]
	return v, ok
}

func (kv *KVStore) GetByPrefix(prefix string) map[string]json.RawMessage {
	result := make(map[string]json.RawMessage)
	for k, v := range kv.data {
		if strings.HasPrefix(k, prefix) {
			result[k] = v
		}
	}
	return result
}

func (kv *KVStore) GetAll() map[string]json.RawMessage {
	result := make(map[string]json.RawMessage, len(kv.data))
	for k, v := range kv.data {
		result[k] = v
	}
	return result
}

// NetworkID returns the network identifier from the state chain.
// Returns empty string if not set (backward compatible).
func (kv *KVStore) NetworkID() string {
	raw, ok := kv.data["sys.network_id"]
	if !ok {
		return ""
	}
	var id string
	if err := json.Unmarshal(raw, &id); err != nil {
		return ""
	}
	return id
}

// OracleConfig returns the oracle configuration from the state chain.
// Returns nil, nil if sys.oracle is not set (oracle not configured).
func (kv *KVStore) OracleConfig() (*OracleConfig, error) {
	raw, ok := kv.data["sys.oracle"]
	if !ok {
		return nil, nil
	}
	var oc OracleConfig
	if err := json.Unmarshal(raw, &oc); err != nil {
		return nil, fmt.Errorf("sys.oracle: invalid JSON: %w", err)
	}
	if len(oc.Keys) == 0 {
		return nil, fmt.Errorf("sys.oracle: no keys")
	}
	if oc.Threshold < 1 || oc.Threshold > len(oc.Keys) {
		return nil, fmt.Errorf("sys.oracle: invalid threshold %d for %d keys", oc.Threshold, len(oc.Keys))
	}
	if len(oc.AllowedPrefix) == 0 {
		return nil, fmt.Errorf("sys.oracle: no allowed_prefix")
	}
	return &oc, nil
}

// Phase returns the current tokenomics phase from sys.phase. Returns 1 when
// the key is missing (pre-migration chains, fresh test chains without the
// bake) so callers get a safe Phase 1 default. Returns an error only when
// the stored value is structurally invalid (should be impossible given the
// validator, but guarded for forward-compat). See "XE Token Economy Model"
// v15 §C3 + §C4.
func (kv *KVStore) Phase() (uint8, error) {
	raw, ok := kv.data["sys.phase"]
	if !ok {
		return 1, nil
	}
	var phase uint8
	if err := json.Unmarshal(raw, &phase); err != nil {
		return 0, fmt.Errorf("sys.phase: invalid JSON: %w", err)
	}
	if phase != 1 && phase != 2 {
		return 0, fmt.Errorf("sys.phase: invalid value %d", phase)
	}
	return phase, nil
}

// Tokenomics returns the parsed sys.tokenomics config. Returns (nil, nil)
// when the key is missing (pre-#435 chains) so callers can fall back to
// compile-time defaults. Returns an error only when the stored value is
// structurally invalid. See "XE Token Economy Model" v15 §C2 and #435.
func (kv *KVStore) Tokenomics() (*TokenomicsConfig, error) {
	raw, ok := kv.data["sys.tokenomics"]
	if !ok {
		return nil, nil
	}
	var tc TokenomicsConfig
	if err := json.Unmarshal(raw, &tc); err != nil {
		return nil, fmt.Errorf("sys.tokenomics: invalid JSON: %w", err)
	}
	return &tc, nil
}

// Representative eligibility modes. Mirrors core.RepModeOpen /
// core.RepModeAllowlist; statechain must not import core.
const (
	RepModeOpen      = "open"
	RepModeAllowlist = "allowlist"
)

// MaxEligibleRepresentatives bounds a published allowlist. Mirrors
// core.MaxEligibleRepresentatives.
const MaxEligibleRepresentatives = 1000

// RepresentativeConfig is the sys.representatives value: which representatives'
// delegated weight counts toward the quorum denominator (#832).
type RepresentativeConfig struct {
	Mode      string   `json:"mode"`
	Addresses []string `json:"addresses,omitempty"`
}

// Representatives returns the parsed sys.representatives policy, or (nil, nil)
// when the key is absent — which means unrestricted, today's behaviour. Returns
// an error only when the stored value is structurally invalid; callers treat an
// error as unrestricted, never as "nobody is eligible".
func (kv *KVStore) Representatives() (*RepresentativeConfig, error) {
	raw, ok := kv.data["sys.representatives"]
	if !ok {
		return nil, nil
	}
	var rc RepresentativeConfig
	if err := json.Unmarshal(raw, &rc); err != nil {
		return nil, fmt.Errorf("sys.representatives: invalid JSON: %w", err)
	}
	return &rc, nil
}

func (kv *KVStore) DAOKeyset() (*DAOKeyset, error) {
	raw, ok := kv.data["sys.dao_keyset"]
	if !ok {
		return nil, fmt.Errorf("sys.dao_keyset not found in state")
	}
	var ks DAOKeyset
	if err := json.Unmarshal(raw, &ks); err != nil {
		return nil, fmt.Errorf("sys.dao_keyset: invalid JSON: %w", err)
	}
	if len(ks.Keys) == 0 {
		return nil, fmt.Errorf("sys.dao_keyset: no keys")
	}
	if ks.Threshold < MinDAOThreshold || ks.Threshold > len(ks.Keys) {
		return nil, fmt.Errorf("sys.dao_keyset: invalid threshold %d for %d keys (min %d)", ks.Threshold, len(ks.Keys), MinDAOThreshold)
	}
	return &ks, nil
}
