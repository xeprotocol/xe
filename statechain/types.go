package statechain

import "encoding/json"

type Block struct {
	Index      uint64           `json:"index"`
	PrevHash   string           `json:"prev_hash"`
	Ops        []Op             `json:"ops"`
	Signatures []BlockSignature `json:"signatures"`
	Hash       string           `json:"hash"`
	Timestamp  int64            `json:"timestamp"`
}

type Op struct {
	Action string          `json:"action"`
	Key    string          `json:"key"`
	Value  json.RawMessage `json:"value,omitempty"`
}

type BlockSignature struct {
	PublicKey string `json:"public_key"`
	Sig       string `json:"signature"`
}

type DAOKeyset struct {
	Keys      []string `json:"keys"`
	Threshold int      `json:"threshold"`
}

// OracleConfig defines the trusted oracle keys and the key prefix they are
// authorized to write. The oracle publishes epoch data (R_effective, TWAP,
// TWAV) to the state chain — see xeprotocol/oracle and the XE Token Economy
// Model (RelationsMGMT v12) for the emission mechanics.
type OracleConfig struct {
	Keys          []string `json:"keys"`
	Threshold     int      `json:"threshold"`
	AllowedPrefix string   `json:"allowed_prefix"`
}

// EpochValue is the data published by the oracle for each epoch.
// All R values are scaled ×1000 (e.g. 2000 = R of 2.000).
// All monetary values are in milli-USD (e.g. 250 = $0.25).
//
// The dual R mechanism determines XE emission per lease settlement:
//   - R_volume decays exponentially with network volume maturity
//   - R_price_floor enforces a minimum R based on token price (TWAP)
//   - R_effective = max(R_volume, R_price_floor)
//
// See "XE Token Economy Model" §Dual R Emission for formula details.
type EpochValue struct {
	Epoch        uint64 `json:"epoch"`
	StartNS      int64  `json:"start_ns"`
	EndNS        int64  `json:"end_ns"`
	TWAPMilliUSD uint64 `json:"twap_milli_usd"`
	TWAVMilliUSD uint64 `json:"twav_milli_usd"`
	RVolume      uint64 `json:"r_volume"`
	RPriceFloor  uint64 `json:"r_price_floor"`
	RCollusion   uint64 `json:"r_collusion,omitempty"` // v15 §C2; zero on pre-v15 epochs
	REffective   uint64 `json:"r_effective"`
	RSource      string `json:"r_source"`
	Phase        uint8  `json:"phase"`
	SMilli       uint16 `json:"s_milli,omitempty"` // v15 §C2 provider stable share ×1000

	// Phase-2 trigger signals (v15 §C4). Advisory only — Operations multisig
	// enacts the actual sys.phase transition. Optional for backward compat
	// with pre-v15 epochs; validator treats missing as false.
	VolumeTriggerMet bool `json:"volume_trigger_met,omitempty"`
	TWAPTriggerMet   bool `json:"twap_trigger_met,omitempty"`

	// PayoutCap is the Hermite self-lease payout cap, scaled ×1000.
	// Ledger applies R_capped = min(R, PayoutCap × 1000 / TWAP) at settle.
	// Zero means the cap is absent (older epochs) — ledger treats as no-op.
	// See "XE Token Economy Model" v13 §Hermite Self-Lease Payout Cap.
	PayoutCap uint64 `json:"payout_cap"`
}

// TokenomicsConfig is the governance-tunable R-curve and Hermite payout-cap
// parameter set held under sys.tokenomics. All ratio values are scaled ×1000;
// monetary values are in milli-USD or whole USD as documented per field.
//
// Genesis supply is intentionally NOT part of this struct: it belongs on the
// genesis block, not under DAO control. See "XE Token Economy Model" v15 §A8
// item 6 (optional but recommended on-chain) and §C2 / §Hermite Self-Lease
// Payout Cap for formula details. Bake defaults match oracle DefaultRParams
// and DefaultHermiteParams.
type TokenomicsConfig struct {
	// R_volume curve.
	RInit  uint64 `json:"r_init"`  // cold-start ceiling (asymptote at vol=0), ×1000
	RFloor uint64 `json:"r_floor"` // high-volume asymptote, ×1000
	VHalf  uint64 `json:"v_half"`  // exp decay half-life, milli-USD/month

	// R_price_floor tiers.
	PriceTier1       uint64 `json:"price_tier_1"`         // TWAP breakpoint, milli-USD
	PriceTier2       uint64 `json:"price_tier_2"`         // TWAP breakpoint, milli-USD
	PriceTier3       uint64 `json:"price_tier_3"`         // TWAP breakpoint, milli-USD
	RPriceFloorTier1 uint64 `json:"r_price_floor_tier_1"` // R at TWAP < tier_1, ×1000
	RPriceFloorTier2 uint64 `json:"r_price_floor_tier_2"` // R at tier_1 ≤ TWAP < tier_2, ×1000

	// R_collusion safety margin (v15 §C2).
	RCollusionFactorMilli uint64 `json:"r_collusion_factor_milli"` // ×1000, strictly < 1000

	// Hermite payout-cap anchors (Phase 2+ secondary cap, #382).
	HermiteFDVMinUSD    uint64 `json:"hermite_fdv_min_usd"`   // ceiling anchor in USD
	HermiteFDVMaxUSD    uint64 `json:"hermite_fdv_max_usd"`   // floor anchor in USD
	HermiteCeilingMilli uint64 `json:"hermite_ceiling_milli"` // cap at FDV min anchor, ×1000
	HermiteFloorMilli   uint64 `json:"hermite_floor_milli"`   // cap at FDV max anchor, ×1000
}

// DefaultTokenomicsConfig returns the v15 §C2 production defaults. These
// match oracle.DefaultRParams + oracle.DefaultHermiteParams exactly so the
// oracle's chain-fetch fallback path and the genesis bake stay consistent.
func DefaultTokenomicsConfig() TokenomicsConfig {
	return TokenomicsConfig{
		RInit:                 2000,
		RFloor:                100,
		VHalf:                 500_000_000,
		PriceTier1:            500,
		PriceTier2:            1010,
		PriceTier3:            10000,
		RPriceFloorTier1:      2000,
		RPriceFloorTier2:      1250,
		RCollusionFactorMilli: 950,
		HermiteFDVMinUSD:      5_000_000,
		HermiteFDVMaxUSD:      1_000_000_000,
		HermiteCeilingMilli:   1550,
		HermiteFloorMilli:     1120,
	}
}

const (
	ActionSet    = "set"
	ActionDelete = "delete"

	actionByteSet    = byte(0x01)
	actionByteDelete = byte(0x02)

	MaxKeyLength = 128
	MaxValueSize = 65536  // 64KB
	MaxBlockSize = 262144 // 256KB
)
