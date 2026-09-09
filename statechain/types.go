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

type OracleConfig struct {
	Keys          []string `json:"keys"`
	Threshold     int      `json:"threshold"`
	AllowedPrefix string   `json:"allowed_prefix"`
}

type EpochValue struct {
	Epoch        uint64 `json:"epoch"`
	StartNS      int64  `json:"start_ns"`
	EndNS        int64  `json:"end_ns"`
	TWAPMilliUSD uint64 `json:"twap_milli_usd"`
	TWAVMilliUSD uint64 `json:"twav_milli_usd"`
	RVolume      uint64 `json:"r_volume"`
	RPriceFloor  uint64 `json:"r_price_floor"`
	RCollusion   uint64 `json:"r_collusion,omitempty"`
	REffective   uint64 `json:"r_effective"`
	RSource      string `json:"r_source"`
	Phase        uint8  `json:"phase"`
	SMilli       uint16 `json:"s_milli,omitempty"`

	VolumeTriggerMet bool `json:"volume_trigger_met,omitempty"`
	TWAPTriggerMet   bool `json:"twap_trigger_met,omitempty"`

	PayoutCap uint64 `json:"payout_cap"`
}

type TokenomicsConfig struct {
	RInit  uint64 `json:"r_init"`
	RFloor uint64 `json:"r_floor"`
	VHalf  uint64 `json:"v_half"`

	PriceTier1       uint64 `json:"price_tier_1"`
	PriceTier2       uint64 `json:"price_tier_2"`
	PriceTier3       uint64 `json:"price_tier_3"`
	RPriceFloorTier1 uint64 `json:"r_price_floor_tier_1"`
	RPriceFloorTier2 uint64 `json:"r_price_floor_tier_2"`

	RCollusionFactorMilli uint64 `json:"r_collusion_factor_milli"`

	HermiteFDVMinUSD    uint64 `json:"hermite_fdv_min_usd"`
	HermiteFDVMaxUSD    uint64 `json:"hermite_fdv_max_usd"`
	HermiteCeilingMilli uint64 `json:"hermite_ceiling_milli"`
	HermiteFloorMilli   uint64 `json:"hermite_floor_milli"`
}

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
	MaxValueSize = 65536
	MaxBlockSize = 262144
)
