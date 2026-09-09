package core

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync/atomic"
)

//go:embed genesis.json
var embeddedGenesisJSON []byte

var genesisOverride atomic.Pointer[[]byte]

func SetGenesisJSON(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("genesis: empty genesis document")
	}
	if _, err := parseGenesisBlock(data); err != nil {
		return err
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	genesisOverride.Store(&cp)
	return nil
}

func ClearGenesisOverride() {
	genesisOverride.Store(nil)
}

func GenesisJSON() []byte {
	if p := genesisOverride.Load(); p != nil {
		out := make([]byte, len(*p))
		copy(out, *p)
		return out
	}
	out := make([]byte, len(embeddedGenesisJSON))
	copy(out, embeddedGenesisJSON)
	return out
}

func EmbeddedGenesisJSON() []byte {
	out := make([]byte, len(embeddedGenesisJSON))
	copy(out, embeddedGenesisJSON)
	return out
}

var GenesisSupply uint64 = 42_000_000 * AssetXE.UnitsPerToken

func LoadGenesisBlock() (*Block, error) {
	b, err := parseGenesisBlock(GenesisJSON())
	if err != nil {
		return nil, err
	}

	ApplyGenesisLeaseTiming(b)
	return b, nil
}

func ParseGenesisDocument(data []byte) (*Block, error) {
	return parseGenesisBlock(data)
}

func parseGenesisBlock(data []byte) (*Block, error) {
	var b Block
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse genesis: %w", err)
	}
	if err := ValidateGenesisBlock(&b); err != nil {
		return nil, err
	}
	return &b, nil
}

func ValidateGenesisBlock(b *Block) error {
	if b.Type != BlockGenesis {
		return fmt.Errorf("genesis: type must be %q, got %q", BlockGenesis, b.Type)
	}
	if b.Previous != "0" {
		return fmt.Errorf("genesis: previous must be \"0\"")
	}
	if b.Timestamp != 0 {
		return fmt.Errorf("genesis: timestamp must be 0")
	}
	if b.Asset != "XE" {
		return fmt.Errorf("genesis: asset must be \"XE\", got %q", b.Asset)
	}
	if b.Balance != GenesisSupply {
		return fmt.Errorf("genesis: balance must be %d, got %d", GenesisSupply, b.Balance)
	}
	if b.Account == "" {
		return fmt.Errorf("genesis: account must not be empty")
	}

	if err := validateGenesisRepresentative(b); err != nil {
		return err
	}

	if err := validateGenesisLeaseTiming(b); err != nil {
		return err
	}

	savedID := GetNetworkID()
	SetNetworkID("")
	err := VerifyBlock(b)
	SetNetworkID(savedID)
	if err != nil {
		return fmt.Errorf("genesis: %w", err)
	}

	return nil
}

const ZeroAddress = "0000000000000000000000000000000000000000000000000000000000000000"

func validateGenesisRepresentative(b *Block) error {
	if b.Representative == "" {
		return fmt.Errorf("genesis: representative is required — a genesis that delegates nothing yields zero total delegated weight, so no block can ever finalize and every balance stays unspendable while all health checks read green")
	}
	rep, err := hex.DecodeString(b.Representative)
	if err != nil || len(rep) != 32 {
		return fmt.Errorf("genesis: representative must be 64 hex characters (32-byte account address), got %q", b.Representative)
	}
	if b.Representative == ZeroAddress {
		return fmt.Errorf("genesis: representative must not be the all-zero address — that is how the canonical encoding spells \"no representative\"")
	}
	if b.PubKey != "" && b.Representative == b.PubKey {
		return fmt.Errorf("genesis: representative is the genesis PUBLIC KEY, not an account address — an address is sha256(%q || pubkey), so this delegates the whole supply to an account that cannot exist and nothing can ever finalize", AccountAddressDomain)
	}
	return nil
}

func validateGenesisLeaseTiming(b *Block) error {
	minDur := b.LeaseMinDurationSecs
	if minDur == 0 {
		minDur = DefaultLeaseMinDuration
	}
	grace := b.LeaseSettleGraceNs
	if grace == 0 {
		grace = DefaultLeaseSettleGrace
	}
	gap := b.LeaseForceSettleGapNs
	if gap == 0 {
		gap = DefaultLeaseForceSettleGap
	}
	escrow := b.LeaseEscrowExpiryNs
	if escrow == 0 {
		escrow = DefaultLeaseEscrowExpiry
	}
	archive := b.LeaseArchiveGapNs
	if archive == 0 {
		archive = DefaultLeaseArchiveGap
	}
	skew := b.MaxAttestationSkewNs
	if skew == 0 {
		skew = DefaultMaxAttestationSkew
	}

	if minDur < 1 {
		return fmt.Errorf("genesis: lease_min_duration_secs must be >= 1, got %d", minDur)
	}
	if grace <= 0 {
		return fmt.Errorf("genesis: lease_settle_grace_ns must be > 0, got %d", grace)
	}
	if skew <= 0 {
		return fmt.Errorf("genesis: max_attestation_skew_ns must be > 0, got %d", skew)
	}
	if gap <= 2*skew {
		return fmt.Errorf("genesis: lease_force_settle_gap_ns (%d) must exceed 2×max_attestation_skew_ns (%d)", gap, 2*skew)
	}
	if escrow <= grace+gap {
		return fmt.Errorf("genesis: lease_escrow_expiry_ns (%d) must exceed settle_grace+force_settle_gap (%d)", escrow, grace+gap)
	}
	if archive <= 0 {
		return fmt.Errorf("genesis: lease_archive_gap_ns must be > 0, got %d", archive)
	}
	return nil
}

func GenesisAccount() string {
	b, err := LoadGenesisBlock()
	if err != nil {
		panic("genesis: " + err.Error())
	}
	return b.Account
}
