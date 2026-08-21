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

// genesisOverride holds a runtime-supplied ledger genesis (#733, #839). When
// nil the embedded genesis.json is used, so a plain `go build` still produces
// a binary bound to the committed genesis. SetGenesisJSON replaces it once at
// startup, before any Ledger exists.
//
// Atomic because the in-process integration harness constructs several nodes
// in one process, racing a later write against live reads (same reasoning as
// networkID in crypto.go, #717).
var genesisOverride atomic.Pointer[[]byte]

// SetGenesisJSON overrides the embedded ledger genesis with runtime-supplied
// JSON. It validates the block before installing it, so a bad file fails at
// the flag-parsing call site rather than deep inside NewLedger's panic path.
//
// MUST be called before any Ledger is created. Calling it after a ledger has
// been opened does not migrate anything — the persisted block 0 stays
// authoritative and the node will refuse to boot on mismatch.
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

// ClearGenesisOverride restores the embedded genesis. Test helper.
func ClearGenesisOverride() {
	genesisOverride.Store(nil)
}

// GenesisJSON returns the raw genesis document this process is running with —
// the runtime override when one is installed, otherwise the embedded file.
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

// EmbeddedGenesisJSON returns the compiled-in genesis document, ignoring any
// runtime override. Used by `xe verify-genesis` to report what the binary was
// built against versus what it was pointed at.
func EmbeddedGenesisJSON() []byte {
	out := make([]byte, len(embeddedGenesisJSON))
	copy(out, embeddedGenesisJSON)
	return out
}

// GenesisSupply is the total XE minted in the genesis block, expressed in
// micro-units of AssetXE. This is the mainnet launch figure: 42M whole XE =
// 42_000_000 × 10^6 micro-XE = 4.2×10^13. Some portion will be burned at
// deploy time (exact amount tbd).
var GenesisSupply uint64 = 42_000_000 * AssetXE.UnitsPerToken

// LoadGenesisBlock parses this process's genesis document (the runtime
// override when set, otherwise the embedded genesis.json) and validates it.
func LoadGenesisBlock() (*Block, error) {
	b, err := parseGenesisBlock(GenesisJSON())
	if err != nil {
		return nil, err
	}
	// Pin this network's lease timing from the genesis (#524). A genesis with no
	// timing fields restores the production defaults, so existing networks and the
	// embedded canonical genesis keep production timing unchanged.
	ApplyGenesisLeaseTiming(b)
	return b, nil
}

// ParseGenesisDocument parses and validates a genesis document from raw JSON
// without installing it or touching process-wide lease timing. Used by
// `xe verify-genesis` and by the node's genesis preflight.
func ParseGenesisDocument(data []byte) (*Block, error) {
	return parseGenesisBlock(data)
}

// parseGenesisBlock unmarshals and validates a genesis document WITHOUT
// applying its lease timing — SetGenesisJSON must be able to reject a bad file
// without mutating process-wide timing state as a side effect.
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

// ValidateGenesisBlock checks that a genesis block is well-formed.
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
	// MANDATORY representative (#833). It seeds the treasury's delegation, and it
	// is the only thing that makes vote weight exist at block 0 (#515). With no
	// representative the total delegated weight is zero, and zero is treated
	// everywhere as "no quorum yet", silently: finalTally returns (nil, nil)
	// (quorum.go), thresholdMet and strictMajority return false, and every
	// representative's castVoteLocked early-returns on its own zero weight. The
	// network then commits and gossips blocks perfectly while NOTHING ever
	// finalizes — SpendableBalances is empty for every account, all the money is
	// unspendable — and every health signal reads green. Failing closed here, at
	// generation and at load, is vastly preferable to that.
	if err := validateGenesisRepresentative(b); err != nil {
		return err
	}

	// Lease timing (#524): each field is optional (zero → production default). The
	// effective values, after defaulting, must satisfy the same safety invariants
	// the production constants were chosen to meet, so a typo can't brick conflict
	// timing on a network rather than only failing a test.
	if err := validateGenesisLeaseTiming(b); err != nil {
		return err
	}

	// Verify hash and signature. Genesis blocks are always signed without a
	// network ID prefix (they are created before the network ID is known),
	// so temporarily clear the network ID for verification.
	savedID := GetNetworkID()
	SetNetworkID("")
	err := VerifyBlock(b)
	SetNetworkID(savedID)
	if err != nil {
		return fmt.Errorf("genesis: %w", err)
	}

	return nil
}

// ZeroAddress is 32 zero bytes in hex. The canonical encoding spells "no
// representative" as 32 zero bytes, so this string is the same defect as an empty
// field wearing a well-formed disguise — and no key derives it.
const ZeroAddress = "0000000000000000000000000000000000000000000000000000000000000000"

// validateGenesisRepresentative enforces #833: a ledger genesis MUST delegate its
// supply, and it must delegate to an ACCOUNT ADDRESS.
//
// The address/pubkey distinction is load-bearing since #829: an address is
// sha256("xe/account/v1" || pubkey), vote weight is keyed by address
// (Vote.RepAccount()), and both values are 64 hex characters — so a public key in
// this field compiles, validates, and yields a NON-ZERO total delegated weight
// delegated to an account that cannot exist. That failure is strictly worse than
// an empty field, because it also defeats a "total weight > 0" health check. The
// one instance detectable from the block alone is the genesis declaring its own
// key, and it is rejected below; the rest is why callers must derive addresses
// with scripts/seed2addr rather than inline, and why the health signal asserts
// finality progress as well as weight.
func validateGenesisRepresentative(b *Block) error {
	if b.Representative == "" {
		return fmt.Errorf("genesis: representative is required — a genesis that delegates nothing yields zero total delegated weight, so no block can ever finalize and every balance stays unspendable while all health checks read green (#833); regenerate with gen-ledger-genesis -rep <account address>")
	}
	rep, err := hex.DecodeString(b.Representative)
	if err != nil || len(rep) != 32 {
		return fmt.Errorf("genesis: representative must be 64 hex characters (32-byte account address), got %q", b.Representative)
	}
	if b.Representative == ZeroAddress {
		return fmt.Errorf("genesis: representative must not be the all-zero address — that is how the canonical encoding spells \"no representative\" (#833)")
	}
	if b.PubKey != "" && b.Representative == b.PubKey {
		return fmt.Errorf("genesis: representative is the genesis PUBLIC KEY, not an account address — since #829 an address is sha256(%q || pubkey), so this delegates the whole supply to an account that cannot exist and nothing can ever finalize; derive the address with scripts/seed2addr", AccountAddressDomain)
	}
	return nil
}

// validateGenesisLeaseTiming checks the effective (post-defaulting) lease-timing
// values pinned by a genesis block (#524, #662). The invariants mirror those the
// production constants were chosen to satisfy:
//   - min duration >= 1 second (a lease must have a positive duration)
//   - settle grace > 0 (the provider must have a non-empty settle window)
//   - max attestation skew > 0 (#662)
//   - force-settle gap > 2×max attestation skew, so no single real timestamp — even
//     shifted by the maximum skew on each side — can satisfy both the provider's
//     settle window and the consumer's force-settle window (#488, FM3). The skew here
//     is the EFFECTIVE genesis-pinned value, not the package var (which is only set
//     after validation, by ApplyGenesisLeaseTiming) — so a compressed network with a
//     small pinned skew can legitimately run a sub-20-minute gap (#662).
//   - escrow expiry > settle grace + force-settle gap, so the escrow-burn deadline
//     is past the force-settle window's open (otherwise force-settle could never run)
//   - archive gap > 0 (local GC must trail the consensus deadline)
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

// GenesisAccount returns the ADDRESS of the genesis treasury account — since
// #829 that is sha256("xe/account/v1" || treasury_pubkey), not the pubkey; the
// pubkey itself is the genesis block's PubKey field.
func GenesisAccount() string {
	b, err := LoadGenesisBlock()
	if err != nil {
		panic("genesis: " + err.Error())
	}
	return b.Account
}
