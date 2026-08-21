package core

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math"
	"math/big"
	"math/bits"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// safeMul returns a*b and true if the multiplication does not overflow uint64.
// Returns (0, false) on overflow.
func safeMul(a, b uint64) (uint64, bool) {
	if a == 0 || b == 0 {
		return 0, true
	}
	hi, lo := bits.Mul64(a, b)
	if hi != 0 {
		return 0, false
	}
	return lo, true
}

// safeAdd returns a+b and true if the addition does not overflow uint64.
// Returns (0, false) on overflow.
func safeAdd(a, b uint64) (uint64, bool) {
	sum := a + b
	if sum < a {
		return 0, false
	}
	return sum, true
}

// ceilDiv returns ⌈a/b⌉. Rounding policy (#570/L1): where integer division
// on amounts can't be avoided, always round up, consistently. The (a-1)/b+1
// form cannot overflow, unlike (a+b-1)/b.
func ceilDiv(a, b uint64) uint64 {
	if a == 0 {
		return 0
	}
	return (a-1)/b + 1
}

// LeaseStake is the provider stake required to accept a lease of the given
// cost: ⌈cost / LeaseStakeDivisor⌉, minimum 1 micro-XUSD. Producers and
// validators must both use this so accept blocks agree (#570/L1).
func LeaseStake(cost uint64) uint64 {
	stake := ceilDiv(cost, LeaseStakeDivisor)
	if stake == 0 {
		stake = 1
	}
	return stake
}

// LeaseCost computes the XUSD cost for a lease in micro-XUSD (10^-6 XUSD).
//
// Inputs: resource dimensions, duration in seconds, and the provider's price
// multiplier (multiplierMilli scaled ×1000 — 1000 = 1.000×, 2500 = 2.500×).
// Rates are in micro-XUSD per hour, so the unscaled product lands directly
// in micro-XUSD; the multiplier scaling has a single ceiling-divide-by-1000.
// Minimum cost is 1 micro-XUSD as a non-zero safety floor — realistic
// resource dimensions always produce far more.
//
// Billing granularity is one MINUTE (#805): the duration is rounded up to whole
// minutes, and the per-hour rate is divided down by 60. Exact-hour durations
// price identically to the previous hour-granular scheme; only sub-hour and
// part-hour leases move, and they move to the minutes they actually use rather
// than being rounded up to a whole hour. LeaseMinDuration (60s) is therefore
// exactly one billing unit.
//
// Target: 1 vCPU, 1 GB, 10 GB disk, 1 day at 1000× → 960_000 micro-XUSD
// (= 1440 min × (20_000 + 10_000 + 10×1_000) micro-XUSD/hr ÷ 60).
//
// Every step is overflow-checked (#808): the per-hour rate is a sum of three
// products, and an unguarded version wrapped silently — ~9.22e14 vCPUs wrapped
// to 8_384 micro-XUSD/hr and priced a 60s lease at 140 micro-XUSD. The function
// returns a descriptive error rather than a wrapped value for any input.
//
// Duration is range-checked here as well as at the consensus call site (#809),
// so every caller inherits the bound. The CLI and the provider's marketplace
// offer quote do not run behind validateAndAddLease and would otherwise
// confidently price a lease the chain always rejects. Note that LeaseMinDuration
// is genesis-pinned (#524): client binaries that never load a genesis check
// against the compiled-in defaults, so the node-side check in validateAndAddLease
// remains the authoritative one.
func LeaseCost(vcpus, memoryMB, diskGB, duration, multiplierMilli uint64) (uint64, error) {
	if multiplierMilli == 0 {
		return 0, fmt.Errorf("multiplierMilli must be non-zero")
	}
	if duration < LeaseMinDuration {
		return 0, fmt.Errorf("duration must be >= %d seconds, got %d", LeaseMinDuration, duration)
	}
	if duration > LeaseMaxDuration {
		return 0, fmt.Errorf("duration must be <= %d seconds, got %d", LeaseMaxDuration, duration)
	}
	minutes := ceilDiv(duration, 60)
	// ceilDiv, not (memoryMB+1023)/1024 — the bare add wraps at MaxUint64 and
	// collapses memGB to 0, silently dropping the memory term from the price.
	memGB := ceilDiv(memoryMB, 1024)
	vcpuMicro, ok := safeMul(vcpus, LeaseVCPURate)
	if !ok {
		return 0, fmt.Errorf("overflow: vcpus(%d) * LeaseVCPURate(%d)", vcpus, LeaseVCPURate)
	}
	memMicro, ok := safeMul(memGB, LeaseMemGBRate)
	if !ok {
		return 0, fmt.Errorf("overflow: memGB(%d) * LeaseMemGBRate(%d)", memGB, LeaseMemGBRate)
	}
	diskMicro, ok := safeMul(diskGB, LeaseDiskGBRate)
	if !ok {
		return 0, fmt.Errorf("overflow: diskGB(%d) * LeaseDiskGBRate(%d)", diskGB, LeaseDiskGBRate)
	}
	perHourMicro, ok := safeAdd(vcpuMicro, memMicro)
	if !ok {
		return 0, fmt.Errorf("overflow: perHourMicro vcpu(%d) + mem(%d)", vcpuMicro, memMicro)
	}
	perHourMicro, ok = safeAdd(perHourMicro, diskMicro)
	if !ok {
		return 0, fmt.Errorf("overflow: perHourMicro(%d) + disk(%d)", perHourMicro, diskMicro)
	}
	if perHourMicro == 0 {
		return 0, fmt.Errorf("lease requires at least some resources")
	}
	perMinuteScaled, ok := safeMul(perHourMicro, minutes)
	if !ok {
		return 0, fmt.Errorf("overflow: perHourMicro(%d) * minutes(%d)", perHourMicro, minutes)
	}
	costMicro := ceilDiv(perMinuteScaled, 60) // hourly rate → the minutes actually used
	scaled, ok := safeMul(costMicro, multiplierMilli)
	if !ok {
		return 0, fmt.Errorf("overflow: costMicro(%d) * multiplierMilli(%d)", costMicro, multiplierMilli)
	}
	cost := ceilDiv(scaled, 1000) // ceiling-divide the ×1000 multiplier → micro-XUSD
	if cost == 0 {
		cost = 1
	}
	return cost, nil
}

// ErrInvalidPoW is returned when a block's PoWNonce does not satisfy the
// ledger's configured difficulty threshold.
var ErrInvalidPoW = errors.New("invalid proof of work")

// DefaultTimestampWindow is the default allowed clock skew for block timestamps (±1 hour).
const DefaultTimestampWindow = int64(time.Hour)

// Lease economic constants.
const (
	LeaseMaxDuration  = uint64(31536000) // maximum duration (365 days)
	LeaseVCPURate     = uint64(20_000)   // micro-XUSD per vCPU per hour (= 20 milli)
	LeaseMemGBRate    = uint64(10_000)   // micro-XUSD per GB memory per hour (= 10 milli)
	LeaseDiskGBRate   = uint64(1_000)    // micro-XUSD per GB disk per hour (= 1 milli)
	LeaseStakeDivisor = uint64(5)        // stake = ⌈cost / 5⌉
)

// Lease resource-dimension ceilings (#808). Duration has always had both a
// floor and a ceiling; the resource dimensions had neither, which is what made
// the perHourMicro wrap reachable from consensus.
//
// These are a sanity ceiling, not a policy knob — the real limit on a lease is
// the provider's own capacity, checked locally at accept (node/node.go). They
// are compile-time constants rather than genesis-pinned like the lease timing
// group (#524): unlike timing, there is no test-network reason to compress
// them, and #436 already covers the governance-tunable pricing surface.
//
// A lease is one VM on one machine, so the ceiling only has to clear the
// largest single machine anyone sells — today the biggest x86 systems are in
// the hundreds to low thousands of vCPUs with tens of TiB of RAM. Each ceiling
// sits above that and ~10 orders of magnitude below the value at which its rate
// multiplication would wrap (vCPUs wrap at ⌈2^64/20_000⌉ ≈ 9.22e14).
//
// At all three ceilings simultaneously the per-hour rate is 1_785_856_000
// micro-XUSD/hr, so even at LeaseMaxDuration and the most expensive certificate
// multiplier a provider may carry (perf.PriceMultiplierMax = 10_000) every
// intermediate in LeaseCost stays under 2e17. A consensus-valid lease therefore
// cannot reach the overflow guards at all — they are defence in depth for the
// non-consensus callers.
const (
	LeaseMaxVCPUs    = uint64(4_096)      // 4096 vCPUs
	LeaseMaxMemoryMB = uint64(67_108_864) // 64 TiB of memory
	LeaseMaxDiskGB   = uint64(1_048_576)  // 1 PiB of disk
)

// ValidateLeaseDimensions checks a lease's resource dimensions and duration
// against the consensus bounds (#808/#809). validateAndAddLease is the
// authoritative caller — it is what actually admits or rejects a block. The
// CLI, the API and the provider's marketplace offer path call it to fail fast
// rather than sign, PoW and gossip something the chain will always reject.
//
// LeaseMinDuration is genesis-pinned (#524), so a client binary that never
// loaded a genesis is checking against the compiled-in default. That makes the
// client-side check best-effort and the node-side check authoritative.
func ValidateLeaseDimensions(vcpus, memoryMB, diskGB, duration uint64) error {
	if vcpus == 0 && memoryMB == 0 && diskGB == 0 {
		return fmt.Errorf("lease must request at least one resource (vcpus, memory, or disk)")
	}
	if vcpus > LeaseMaxVCPUs {
		return fmt.Errorf("lease vcpus must be <= %d, got %d", LeaseMaxVCPUs, vcpus)
	}
	if memoryMB > LeaseMaxMemoryMB {
		return fmt.Errorf("lease memory_mb must be <= %d, got %d", LeaseMaxMemoryMB, memoryMB)
	}
	if diskGB > LeaseMaxDiskGB {
		return fmt.Errorf("lease disk_gb must be <= %d, got %d", LeaseMaxDiskGB, diskGB)
	}
	if duration < LeaseMinDuration {
		return fmt.Errorf("lease duration must be >= %d seconds", LeaseMinDuration)
	}
	if duration > LeaseMaxDuration {
		return fmt.Errorf("lease duration must be <= %d seconds", LeaseMaxDuration)
	}
	return nil
}

// Lease timing defaults. These are the production (mainnet) values. They are the
// fallback used when a genesis block does not pin lease timing explicitly, which
// keeps the embedded canonical genesis (and every existing network) on production
// timing with no change. A network can override them at genesis time (#524) — see
// ApplyGenesisLeaseTiming and gen-ledger-genesis — so a compressed test network is
// just a different genesis, not a different binary.
const (
	DefaultLeaseMinDuration    = uint64(60)                  // minimum duration in seconds
	DefaultLeaseSettleGrace    = int64(time.Hour)            // expiry → end of provider settle window
	DefaultLeaseForceSettleGap = int64(25 * time.Minute)     // dead zone before consumer force-settle window
	DefaultLeaseEscrowExpiry   = int64(365 * 24 * time.Hour) // expiry → escrow burn deadline
	DefaultLeaseArchiveGap     = int64(time.Hour)            // local GC delay past the consensus deadline
)

// Lease timing is read from the ledger genesis at init (ApplyGenesisLeaseTiming),
// defaulting to the production values above. They are package-level vars so the hot
// validation paths read them without a Ledger receiver, exactly as the old consts
// were read; every node on a network agrees because they derive from the genesis
// block, which is matched byte-for-byte at boot. Client binaries that never load a
// genesis keep the defaults and should read the live values from a node (GET /node)
// rather than relying on these.
var (
	// LeaseMinDuration is the minimum lease duration in seconds.
	LeaseMinDuration = DefaultLeaseMinDuration

	// LeaseSettleGrace is how long after a lease's expiry the provider may still
	// settle. Past expiry+grace the settle is rejected (#487, FM5: a provider must
	// not be able to settle arbitrarily late). The node settle loop retries every
	// 10s, so the production 1h ≈ 360 tries.
	LeaseSettleGrace = DefaultLeaseSettleGrace

	// LeaseForceSettleGap is the dead zone between the close of the provider's
	// settle window (expiry+grace) and the open of the consumer's force-settle
	// window (expiry+grace+gap). It MUST exceed 2×MaxAttestationSkew so that no
	// single real timestamp — even shifted by the maximum attestation skew on each
	// side — can satisfy both windows at once, keeping lease_settle (provider's
	// chain) and lease_force_settle (consumer's chain) disjoint (#488, FM3).
	// ValidateGenesisBlock enforces this bound on any genesis-pinned value.
	LeaseForceSettleGap = DefaultLeaseForceSettleGap

	// LeaseEscrowExpiry bounds how long after expiry a lease's escrow can be
	// settled at all (#493, lease outcome #4: both consumer and provider offline).
	// A lease_force_settle whose attested median is >= expiry+LeaseEscrowExpiry is
	// rejected: the refund window has closed and the escrow is considered burnt.
	// This is consensus state — it is a pure function of the (immutable) lease + the
	// block's own attested timestamp, so every node agrees regardless of local clock.
	// lease_settle needs no equivalent bound: it is already capped at
	// expiry+LeaseSettleGrace (#487), far inside this window.
	LeaseEscrowExpiry = DefaultLeaseEscrowExpiry

	// LeaseArchiveGap is the delay PAST the consensus deadline (expiry+escrow-expiry)
	// before a node locally garbage-collects an abandoned lease — deletes its escrow
	// PendingSend and marks it LeaseExpired. It is NOT a consensus value: archiving
	// is a local, blockless derived-state op. The gap exists so a late-synced but
	// still-valid force-settle (attested median < expiry+LeaseEscrowExpiry) finds its
	// escrow on every node, never racing the GC into a divergence. It MUST exceed the
	// maximum block sync/quarantine latency — which is why this feature lands only
	// after #501 (unbounded quarantine) is fixed.
	LeaseArchiveGap = DefaultLeaseArchiveGap
)

// ApplyGenesisLeaseTiming sets the package-level lease timing vars from a genesis
// block, falling back to the production defaults for any field the genesis leaves
// at zero. It is called once when the genesis is loaded (LoadGenesisBlock). Idempotent:
// re-applying the same genesis yields the same values. A genesis with no timing fields
// (every existing network, and the embedded canonical genesis) restores the defaults.
// MaxAttestationSkew (#662) lives in attestation.go but is part of the same genesis
// timing group, so it is pinned here too.
func ApplyGenesisLeaseTiming(b *Block) {
	LeaseMinDuration = DefaultLeaseMinDuration
	LeaseSettleGrace = DefaultLeaseSettleGrace
	LeaseForceSettleGap = DefaultLeaseForceSettleGap
	LeaseEscrowExpiry = DefaultLeaseEscrowExpiry
	LeaseArchiveGap = DefaultLeaseArchiveGap
	MaxAttestationSkew = DefaultMaxAttestationSkew
	if b == nil {
		return
	}
	if b.LeaseMinDurationSecs != 0 {
		LeaseMinDuration = b.LeaseMinDurationSecs
	}
	if b.LeaseSettleGraceNs != 0 {
		LeaseSettleGrace = b.LeaseSettleGraceNs
	}
	if b.LeaseForceSettleGapNs != 0 {
		LeaseForceSettleGap = b.LeaseForceSettleGapNs
	}
	if b.LeaseEscrowExpiryNs != 0 {
		LeaseEscrowExpiry = b.LeaseEscrowExpiryNs
	}
	if b.LeaseArchiveGapNs != 0 {
		LeaseArchiveGap = b.LeaseArchiveGapNs
	}
	if b.MaxAttestationSkewNs != 0 {
		MaxAttestationSkew = b.MaxAttestationSkewNs
	}
}

// RFallback is the R_effective used when no epoch has been published by the
// oracle (bootstrap period). Equal to R_init from the XE Token Economy Model.
// 2000 = R of 2.000 (provider earns 2× the XUSD cost in XE).
const RFallback = uint64(2000)

// FaucetMintAmount is a test-fixture mint amount in micro-units of AssetXUSD,
// set so that each fixture drip is 100 whole XUSD. The permissionless faucet
// claim has been removed (#557); this constant now only seeds XUSD in tests
// via MintForTesting.
var FaucetMintAmount = 100 * AssetXUSD.UnitsPerToken

// LedgerConfig holds configuration options for a Ledger.
type LedgerConfig struct {
	// Difficulty is the PoW threshold. A block's powHash must be >= Difficulty.
	// Zero means PoW validation is disabled (useful for testing).
	Difficulty uint64
	// TimestampWindow is the maximum allowed delta between a block's timestamp
	// and the current time (in nanoseconds). Zero disables timestamp validation.
	TimestampWindow int64
	// TimekeeperConfigFn returns the current timekeeper configuration.
	// If set, lease_accept and lease_settle blocks require attestations.
	// If nil, attestation validation is skipped (backward compatible).
	TimekeeperConfigFn func() *TimekeeperConfig
	// MinterConfigFn returns the current set of accounts authorized to mint
	// XUSD (sys.minter on the state chain). Used by mint-block validation.
	// If nil or it returns nil, no account is an authorized minter and every
	// mint block is rejected (the safe default for a genesis without sys.minter).
	MinterConfigFn func() *MinterConfig
	// CertificateLookupFn looks up a performance certificate by its hash.
	// Used by lease_accept validation to verify the certificate exists,
	// belongs to the provider, and is not expired.
	CertificateLookupFn func(hash string) *CertificateInfo
	// EpochRFn returns the current epoch's R_effective (emission ratio, scaled ×1000).
	// Used by lease_settle to compute XE emission: emission = lease.Cost * R / 1000.
	// If nil or returns 0, falls back to RFallback (R_init = 2000 = 2.000).
	// See "XE Token Economy Model" §Dual R Emission.
	EpochRFn func() uint64
	// EpochPayoutCapFn returns the latest epoch's Hermite payout cap, scaled ×1000.
	// Used by lease_settle to bound XE emission against self-lease attacks:
	// R_capped = min(R, PayoutCap × 1000 / TWAP). Zero disables the cap
	// (treated as no-op; backward compatible with pre-v13 epochs).
	// See "XE Token Economy Model" v13 §Hermite Self-Lease Payout Cap.
	EpochPayoutCapFn func() uint64
	// EpochTWAPFn returns the latest epoch's TWAP in milli-USD. Used together
	// with EpochPayoutCapFn to compute R_capped at lease_settle.
	// Zero disables the cap (treated as no-op).
	EpochTWAPFn func() uint64
	// EpochAtFn returns the emission params of the statechain epochs that an
	// accept at unix-nanos ns may legitimately have locked: the covering
	// epoch first (highest StartNS <= ns), then up to EpochLockTolerance of
	// its predecessors, newest first. Empty when no epoch covers ns. Used on
	// the lease_accept path to verify the block's carried locked params
	// (anti-forgery, #501). Predecessors matter because epochs are published
	// AFTER the interval they cover begins: an accept admitted before later
	// epochs were published legitimately locked the then-latest epoch's
	// params, but once they land their StartNS retroactively covers the
	// accept time — re-validation (epoch-boundary races #574, cold-sync
	// replay #630) must accept the params of any epoch within the publish-lag
	// window. A forged LockedR matches none of them. The bounded window keeps
	// the rate-shopping surface small; the principled successor is carrying
	// the locked epoch index in the signed accept (#574, protocol break).
	// nil disables the check (tests / pre-oracle ledgers trust the signed
	// value).
	EpochAtFn func(ns int64) []EpochParams

	// FeatureActiveFn reports whether an activation feature named in
	// sys.activations is live as of the state chain's current tip (#830). The
	// node wires it to statechain.Chain.FeatureActive. It MUST be a pure
	// function of converged chain state — never the local clock, config or
	// peer set (#501). Leaving it nil disables every gated block type.
	FeatureActiveFn func(feature string) bool
}

// EpochLockTolerance is how many epochs before the covering epoch a
// lease_accept's locked params may reference (publish-lag window, #574/#630).
const EpochLockTolerance = 3

// EpochParams is one statechain epoch's emission-relevant content, as carried
// by lease_accept locked params: R ×1000, payout cap ×1000, TWAP milli-USD.
type EpochParams struct {
	R         uint64
	PayoutCap uint64
	TWAP      uint64
}

// accountLock holds a per-account mutex and a reference count of waiters.
type accountLock struct {
	mu      sync.Mutex // work lock; held for the duration of an AddBlock call
	waiters int        // number of goroutines that have registered interest
}

// Ledger is a block lattice backed by a Store.
type Ledger struct {
	locksMu         sync.Mutex              // guards the locks map; held nanoseconds only
	locks           map[string]*accountLock // per-account lock registry
	leaseLocksMu    sync.Mutex              // guards the leaseLocks map
	leaseLocks      map[string]*accountLock // per-lease lock registry (#570/C3)
	store           Store
	atomicStore     AtomicBlockStore // same as store; cached to avoid repeated type assertion
	difficulty      uint64           // PoW difficulty threshold; 0 disables PoW validation
	timestampWindow int64            // max clock skew in nanos; 0 disables timestamp validation

	delegationMu sync.RWMutex        // guards delegation and weights maps
	delegation   map[string]string   // account → representative
	weights      map[string]*big.Int // representative → total delegated balance

	// repElig gates which representatives' weight counts toward the quorum
	// denominator (and numerator). Unrestricted unless a policy is wired. (#832)
	repElig repEligibility

	// Per-asset balance tracking: assetBalances[account][asset] = balance.
	// Updated on every block commit; used for validation instead of chain.LatestBalance().
	assetBalMu    sync.RWMutex
	assetBalances map[string]map[string]uint64

	blockCount          atomic.Int64   // cached total block count across all accounts
	delegationUnderflow atomic.Uint64  // count of delegation weight underflows (#728, data-corruption signal)
	finalityAdvances    atomic.Uint64  // times a final-height watermark advanced since startup (#833 liveness signal)
	lastFinalityNs      atomic.Int64   // wall-clock ns of the most recent watermark advance (#833)
	conflictMu          sync.Mutex     // guards conflictCallback + blockAddedCallback
	conflictCallback    func(Conflict) // fired once when a conflict reaches size 2
	blockAddedCallback  func(*Block)   // fired after a non-conflicting block is added (#526)
	timekeeperConfigFn  func() *TimekeeperConfig
	minterConfigFn      func() *MinterConfig
	certificateLookupFn func(hash string) *CertificateInfo
	epochRFn            func() uint64
	epochPayoutCapFn    func() uint64
	epochTWAPFn         func() uint64
	epochAtFn           func(ns int64) []EpochParams

	// featureActiveFn reports whether an activation feature is live as of the
	// converged state chain (#830). nil ⇒ nothing is ever active (fail-closed).
	featureActiveFn func(feature string) bool

	// Multisig keyset tracking: keysets[account] = keyset.
	// Populated on multisig_open and multisig_update; rebuilt on startup.
	keysetMu sync.RWMutex
	keysets  map[string]*Keyset

	// accountKeys is the single-key credential registry: account address → hex
	// ed25519 public key, declared by the first block on each single-key chain
	// (#829). Every non-open single-key block is verified against this map, not
	// against its own account field. Rebuilt from the chains on restart (like
	// keysets) and written through to the store inside the block commit.
	accountKeyMu sync.RWMutex
	accountKeys  map[string]string

	// Reputation aggregates derived from lease lifecycle events.
	// See core/reputation.go and #380/#402.
	reputation *ReputationEngine

	// finalStore persists block finalization status and per-account final
	// height. Optional — nil if the store doesn't implement QuorumStore, in
	// which case nothing is ever finalized (FinalHeight returns 0). See #525.
	finalStore QuorumStore

	// finalVoteStore holds the write-once finalization commit-lock: one finalized
	// hash per (account, previous), ever. Optional. See #526.
	finalVoteStore FinalVoteStore

	// #622 conflict-promotion overlay: while a single promotion is in flight,
	// activeCascade holds the not-yet-committed post-undo state (truncated chains,
	// re-created pendings, reversed lease/keyset side effects, post-undo
	// delegation pointers). The winner re-validation reads through it via the
	// overlay helpers so the whole promotion can land in ONE CommitCascade store
	// transaction. nil when no promotion is in progress; at most one ever active
	// (promotions are serialized by the quorum lock). Guarded by cascadeMu.
	cascadeMu     sync.RWMutex
	activeCascade *cascadeBuild
}

// NewLedger creates a ledger backed by s with the given config.
// The store must implement AtomicBlockStore for crash-safe block commits.
func NewLedger(s Store, cfg LedgerConfig) *Ledger {
	abs, ok := s.(AtomicBlockStore)
	if !ok {
		panic("ledger: store must implement AtomicBlockStore")
	}
	l := &Ledger{
		locks:               make(map[string]*accountLock),
		leaseLocks:          make(map[string]*accountLock),
		store:               s,
		atomicStore:         abs,
		difficulty:          cfg.Difficulty,
		timestampWindow:     cfg.TimestampWindow,
		timekeeperConfigFn:  cfg.TimekeeperConfigFn,
		minterConfigFn:      cfg.MinterConfigFn,
		certificateLookupFn: cfg.CertificateLookupFn,
		epochRFn:            cfg.EpochRFn,
		featureActiveFn:     cfg.FeatureActiveFn,
		epochPayoutCapFn:    cfg.EpochPayoutCapFn,
		epochTWAPFn:         cfg.EpochTWAPFn,
		epochAtFn:           cfg.EpochAtFn,
		delegation:          make(map[string]string),
		weights:             make(map[string]*big.Int),
		assetBalances:       make(map[string]map[string]uint64),
		keysets:             make(map[string]*Keyset),
		accountKeys:         make(map[string]string),
	}
	// ReputationStore is optional — engine falls back to in-memory only if
	// the store doesn't implement it.
	repStore, _ := s.(ReputationStore)
	l.reputation = NewReputationEngine(repStore)
	// QuorumStore is optional — carries finalization status + final height.
	l.finalStore, _ = s.(QuorumStore)
	// FinalVoteStore is optional — the write-once finalization commit-lock.
	l.finalVoteStore, _ = s.(FinalVoteStore)
	empty, err := s.IsEmpty()
	if err != nil {
		panic(fmt.Sprintf("ledger: IsEmpty: %v", err))
	}
	if empty {
		genesis, err := LoadGenesisBlock()
		if err != nil {
			panic(fmt.Sprintf("ledger: load genesis: %v", err))
		}
		commit, prevBal, err := l.prepareBlockWrite(genesis)
		if err != nil {
			panic(fmt.Sprintf("ledger: prepare genesis: %v", err))
		}
		if err := l.commitBlockWrite(commit, prevBal); err != nil {
			panic(fmt.Sprintf("ledger: commit genesis: %v", err))
		}
		// Genesis is the inherently-final trusted root — byte-identical and
		// embedded on every node. Mark it finalized (height 1) at bootstrap, or
		// dependency-ordered finalization (#526) can never advance past it: the
		// first real block's `previous` is the genesis hash, so nothing rooted at
		// genesis (the treasury and everything funded from it) could finalize. See
		// #534. Genesis itself never runs an election (it's committed before any
		// vote callback is wired, and the trigger/sweep skip BlockGenesis).
		if l.finalStore != nil {
			if err := l.finalStore.SetFinalHeight(genesis.Account, 1); err != nil {
				log.Printf("ledger: finalize genesis: %v", err)
			}
		}
		log.Printf("Genesis block applied: %s XE to %s", fmt.Sprint(genesis.Balance), shortAddr(genesis.Account))

		// #833: refuse to bootstrap a network that cannot finalize. The genesis
		// representative is validated as a field by ValidateGenesisBlock; this
		// asserts the property that actually matters — that applying genesis
		// produced vote weight — so no future change to the delegation path can
		// reintroduce a zero-weight launch. A fresh bootstrap is a launch
		// misconfiguration and the operator's fix is to regenerate the genesis, so
		// fail closed here, as loudly as possible: booting would mean a network
		// that commits blocks, reports green, and finalizes nothing, forever.
		if l.GetTotalDelegatedWeight().Sign() == 0 {
			panic(fmt.Sprintf("ledger: genesis %s yielded ZERO total delegated weight — refusing to bootstrap a network that can never finalize a block (#833); regenerate the genesis with gen-ledger-genesis -rep <account address>", shortHash(genesis.Hash)))
		}
	} else {
		// #671: re-pin the genesis lease/skew timing on a non-empty restart. The
		// empty branch above applies it via LoadGenesisBlock, but the restart
		// branch only rebuilds in-memory state from disk — so without this the six
		// timing vars (LeaseMinDuration, LeaseSettleGrace, LeaseForceSettleGap,
		// LeaseEscrowExpiry, LeaseArchiveGap, MaxAttestationSkew) silently reverted
		// to their compile-time Default* values after any process restart. On a
		// network whose genesis pins compressed timing that splits restarted nodes
		// from their peers (divergent attestation-skew windows and force-settle
		// eligibility) → consensus split, no attacker required.
		//
		// The PERSISTED block 0 is authoritative — it carries this network's
		// actual, signed timing fields, so they win regardless of what genesis the
		// running binary happens to embed (the embedded canonical genesis pins no
		// timing, so re-applying it would itself reset a compressed network to
		// defaults). A missing/unreadable genesis on a non-empty store is
		// unrecoverable corruption: fail loud, matching the rebuild* policy below.
		genesisAcct := GenesisAccount()
		gchain, err := l.store.GetAccountChain(genesisAcct)
		if err != nil {
			panic(fmt.Sprintf("ledger: load persisted genesis on restart: %v", err))
		}
		if gchain == nil || len(gchain.Blocks) == 0 {
			panic(fmt.Sprintf("ledger: persisted genesis chain for %s is missing on restart", shortAddr(genesisAcct)))
		}
		ApplyGenesisLeaseTiming(gchain.Blocks[0])

		// #570/M10: a store read error during recovery means the persisted
		// state is only partially readable. Refuse to boot (panic, like the
		// other unrecoverable startup conditions above) rather than continuing
		// with silently-zeroed balances / dropped vote weights.
		if err := l.rebuildDelegation(); err != nil {
			panic(fmt.Sprintf("ledger: %v", err))
		}
		if err := l.rebuildAssetBalances(); err != nil {
			panic(fmt.Sprintf("ledger: %v", err))
		}
		l.rebuildKeysets()
		l.rebuildAccountKeys()
		l.rebuildReputation()
		l.initBlockCount()
		l.pruneChainlessAccounts()

		// #833: on a RESTART, zero total delegated weight is the same silent
		// finality death — but deliberately NOT a panic here, unlike the bootstrap
		// branch above. A live chain that has lost all delegation (every delegator
		// re-pointed at "", or all delegated balances moved to accounts naming no
		// representative) is recoverable by exactly one thing: a block that
		// delegates again. That block can only be accepted by nodes that are
		// RUNNING, so refusing to boot would convert a recoverable stall into a
		// permanently dead network. Instead it is made impossible to miss: a
		// startup ERROR line plus the total_delegated_weight / finality_advances
		// fields on /node that the health gate asserts.
		if l.GetTotalDelegatedWeight().Sign() == 0 {
			log.Printf("ERROR: total delegated weight is ZERO on startup — no block can finalize and every balance is unspendable until some account delegates again; the network is in silent finality death (#833)")
		}
	}
	return l
}

// pruneChainlessAccounts removes account records that have a frontier entry but
// ZERO canonical blocks — "ghost" accounts. The #701 forward fix deletes an
// account when an undo empties its chain, but it cannot reach ghosts that were
// already persisted before the fix shipped (a cascade that unwound a recipient's
// only receive used to leave an empty chain + "0" frontier instead of deleting
// the record). Those linger in the store, show up in /accounts with block_count=0,
// and diverge the per-account census from a node that never built the rolled-back
// cone. This startup pass clears them so a restart heals the divergence without a
// full cold-sync, matching a fresh rebuild-from-chain (which omits chainless
// accounts). Idempotent; reuses the tested DeleteAccount commit path. (#701)
func (l *Ledger) pruneChainlessAccounts() {
	var pruned int
	for acc := range l.Frontiers() {
		chain, err := l.store.GetAccountChain(acc)
		if err != nil {
			continue
		}
		if chain != nil && len(chain.Blocks) > 0 {
			continue // real account with blocks
		}
		if err := l.store.CommitUndo(&BlockUndo{
			Account:           acc,
			Chain:             &AccountChain{},
			FrontierHash:      "0",
			DeleteAccount:     true,
			RestoreDelegation: true,
			PrevRep:           "",
		}); err != nil {
			log.Printf("pruneChainlessAccounts: delete ghost %s: %v", shortAddr(acc), err)
			continue
		}
		l.deleteAccountBalances(acc)
		pruned++
	}
	if pruned > 0 {
		log.Printf("ledger: pruned %d chainless ghost account(s) at startup (#701)", pruned)
	}
}

// SetConflictCallback sets a function that is called exactly once when a
// conflict (equivocation) is first detected for a given (account, previous)
// pair — i.e. when the conflict's BlockHashes slice reaches length 2.
// Subsequent blocks that extend the same conflict do not re-fire the callback.
// The callback is invoked with the account lock held; it must not call back
// into the Ledger.
func (l *Ledger) SetConflictCallback(fn func(Conflict)) {
	l.conflictMu.Lock()
	l.conflictCallback = fn
	l.conflictMu.Unlock()
}

// SetBlockAddedCallback sets a function called (asynchronously) after every
// non-conflicting block is successfully added, driving per-block finalization
// voting. See #526.
func (l *Ledger) SetBlockAddedCallback(fn func(*Block)) {
	l.conflictMu.Lock()
	l.blockAddedCallback = fn
	l.conflictMu.Unlock()
}

// acquireAccountLock looks up or creates the per-account lock for accountID,
// increments its waiter count (while locksMu is held), then blocks until the
// account's work mutex is acquired. Returns the entry for use with
// releaseAccountLock.
func (l *Ledger) acquireAccountLock(accountID string) *accountLock {
	l.locksMu.Lock()
	entry, ok := l.locks[accountID]
	if !ok {
		entry = &accountLock{}
		l.locks[accountID] = entry
	}
	entry.waiters++
	l.locksMu.Unlock()

	entry.mu.Lock()
	return entry
}

// acquireAccountLockTry is the non-blocking form of acquireAccountLock: it
// returns (entry, true) only if the work lock was taken immediately, and
// (nil, false) otherwise without ever blocking. The #570/C3b cancel-wins
// resolution uses it to grab the provider's account lock while processing a
// cancel on the consumer's chain — a blocking acquire there could deadlock
// against a concurrent provider lease-transition. Release with releaseAccountLock.
func (l *Ledger) acquireAccountLockTry(accountID string) (*accountLock, bool) {
	l.locksMu.Lock()
	entry, ok := l.locks[accountID]
	if !ok {
		entry = &accountLock{}
		l.locks[accountID] = entry
	}
	entry.waiters++
	l.locksMu.Unlock()

	if entry.mu.TryLock() {
		return entry, true
	}
	l.locksMu.Lock()
	entry.waiters--
	if entry.waiters == 0 {
		delete(l.locks, accountID)
	}
	l.locksMu.Unlock()
	return nil, false
}

// releaseAccountLock unlocks the account work mutex, then decrements the waiter
// count and removes the entry from the registry if no other goroutines are waiting.
func (l *Ledger) releaseAccountLock(accountID string, entry *accountLock) {
	entry.mu.Unlock()

	l.locksMu.Lock()
	entry.waiters--
	if entry.waiters == 0 {
		delete(l.locks, accountID)
	}
	l.locksMu.Unlock()
}

// acquireLeaseLock/releaseLeaseLock mirror the account lock registry for
// lease hashes (#570/C3). Lease-state transitions live on different account
// chains — lease_accept/lease_settle on the provider's, lease_cancel/
// lease_force_settle on the consumer's — so the account lock alone cannot
// serialize two transitions of the SAME lease: an accept and a cancel can
// both read state==created and both commit (escrow refunded AND lease
// accepted → a later settle mints XE with no XUSD burn). Holding this lock
// across validate→commit makes the state gate atomic on one node. Lock
// ordering is always account → lease; nothing acquires in reverse.
func (l *Ledger) acquireLeaseLock(leaseHash string) *accountLock {
	l.leaseLocksMu.Lock()
	entry, ok := l.leaseLocks[leaseHash]
	if !ok {
		entry = &accountLock{}
		l.leaseLocks[leaseHash] = entry
	}
	entry.waiters++
	l.leaseLocksMu.Unlock()

	entry.mu.Lock()
	return entry
}

func (l *Ledger) releaseLeaseLock(leaseHash string, entry *accountLock) {
	entry.mu.Unlock()

	l.leaseLocksMu.Lock()
	entry.waiters--
	if entry.waiters == 0 {
		delete(l.leaseLocks, leaseHash)
	}
	l.leaseLocksMu.Unlock()
}

// isLeaseStateTransition reports whether the block type transitions the
// state of the lease referenced by its Source field.
func isLeaseStateTransition(t BlockType) bool {
	switch t {
	case BlockLeaseAccept, BlockLeaseSettle, BlockLeaseCancel, BlockLeaseForceSettle:
		return true
	}
	return false
}

// getAssetBalance returns the current balance for an account+asset pair.
// Must be called with assetBalMu held (at least RLock).
func (l *Ledger) getAssetBalance(account, asset string) uint64 {
	l.assetBalMu.RLock()
	defer l.assetBalMu.RUnlock()
	if m, ok := l.assetBalances[account]; ok {
		return m[asset]
	}
	return 0
}

// addAssetBalance atomically adds delta to the in-memory asset balance.
func (l *Ledger) addAssetBalance(account, asset string, delta uint64) {
	l.assetBalMu.Lock()
	defer l.assetBalMu.Unlock()
	if l.assetBalances[account] == nil {
		l.assetBalances[account] = make(map[string]uint64)
	}
	l.assetBalances[account][asset] += delta
}

// subAssetBalance atomically subtracts delta from the in-memory asset balance,
// flooring at zero. The floor is defensive: the authoritative balance is the
// rebuild-from-store value (recomputed every boot), and the apply order of an
// undo cascade restores each block's own asset to its chain-walk value, so a
// well-formed reorg never drives this below zero. Used to reverse a
// lease_settle stake return on undo (#674).
func (l *Ledger) subAssetBalance(account, asset string, delta uint64) {
	l.assetBalMu.Lock()
	defer l.assetBalMu.Unlock()
	m := l.assetBalances[account]
	if m == nil {
		return
	}
	if delta >= m[asset] {
		m[asset] = 0
		return
	}
	m[asset] -= delta
}

// setAssetBalance updates the in-memory asset balance for an account.
func (l *Ledger) setAssetBalance(account, asset string, balance uint64) {
	l.assetBalMu.Lock()
	defer l.assetBalMu.Unlock()
	if l.assetBalances[account] == nil {
		l.assetBalances[account] = make(map[string]uint64)
	}
	l.assetBalances[account][asset] = balance
}

// deleteAccountBalances drops an account's entire in-memory balance map. Called
// when an undo empties the account's chain (#701) so the live balance map matches
// a fresh rebuild-from-chain, which never creates an entry for a chainless account.
func (l *Ledger) deleteAccountBalances(account string) {
	l.assetBalMu.Lock()
	defer l.assetBalMu.Unlock()
	delete(l.assetBalances, account)
}

// GetAssetBalances returns a copy of all asset balances for an account.
func (l *Ledger) GetAssetBalances(account string) map[string]uint64 {
	l.assetBalMu.RLock()
	defer l.assetBalMu.RUnlock()
	m := l.assetBalances[account]
	if m == nil {
		return map[string]uint64{}
	}
	out := make(map[string]uint64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// rebuildAssetBalances scans all chains to populate the assetBalances map on
// startup. Called when the store is non-empty.
func (l *Ledger) rebuildAssetBalances() error {
	ls, hasLeases := l.store.(LeaseStore)
	frontiers := l.Frontiers()
	for acc := range frontiers {
		chain, err := l.store.GetAccountChain(acc)
		// #570/M10: a store read error means the store is partially readable.
		// Returning here makes startup refuse to boot rather than silently
		// zeroing this account's balance and booting into divergence.
		if err != nil {
			return fmt.Errorf("rebuildAssetBalances: GetAccountChain(%s): %w", shortAddr(acc), err)
		}
		if chain == nil {
			continue
		}
		balByAsset := make(map[string]uint64)
		for _, b := range chain.Blocks {
			asset := b.Asset
			if asset == "" {
				asset = "XE" // legacy blocks without asset field
			}
			balByAsset[asset] = b.Balance
			// When we encounter a lease_settle block, also return the XUSD
			// stake — mirroring the addAssetBalance side effect in
			// validateAndAddLeaseSettle. This must happen inline so that
			// subsequent XUSD blocks (which already baked in the return)
			// correctly overwrite the balance.
			if b.Type == BlockLeaseSettle {
				if !hasLeases {
					log.Printf("rebuildAssetBalances: lease_settle block %s but store has no LeaseStore", shortHash(b.Hash))
					continue
				}
				lease, err := ls.GetLease(b.Source)
				if err != nil || lease == nil {
					log.Printf("rebuildAssetBalances: lease_settle block %s references missing lease %s", shortHash(b.Hash), shortHash(b.Source))
					continue
				}
				balByAsset["XUSD"] += lease.Stake
			}
		}
		l.assetBalances[acc] = balByAsset
	}
	return nil
}

// GetReputation returns a copy of the reputation aggregate for account, or
// nil if no events have touched the account yet.
func (l *Ledger) GetReputation(account string) *ReputationAggregate {
	return l.reputation.Get(account)
}

// AllReputations returns a copy of every account's reputation aggregate.
// Used by the leaderboard endpoint and the cross-node convergence tests.
func (l *Ledger) AllReputations() map[string]*ReputationAggregate {
	return l.reputation.All()
}

// rebuildReputation reconstructs the in-memory reputation aggregates by
// replaying every settle / accept / cancel observable in the ledger. Called
// on non-empty startup, mirroring rebuildDelegation / rebuildAssetBalances.
// Detailed implementation lands with phase 1 task #4.
func (l *Ledger) rebuildReputation() {
	l.reputation.Reset()

	ls, ok := l.store.(LeaseStore)
	if !ok {
		return
	}
	leases, err := ls.GetAllLeases()
	if err != nil {
		log.Printf("rebuildReputation: GetAllLeases: %v", err)
		return
	}

	// Replay accept and (optionally) settle for each lease. We don't have
	// per-lease cancel records because cancel deletes the pending send and
	// never produces a Lease entry — cancels are scanned out of account
	// chains below.
	for _, lease := range leases {
		// #681: a lease record is created (in "created" state) by the lease block
		// itself, and persists in that state when an accept is reorged back to
		// created. Only count an accept for leases that were actually accepted.
		// StartTime is set at accept and zeroed when an accept is unwound, so it
		// is the precise marker — this keeps the cold rebuild in step with the
		// live path, which only increments on a lease_accept block (never on a
		// bare lease creation).
		if lease.StartTime == 0 {
			continue
		}
		// Accept: timestamp is StartTime (unix nanos at lease_accept).
		l.reputation.Apply(ReputationEvent{
			Kind:      EventLeaseAccepted,
			Provider:  lease.Provider,
			Consumer:  lease.Consumer,
			Timestamp: lease.StartTime,
		})
		if !lease.Settled {
			continue
		}
		// Expired/archived (#493, outcome #4): both parties abandoned the lease,
		// the escrow was burnt by the local sweep, and accountability is left to
		// a resolved dispute (#506). It is reputation-neutral — replay nothing
		// beyond the accept already applied above.
		if lease.State == LeaseExpired {
			continue
		}
		// Force-settled (#490): the lease is marked Settled but was never
		// settled by the provider. Replay it as EventLeaseUnfulfilled — NOT a
		// settle — mirroring the live emit, using the force-settle block's
		// timestamp from the consumer's chain so replay is deterministic.
		if lease.State == LeaseUnfulfilled {
			forceTs := lookupLeaseForceSettleTimestamp(l.store, lease)
			l.reputation.Apply(ReputationEvent{
				Kind:      EventLeaseUnfulfilled,
				Provider:  lease.Provider,
				Consumer:  lease.Consumer,
				Timestamp: forceTs,
			})
			continue
		}
		// Settle: timestamp from the provider's lease_settle block.
		settleTs := lookupLeaseSettleTimestamp(l.store, lease)
		l.reputation.Apply(ReputationEvent{
			Kind:         EventLeaseSettled,
			Provider:     lease.Provider,
			Consumer:     lease.Consumer,
			Timestamp:    settleTs,
			DurationSecs: lease.Duration,
		})
	}

	// Cancels: scan every account chain for BlockLeaseCancel.
	frontiers := l.Frontiers()
	for acc := range frontiers {
		chain, err := l.store.GetAccountChain(acc)
		if err != nil || chain == nil {
			continue
		}
		for _, b := range chain.Blocks {
			if b.Type != BlockLeaseCancel {
				continue
			}
			leaseBlock, err := l.store.GetBlock(b.Source)
			if err != nil || leaseBlock == nil {
				continue
			}
			l.reputation.Apply(ReputationEvent{
				Kind:      EventLeaseCancelled,
				Provider:  leaseBlock.Destination,
				Consumer:  b.Account,
				Timestamp: b.Timestamp,
			})
		}
	}
}

// lookupLeaseSettleTimestamp finds the lease_settle block on the provider's
// chain that settled the given lease and returns its timestamp. Returns
// lease.StartTime + Duration as a fallback if the block can't be located.
func lookupLeaseSettleTimestamp(store Store, lease *Lease) int64 {
	chain, err := store.GetAccountChain(lease.Provider)
	if err != nil || chain == nil {
		return lease.StartTime + int64(lease.Duration)*1e9
	}
	for _, b := range chain.Blocks {
		if b.Type == BlockLeaseSettle && b.Source == lease.LeaseHash {
			return b.Timestamp
		}
	}
	return lease.StartTime + int64(lease.Duration)*1e9
}

// lookupLeaseForceSettleTimestamp returns the timestamp of the lease_force_settle
// block on the consumer's chain (#490). Mirrors lookupLeaseSettleTimestamp but
// scans the consumer side, since force-settle lives on the consumer's chain.
func lookupLeaseForceSettleTimestamp(store Store, lease *Lease) int64 {
	chain, err := store.GetAccountChain(lease.Consumer)
	if err != nil || chain == nil {
		return lease.StartTime + int64(lease.Duration)*1e9
	}
	for _, b := range chain.Blocks {
		if b.Type == BlockLeaseForceSettle && b.Source == lease.LeaseHash {
			return b.Timestamp
		}
	}
	return lease.StartTime + int64(lease.Duration)*1e9
}

// normalizeBlockHex lowercases all hex string fields on a block to prevent
// mixed-case identity splitting.
func normalizeBlockHex(b *Block) {
	b.Account = strings.ToLower(b.Account)
	b.Previous = strings.ToLower(b.Previous)
	b.Hash = strings.ToLower(b.Hash)
	b.Signature = strings.ToLower(b.Signature)
	b.Destination = strings.ToLower(b.Destination)
	b.Source = strings.ToLower(b.Source)
	b.Representative = strings.ToLower(b.Representative)
	b.PubKey = strings.ToLower(b.PubKey)
	for i := range b.Signatures {
		b.Signatures[i].PublicKey = strings.ToLower(b.Signatures[i].PublicKey)
		b.Signatures[i].Sig = strings.ToLower(b.Signatures[i].Sig)
	}
	if b.MSKeyset != nil {
		for i := range b.MSKeyset.Keys {
			b.MSKeyset.Keys[i] = strings.ToLower(b.MSKeyset.Keys[i])
		}
	}
}

// AddBlock validates and adds a block to the ledger. Returns error if invalid.
func (l *Ledger) AddBlock(b *Block) error {
	return l.addBlock(b, false)
}

// AddSyncedBlock validates and adds a block received via the sync protocol.
// It skips the timestamp window check because synced blocks are historical
// data that was already validated when originally published.
func (l *Ledger) AddSyncedBlock(b *Block) error {
	return l.addBlock(b, true)
}

func (l *Ledger) addBlock(b *Block, skipTimestamp bool) error {
	bc := *b // shallow copy
	if len(bc.Attestations) > 0 {
		bc.Attestations = append([]TimekeeperAttestation(nil), bc.Attestations...)
	}
	b = &bc
	normalizeBlockHex(b)

	// Strip attestations from non-lease blocks to prevent gossip pollution.
	// lease_accept/settle/force_settle are the only types that carry them.
	if b.Type != BlockLeaseAccept && b.Type != BlockLeaseSettle && b.Type != BlockLeaseForceSettle {
		b.Attestations = nil
	}
	// Reject oversized attestation arrays outright. Post-#596 the set is bound
	// into the block hash, so the old truncation could only turn a
	// validly-signed block into a hash-mismatch reject — same outcome, worse
	// diagnostics, and it masked producers building unprocessable blocks (#599).
	if len(b.Attestations) > MaxAttestationsPerBlock {
		return fmt.Errorf("too many attestations: %d exceeds max %d", len(b.Attestations), MaxAttestationsPerBlock)
	}

	if err := VerifyBlock(b); err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	// Validate proof-of-work if difficulty is configured.
	if l.difficulty > 0 {
		hashBytes, err := hex.DecodeString(b.Hash)
		if err != nil {
			return fmt.Errorf("decode hash: %w", err)
		}
		if !ValidatePoW(hashBytes, b.PoWNonce, l.difficulty) {
			return ErrInvalidPoW
		}
	}

	// Validate block timestamp is within the configured window of now.
	// Window=0 disables validation. Skipped for synced blocks (historical data).
	if !skipTimestamp && l.timestampWindow > 0 {
		if b.Timestamp < 0 {
			return fmt.Errorf("block timestamp must not be negative")
		}
		nowNanos := Now().UnixNano()
		var delta int64
		if b.Timestamp > nowNanos {
			delta = b.Timestamp - nowNanos
		} else {
			delta = nowNanos - b.Timestamp
		}
		if delta > l.timestampWindow {
			return fmt.Errorf("block timestamp out of range: delta=%v", time.Duration(delta))
		}
	}

	entry := l.acquireAccountLock(b.Account)
	defer l.releaseAccountLock(b.Account, entry)

	// #570/C3: additionally serialize lease-state transitions per lease —
	// the racing transitions arrive on different account chains (see
	// acquireLeaseLock).
	if isLeaseStateTransition(b.Type) && b.Source != "" {
		leaseEntry := l.acquireLeaseLock(b.Source)
		defer l.releaseLeaseLock(b.Source, leaseEntry)
	}

	// Reject duplicates.
	existing, err := l.store.GetBlock(b.Hash)
	if err != nil {
		return fmt.Errorf("GetBlock: %w", err)
	}
	if existing != nil {
		return nil // idempotent
	}

	// Credential verification — the multisig keyset, or (since #829) the account's
	// declared ed25519 public key resolved from the ledger's key registry. It runs
	// HERE, before conflict detection, deliberately: a block whose signature does
	// not check out must never be able to seed a conflict record and freeze the
	// account (the #519 remotely-triggerable wedge).
	if err := l.verifyBlockCredential(b); err != nil {
		return err
	}

	// Conflict detection (equivocation tracking): if the store supports
	// ConflictStore, check whether another block already occupies the same
	// (account, previous) slot. If so, save the incoming block to staging and
	// fire the callback on first detection; do NOT insert into the main chain.
	if cs, ok := l.store.(ConflictStore); ok {
		// AddBlock's conflict detection runs on the live store — never the #622
		// promotion overlay (the winner is re-applied via dispatchValidateAndAdd,
		// which bypasses this entry path), so read the store directly here.
		chain, err := l.store.GetAccountChain(b.Account)
		if err != nil {
			return fmt.Errorf("GetAccountChain (conflict detect): %w", err)
		}
		// Detect — read-only — whether a block already occupies this
		// (account, previous) slot. Recording is deferred until AFTER the
		// incoming block passes staging validation, so a semantically-invalid
		// equivocation can never seed a phantom conflict record and freeze the
		// account (a remotely-triggerable wedge on the public-keyed minter — #519).
		siblingHash := detectConflictSibling(chain, b)
		if siblingHash == "" {
			// Not a conflict, but check if this account has any unresolved
			// conflicts. Accepting new blocks while a conflict is pending would
			// create orphaned children when the loser block is swapped out
			// during resolution. (Falls through to the type switch below.)
			conflicts, cerr := cs.GetConflictsForAccount(b.Account)
			if cerr == nil && len(conflicts) > 0 {
				return fmt.Errorf("account has unresolved conflict — block rejected pending resolution")
			}
		} else {
			// If the sibling at this slot is already finalized, the incoming block
			// can never win — a finalized prefix is immutable. Staging a conflict
			// against it would create an unresolvable record that wedges the account
			// forever, so reject the block outright instead (#555).
			if l.IsFinalized(b.Account, siblingHash) {
				return fmt.Errorf("block conflicts with finalized block %s — rejected", shortHash(siblingHash))
			}
			// Validate asset and block semantics BEFORE recording the conflict.
			if b.Asset == "" {
				return fmt.Errorf("conflict block must have an asset")
			}
			if !IsValidAsset(b.Asset) {
				return fmt.Errorf("conflict block: unsupported asset: %q", b.Asset)
			}
			// Compute parent balance: the asset balance at the Previous block.
			// For open blocks (previous=0), parent balance is 0.
			var parentBalance uint64
			if chain != nil && b.Previous != "0" {
				for _, cb := range chain.Blocks {
					if cb.Asset == b.Asset {
						parentBalance = cb.Balance
					}
					if cb.Hash == b.Previous {
						break
					}
				}
			}
			if err := l.ValidateStagedBlock(b, parentBalance); err != nil {
				return fmt.Errorf("conflict block: %w", err)
			}

			// Validated — now it is safe to record the equivocation.
			isNew, rerr := recordConflict(cs, b.Account, b.Previous, siblingHash, b.Hash)
			if rerr != nil {
				return fmt.Errorf("recordConflict: %w", rerr)
			}

			// Only save to staging if this hash was actually added to the
			// conflict record (not if it was capped or duplicate).
			record, _ := cs.GetConflict(b.Account, b.Previous)
			bodyNewlyStaged := false
			if record != nil && containsConflictHash(record.BlockHashes, b.Hash) {
				if prev, _ := cs.GetStagedBlock(b.Hash); prev == nil {
					bodyNewlyStaged = true
				}
				if err := cs.SaveStagedBlock(b); err != nil {
					return fmt.Errorf("SaveStagedBlock: %w", err)
				}
			}
			if isNew {
				// Retrieve the full conflict record to pass to the callback.
				// Fire asynchronously to avoid holding the account lock during
				// the heavy I/O chain (vote store, quorum checks, etc.).
				record, err := cs.GetConflict(b.Account, b.Previous)
				if err == nil && record != nil {
					// Snapshot all rep weights at conflict detection time to
					// prevent weight manipulation between detection and voting.
					record.WeightSnapshot = l.snapshotWeights()
					var total uint64
					for _, w := range record.WeightSnapshot {
						total += w
					}
					record.TotalWeight = total
					if err := cs.SaveConflict(record); err != nil {
						return fmt.Errorf("SaveConflict (weight snapshot): %w", err)
					}
					l.conflictMu.Lock()
					cb := l.conflictCallback
					l.conflictMu.Unlock()
					if cb != nil {
						rec := *record
						go cb(rec)
					}
				}
			} else if bodyNewlyStaged {
				// A sibling body arrived for an ALREADY-known conflict — a
				// later equivocation, or a phantom body filled in by a #540
				// pull. Re-drive voting for the position now instead of
				// idling until the next 15s sweep; the new body can change
				// the deterministic preference and is often the missing
				// piece for convergence. Duplicates never get here (the body
				// was already staged), so gossip re-deliveries cannot storm
				// the callback. (#645)
				l.conflictMu.Lock()
				cb := l.conflictCallback
				l.conflictMu.Unlock()
				if cb != nil && record != nil {
					rec := *record
					go cb(rec)
				}
			}
			return nil
		}
	}

	// Validate asset allowlist.
	if b.Asset == "" {
		return fmt.Errorf("block must have an asset")
	}
	if !IsValidAsset(b.Asset) {
		return fmt.Errorf("unsupported asset: %q", b.Asset)
	}

	addErr := l.dispatchValidateAndAdd(b, skipTimestamp)
	if addErr == errUnknownBlockType {
		return fmt.Errorf("unknown block type: %s", b.Type)
	}
	if addErr == nil {
		// Per-block finalization trigger (#526): drive an election for this newly
		// accepted uncontested block. Fired async so it never runs under the
		// account lock (mirrors the conflict callback).
		l.fireBlockAdded(b)
	}
	return addErr
}

// errUnknownBlockType is returned by dispatchValidateAndAdd for an unrecognized
// block type — the one case the caller must propagate before the finalization
// trigger (the old inline switch returned early on default).
var errUnknownBlockType = errors.New("unknown block type")

// dispatchValidateAndAdd runs the type-specific validate-and-commit for b
// assuming the account lock is held and conflict detection has already run. It
// is the single source of truth for the live add path AND the conflict-winner
// promotion (#570/C1): a promoted winner is re-applied here so it gets the
// exact same full validation and side-effect commit as a normal block.
func (l *Ledger) dispatchValidateAndAdd(b *Block, skipTimestamp bool) error {
	// #829: re-verify the credential here as well as in addBlock. This function
	// is also the entry point for the #622 conflict-winner promotion, which
	// re-applies a block that arrived through staging — so anchoring the check on
	// the shared dispatch keeps "every accepted block had its signature verified
	// against the account's resolved credential" true by construction rather than
	// by tracing which caller happened to check first. An ed25519 verify is
	// microseconds against a ~1s proof-of-work per block; safety outranks it.
	if err := l.verifyBlockCredential(b); err != nil {
		return err
	}
	switch b.Type {
	case BlockSend:
		return l.validateAndAddSend(b)
	case BlockReceive:
		return l.validateAndAddReceive(b)
	case BlockGenesis:
		return l.validateAndAddGenesis(b)
	case BlockLease:
		return l.validateAndAddLease(b)
	case BlockLeaseAccept:
		return l.validateAndAddLeaseAccept(b, skipTimestamp)
	case BlockLeaseSettle:
		return l.validateAndAddLeaseSettle(b, skipTimestamp)
	case BlockLeaseCancel:
		return l.validateAndAddLeaseCancel(b)
	case BlockLeaseForceSettle:
		return l.validateAndAddLeaseForceSettle(b, skipTimestamp)
	case BlockMultisigOpen:
		return l.validateAndAddMultisigOpen(b)
	case BlockMultisigUpdate:
		return l.validateAndAddMultisigUpdate(b)
	case BlockBurn:
		return l.validateAndAddBurn(b)
	case BlockMint:
		return l.validateAndAddMint(b)
	default:
		// Ship-dark gate (#830). A type this binary knows but the chain has
		// not activated is refused RETRYABLY; a type it does not know at all
		// falls through to exactly the pre-#830 rejection. See
		// core/activations.go for why the registry is empty at Genesis(1).
		if dv, gated := darkValidators[b.Type]; gated {
			if !l.FeatureActive(dv.feature) {
				return errFeatureNotActivatedFor(b.Type, dv.feature)
			}
			return dv.validate(l, b, skipTimestamp)
		}
		return errUnknownBlockType
	}
}

// fireBlockAdded invokes the block-added callback (async) after a non-conflicting
// block is successfully committed, driving per-block finalization voting. (#526)
func (l *Ledger) fireBlockAdded(b *Block) {
	l.conflictMu.Lock()
	cb := l.blockAddedCallback
	l.conflictMu.Unlock()
	if cb != nil {
		bc := *b
		go cb(&bc)
	}
}

func (l *Ledger) validateAndAddSend(b *Block) error {
	chain, err := l.getAccountChainOverlay(b.Account)
	if err != nil {
		return fmt.Errorf("GetAccountChain: %w", err)
	}
	if chain == nil {
		return fmt.Errorf("send from unopened account: %s", shortAddr(b.Account))
	}
	// Previous must match frontier.
	if b.Previous != chain.Frontier() {
		return fmt.Errorf("previous mismatch: got %s, want %s", shortHash(b.Previous), shortHash(chain.Frontier()))
	}
	// Timestamps must be monotonically non-decreasing within a chain.
	if len(chain.Blocks) > 0 {
		lastTs := chain.Blocks[len(chain.Blocks)-1].Timestamp
		if b.Timestamp < lastTs {
			return fmt.Errorf("block timestamp %d is before previous block timestamp %d", b.Timestamp, lastTs)
		}
	}
	// Check balance: old asset balance minus amount must equal new balance.
	oldBal := l.getAssetBalanceOverlay(b.Account, b.Asset)
	if b.Amount == 0 {
		return fmt.Errorf("send amount must be > 0")
	}
	if b.Amount > oldBal {
		return fmt.Errorf("insufficient balance: have %d, sending %d", oldBal, b.Amount)
	}
	if b.Balance != oldBal-b.Amount {
		return fmt.Errorf("balance mismatch: expected %d, got %d", oldBal-b.Amount, b.Balance)
	}
	if b.Destination == "" {
		return fmt.Errorf("send must have a destination")
	}
	if b.Destination == b.Account {
		return fmt.Errorf("cannot send to self")
	}
	if err := ValidateMemo(b.Memo); err != nil {
		return fmt.Errorf("send: %w", err)
	}

	commit, prevBalance, err := l.prepareBlockWrite(b)
	if err != nil {
		return err
	}
	commit.AddPending = &PendingSend{
		SendHash:    b.Hash,
		Source:      b.Account,
		Destination: b.Destination,
		Amount:      b.Amount,
		Asset:       b.Asset,
	}
	return l.commitBlockWrite(commit, prevBalance)
}

// validateAndAddBurn validates a burn block and applies it to the ledger.
// Burn permanently destroys XE from the issuing account's balance — there is
// no destination, no pending entry, no counterpart. XE-only by design;
// burning XUSD is not supported.
func (l *Ledger) validateAndAddBurn(b *Block) error {
	if b.Asset != "XE" {
		return fmt.Errorf("burn: restricted to XE")
	}
	if b.Destination != "" || b.Source != "" {
		return fmt.Errorf("burn: must not have source or destination")
	}
	if b.Amount == 0 {
		return fmt.Errorf("burn: amount must be > 0")
	}

	chain, err := l.getAccountChainOverlay(b.Account)
	if err != nil {
		return fmt.Errorf("GetAccountChain: %w", err)
	}
	if chain == nil {
		return fmt.Errorf("burn from unopened account: %s", shortAddr(b.Account))
	}
	if b.Previous != chain.Frontier() {
		return fmt.Errorf("previous mismatch: got %s, want %s", shortHash(b.Previous), shortHash(chain.Frontier()))
	}
	if len(chain.Blocks) > 0 {
		lastTs := chain.Blocks[len(chain.Blocks)-1].Timestamp
		if b.Timestamp < lastTs {
			return fmt.Errorf("block timestamp %d is before previous block timestamp %d", b.Timestamp, lastTs)
		}
	}

	oldBal := l.getAssetBalanceOverlay(b.Account, b.Asset)
	if b.Amount > oldBal {
		return fmt.Errorf("insufficient balance: have %d XE, burning %d", oldBal, b.Amount)
	}
	if b.Balance != oldBal-b.Amount {
		return fmt.Errorf("balance mismatch: expected %d, got %d", oldBal-b.Amount, b.Balance)
	}
	if err := ValidateMemo(b.Memo); err != nil {
		return fmt.Errorf("burn: %w", err)
	}

	commit, prevBalance, err := l.prepareBlockWrite(b)
	if err != nil {
		return err
	}
	return l.commitBlockWrite(commit, prevBalance)
}

// isLiveLeaseEscrow reports whether sendHash is the consumer's escrow PendingSend
// for a lease that has not yet settled or been cancelled (state created/accepted).
// Such a pending send is addressed to the provider but is held for the lease, not
// spendable: it is burned at settle or refunded at cancel via the dedicated lease
// block types. A plain receive of it must be rejected (#486) — otherwise the
// provider could drain `cost` and still settle for XE + stake (a double-dip).
//
// If you add a lease state, update BOTH this and LeaseState.Terminal()
// (types.go) — over the valid states they are exact complements, verified by
// TestLeaseStatePartition (#763). Do NOT rewrite this as !State.Terminal():
// getLeaseOverlay returns records raw (no BackfillState), so legacy State==""
// records would flip from not-live to live — a consensus change on a no-wipe
// network. Unification waits for a wipe.
func (l *Ledger) isLiveLeaseEscrow(sendHash string) bool {
	// Overlay-aware (#622): during a promotion that unwound a loser lease's
	// side effects, the lease record may be restored/deleted only in the overlay.
	lease, ok, err := l.getLeaseOverlay(sendHash)
	if !ok || err != nil || lease == nil {
		return false
	}
	return lease.State == LeaseCreated || lease.State == LeaseAccepted
}

func (l *Ledger) validateAndAddReceive(b *Block) error {
	if b.Source == "" {
		return fmt.Errorf("receive must reference a source send")
	}
	// Source must be a pending send addressed to this account.
	pending, err := l.getPendingSendOverlay(b.Source)
	if err != nil {
		return fmt.Errorf("GetPendingSend: %w", err)
	}
	if pending == nil {
		return fmt.Errorf("source send not pending: %s", shortHash(b.Source))
	}
	if pending.Destination != b.Account {
		return fmt.Errorf("send not addressed to this account")
	}
	// #486: a live lease escrow is addressed to the provider but must never be
	// drained by a plain receive — it is settled/cancelled via lease blocks.
	if l.isLiveLeaseEscrow(b.Source) {
		return fmt.Errorf("cannot receive a live lease escrow: %s", shortHash(b.Source))
	}

	// #687 spend-before-final (uncontested-source) gate: do not let a send's
	// pending be RECEIVED while that send is CONTESTED. An equivocating sender
	// can double-sign two valid sends of the same funds at one (account,
	// previous) position to different recipients; each side creates a pending.
	// Under a partition different nodes land different siblings, so both
	// recipients could receive independently — and if both finalize, the same
	// amount is credited twice (a realized double-spend). Defer the receive
	// while an unresolved conflict covers the source send's position: a
	// retryable error so it lands later once exactly ONE sibling wins. The
	// loser's pending is removed by the resolution cascade, so only the winning
	// send's recipient can ever receive → credited at most once. This gates only
	// on an OPEN conflict at the source's position, NOT on full finality, so
	// uncontested transfers are unaffected. Read the live store directly (never
	// the cascade overlay) — conflict records are not overlaid.
	if src := l.GetBlockOrStaged(b.Source); src != nil {
		if l.GetConflict(src.Account, src.Previous) != nil {
			return fmt.Errorf("source send %s is contested by an unresolved conflict — receive deferred pending resolution", shortHash(b.Source))
		}
	}

	// Receive block asset must match the pending send's asset.
	pendingAsset := pending.Asset
	if pendingAsset == "" {
		pendingAsset = "XE" // legacy pending sends without asset
	}
	if b.Asset != pendingAsset {
		return fmt.Errorf("receive asset %q does not match pending send asset %q", b.Asset, pendingAsset)
	}

	chain, err := l.getAccountChainOverlay(b.Account)
	if err != nil {
		return fmt.Errorf("GetAccountChain: %w", err)
	}
	if chain == nil {
		// First block on this account — this is a receive-open.
		if b.Previous != "0" {
			return fmt.Errorf("first block on account must have previous=0")
		}
	} else {
		// Timestamps must be monotonically non-decreasing within a chain.
		if len(chain.Blocks) > 0 {
			lastTs := chain.Blocks[len(chain.Blocks)-1].Timestamp
			if b.Timestamp < lastTs {
				return fmt.Errorf("block timestamp %d is before previous block timestamp %d", b.Timestamp, lastTs)
			}
		}
	}

	oldBal := l.getAssetBalanceOverlay(b.Account, b.Asset)
	if chain == nil {
		if b.Balance != pending.Amount {
			return fmt.Errorf("open-receive balance mismatch: expected %d, got %d", pending.Amount, b.Balance)
		}
	} else {
		if b.Previous != chain.Frontier() {
			return fmt.Errorf("previous mismatch: got %s, want %s", shortHash(b.Previous), shortHash(chain.Frontier()))
		}
		expectedBal := oldBal + pending.Amount
		if expectedBal < oldBal {
			return fmt.Errorf("receive would overflow uint64 balance")
		}
		if b.Balance != expectedBal {
			return fmt.Errorf("receive balance mismatch: expected %d, got %d", expectedBal, b.Balance)
		}
	}

	commit, prevBalance, err := l.prepareBlockWrite(b)
	if err != nil {
		return err
	}
	commit.DeletePendingID = b.Source
	return l.commitBlockWrite(commit, prevBalance)
}

// MintForTesting applies a BlockMint to the ledger, bypassing the sys.minter
// authorization check so test fixtures can seed XUSD without configuring a
// minter. It mirrors validateAndAddMint MINUS the isMinter check (exactly as
// the removed claim fixture bypassed the once-per-account check). Test-only —
// do NOT call from production code paths; real mints go through AddBlock.
func (l *Ledger) MintForTesting(b *Block) error {
	if b.Asset != "XUSD" {
		return fmt.Errorf("mint: restricted to XUSD")
	}
	return l.seedForTesting(b)
}

// SeedAssetForTesting is the asset-agnostic sibling of MintForTesting. The mint
// primitive itself is XUSD-only by protocol (XE supply is fixed at genesis plus
// lease emission), but fixtures still need to seed XE balances cheaply without a
// genesis send. This applies a BlockMint of ANY supported asset directly, so it
// is strictly test-only. Do NOT call from production code paths.
func (l *Ledger) SeedAssetForTesting(b *Block) error {
	if !IsValidAsset(b.Asset) {
		return fmt.Errorf("mint: unsupported asset: %q", b.Asset)
	}
	return l.seedForTesting(b)
}

func (l *Ledger) seedForTesting(b *Block) error {
	if b.Type != BlockMint {
		return fmt.Errorf("mint: block type must be mint")
	}
	if b.Amount == 0 {
		return fmt.Errorf("mint: amount must be > 0")
	}

	if err := VerifyBlock(b); err != nil {
		return fmt.Errorf("mint verify: %w", err)
	}
	// #829: VerifyBlock only checks a NON-open block's signature when the ledger
	// can resolve the account's credential, which it cannot do standalone. This
	// seed path bypasses addBlock, so it must resolve the credential itself or a
	// seeded block would be committed with its signature unchecked.
	if err := l.verifyBlockCredential(b); err != nil {
		return fmt.Errorf("mint verify: %w", err)
	}
	if l.difficulty > 0 {
		hashBytes, err := hex.DecodeString(b.Hash)
		if err != nil {
			return fmt.Errorf("decode hash: %w", err)
		}
		if !ValidatePoW(hashBytes, b.PoWNonce, l.difficulty) {
			return ErrInvalidPoW
		}
	}

	entry := l.acquireAccountLock(b.Account)
	defer l.releaseAccountLock(b.Account, entry)

	// Idempotent: if this exact block (by hash) is already stored, treat the
	// re-application as a no-op. Mirrors addBlock's duplicate handling.
	existing, err := l.store.GetBlock(b.Hash)
	if err != nil {
		return fmt.Errorf("GetBlock: %w", err)
	}
	if existing != nil {
		return nil
	}

	chain, err := l.getAccountChainOverlay(b.Account)
	if err != nil {
		return fmt.Errorf("GetAccountChain: %w", err)
	}

	if chain == nil {
		if b.Previous != "0" {
			return fmt.Errorf("mint: first block must have previous=0")
		}
		if b.Balance != b.Amount {
			return fmt.Errorf("mint: balance mismatch: expected %d, got %d", b.Amount, b.Balance)
		}
	} else {
		if b.Previous != chain.Frontier() {
			return fmt.Errorf("mint: previous mismatch: got %s, want %s", shortHash(b.Previous), shortHash(chain.Frontier()))
		}
		if len(chain.Blocks) > 0 {
			lastTs := chain.Blocks[len(chain.Blocks)-1].Timestamp
			if b.Timestamp < lastTs {
				return fmt.Errorf("mint: timestamp before previous block")
			}
		}
		oldBal := l.getAssetBalanceOverlay(b.Account, b.Asset)
		if b.Balance != oldBal+b.Amount {
			return fmt.Errorf("mint: balance must be previous + %d", b.Amount)
		}
	}

	return l.addBlockLocked(b)
}

func (l *Ledger) validateAndAddGenesis(b *Block) error {
	// Genesis block must be the very first block on the ledger.
	empty, err := l.store.IsEmpty()
	if err != nil {
		return fmt.Errorf("IsEmpty: %w", err)
	}
	if !empty {
		return fmt.Errorf("genesis block rejected: ledger is not empty")
	}

	// Must match the embedded genesis block exactly.
	expected, err := LoadGenesisBlock()
	if err != nil {
		return fmt.Errorf("load embedded genesis: %w", err)
	}
	if b.Hash != expected.Hash {
		return fmt.Errorf("genesis hash mismatch: got %s, want %s", shortHash(b.Hash), shortHash(expected.Hash))
	}

	// Validate structure.
	if err := ValidateGenesisBlock(b); err != nil {
		return err
	}

	return l.addBlockLocked(b)
}

func (l *Ledger) validateAndAddMultisigOpen(b *Block) error {
	if b.MSKeyset == nil {
		return fmt.Errorf("multisig_open must include a keyset")
	}
	if err := ValidateKeyset(b.MSKeyset); err != nil {
		return fmt.Errorf("multisig_open keyset: %w", err)
	}

	// Account must be the hash-derived address of the keyset.
	expected, err := DeriveMultisigAddress(b.MSKeyset)
	if err != nil {
		return fmt.Errorf("derive address: %w", err)
	}
	if b.Account != expected {
		return fmt.Errorf("multisig_open account mismatch: got %s, want %s", shortHash(b.Account), shortHash(expected))
	}

	// Account must not already exist.
	chain, err := l.getAccountChainOverlay(b.Account)
	if err != nil {
		return fmt.Errorf("GetAccountChain: %w", err)
	}
	if chain != nil {
		return fmt.Errorf("multisig_open: account already exists")
	}
	if b.Previous != "0" {
		return fmt.Errorf("multisig_open must have previous=0")
	}
	if b.Balance != 0 {
		return fmt.Errorf("multisig_open balance must be 0, got %d", b.Balance)
	}

	commit, prevBalance, err := l.prepareBlockWrite(b)
	if err != nil {
		return err
	}
	commit.PutKeyset = b.MSKeyset
	if err := l.commitBlockWrite(commit, prevBalance); err != nil {
		return err
	}
	l.setKeyset(b.Account, b.MSKeyset)
	return nil
}

func (l *Ledger) validateAndAddMultisigUpdate(b *Block) error {
	if b.MSKeyset == nil {
		return fmt.Errorf("multisig_update must include a keyset")
	}
	if err := ValidateKeyset(b.MSKeyset); err != nil {
		return fmt.Errorf("multisig_update keyset: %w", err)
	}

	// Account must already be multisig.
	oldKs := l.getKeysetOverlay(b.Account)
	if oldKs == nil {
		return fmt.Errorf("multisig_update: account is not multisig")
	}

	chain, err := l.getAccountChainOverlay(b.Account)
	if err != nil {
		return fmt.Errorf("GetAccountChain: %w", err)
	}
	if chain == nil {
		return fmt.Errorf("multisig_update: account not found")
	}
	if b.Previous != chain.Frontier() {
		return fmt.Errorf("previous mismatch: got %s, want %s", shortHash(b.Previous), shortHash(chain.Frontier()))
	}
	if len(chain.Blocks) > 0 {
		lastTs := chain.Blocks[len(chain.Blocks)-1].Timestamp
		if b.Timestamp < lastTs {
			return fmt.Errorf("block timestamp %d is before previous block timestamp %d", b.Timestamp, lastTs)
		}
	}

	// Balance must match current balance (keyset rotation doesn't change balance).
	oldBal := l.getAssetBalanceOverlay(b.Account, b.Asset)
	if b.Balance != oldBal {
		return fmt.Errorf("multisig_update balance mismatch: expected %d, got %d", oldBal, b.Balance)
	}

	commit, prevBalance, err := l.prepareBlockWrite(b)
	if err != nil {
		return err
	}
	commit.PutKeyset = b.MSKeyset
	if err := l.commitBlockWrite(commit, prevBalance); err != nil {
		return err
	}
	l.setKeyset(b.Account, b.MSKeyset)
	return nil
}

// GetKeyset returns the keyset for a multisig account, or nil for single-key accounts.
func (l *Ledger) GetKeyset(account string) *Keyset {
	l.keysetMu.RLock()
	defer l.keysetMu.RUnlock()
	return l.keysets[account]
}

// setKeyset updates the in-memory keyset cache.
func (l *Ledger) setKeyset(account string, ks *Keyset) {
	l.keysetMu.Lock()
	defer l.keysetMu.Unlock()
	cp := *ks
	keys := make([]string, len(ks.Keys))
	copy(keys, ks.Keys)
	cp.Keys = keys
	l.keysets[account] = &cp
}

// GetAccountKey returns the ed25519 public key declared by an account's opening
// block, or "" if the account is unknown (or is a multisig account, which has a
// keyset instead). This is the credential every non-open single-key block on the
// chain is verified against (#829).
func (l *Ledger) GetAccountKey(account string) string {
	l.accountKeyMu.RLock()
	pub, ok := l.accountKeys[account]
	l.accountKeyMu.RUnlock()
	if ok {
		return pub
	}
	// Lazy rebuild from chain data. The declaring block is part of the account's
	// chain, so the chain is the authority and the map is only a cache — reading
	// through on a miss means the registry can never disagree with the chain it
	// is derived from, whatever wrote that chain (a startup before
	// rebuildAccountKeys ran, a store populated out of band, a test harness). In
	// steady state this is dead code: the commit path fills the map.
	chain, err := l.store.GetAccountChain(account)
	if err != nil || chain == nil {
		return ""
	}
	found := ""
	for _, b := range chain.Blocks {
		if b.PubKey != "" {
			found = b.PubKey
		}
	}
	if found == "" {
		return ""
	}
	l.setAccountKey(account, found)
	return found
}

// setAccountKey installs (or REPLACES) an account's credential in the in-memory
// registry. Replacement is deliberate — see AccountKeyStore — so #424 key
// rotation is a follow-up block type, not a storage redesign.
func (l *Ledger) setAccountKey(account, pubKey string) {
	l.accountKeyMu.Lock()
	defer l.accountKeyMu.Unlock()
	l.accountKeys[account] = pubKey
}

// rebuildAccountKeys scans all chains to repopulate the credential registry on
// startup. The declaring block is chain data, so the registry is derivable from
// the chains alone and a rebuild can never disagree with a cold sync.
func (l *Ledger) rebuildAccountKeys() {
	for acc := range l.Frontiers() {
		chain, err := l.store.GetAccountChain(acc)
		if err != nil || chain == nil {
			continue
		}
		for _, b := range chain.Blocks {
			if b.PubKey != "" {
				l.accountKeys[acc] = b.PubKey
			}
		}
	}
}

// verifyBlockCredential verifies a block's signature(s) against the account's
// CREDENTIAL as the ledger knows it — the multisig keyset, or the ed25519 public
// key the account declared on its opening block (#829). Since an address is now
// sha256("xe/account/v1" || pubkey), the account field is not a verifying key
// and this lookup is the only way to check a non-open block's signature.
//
// One function, called from the one validated add path (addBlock before conflict
// detection, dispatchValidateAndAdd for the live apply AND the #622 promotion
// re-apply, ValidateStagedBlock for staging) — invariant C1. It never creates a
// second validation path.
//
// SELF-SUFFICIENT BY CONSTRUCTION. b.PubKey is attacker-controlled input, and
// this function is the only thing between it and a signature check, so it
// re-runs the declaration rules itself instead of assuming a caller already
// did. Relying on call ordering would be a trap: dispatchValidateAndAdd
// documents itself as the single source of truth, and ValidateStagedBlock and
// SwapBlock are exported, so a future caller that skips VerifyBlock would
// otherwise be able to pass a non-open block on a victim's account carrying an
// attacker's pub_key and an attacker's signature, and have it verify.
// ValidatePubKeyDeclaration is a pure O(1) check — at most one derivation, and
// only on an opening block — against a ~1s proof-of-work per block, so the
// duplicate costs nothing worth measuring. Pinned by
// core/credential_bypass_829_test.go, which calls this function directly.
//
// Error classification (#673) is load-bearing, because net/sync.go turns
// "not retryable" into a PERMANENT per-node quarantine of the block hash — the
// block is filtered out of every future sync round, the account chain pins at
// that height, and in a lattice every downstream receive starves with it. The
// rule is: an outcome that depends on WHICH BLOCKS THIS NODE HAS SYNCED is
// retryable; an outcome that is a pure function of the block plus a credential
// this node definitively holds is deterministic. Full audit of every failure
// this function and ValidatePubKeyDeclaration can emit (#846 AC3):
//
//	MESSAGE                                              CLASS      WHY
//	multisig block must not declare pub_key              det.       pure function of the block
//	open block must declare pub_key                      det.       pure function of the block
//	invalid pub_key: ...                                 det.       pure function of the block
//	pub_key does not derive account address: ...         det.       pure function of the block
//	non-open block must not declare pub_key              det.       pure function of the block
//	GetAccountChain (keyset lookup): ...                 RETRY      transient store failure
//	... multisig keyset is not known: unopened account   RETRY      #846: multisig_open not synced yet
//	block has signatures but account is not multisig     det.       chain IS held and is single-key; a
//	                                                                credential class is fixed at open, so
//	                                                                no later block can change this
//	multisig account requires signatures                 det.       keyset IS held; block genuinely has none
//	multisig: threshold not met / invalid signature      det.       arithmetic over a keyset we hold
//	signature: unopened account ... no declared key      RETRY      #630: declaring block not synced yet
//	signature: <ed25519 failure>                         det.       checked against the STORED credential
//
// Both retryable cases are dependency misses, so they are also the only two
// that a peer can trigger repeatedly without ever being quarantined; the DoS
// bound on that is the ~1s proof-of-work each block must already carry
// (addBlock validates PoW before reaching here), the 10000-block per-round sync
// cap, and requestSync's "no progress in a pass => stop retrying" early exit.
// Nothing is queued or persisted, so no park queue can grow.
//
// The credential is read from LIVE state, never through the #622 cascade
// overlay, and that is deliberate on both branches. It keeps the multisig
// lookup byte-for-byte the behaviour it had before #829 (addBlock always read
// l.GetKeyset), which matters because a cascade that later fails leaves the
// pre-promotion state intact — an overlay read could reject a perfectly valid
// block for the duration of a doomed promotion, and "not multisig" is
// non-retryable, so that transient would look like a reason to quarantine a
// peer. Consulting the overlay could not change an outcome anyway: the overlay
// only ever RETRACTS a credential whose declaring block is being unwound, and a
// declaring block is by definition the chain's opening block, so the winner
// re-applied at that position is itself an opening block — it carries its own
// keyset (multisig_open) or its own pub_key, and never consults the registry.
func (l *Ledger) verifyBlockCredential(b *Block) error {
	if err := ValidatePubKeyDeclaration(b); err != nil {
		return err
	}

	if len(b.Signatures) > 0 {
		var ks *Keyset
		if b.Type == BlockMultisigOpen {
			ks = b.MSKeyset
		} else {
			ks = l.GetKeyset(b.Account)
		}
		if ks == nil {
			ks2, err := l.resolveMissingKeyset(b.Account)
			if err != nil {
				return err
			}
			ks = ks2
		}
		if IsSpendingOp(b.Type) {
			if err := VerifyMultisig(b.Hash, b.Signatures, ks); err != nil {
				return fmt.Errorf("multisig: %w", err)
			}
			return nil
		}
		if err := VerifyMultisigAny(b.Hash, b.Signatures, ks); err != nil {
			return fmt.Errorf("multisig: %w", err)
		}
		return nil
	}

	if l.GetKeyset(b.Account) != nil {
		// Account is multisig but block has no signatures — reject.
		return fmt.Errorf("multisig account requires signatures")
	}

	// ONLY an opening block may supply its own key, and the declaration check
	// above has already proven that key derives b.Account. Every later block is
	// verified against the STORED credential — never against anything it
	// carries. The branch is explicit rather than an `if pubKey == ""` fallback
	// so that this rule is impossible to misread at a glance.
	var pubKey string
	if b.Previous == "0" {
		pubKey = b.PubKey
	} else {
		pubKey = l.GetAccountKey(b.Account)
		if pubKey == "" {
			return fmt.Errorf("signature: unopened account %s has no declared public key", shortAddr(b.Account))
		}
	}
	if err := VerifyBlockSignatureWith(b, pubKey); err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	return nil
}

// resolveMissingKeyset is the cold path taken when a block carries multisig
// Signatures but the in-memory keyset cache has nothing for its account. It
// exists to separate two situations the old single error message conflated —
// and getting that separation wrong is #846, a permanent quarantine of a
// perfectly valid block.
//
//   - The node holds NO chain for the account. The multisig_open that declares
//     the keyset simply has not synced yet, which is ordinary out-of-order
//     sync: the peer served a later block first, or the open landed on a later
//     page. This is a DEPENDENCY MISS. It returns an "unopened account" error,
//     which core.IsRetryableError already classifies as retryable (#630), so
//     net/sync.go parks the block for a later round instead of quarantining it.
//     Getting this wrong pins the account chain forever and, in a lattice,
//     starves every downstream receive with it — and the Genesis(1) Edge->XE
//     bridge is a 3-of-5 multisig whose sends fund every claim.
//
//   - The node HOLDS a chain for the account and that chain declares no keyset.
//     Then the account is definitively single-key and always will be:
//     validateAndAddMultisigOpen requires Previous=="0" AND a non-existent
//     chain, so an account's credential CLASS is fixed at open and a single-key
//     chain can never become multisig. Nothing a later block delivers can make
//     these signatures valid, so this is DETERMINISTIC — identical on every
//     node that holds the chain — and safe to quarantine (invariant C7, #673).
//     Keeping it deterministic also matters for DoS: a forged Signatures array
//     stapled to a victim's known single-key address is rejected once and
//     quarantined, not re-driven every round.
//
// The chain scan doubles as a cache repair, mirroring the read-through
// GetAccountKey already performs, so the registry can never disagree with the
// chain it is derived from (a store populated out of band, a restore, a test
// harness). It is deliberately NOT folded into GetKeyset: GetKeyset is called
// once per single-key block on the hot path, where a miss is the normal case,
// and a read-through there would add a store read to every block. Here the miss
// is the rare case, already gated behind a ~1s proof-of-work.
//
// Reads LIVE store state, never the #622 cascade overlay — same reasoning as
// verifyBlockCredential's doc comment: an overlay read could transiently
// retract a credential during a doomed promotion.
func (l *Ledger) resolveMissingKeyset(account string) (*Keyset, error) {
	chain, err := l.store.GetAccountChain(account)
	if err != nil {
		// Transient store failure — "GetAccountChain" is on the retryable
		// allowlist, so this never quarantines.
		return nil, fmt.Errorf("GetAccountChain (keyset lookup): %w", err)
	}
	if chain == nil {
		return nil, fmt.Errorf("block has signatures but multisig keyset is not known: unopened account %s (multisig_open not yet synced)", shortAddr(account))
	}
	var found *Keyset
	for _, cb := range chain.Blocks {
		if (cb.Type == BlockMultisigOpen || cb.Type == BlockMultisigUpdate) && cb.MSKeyset != nil {
			found = cb.MSKeyset
		}
	}
	if found == nil {
		return nil, fmt.Errorf("block has signatures but account is not multisig")
	}
	l.setKeyset(account, found)
	return found, nil
}

// rebuildKeysets scans all chains to populate the keysets map on startup.
func (l *Ledger) rebuildKeysets() {
	frontiers := l.Frontiers()
	for acc := range frontiers {
		chain, err := l.store.GetAccountChain(acc)
		if err != nil || chain == nil {
			continue
		}
		for _, b := range chain.Blocks {
			if b.Type == BlockMultisigOpen || b.Type == BlockMultisigUpdate {
				if b.MSKeyset != nil {
					l.keysets[acc] = b.MSKeyset
				}
			}
		}
	}
}

func (l *Ledger) validateAndAddLease(b *Block) error {
	if b.Asset != "XUSD" {
		return fmt.Errorf("lease block must have asset=XUSD")
	}
	if b.Destination == "" {
		return fmt.Errorf("lease block must have a destination (provider)")
	}
	if b.Destination == b.Account {
		return fmt.Errorf("cannot lease to self")
	}
	if err := ValidateLeaseDimensions(b.VCPUs, b.MemoryMB, b.DiskGB, b.Duration); err != nil {
		return err
	}
	if b.AccessPubKey != "" {
		sshBytes, err := hex.DecodeString(b.AccessPubKey)
		if err != nil {
			return fmt.Errorf("invalid access_pub_key hex: %w", err)
		}
		if len(sshBytes) != 32 {
			return fmt.Errorf("access_pub_key must be 32 bytes, got %d", len(sshBytes))
		}
	}
	// Lease blocks must reference the provider's active performance
	// certificate, which locks in the price multiplier at offer time (#297).
	if b.CertificateHash == "" {
		return fmt.Errorf("lease block must include certificate_hash")
	}
	if l.certificateLookupFn == nil {
		return fmt.Errorf("lease block cannot be validated: certificate lookup not configured")
	}
	cert := l.certificateLookupFn(b.CertificateHash)
	if cert == nil {
		return fmt.Errorf("certificate %s not found", shortHash(b.CertificateHash))
	}
	if cert.Provider != b.Destination {
		return fmt.Errorf("certificate %s belongs to %s, not lease destination %s",
			shortHash(b.CertificateHash), shortHash(cert.Provider), shortHash(b.Destination))
	}
	if cert.ExpiresAt != 0 && b.Timestamp > cert.ExpiresAt {
		return fmt.Errorf("certificate %s expired at %d, lease timestamp %d",
			shortHash(b.CertificateHash), cert.ExpiresAt, b.Timestamp)
	}
	expectedCost, err := LeaseCost(b.VCPUs, b.MemoryMB, b.DiskGB, b.Duration, cert.PriceMultiplierMilli)
	if err != nil {
		return fmt.Errorf("lease cost %w", err)
	}
	if b.Amount != expectedCost {
		return fmt.Errorf("lease cost mismatch: expected %d (multiplier %d), got %d", expectedCost, cert.PriceMultiplierMilli, b.Amount)
	}

	chain, err := l.getAccountChainOverlay(b.Account)
	if err != nil {
		return fmt.Errorf("GetAccountChain: %w", err)
	}
	if chain == nil {
		return fmt.Errorf("lease from unopened account")
	}
	if b.Previous != chain.Frontier() {
		return fmt.Errorf("previous mismatch: got %s, want %s", shortHash(b.Previous), shortHash(chain.Frontier()))
	}
	if len(chain.Blocks) > 0 {
		lastTs := chain.Blocks[len(chain.Blocks)-1].Timestamp
		if b.Timestamp < lastTs {
			return fmt.Errorf("block timestamp %d is before previous block timestamp %d", b.Timestamp, lastTs)
		}
	}

	oldBal := l.getAssetBalanceOverlay(b.Account, "XUSD")
	if b.Amount > oldBal {
		return fmt.Errorf("insufficient XUSD balance: have %d, need %d", oldBal, b.Amount)
	}
	if b.Balance != oldBal-b.Amount {
		return fmt.Errorf("balance mismatch: expected %d, got %d", oldBal-b.Amount, b.Balance)
	}

	commit, prevBalance, err := l.prepareBlockWrite(b)
	if err != nil {
		return err
	}
	commit.AddPending = &PendingSend{
		SendHash:    b.Hash,
		Source:      b.Account,
		Destination: b.Destination,
		Amount:      b.Amount,
		Asset:       "XUSD",
	}
	commit.PutLease = &Lease{
		LeaseHash:       b.Hash,
		State:           LeaseCreated,
		Consumer:        b.Account,
		Provider:        b.Destination,
		VCPUs:           b.VCPUs,
		MemoryMB:        b.MemoryMB,
		DiskGB:          b.DiskGB,
		Duration:        b.Duration,
		AccessPubKey:    b.AccessPubKey,
		Cost:            b.Amount,
		CertificateHash: b.CertificateHash,
	}
	return l.commitBlockWrite(commit, prevBalance)
}

func (l *Ledger) validateAndAddLeaseAccept(b *Block, skipSkew bool) error {
	if b.Asset != "XUSD" {
		return fmt.Errorf("lease_accept block must have asset=XUSD")
	}
	if b.Source == "" {
		return fmt.Errorf("lease_accept must reference a source lease block")
	}

	// Source must be a valid lease block.
	leaseBlock, err := l.store.GetBlock(b.Source)
	if err != nil {
		return fmt.Errorf("GetBlock: %w", err)
	}
	if leaseBlock == nil {
		return fmt.Errorf("source lease block not found: %s", shortHash(b.Source))
	}
	if leaseBlock.Type != BlockLease {
		return fmt.Errorf("source block is not a lease block")
	}
	if leaseBlock.Destination != b.Account {
		return fmt.Errorf("lease_accept: provider account mismatch")
	}

	// Check lease hasn't already been accepted.
	if existing, ok, err := l.getLeaseOverlay(b.Source); ok {
		if err != nil {
			return fmt.Errorf("GetLease: %w", err)
		}
		if existing != nil && existing.State != LeaseCreated {
			return fmt.Errorf("lease already accepted")
		}
	}

	// Stake = ⌈cost / 5⌉ (min 1).
	expectedStake := LeaseStake(leaseBlock.Amount)
	if b.Amount != expectedStake {
		return fmt.Errorf("lease_accept stake mismatch: expected %d, got %d", expectedStake, b.Amount)
	}

	chain, err := l.getAccountChainOverlay(b.Account)
	if err != nil {
		return fmt.Errorf("GetAccountChain: %w", err)
	}
	if chain == nil {
		return fmt.Errorf("lease_accept from unopened account")
	}
	if b.Previous != chain.Frontier() {
		return fmt.Errorf("previous mismatch: got %s, want %s", shortHash(b.Previous), shortHash(chain.Frontier()))
	}
	if len(chain.Blocks) > 0 {
		lastTs := chain.Blocks[len(chain.Blocks)-1].Timestamp
		if b.Timestamp < lastTs {
			return fmt.Errorf("block timestamp %d is before previous block timestamp %d", b.Timestamp, lastTs)
		}
	}

	oldBal := l.getAssetBalanceOverlay(b.Account, "XUSD")
	if b.Amount > oldBal {
		return fmt.Errorf("insufficient XUSD balance for stake: have %d, need %d", oldBal, b.Amount)
	}
	if b.Balance != oldBal-b.Amount {
		return fmt.Errorf("balance mismatch: expected %d, got %d", oldBal-b.Amount, b.Balance)
	}

	// Validate timekeeper attestations for lease_accept. Attestations are
	// mandatory — self-reported timestamps are not accepted.
	if l.timekeeperConfigFn == nil {
		return fmt.Errorf("lease_accept: timekeepers not configured")
	}
	tkConfig := l.timekeeperConfigFn()
	if tkConfig == nil {
		return fmt.Errorf("lease_accept: timekeepers not configured")
	}
	startTime, err := ValidateAttestations(b.Attestations, b.Source, tkConfig, skipSkew)
	if err != nil {
		return fmt.Errorf("lease_accept attestation: %w", err)
	}

	// Validate performance certificate. Provider must accept using the same
	// certificate the consumer referenced on the lease block — this is the
	// rate-lock guarantee (#297).
	if b.CertificateHash == "" {
		return fmt.Errorf("lease_accept: performance certificate required")
	}
	if leaseBlock.CertificateHash != b.CertificateHash {
		return fmt.Errorf("lease_accept: certificate hash %s does not match lease's referenced cert %s",
			shortHash(b.CertificateHash), shortHash(leaseBlock.CertificateHash))
	}
	if l.certificateLookupFn == nil {
		return fmt.Errorf("lease_accept: certificate lookup not configured")
	}
	certInfo := l.certificateLookupFn(b.CertificateHash)
	if certInfo == nil {
		return fmt.Errorf("lease_accept: certificate not found: %s", b.CertificateHash[:12])
	}
	if certInfo.Provider != b.Account {
		return fmt.Errorf("lease_accept: certificate belongs to different provider")
	}
	if startTime > certInfo.ExpiresAt {
		return fmt.Errorf("lease_accept: certificate expired")
	}

	commit, prevBalance, err := l.prepareBlockWrite(b)
	if err != nil {
		return err
	}

	// #486: the consumer's XUSD escrow (a PendingSend addressed to the provider)
	// stays alive through the accepted lease. It is burned at settle or refunded
	// at cancel — NOT drained here. A receive of it is blocked by isLiveLeaseEscrow.

	// Lock the emission parameters so settle is deterministic from the lease's
	// own properties, independent of any epoch transitions during the lease's
	// lifetime (#401: provider gets rate certainty when committing stake).
	//
	// #501: the locked params come from the SIGNED accept block, NOT this node's
	// live CurrentR(). Reading live epoch state here was non-deterministic — a
	// node applying the accept in a later epoch (sync lag) locked a different R,
	// then rejected the canonical settle as an un-healable "XE mismatch" gap.
	// The block-carried values are byte-identical on every node (canonical bytes
	// + provider signature), so all nodes record the same settle inputs.
	// #514: the locked emission params MUST be carried in the signed accept
	// block. The old LockedR==0 fallback to live CurrentR() was non-deterministic
	// across nodes — a node applying the accept in a later epoch fell back to a
	// different R and then rejected the canonical settle as an un-healable
	// "XE mismatch" (the exact #501 wedge mechanism). There are no legacy
	// pre-#401 leases — pre-1.0, protocol-breaking changes wipe and
	// re-bootstrap the testnet rather than migrate — so a missing LockedR has
	// nothing legitimate to serve:
	// reject it outright so settle is a pure function of the signed block.
	lockedR, lockedCap, lockedTWAP := b.LockedR, b.LockedPayoutCap, b.LockedTWAP
	if lockedR == 0 {
		return fmt.Errorf("lease_accept missing locked emission params: locked_r must be set (the accept must carry locked_r/locked_payout_cap/locked_twap)")
	}
	if l.epochAtFn != nil {
		// The provider must have locked the canonical epoch-at-accept rate,
		// looked up from the converged statechain at the attested accept time.
		// #601: this runs on BOTH the live and sync paths — it is value
		// validation, not clock-skew validation, so it must not sit under the
		// skipSkew gate. The old gate let a provider self-insert an accept with
		// arbitrary LockedR into its own chain and serve it via sync; every
		// honest node admitted it unverified (the #570/M1 attack through the
		// side door). epochAt(startTime) is identical on every node, so
		// admit/reject is uniform — no divergence.
		candidates := l.epochAtFn(startTime)
		if len(candidates) == 0 {
			// #570/M1: no epoch covers the accept time on this node (pre-first-
			// epoch, or this node is lagging on statechain sync). Do NOT admit
			// the provider-supplied locked R unverified — a node that does have
			// the epoch would verify (and possibly reject) it, so the settle
			// emission inputs would diverge across nodes (#501-class). Defer with
			// a retryable error (see isRetryableError) so the accept is
			// re-evaluated once the epoch history syncs, instead of being
			// admitted unverified or terminally quarantined.
			return fmt.Errorf("lease_accept epoch not yet available for accept time %d: retry after statechain syncs", startTime)
		}
		matched := false
		for i := range candidates {
			e := &candidates[i]
			if lockedR == e.R && lockedCap == e.PayoutCap && lockedTWAP == e.TWAP {
				matched = true
				break
			}
		}
		// Accept the covering epoch or any predecessor within the publish-lag
		// window: an accept admitted before later epochs were published
		// legitimately locked the then-latest epoch's params (#574 boundary
		// race; deterministic for cold-sync re-validation #630). Forged
		// params match none of them.
		if !matched {
			cur := candidates[0]
			if skipSkew {
				// Sync path: a mismatch may mean OUR epoch history is behind the
				// accept's epoch (cold sync: ledger blocks can arrive before the
				// statechain catches up), not that the value is forged. Retryable
				// — the block parks and re-validates each sync round; once the
				// epoch lands a genuine accept admits, while a forged LockedR
				// never converges and stays parked (#601).
				return fmt.Errorf("lease_accept locked emission mismatch on sync: block (R=%d cap=%d twap=%d) != epoch@accept (R=%d cap=%d twap=%d): retry after statechain syncs",
					lockedR, lockedCap, lockedTWAP, cur.R, cur.PayoutCap, cur.TWAP)
			}
			return fmt.Errorf("lease_accept locked emission mismatch: block (R=%d cap=%d twap=%d) != epoch@accept (R=%d cap=%d twap=%d)",
				lockedR, lockedCap, lockedTWAP, cur.R, cur.PayoutCap, cur.TWAP)
		}
	}
	// #570/C3: the state==created gate above ran outside the commit; re-check
	// it inside the commit transaction so a racing cancel cannot be overwritten.
	commit.ExpectLeaseHash = b.Source
	commit.ExpectLeaseState = LeaseCreated
	commit.PutLease = &Lease{
		LeaseHash:       b.Source,
		State:           LeaseAccepted,
		Consumer:        leaseBlock.Account,
		Provider:        b.Account,
		VCPUs:           leaseBlock.VCPUs,
		MemoryMB:        leaseBlock.MemoryMB,
		DiskGB:          leaseBlock.DiskGB,
		Duration:        leaseBlock.Duration,
		AccessPubKey:    leaseBlock.AccessPubKey,
		Cost:            leaseBlock.Amount,
		Stake:           b.Amount,
		StartTime:       startTime,
		CertificateHash: b.CertificateHash,
		Settled:         false,
		LockedR:         lockedR,
		LockedPayoutCap: lockedCap,
		LockedTWAP:      lockedTWAP,
	}

	if err := l.commitBlockWrite(commit, prevBalance); err != nil {
		return err
	}
	// FirstActivityAt must agree with rebuildReputation, which uses
	// lease.StartTime (the attestation median). Using b.Timestamp here
	// would make live diverge from replay across a node restart.
	l.reputation.Apply(ReputationEvent{
		Kind:      EventLeaseAccepted,
		Provider:  b.Account,
		Consumer:  leaseBlock.Account,
		Timestamp: startTime,
	})
	return nil
}

// resolveCancelWinsOverAccept implements the deterministic #570/C3b resolution
// of a lease_cancel that races a lease_accept. The caller holds the consumer's
// account lock and has found the lease in "accepted" state. To converge with
// nodes that applied the cancel first (and rejected the accept), this node
// unwinds the provider's accept block — refunding the stake and restoring the
// lease to "created" — so the cancel can then proceed normally.
//
// Only the provider's FRONTIER accept is unwound, and only when it is not
// finalized and its account lock is immediately available; otherwise a
// retryable error is returned so the cancel re-attempts on a later sync/sweep
// once the provider chain is quiescent (rather than blocking and risking a
// deadlock against a concurrent provider transition). The finality wall makes
// this correct: a finalized accept legitimately won consensus, so a cancel
// must not supersede it.
func (l *Ledger) resolveCancelWinsOverAccept(leaseHash, provider string) error {
	pchain, err := l.store.GetAccountChain(provider)
	if err != nil {
		return fmt.Errorf("cancel-wins: GetAccountChain(provider): %w", err)
	}
	if pchain == nil || len(pchain.Blocks) == 0 {
		// The accept hasn't been applied here yet — retry once it syncs.
		return fmt.Errorf("cancel-wins: provider accept not found locally: retry after sync")
	}
	acceptIdx := -1
	for i, blk := range pchain.Blocks {
		if blk.Type == BlockLeaseAccept && blk.Source == leaseHash {
			acceptIdx = i
			break
		}
	}
	if acceptIdx == -1 {
		return fmt.Errorf("cancel-wins: provider accept not found locally: retry after sync")
	}
	if acceptIdx != len(pchain.Blocks)-1 {
		// The provider built on top of the accept; unwinding it would need a
		// same-account cascade under the provider lock. Defer to a later attempt.
		return fmt.Errorf("cancel-wins: provider built on the accept: retry after sync")
	}
	if fh := l.FinalHeight(provider); uint64(acceptIdx+1) <= fh {
		// The accept is finalized — it legitimately won; the cancel cannot supersede it.
		return fmt.Errorf("cannot cancel lease in accepted state: accept is finalized")
	}
	acceptBlock := pchain.Blocks[acceptIdx]

	entry, ok := l.acquireAccountLockTry(provider)
	if !ok {
		return fmt.Errorf("cancel-wins: provider chain busy: retry after sync")
	}
	defer l.releaseAccountLock(provider, entry)

	// #622 residual: this nested accept-unwind happens when a lease_cancel WINNER
	// is being re-applied (#625), and it commits in its OWN CommitUndo store
	// transaction — it is NOT folded into the promotion's spanning CommitCascade.
	// A crash between this undo and the cancel's own commit can therefore still
	// strand the provider's accept unwound with the cancel not yet applied. This
	// is a known, out-of-scope residual of #622 (the spanning-commit work covers
	// the loser + cross-account cascade + winner, not a winner's own further
	// rollback of a third account).
	if err := l.undoBlockApply(provider, acceptBlock); err != nil {
		return fmt.Errorf("cancel-wins: unwind provider accept: %w", err)
	}
	log.Printf("lease %s: cancel-wins over a racing accept — unwound provider %s's accept %s (#570/C3b)",
		shortHash(leaseHash), shortAddr(provider), shortHash(acceptBlock.Hash))
	return nil
}

func (l *Ledger) validateAndAddLeaseCancel(b *Block) error {
	if b.Asset != "XUSD" {
		return fmt.Errorf("lease_cancel block must have asset=XUSD")
	}
	if b.Source == "" {
		return fmt.Errorf("lease_cancel must reference a source lease block")
	}

	// Source must be a valid lease block created by this account.
	leaseBlock, err := l.store.GetBlock(b.Source)
	if err != nil {
		return fmt.Errorf("GetBlock: %w", err)
	}
	if leaseBlock == nil {
		return fmt.Errorf("source lease block not found: %s", shortHash(b.Source))
	}
	if leaseBlock.Type != BlockLease {
		return fmt.Errorf("source block is not a lease block")
	}
	if leaseBlock.Account != b.Account {
		return fmt.Errorf("lease_cancel: only the consumer can cancel a lease")
	}

	// Only leases in "created" state can be cancelled — EXCEPT for the #570/C3b
	// cross-node accept/cancel race: a cancel racing an accept resolves
	// deterministically cancel-wins. On a node that already applied the
	// provider's accept (lease is "accepted"), unwind that accept here so the
	// cancel proceeds against a created lease, converging with nodes that
	// applied the cancel first and rejected the accept.
	if existing, ok, err := l.getLeaseOverlay(b.Source); ok {
		if err != nil {
			return fmt.Errorf("GetLease: %w", err)
		}
		if existing != nil && existing.State == LeaseAccepted && existing.Provider != b.Account {
			if rerr := l.resolveCancelWinsOverAccept(b.Source, existing.Provider); rerr != nil {
				return rerr
			}
		} else if existing != nil && existing.State != LeaseCreated {
			return fmt.Errorf("cannot cancel lease in %s state", existing.State)
		}
	}

	// Pending send must still exist.
	pending, err := l.getPendingSendOverlay(b.Source)
	if err != nil {
		return fmt.Errorf("GetPendingSend: %w", err)
	}
	if pending == nil {
		return fmt.Errorf("no pending send for lease: %s", shortHash(b.Source))
	}

	chain, err := l.getAccountChainOverlay(b.Account)
	if err != nil {
		return fmt.Errorf("GetAccountChain: %w", err)
	}
	if chain == nil {
		return fmt.Errorf("lease_cancel from unopened account")
	}
	if b.Previous != chain.Frontier() {
		return fmt.Errorf("previous mismatch: got %s, want %s", shortHash(b.Previous), shortHash(chain.Frontier()))
	}
	if len(chain.Blocks) > 0 {
		lastTs := chain.Blocks[len(chain.Blocks)-1].Timestamp
		if b.Timestamp < lastTs {
			return fmt.Errorf("block timestamp %d is before previous block timestamp %d", b.Timestamp, lastTs)
		}
	}

	// Balance must equal current + refund.
	oldBal := l.getAssetBalanceOverlay(b.Account, "XUSD")
	expectedBal := oldBal + leaseBlock.Amount
	if b.Balance != expectedBal {
		return fmt.Errorf("balance mismatch: expected %d, got %d", expectedBal, b.Balance)
	}

	commit, prevBalance, err := l.prepareBlockWrite(b)
	if err != nil {
		return err
	}
	commit.DeletePendingID = b.Source
	commit.CancelLeaseHash = b.Source
	// #570/C3: re-check state==created inside the commit transaction so a
	// racing accept cannot be refunded over.
	commit.ExpectLeaseHash = b.Source
	commit.ExpectLeaseState = LeaseCreated
	if err := l.commitBlockWrite(commit, prevBalance); err != nil {
		return err
	}
	l.reputation.Apply(ReputationEvent{
		Kind:      EventLeaseCancelled,
		Provider:  leaseBlock.Destination, // intended provider, never accepted
		Consumer:  b.Account,
		Timestamp: b.Timestamp,
	})
	return nil
}

// validateAndAddLeaseForceSettle resolves an accepted lease that the provider
// never settled (#488, FM3). It lives on the CONSUMER's chain — disjoint from the
// provider's lease_settle — and is valid only once the attested median is past
// expiry+grace+gap. It refunds the consumer's full cost from the escrow and
// burns the provider's stake (the stake is NOT re-added, unlike lease_settle),
// marking the lease unfulfilled. Cloned from validateAndAddLeaseCancel; the key
// differences are the LeaseAccepted state gate, the attested time predicate, and
// UnfulfillLeaseHash in place of CancelLeaseHash.
func (l *Ledger) validateAndAddLeaseForceSettle(b *Block, skipSkew bool) error {
	if b.Asset != "XUSD" {
		return fmt.Errorf("lease_force_settle block must have asset=XUSD")
	}
	if b.Source == "" {
		return fmt.Errorf("lease_force_settle must reference a source lease block")
	}

	// Source must be a valid lease block created by this account (the consumer).
	leaseBlock, err := l.store.GetBlock(b.Source)
	if err != nil {
		return fmt.Errorf("GetBlock: %w", err)
	}
	if leaseBlock == nil {
		return fmt.Errorf("source lease block not found: %s", shortHash(b.Source))
	}
	if leaseBlock.Type != BlockLease {
		return fmt.Errorf("source block is not a lease block")
	}
	if leaseBlock.Account != b.Account {
		return fmt.Errorf("lease_force_settle: only the consumer can force-settle a lease")
	}

	// Only an accepted, unsettled lease can be force-settled. A created lease is
	// cancelled (not force-settled); a settled/cancelled one is already resolved.
	lease, ok, err := l.getLeaseOverlay(b.Source)
	if !ok {
		return fmt.Errorf("store does not support leases")
	}
	if err != nil {
		return fmt.Errorf("GetLease: %w", err)
	}
	if lease == nil {
		return fmt.Errorf("lease not found: %s", shortHash(b.Source))
	}
	if lease.Settled {
		return fmt.Errorf("lease already settled")
	}
	if lease.State != LeaseAccepted {
		// #497: during out-of-order sync the lease_accept may not have applied
		// yet, leaving the lease in created state (StartTime==0). Defer with a
		// retryable error (see isRetryableError) so the block is held for a later
		// round rather than quarantined. Other non-accepted states (cancelled,
		// settled) are genuinely terminal.
		if lease.State == LeaseCreated {
			return fmt.Errorf("lease not yet accepted for force-settle (state %s): retry after accept", lease.State)
		}
		return fmt.Errorf("cannot force-settle lease in %s state", lease.State)
	}

	// Timekeeper attestations prove the lease is past expiry+grace+gap. The gap
	// (> 2×MaxAttestationSkew) keeps this window disjoint from the provider's
	// settle window [expiry, expiry+grace] — see LeaseForceSettleGap.
	if l.timekeeperConfigFn == nil {
		return fmt.Errorf("lease_force_settle: timekeepers not configured")
	}
	tkConfig := l.timekeeperConfigFn()
	if tkConfig == nil {
		return fmt.Errorf("lease_force_settle: timekeepers not configured")
	}
	forceTime, err := ValidateAttestations(b.Attestations, b.Source, tkConfig, skipSkew)
	if err != nil {
		return fmt.Errorf("lease_force_settle attestation: %w", err)
	}
	expiry := lease.StartTime + int64(lease.Duration)*1e9
	eligibleAt := expiry + LeaseSettleGrace + LeaseForceSettleGap
	if forceTime < eligibleAt {
		return fmt.Errorf("lease not yet force-settleable: need timestamp >= %d, got %d", eligibleAt, forceTime)
	}
	// #493 (outcome #4): the refund window is bounded above. Past
	// expiry+LeaseEscrowExpiry the escrow is considered burnt and no settle of
	// any kind is valid — checked against the block's own attested median so the
	// verdict is identical on every node regardless of local clock or whether a
	// node has run its local archive sweep yet.
	if expireAt := expiry + LeaseEscrowExpiry; forceTime >= expireAt {
		return fmt.Errorf("lease escrow expired: refund window closed at %d, got %d", expireAt, forceTime)
	}

	// The escrow PendingSend must still exist (it survives accept since #486).
	pending, err := l.getPendingSendOverlay(b.Source)
	if err != nil {
		return fmt.Errorf("GetPendingSend: %w", err)
	}
	if pending == nil {
		return fmt.Errorf("no pending escrow for lease: %s", shortHash(b.Source))
	}

	chain, err := l.getAccountChainOverlay(b.Account)
	if err != nil {
		return fmt.Errorf("GetAccountChain: %w", err)
	}
	if chain == nil {
		return fmt.Errorf("lease_force_settle from unopened account")
	}
	if b.Previous != chain.Frontier() {
		return fmt.Errorf("previous mismatch: got %s, want %s", shortHash(b.Previous), shortHash(chain.Frontier()))
	}
	if len(chain.Blocks) > 0 {
		lastTs := chain.Blocks[len(chain.Blocks)-1].Timestamp
		if b.Timestamp < lastTs {
			return fmt.Errorf("block timestamp %d is before previous block timestamp %d", b.Timestamp, lastTs)
		}
	}

	// Refund the consumer's full escrowed cost. The provider's stake is NOT
	// re-added — it stays burned-by-absence as the penalty for never settling.
	oldBal := l.getAssetBalanceOverlay(b.Account, "XUSD")
	expectedBal := oldBal + leaseBlock.Amount
	if expectedBal < oldBal {
		return fmt.Errorf("lease_force_settle would overflow uint64 balance")
	}
	if b.Balance != expectedBal {
		return fmt.Errorf("balance mismatch: expected %d, got %d", expectedBal, b.Balance)
	}

	commit, prevBalance, err := l.prepareBlockWrite(b)
	if err != nil {
		return err
	}
	commit.DeletePendingID = b.Source
	commit.UnfulfillLeaseHash = b.Source
	// #570/C3: re-check state==accepted inside the commit transaction.
	commit.ExpectLeaseHash = b.Source
	commit.ExpectLeaseState = LeaseAccepted
	if err := l.commitBlockWrite(commit, prevBalance); err != nil {
		return err
	}
	// #490: record the unfulfilled lease against both parties. The provider
	// counter is the deterrent; rebuildReputation replays this from the
	// force-settle block on the consumer's chain (same Timestamp) for determinism.
	l.reputation.Apply(ReputationEvent{
		Kind:      EventLeaseUnfulfilled,
		Provider:  lease.Provider,
		Consumer:  b.Account,
		Timestamp: b.Timestamp,
	})
	return nil
}

// CurrentR returns the current epoch's R_effective (scaled ×1000).
// Falls back to RFallback if the oracle hasn't published an epoch.
func (l *Ledger) CurrentR() uint64 {
	if l.epochRFn != nil {
		r := l.epochRFn()
		if r > 0 {
			return r
		}
	}
	return RFallback
}

// CurrentPayoutCap returns the latest epoch's Hermite payout cap, scaled ×1000.
// Zero indicates the cap is unavailable (no oracle epoch, or an older epoch
// without the field) — callers must treat zero as "no cap applied."
// See "XE Token Economy Model" v13 §Hermite Self-Lease Payout Cap.
func (l *Ledger) CurrentPayoutCap() uint64 {
	if l.epochPayoutCapFn == nil {
		return 0
	}
	return l.epochPayoutCapFn()
}

// CurrentTWAP returns the latest epoch's TWAP in milli-USD. Zero indicates
// unavailable — callers must treat zero as "no cap applied" when computing
// the Hermite payout cap.
func (l *Ledger) CurrentTWAP() uint64 {
	if l.epochTWAPFn == nil {
		return 0
	}
	return l.epochTWAPFn()
}

// CapR applies the Hermite self-lease payout cap to R_effective:
//
//	R_capped = min(R, payoutCap × 1000 / twapMilliUSD)
//
// payoutCap is the dollar-ROI ceiling (×1000 scaled) and twapMilliUSD is the
// price in milli-USD. Either being zero disables the cap (returns R unchanged)
// for backward compatibility with pre-v13 epochs and tests that don't wire
// the oracle.
//
// See "XE Token Economy Model" v13 §Hermite Self-Lease Payout Cap.
func CapR(r, payoutCap, twapMilliUSD uint64) uint64 {
	if payoutCap == 0 || twapMilliUSD == 0 {
		return r
	}
	// payoutCap is ×1000 scaled (e.g. 1550 = 1.55). To convert to an R-equivalent
	// bound (also ×1000 scaled): rCapMax = ⌈payoutCap × 1000 / twapMilliUSD⌉.
	// An overflowing payoutCap×1000 means the cap is above any representable R
	// and cannot bind.
	scaled, ok := safeMul(payoutCap, 1000)
	if !ok {
		return r
	}
	rCapMax := ceilDiv(scaled, twapMilliUSD)
	if rCapMax < r {
		return rCapMax
	}
	return r
}

// LeaseEmission computes XE emission from a lease cost and R_effective.
// Both inputs and the result are in micro-units (cost in micro-XUSD,
// emission in micro-XE). R is a unitless ratio scaled ×1000 (e.g. 2000 =
// 2.000), so emission = cost * R / 1000 produces micro-XE when cost is
// micro-XUSD. Minimum is 1 micro-XE as a non-zero safety floor.
// LeaseEmissionChecked computes XE emission = cost × R_capped / 1000 in
// micro-XE, reporting overflow of the cost×r product. #570/M4: the old
// LeaseEmission multiplied without a guard (unlike LeaseCost), so an overflowing
// product silently wrapped to a wrong (smaller) mint. The settle validation uses
// this checked form so an overflowing emission is rejected, never minted.
func LeaseEmissionChecked(cost, r uint64) (uint64, error) {
	product, ok := safeMul(cost, r)
	if !ok {
		return 0, fmt.Errorf("lease emission overflow: cost(%d) * r(%d)", cost, r)
	}
	emission := ceilDiv(product, 1000)
	if emission == 0 {
		emission = 1
	}
	return emission, nil
}

// LeaseEmission is the unchecked convenience form for simulation/test callers
// with controlled inputs. It returns 0 on overflow (never a wrapped value);
// consensus-critical paths use LeaseEmissionChecked instead.
func LeaseEmission(cost, r uint64) uint64 {
	emission, _ := LeaseEmissionChecked(cost, r)
	return emission
}

func (l *Ledger) validateAndAddLeaseSettle(b *Block, skipSkew bool) error {
	if b.Asset != "XE" {
		return fmt.Errorf("lease_settle block must have asset=XE")
	}
	if b.Source == "" {
		return fmt.Errorf("lease_settle must reference a source lease hash")
	}

	// Source must reference an active, unsettled lease.
	lease, ok, err := l.getLeaseOverlay(b.Source)
	if !ok {
		return fmt.Errorf("store does not support leases")
	}
	if err != nil {
		return fmt.Errorf("GetLease: %w", err)
	}
	if lease == nil {
		return fmt.Errorf("lease not found: %s", shortHash(b.Source))
	}
	if lease.Settled {
		return fmt.Errorf("lease already settled")
	}
	if lease.Provider != b.Account {
		return fmt.Errorf("lease_settle: provider account mismatch")
	}
	// #497: a settle can be validated during out-of-order sync before its
	// lease_accept has applied. StartTime is set only by accept, so a not-yet-
	// accepted lease (state created, StartTime==0) collapses expiry to a near-
	// zero absolute timestamp and spuriously trips the #487 grace guard below.
	// Defer the created case with a retryable error (see isRetryableError) so
	// the block is held for a later round and re-evaluated once the accept
	// lands, instead of being quarantined. Gating before the StartTime-dependent
	// expiry math keeps the genuine grace guard terminal for accepted leases;
	// other non-accepted states (cancelled) are genuinely terminal.
	if lease.State != LeaseAccepted {
		if lease.State == LeaseCreated {
			return fmt.Errorf("lease not yet accepted for settle (state %s): retry after accept", lease.State)
		}
		return fmt.Errorf("lease_settle: lease not settleable in %s state", lease.State)
	}

	// Validate timekeeper attestations for lease_settle. Attestations are
	// mandatory — self-reported timestamps are not accepted.
	if l.timekeeperConfigFn == nil {
		return fmt.Errorf("lease_settle: timekeepers not configured")
	}
	tkConfigSettle := l.timekeeperConfigFn()
	if tkConfigSettle == nil {
		return fmt.Errorf("lease_settle: timekeepers not configured")
	}
	settleTime, err := ValidateAttestations(b.Attestations, b.Source, tkConfigSettle, skipSkew)
	if err != nil {
		return fmt.Errorf("lease_settle attestation: %w", err)
	}

	// Lease must be expired: attested timestamp >= startTime + duration*1e9.
	expiry := lease.StartTime + int64(lease.Duration)*1e9
	if settleTime < expiry {
		return fmt.Errorf("lease not yet expired: need timestamp >= %d, got %d", expiry, settleTime)
	}
	// #487 (FM5): reject a settle whose attested median is past the grace window.
	// Past expiry+grace the lease is eligible for consumer force-settle instead;
	// keeping the windows disjoint avoids settle/force-settle both being valid.
	if settleTime > expiry+LeaseSettleGrace {
		return fmt.Errorf("lease settle past grace: timestamp %d exceeds expiry+grace %d", settleTime, expiry+LeaseSettleGrace)
	}

	// XE emission = lease cost × R_capped / 1000.
	// R_capped = min(R_effective, payout_cap × 1000 / TWAP), bounding dollar
	// ROI per the Hermite self-lease cap. When the oracle hasn't published a
	// payout_cap (older epochs or test fixtures without the wiring), CapR
	// returns R unchanged.
	//
	// Per #401, emission parameters are locked at accept time onto the lease
	// record. Settle uses the locked values so the provider's payout is
	// deterministic from the moment they commit stake. #514: there is no
	// fallback to live CurrentR() — validateAndAddLeaseAccept rejects any accept
	// with LockedR==0, so every accepted lease carries non-zero locked params
	// and the settle emission is identical on every node (the non-deterministic
	// fallback was the #501 cross-epoch wedge).
	// See "XE Token Economy Model" §Dual R Emission + v13 §Hermite Cap.
	r := lease.LockedR
	payoutCap := lease.LockedPayoutCap
	twap := lease.LockedTWAP
	rCapped := CapR(r, payoutCap, twap)
	expectedXE, err := LeaseEmissionChecked(lease.Cost, rCapped)
	if err != nil {
		return fmt.Errorf("lease_settle: %w", err)
	}
	if b.Amount != expectedXE {
		return fmt.Errorf("lease_settle XE mismatch: expected %d (cost=%d, R=%d, R_capped=%d), got %d", expectedXE, lease.Cost, r, rCapped, b.Amount)
	}

	// #570/M2: the consumer escrow must still exist so the settle actually burns
	// it. Without this guard a settle whose escrow was already consumed (e.g. by
	// a racing resolution path) would still mint emission XE and return the
	// provider stake while DeletePendingID below is a silent no-op. By the time a
	// settle is valid (lease accepted + expired) the escrow created at lease
	// creation is still pending unless already consumed, so its absence is a
	// genuine terminal error. Mirrors lease_cancel and lease_force_settle.
	escrow, err := l.getPendingSendOverlay(b.Source)
	if err != nil {
		return fmt.Errorf("GetPendingSend: %w", err)
	}
	if escrow == nil {
		return fmt.Errorf("no escrow pending to burn for lease: %s", shortHash(b.Source))
	}

	chain, err := l.getAccountChainOverlay(b.Account)
	if err != nil {
		return fmt.Errorf("GetAccountChain: %w", err)
	}
	if chain == nil {
		return fmt.Errorf("lease_settle from unopened account")
	}
	if b.Previous != chain.Frontier() {
		return fmt.Errorf("previous mismatch: got %s, want %s", shortHash(b.Previous), shortHash(chain.Frontier()))
	}
	if len(chain.Blocks) > 0 {
		lastTs := chain.Blocks[len(chain.Blocks)-1].Timestamp
		if b.Timestamp < lastTs {
			return fmt.Errorf("block timestamp %d is before previous block timestamp %d", b.Timestamp, lastTs)
		}
	}

	// Mints XE: balance = old XE + amount.
	oldXEBal := l.getAssetBalanceOverlay(b.Account, "XE")
	expectedBal := oldXEBal + b.Amount
	if expectedBal < oldXEBal {
		return fmt.Errorf("lease_settle would overflow uint64 balance")
	}
	if b.Balance != expectedBal {
		return fmt.Errorf("balance mismatch: expected %d, got %d", expectedBal, b.Balance)
	}

	commit, prevBalance, err := l.prepareBlockWrite(b)
	if err != nil {
		return err
	}
	commit.SettleLeaseHash = b.Source
	// #486: burn the consumer's escrow at settle (kept alive since lease_accept).
	commit.DeletePendingID = b.Source
	// #570/C3: re-check state==accepted inside the commit transaction.
	commit.ExpectLeaseHash = b.Source
	commit.ExpectLeaseState = LeaseAccepted
	// #674: return the provider's XUSD stake atomically with the commit. The
	// settle block's own Balance tracks XE only, so this rides on AssetCredit
	// (reversed by BlockUndo.AssetDebit on a reorg) instead of a post-commit
	// addAssetBalance that no undo could reverse.
	commit.AssetCredit = &AssetDelta{Account: b.Account, Asset: "XUSD", Amount: lease.Stake}

	if err := l.commitBlockWrite(commit, prevBalance); err != nil {
		return err
	}

	l.reputation.Apply(ReputationEvent{
		Kind:         EventLeaseSettled,
		Provider:     lease.Provider,
		Consumer:     lease.Consumer,
		Timestamp:    b.Timestamp,
		DurationSecs: lease.Duration,
	})

	return nil
}

// prepareBlockWrite builds a BlockCommit for the given block without writing
// to the store. Callers can add pending send operations before committing.
// The returned prevBalance is the account's XE balance before this block
// (used for delegation weight updates).
func (l *Ledger) prepareBlockWrite(b *Block) (*BlockCommit, uint64, error) {
	// Overlay-aware: during a #622 conflict promotion the winner's account chain
	// and balance are the post-undo overlay values, not the (still pre-promotion)
	// store/in-memory values.
	chain, err := l.getAccountChainOverlay(b.Account)
	if err != nil {
		return nil, 0, fmt.Errorf("GetAccountChain: %w", err)
	}
	// Previous XE balance for delegation weight tracking. XE confers voting
	// weight; XUSD is mintable (faucet/bridge) and must not mint consensus weight.
	prevBalance := l.getAssetBalanceOverlay(b.Account, "XE")
	if chain == nil {
		chain = &AccountChain{}
	}
	chain.Blocks = append(chain.Blocks, b)
	commit := &BlockCommit{
		Block:        b,
		Account:      b.Account,
		Chain:        chain,
		FrontierHash: b.Hash,
		// #829: whichever block type opens the chain (genesis, receive, mint, …)
		// carries the account's public key declaration. Attaching it centrally
		// here — rather than in each type's validate-and-add — means every path
		// that writes a block also registers the credential, with no type left
		// out. ValidatePubKeyDeclaration has already proven it derives b.Account.
		PutAccountKey: b.PubKey,
	}
	return commit, prevBalance, nil
}

// commitBlockWrite atomically writes a BlockCommit to the store and updates
// in-memory delegation state.
//
// #622 interception: if an active conflict-promotion cascade names THIS block as
// its winner, the winner is not committed on its own — it is committed together
// with all the loser/cascade undos in ONE CommitCascade store transaction (the
// crash-atomicity boundary). Only the winner block is intercepted; concurrent
// commits of any unrelated block pass straight through.
func (l *Ledger) commitBlockWrite(c *BlockCommit, prevBalance uint64) error {
	// The post-undo delegation pointer for c.Account: from the overlay when a
	// promotion unwound this account (the live l.delegation still holds the
	// pre-undo rep until the memApplies run after commit), else the live map.
	oldRep, fromOverlay := l.overlayDelegationRep(c.Account)
	if !fromOverlay {
		l.delegationMu.RLock()
		oldRep = l.delegation[c.Account]
		l.delegationMu.RUnlock()
	}

	effectiveRep := c.Block.Representative
	if effectiveRep == "" {
		effectiveRep = oldRep
	}
	if effectiveRep == "" {
		c.DeleteDelegation = true
	} else {
		c.DelegationRep = effectiveRep
	}

	// #622: intercept the winner's commit and land it as the spanning cascade.
	if cascade := l.activeCascadeFor(); cascade != nil && cascade.winnerHash == c.Block.Hash {
		// One atomic transaction: all undos (loser + cross-account cascade) then
		// the winner commit. On error NOTHING in memory was mutated and the store
		// is untouched — the caller (swapBlockLocked) deactivates the overlay and
		// leaves the pre-promotion state fully intact (#622).
		if err := l.atomicStore.CommitCascade(cascade.undos, c); err != nil {
			return fmt.Errorf("CommitCascade: %w", err)
		}
		// Store committed. Now apply the undos' in-memory deltas in order, then
		// clear the active cascade so the post-commit balance/delegation updates
		// below (and any later reads) see the live maps, not the overlay.
		for _, apply := range cascade.memApplies {
			apply()
		}
		l.deactivateCascade()

		l.blockCount.Add(1)
		asset := c.Block.Asset
		if asset == "" {
			asset = "XE"
		}
		l.setAssetBalance(c.Account, asset, c.Block.Balance)
		// #829: mirror the store write of the credential registry in memory.
		if c.PutAccountKey != "" {
			l.setAccountKey(c.Account, c.PutAccountKey)
		}
		// #674: apply the settle stake return atomically with the (cascade) commit.
		if c.AssetCredit != nil {
			l.addAssetBalance(c.AssetCredit.Account, c.AssetCredit.Asset, c.AssetCredit.Amount)
		}
		// prevBalance was computed by prepareBlockWrite from the overlay (the
		// post-undo XE balance), so updateDelegation moves the winner's weight off
		// exactly the pre-winner balance the promotion left in place.
		if err := l.updateDelegation(c.Account, prevBalance, c.Block); err != nil {
			return fmt.Errorf("updateDelegation: %w", err)
		}
		return nil
	}

	if err := l.atomicStore.CommitBlock(c); err != nil {
		return fmt.Errorf("CommitBlock: %w", err)
	}
	l.blockCount.Add(1)

	// Update per-asset balance tracking.
	asset := c.Block.Asset
	if asset == "" {
		asset = "XE" // legacy
	}
	l.setAssetBalance(c.Account, asset, c.Block.Balance)
	// #829: mirror the store write of the credential registry in memory.
	if c.PutAccountKey != "" {
		l.setAccountKey(c.Account, c.PutAccountKey)
	}
	// #674: apply the settle stake return atomically with the commit.
	if c.AssetCredit != nil {
		l.addAssetBalance(c.AssetCredit.Account, c.AssetCredit.Asset, c.AssetCredit.Amount)
	}

	if err := l.updateDelegation(c.Account, prevBalance, c.Block); err != nil {
		return fmt.Errorf("updateDelegation: %w", err)
	}
	return nil
}

// addBlockLocked is a convenience that prepares and immediately commits a
// block with no pending-send side effects (used by validateAndAddClaim).
func (l *Ledger) addBlockLocked(b *Block) error {
	commit, prevBalance, err := l.prepareBlockWrite(b)
	if err != nil {
		return err
	}
	return l.commitBlockWrite(commit, prevBalance)
}

// Store returns the underlying store.
func (l *Ledger) Store() Store {
	return l.store
}

// GetBalance returns the current balance for an account (0 if not found).
func (l *Ledger) GetBalance(account string) uint64 {
	chain, err := l.store.GetAccountChain(account)
	if err != nil {
		storeReadErrors.Add(1)
		log.Printf("ERROR: GetBalance: store read for %s failed: %v — surfacing as balance 0, NOT a genuine miss (#730)", shortAddr(account), err)
		return 0
	}
	if chain == nil {
		return 0
	}
	return chain.LatestBalance()
}

// GetChain returns a copy of all blocks for an account.
func (l *Ledger) GetChain(account string) []*Block {
	chain, err := l.store.GetAccountChain(account)
	if err != nil {
		storeReadErrors.Add(1)
		log.Printf("ERROR: GetChain: store read for %s failed: %v — surfacing as no chain, NOT a genuine miss (#730)", shortAddr(account), err)
		return nil
	}
	if chain == nil {
		return nil
	}
	out := make([]*Block, len(chain.Blocks))
	copy(out, chain.Blocks)
	return out
}

// storeReadErrors counts store-read errors swallowed by the ledger getters below.
// The store contract returns (nil, nil) on a genuine miss and (nil, err) only on a
// real failure (corruption / transient I/O), so a swallowed error is otherwise
// indistinguishable from a legitimate not-found. Each getter logs and counts here
// while preserving its nil-on-error behavior, making store failures observable (#730).
var storeReadErrors atomic.Uint64

// StoreReadErrors returns the number of store-read errors swallowed by the ledger
// getters (GetBalance, GetChain, GetPendingForAccount, GetAllPending, GetBlock). A
// non-zero value means the store surfaced a real error that was returned only as a
// not-found/empty result (#730).
func StoreReadErrors() uint64 {
	return storeReadErrors.Load()
}

// GetPendingForAccount returns all unreceived sends addressed to the given account.
func (l *Ledger) GetPendingForAccount(account string) []*PendingSend {
	result, err := l.store.GetPendingByDest(account)
	if err != nil {
		storeReadErrors.Add(1)
		log.Printf("ERROR: GetPendingForAccount: store read for %s failed: %v — surfacing as no pending, NOT a genuine miss (#730)", shortAddr(account), err)
		return nil
	}
	return result
}

// GetAllPending returns all unreceived sends across all accounts.
func (l *Ledger) GetAllPending() []*PendingSend {
	result, err := l.store.GetAllPending()
	if err != nil {
		storeReadErrors.Add(1)
		log.Printf("ERROR: GetAllPending: store read failed: %v — surfacing as no pending, NOT a genuine empty (#730)", err)
		return nil
	}
	return result
}

// GetRecentBlocks returns the most recent blocks across all chains, sorted by
// timestamp descending (newest first). Limit controls the maximum returned.
// Only inspects the tail of each account chain to avoid loading the entire
// ledger into memory.
func (l *Ledger) GetRecentBlocks(limit int) []*Block {
	if limit <= 0 {
		return []*Block{}
	}
	frontiers := l.Frontiers()
	result := make([]*Block, 0, limit)
	// Track the minimum timestamp in our result set for early pruning.
	var minTs int64
	for acc := range frontiers {
		chain := l.GetChain(acc)
		// Only examine the last `limit` blocks per account — older blocks
		// cannot make it into the top-N result set anyway.
		start := len(chain) - limit
		if start < 0 {
			start = 0
		}
		for i := len(chain) - 1; i >= start; i-- {
			b := chain[i]
			if len(result) >= limit && b.Timestamp <= minTs {
				break // rest of this chain is older, skip
			}
			result = append(result, b)
		}
		// Sort and truncate after each account to keep memory bounded and
		// update minTs so subsequent chains can prune early.
		if len(result) > limit {
			sort.Slice(result, func(i, j int) bool {
				return result[i].Timestamp > result[j].Timestamp
			})
			result = result[:limit]
			minTs = result[limit-1].Timestamp
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Timestamp > result[j].Timestamp
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result
}

// GetBlock returns a block by hash.
func (l *Ledger) GetBlock(hash string) *Block {
	b, err := l.store.GetBlock(hash)
	if err != nil {
		storeReadErrors.Add(1)
		log.Printf("ERROR: GetBlock: store read for %s failed: %v — surfacing as not-found, NOT a genuine miss (#730)", shortHash(hash), err)
		return nil
	}
	return b
}

// GetBlockOrStaged returns a block by hash from the main chain store, falling
// back to the conflict staging area. A conflicting sibling that this node
// received second (or pulled to resolve a phantom conflict) lives only in
// staging until the fork resolves — but it is a real, validated block body, not
// a phantom. Conflict resolution must treat it as loadable so the node can
// converge-vote for it and run weighted 2-block voting; otherwise an
// equivocated account stalls forever, neither sibling reaching a quorum because
// no node will vote for the sibling whose body it holds only in staging (#540).
func (l *Ledger) GetBlockOrStaged(hash string) *Block {
	if b := l.GetBlock(hash); b != nil {
		return b
	}
	cs, ok := l.store.(ConflictStore)
	if !ok {
		return nil
	}
	b, err := cs.GetStagedBlock(hash)
	if err != nil {
		return nil
	}
	return b
}

// GetConflict returns the Conflict record for the given (account, previousHash)
// pair, or nil if no conflict has been detected. Returns nil if the store does
// not implement ConflictStore.
func (l *Ledger) GetConflict(account, previousHash string) *Conflict {
	cs, ok := l.store.(ConflictStore)
	if !ok {
		return nil
	}
	c, err := cs.GetConflict(account, previousHash)
	if err != nil {
		return nil
	}
	return c
}

// GetConflictsForAccount returns all Conflict records for the given account.
// Returns nil if the store does not implement ConflictStore or on error.
func (l *Ledger) GetConflictsForAccount(account string) []*Conflict {
	cs, ok := l.store.(ConflictStore)
	if !ok {
		return []*Conflict{}
	}
	conflicts, err := cs.GetConflictsForAccount(account)
	if err != nil {
		return []*Conflict{}
	}
	return conflicts
}

// GetAllConflicts returns all Conflict records across all accounts.
// Returns nil if the store does not implement ConflictStore or on error.
func (l *Ledger) GetAllConflicts() []*Conflict {
	cs, ok := l.store.(ConflictStore)
	if !ok {
		return []*Conflict{}
	}
	conflicts, err := cs.GetAllConflicts()
	if err != nil {
		return []*Conflict{}
	}
	return conflicts
}

// AllChains returns a snapshot of all account addresses known to the store.
// NOTE: MemStore does not expose a list-accounts method; this iterates via frontiers.
func (l *Ledger) AllChains() []string {
	frontiers := l.Frontiers()
	accounts := make([]string, 0, len(frontiers))
	for acc := range frontiers {
		accounts = append(accounts, acc)
	}
	return accounts
}

// BlockCount returns the cached total number of blocks across all accounts.
func (l *Ledger) BlockCount() int {
	return int(l.blockCount.Load())
}

// DelegationUnderflows returns the running total of delegation weight
// underflows observed since startup. A non-zero value signals in-memory
// weight divergence from the ledger (data corruption) and should alert (#728).
func (l *Ledger) DelegationUnderflows() uint64 {
	return l.delegationUnderflow.Load()
}

// recordFinalityAdvance notes that a per-account final-height watermark moved
// forward. Genesis is deliberately NOT counted: it is marked final at bootstrap
// on every node, so counting it would make a network that has finalized nothing
// since block 0 look like it is making progress — the exact illusion #833 is
// about.
func (l *Ledger) recordFinalityAdvance() {
	l.finalityAdvances.Add(1)
	l.lastFinalityNs.Store(Now().UnixNano())
}

// FinalityAdvances returns how many times a final-height watermark has advanced
// since startup. This is the positive liveness signal for #833: total delegated
// weight can be non-zero and finality still be dead (weight delegated to an
// address no key controls — e.g. a public key mistakenly used as an address,
// #829), so a health gate must assert weight AND progress.
func (l *Ledger) FinalityAdvances() uint64 {
	return l.finalityAdvances.Load()
}

// LastFinalityNs returns the wall-clock time (unix ns) of the most recent
// final-height advance, or 0 if nothing has finalized since startup (#833).
func (l *Ledger) LastFinalityNs() int64 {
	return l.lastFinalityNs.Load()
}

// initBlockCount populates the cached block count by iterating all chains.
// Called once during startup on non-empty stores.
func (l *Ledger) initBlockCount() {
	frontiers := l.Frontiers()
	var count int64
	for acc := range frontiers {
		chain, err := l.store.GetAccountChain(acc)
		if err != nil || chain == nil {
			continue
		}
		count += int64(len(chain.Blocks))
	}
	l.blockCount.Store(count)
}

// Frontiers returns a map of account → frontier hash for sync.
func (l *Ledger) Frontiers() map[string]string {
	if fl, ok := l.store.(FrontierLister); ok {
		return fl.AllFrontiers()
	}
	return map[string]string{}
}

// LocksCount returns the number of accounts currently tracked in the lock
// registry. Intended for use in tests to verify eager cleanup.
func (l *Ledger) LocksCount() int {
	l.locksMu.Lock()
	defer l.locksMu.Unlock()
	return len(l.locks)
}

// rebuildDelegation repopulates the in-memory delegation and weights maps from
// the store on startup. Only called when the store is non-empty.
func (l *Ledger) rebuildDelegation() error {
	di, ok := l.store.(DelegationIterator)
	if !ok {
		return nil // store does not support delegation persistence
	}
	err := di.IterateDelegations(func(account, representative string) error {
		if representative == "" {
			return nil
		}
		l.delegation[account] = representative

		// Only XE balance confers voting weight (XUSD is mintable via
		// faucet/bridge and must not mint consensus weight). Walk the chain to
		// find the latest XE balance (last block with asset "XE" or empty asset;
		// legacy/genesis blocks may carry an empty Asset).
		chain, err := l.store.GetAccountChain(account)
		// #570/M10: propagate store read errors so a partially-readable store
		// refuses to boot instead of silently dropping this account's vote
		// weight (which diverges consensus weights from a clean replay).
		if err != nil {
			return fmt.Errorf("GetAccountChain(%s): %w", shortAddr(account), err)
		}
		if chain == nil {
			return nil
		}
		var xeBal uint64
		for _, b := range chain.Blocks {
			a := b.Asset
			if a == "" {
				a = "XE"
			}
			if a == "XE" {
				xeBal = b.Balance
			}
		}
		bal := new(big.Int).SetUint64(xeBal)
		if l.weights[representative] == nil {
			l.weights[representative] = new(big.Int)
		}
		l.weights[representative].Add(l.weights[representative], bal)
		return nil
	})
	if err != nil {
		return fmt.Errorf("rebuildDelegation: %w", err)
	}
	return nil
}

// updateDelegation updates in-memory delegation and weight maps after a block
// is confirmed. prevBalance is the account's XE balance before the new block
// (used to subtract old weight). Only XE balance confers voting weight (XUSD is
// mintable via faucet/bridge and must not mint consensus weight).
// Must be called with the account lock held.
func (l *Ledger) updateDelegation(account string, prevBalance uint64, newBlock *Block) error {
	newRep := newBlock.Representative

	// Only XE balance confers voting weight.
	l.assetBalMu.RLock()
	var newXEBal uint64
	if m := l.assetBalances[account]; m != nil {
		newXEBal = m["XE"]
	}
	l.assetBalMu.RUnlock()

	// For XE blocks, prevBalance is the previous XE balance (from caller).
	// For non-XE blocks, the XE balance hasn't changed, but the rep might have.
	// We use the previous XE balance to subtract old weight. Empty-asset blocks
	// (legacy/genesis) default to XE and are treated as balance-changing.
	asset := newBlock.Asset
	if asset == "" {
		asset = "XE"
	}
	prevXEBal := prevBalance
	if asset != "XE" {
		// Non-XE block: XE balance didn't change, so prev = current.
		prevXEBal = newXEBal
	}

	l.delegationMu.Lock()
	defer l.delegationMu.Unlock()

	oldRep := l.delegation[account]

	// Empty Representative means "keep current delegation". Only change
	// delegation when the block explicitly sets a new representative.
	effectiveRep := newRep
	if effectiveRep == "" {
		effectiveRep = oldRep
	}

	// Subtract old XE balance from old representative's weight.
	if oldRep != "" {
		if l.weights[oldRep] == nil {
			l.weights[oldRep] = new(big.Int)
		}
		prev := new(big.Int).SetUint64(prevXEBal)
		l.weights[oldRep].Sub(l.weights[oldRep], prev)
		if l.weights[oldRep].Sign() < 0 {
			// Underflow means the in-memory weight diverged from the ledger (a
			// double-subtract or a missing add) — data corruption that feeds
			// straight into quorum math. We can't recover the true weight, so
			// clamp to 0 to keep quorum math well-defined, but surface the
			// divergence loudly and observably (metric on /node) rather than
			// silently papering over it (#728). Failing the commit here is not
			// an option: the block is already persisted, so an error would
			// desync the store from the caller.
			n := l.delegationUnderflow.Add(1)
			log.Printf("ERROR: delegation weight underflow for representative %s (balance subtracted: %d); clamped to 0 — DATA CORRUPTION, total underflows=%d",
				shortAddr(oldRep), prevXEBal, n)
			l.weights[oldRep].SetInt64(0)
		}
	}

	// Update delegation map.
	if effectiveRep == "" {
		delete(l.delegation, account)
	} else {
		l.delegation[account] = effectiveRep
	}

	// Add new XE balance to new representative's weight.
	if effectiveRep != "" {
		if l.weights[effectiveRep] == nil {
			l.weights[effectiveRep] = new(big.Int)
		}
		l.weights[effectiveRep].Add(l.weights[effectiveRep], new(big.Int).SetUint64(newXEBal))
	}

	return nil
}

// snapshotWeights returns a copy of all ELIGIBLE representative weights as
// uint64 values. Used to freeze weights at conflict detection time, and summed
// into Conflict.TotalWeight — so the eligibility gate (#832) must apply here
// too, or a contested position would tally against the ungated denominator and
// stay unresolvable at exactly the moment resolution matters most.
func (l *Ledger) snapshotWeights() map[string]uint64 {
	l.delegationMu.RLock()
	defer l.delegationMu.RUnlock()
	set := l.eligibleAllowlistLocked()
	snap := make(map[string]uint64, len(l.weights))
	for rep, w := range l.weights {
		if w != nil && w.Sign() > 0 && repEligibleLocked(set, rep) {
			if w.IsUint64() {
				snap[rep] = w.Uint64()
			} else {
				snap[rep] = math.MaxUint64
			}
		}
	}
	return snap
}

// GetRepresentative returns the current representative for an account, or ""
// if no delegation is set.
func (l *Ledger) GetRepresentative(account string) string {
	l.delegationMu.RLock()
	defer l.delegationMu.RUnlock()
	return l.delegation[account]
}

// GetVoteWeight returns a copy of the total vote weight delegated to
// representative, or zero if the network's eligibility policy excludes it
// (#832).
//
// Returning zero here is what keeps the numerator and the denominator in step:
// a zero-weight representative does not emit votes (castVoteLocked), its votes
// are rejected by peers (ValidateVote), and any that slip through are re-weighted
// to zero on ingest (receiveVoteInner). Excluding a representative from the
// denominator but still counting its votes would be strictly worse than the bug
// this closes.
func (l *Ledger) GetVoteWeight(representative string) *big.Int {
	l.delegationMu.RLock()
	defer l.delegationMu.RUnlock()
	if !repEligibleLocked(l.eligibleAllowlistLocked(), representative) {
		return new(big.Int)
	}
	w := l.weights[representative]
	if w == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(w) // return a copy
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12] + "..."
	}
	return h
}

func shortAddr(a string) string {
	return shortHash(a)
}

// GetVoteWeights returns a snapshot of every ELIGIBLE representative's vote
// weight in micro-XE — the consensus view, matching the quorum denominator.
// Representatives with zero weight are omitted. Use GetAllVoteWeights for the
// unfiltered view (#832).
func (l *Ledger) GetVoteWeights() map[string]uint64 {
	return l.snapshotWeights()
}

// GetTotalDelegatedWeight returns the quorum denominator: the sum of the vote
// weight delegated to ELIGIBLE representatives (#832). With no eligibility
// policy published this is the sum over every representative, exactly as before.
func (l *Ledger) GetTotalDelegatedWeight() *big.Int {
	l.delegationMu.RLock()
	defer l.delegationMu.RUnlock()
	return l.sumEligibleLocked(l.eligibleAllowlistLocked())
}

// ValidateStagedBlock checks that a staged conflict winner passes the same
// semantic validation that AddBlock applies before a block is added to the main
// chain. parentBalance is the balance of the block immediately before the
// conflict point (0 for open-block conflicts). Returns nil if valid.
func (l *Ledger) ValidateStagedBlock(b *Block, parentBalance uint64) error {
	// #829: a staged block's credential is checked here too. Staging is reachable
	// from addBlock (which already verified) and from the promotion revalidation
	// in confirmConflict, and this is the function that decides whether a staged
	// candidate is promotable at all — so the credential check belongs on it.
	if err := l.verifyBlockCredential(b); err != nil {
		return err
	}
	switch b.Type {
	case BlockSend:
		if b.Amount == 0 {
			return fmt.Errorf("staged send: amount must be > 0")
		}
		if b.Amount > parentBalance {
			return fmt.Errorf("staged send: insufficient balance: have %d, sending %d", parentBalance, b.Amount)
		}
		if b.Balance != parentBalance-b.Amount {
			return fmt.Errorf("staged send: balance mismatch: expected %d, got %d", parentBalance-b.Amount, b.Balance)
		}
		if b.Destination == "" {
			return fmt.Errorf("staged send: must have a destination")
		}
		if b.Destination == b.Account {
			return fmt.Errorf("staged send: cannot send to self")
		}
	case BlockReceive:
		if b.Source == "" {
			return fmt.Errorf("staged receive: must reference a source send")
		}
		pending, err := l.store.GetPendingSend(b.Source)
		if err != nil {
			return fmt.Errorf("staged receive: GetPendingSend: %w", err)
		}
		if pending == nil {
			return fmt.Errorf("staged receive: source send not pending: %s", shortHash(b.Source))
		}
		if pending.Destination != b.Account {
			return fmt.Errorf("staged receive: send not addressed to this account")
		}
		// #486: mirror the live-path guard — a live lease escrow is not receivable.
		if l.isLiveLeaseEscrow(b.Source) {
			return fmt.Errorf("staged receive: cannot receive a live lease escrow: %s", shortHash(b.Source))
		}
		expectedBal := parentBalance + pending.Amount
		if expectedBal < parentBalance {
			return fmt.Errorf("staged receive: balance would overflow uint64")
		}
		if b.Balance != expectedBal {
			return fmt.Errorf("staged receive: balance mismatch: expected %d, got %d", expectedBal, b.Balance)
		}
	case BlockLease:
		if b.Amount > parentBalance {
			return fmt.Errorf("staged lease: insufficient balance: have %d, need %d", parentBalance, b.Amount)
		}
		if b.Balance != parentBalance-b.Amount {
			return fmt.Errorf("staged lease: balance mismatch: expected %d, got %d", parentBalance-b.Amount, b.Balance)
		}
	case BlockLeaseAccept:
		if b.Amount > parentBalance {
			return fmt.Errorf("staged lease_accept: insufficient balance: have %d, need %d", parentBalance, b.Amount)
		}
		if b.Balance != parentBalance-b.Amount {
			return fmt.Errorf("staged lease_accept: balance mismatch: expected %d, got %d", parentBalance-b.Amount, b.Balance)
		}
	case BlockLeaseSettle:
		// #570/M2 parity with the staged cancel/force-settle cases: the
		// consumer's escrow must still be pending. Without this, a settle
		// arriving as a winning conflict sibling mints emission XE and returns
		// the stake while the escrow "burn" is a silent no-op — the exact gap
		// the live-path guard closes. Full staged re-validation is C1's job;
		// this is the escrow-existence guard only.
		pending, err := l.store.GetPendingSend(b.Source)
		if err != nil {
			return fmt.Errorf("staged lease_settle: GetPendingSend: %w", err)
		}
		if pending == nil {
			return fmt.Errorf("staged lease_settle: no pending escrow for lease")
		}
		expectedBal := parentBalance + b.Amount
		if expectedBal < parentBalance {
			return fmt.Errorf("staged lease_settle: balance would overflow uint64")
		}
		if b.Balance != expectedBal {
			return fmt.Errorf("staged lease_settle: balance mismatch: expected %d, got %d", expectedBal, b.Balance)
		}
	case BlockLeaseCancel:
		pending, err := l.store.GetPendingSend(b.Source)
		if err != nil {
			return fmt.Errorf("staged lease_cancel: GetPendingSend: %w", err)
		}
		if pending == nil {
			return fmt.Errorf("staged lease_cancel: no pending send for lease")
		}
		expectedBal := parentBalance + pending.Amount
		if b.Balance != expectedBal {
			return fmt.Errorf("staged lease_cancel: balance mismatch: expected %d, got %d", expectedBal, b.Balance)
		}
	case BlockLeaseForceSettle:
		pending, err := l.store.GetPendingSend(b.Source)
		if err != nil {
			return fmt.Errorf("staged lease_force_settle: GetPendingSend: %w", err)
		}
		if pending == nil {
			return fmt.Errorf("staged lease_force_settle: no pending escrow for lease")
		}
		expectedBal := parentBalance + pending.Amount
		if b.Balance != expectedBal {
			return fmt.Errorf("staged lease_force_settle: balance mismatch: expected %d, got %d", expectedBal, b.Balance)
		}
	case BlockMultisigOpen:
		return fmt.Errorf("staged multisig_open: conflicting account opens are invalid")
	case BlockMultisigUpdate:
		if b.Balance != parentBalance {
			return fmt.Errorf("staged multisig_update: balance mismatch: expected %d, got %d", parentBalance, b.Balance)
		}
	case BlockBurn:
		if b.Asset != "XE" {
			return fmt.Errorf("staged burn: restricted to XE")
		}
		if b.Amount == 0 {
			return fmt.Errorf("staged burn: amount must be > 0")
		}
		if b.Amount > parentBalance {
			return fmt.Errorf("staged burn: insufficient balance: have %d XE, burning %d", parentBalance, b.Amount)
		}
		if b.Balance != parentBalance-b.Amount {
			return fmt.Errorf("staged burn: balance mismatch: expected %d, got %d", parentBalance-b.Amount, b.Balance)
		}
	case BlockMint:
		// A conflicting (staged) mint can only ever exist on a minter account
		// — the first mint on a non-minter account is rejected at the AddBlock
		// switch before any conflict could form — but assert authorization here
		// too. XUSD-only; balance must credit exactly the minted amount.
		if b.Asset != "XUSD" {
			return fmt.Errorf("staged mint: restricted to XUSD")
		}
		if !l.isMinter(b.Account) {
			return fmt.Errorf("staged mint: account %s is not an authorized minter", shortAddr(b.Account))
		}
		if b.Amount == 0 {
			return fmt.Errorf("staged mint: amount must be > 0")
		}
		expectedBal := parentBalance + b.Amount
		if expectedBal < parentBalance {
			return fmt.Errorf("staged mint: balance would overflow uint64")
		}
		if b.Balance != expectedBal {
			return fmt.Errorf("staged mint: balance mismatch: expected %d, got %d", expectedBal, b.Balance)
		}
	default:
		return fmt.Errorf("staged block: unknown type: %s", b.Type)
	}
	return nil
}

// SwapBlock replaces a block at the given position in an account's chain with a
// new block. This is used by consensus to promote a staged winner over the
// incumbent loser. The caller must ensure the swap is semantically valid.
func (l *Ledger) SwapBlock(account string, oldHash, newHash string, newBlock *Block) error {
	if err := VerifyBlock(newBlock); err != nil {
		return fmt.Errorf("SwapBlock: verify replacement: %w", err)
	}

	entry := l.acquireAccountLock(account)
	defer l.releaseAccountLock(account, entry)

	return l.swapBlockLocked(account, oldHash, newHash, newBlock)
}

// ErrWinnerFullValidation marks a conflict winner that re-ran full validation
// during promotion (swapBlockLocked) and was rejected — as opposed to the swap
// failing for a structural/store reason. confirmConflict's caller (#673) uses
// it, together with IsRetryableError, to decide whether the failure is a
// DETERMINISTIC reject that may be quarantined.
var ErrWinnerFullValidation = errors.New("winner failed full validation")

// swapBlockLocked performs the swap assuming the account lock is already held.
func (l *Ledger) swapBlockLocked(account string, oldHash, newHash string, newBlock *Block) error {
	chain, err := l.store.GetAccountChain(account)
	if err != nil {
		return fmt.Errorf("SwapBlock: GetAccountChain: %w", err)
	}
	if chain == nil {
		return fmt.Errorf("SwapBlock: account %s not found", shortAddr(account))
	}

	idx := -1
	var oldBlock *Block
	for i, b := range chain.Blocks {
		if b.Hash == oldHash {
			idx = i
			oldBlock = b
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("SwapBlock: block %s not found in chain", shortHash(oldHash))
	}

	// Finality wall (#525): a finalized block is irreversible. Refuse — do not
	// panic — to replace any block at or below the account's final height. In
	// correct operation this is unreachable (a position is only finalized once
	// its fork, if any, is resolved); it is the structural backstop that makes
	// "finalized ⇒ never reorged" a hard guarantee. Re-checked here on every
	// swap so future cascading rollback (#527) inherits the same refusal.
	if l.finalStore != nil {
		fh, _ := l.finalStore.GetFinalHeight(account)
		if uint64(idx+1) <= fh {
			return fmt.Errorf("SwapBlock: refusing to replace finalized block %s at height %d (final height %d)",
				shortHash(oldHash), idx+1, fh)
		}
	}

	// Plan ALL rollback work read-only (validating finality, supported types,
	// and no cycle) BEFORE mutating, so an unsafe swap is refused cleanly with
	// no partial state. Two sources of rollback:
	//
	// #570/C2: a non-frontier swap is a reorg. The loser's same-account
	// descendants reference it by Previous and cannot survive its replacement
	// — left in place they dangle (Previous points at a removed block) while
	// the balance cache takes newBlock.Balance, and a descendant send already
	// received cross-account leaves the recipient credit over a broken chain
	// segment (the #518 double-spend). Unwind them tail-first with the same
	// undo machinery as the cross-account cascade; they are NOT replayed on
	// top of the winner (equivocation forfeits descendants, consistent with
	// the conflict model). Descendants with side effects the undo cannot
	// reverse (lease lifecycle, multisig) refuse the swap.
	//
	// #527 cascade: if the loser send (or an unwound descendant send) was
	// already received, roll back the consuming receive (and anything built
	// on it) on the recipient's chain — re-creating the send's pending, which
	// the undo/commit below then deletes.
	// `planned` dedups the whole rollback walk by block hash (#691): the loser's
	// same-account descendants here and the cross-account cone below share it, so a
	// cycle that loops back into an already-slated account is a no-op rather than a
	// refusal. Mark before recursing (so a cyclic re-entry cannot re-process a
	// block), append after (consumer before the send it consumed).
	planned := map[string]bool{}
	var plan []cascadeStep
	for i := len(chain.Blocks) - 1; i > idx; i-- {
		b := chain.Blocks[i]
		if planned[b.Hash] {
			continue // already slated by a cross-account cycle reaching back into this account
		}
		switch b.Type {
		case BlockSend, BlockReceive, BlockBurn, BlockMint:
			// reversible by undoBlockApply
		default:
			return fmt.Errorf("SwapBlock: cannot unwind descendant %q (%s) of the replaced block — reversing its side-effects is not yet implemented", b.Type, shortHash(b.Hash))
		}
		planned[b.Hash] = true
		if b.Type == BlockSend {
			if ps, _ := l.store.GetPendingSend(b.Hash); ps == nil {
				if err := l.planRollbackOfSend(b.Hash, planned, &plan); err != nil {
					return fmt.Errorf("SwapBlock: %w", err)
				}
			}
		}
		plan = append(plan, cascadeStep{account: account, b: b})
	}
	if oldBlock.Type == BlockSend {
		oldPlan, perr := l.planCascade(oldBlock.Hash, planned)
		if perr != nil {
			return fmt.Errorf("SwapBlock: %w", perr)
		}
		plan = append(plan, oldPlan...)
	}
	// #622: the loser's own unwind is the final cascade step on `account` (after
	// all its same-account descendants). Appending it here lets a single build
	// loop produce every undo in apply order, so the whole promotion — the loser,
	// the cross-account cascade, AND the winner re-apply — lands in ONE store
	// transaction (CommitCascade) instead of one txn per step. A crash mid-
	// promotion used to strand the account half-promoted (the cascade unwound on
	// disk, no winner); now it is all-or-nothing.
	plan = append(plan, cascadeStep{account: account, b: oldBlock})

	// Acquire every FOREIGN account's lock (the origin `account` is already held by
	// the caller). With #691 a cycle now brings several foreign accounts into one
	// promotion, so acquire them in a canonical (sorted) order — the swap cascade
	// is the only path that holds more than one account lock at once, so sorted
	// acquisition makes self-deadlock impossible. Hold them until the END of the
	// promotion — not just the unwind — so the winner re-validation reads a stable
	// cascade overlay. confirmConflict is serialized by the quorum lock, so no two
	// promotions run concurrently.
	type heldLock struct {
		acc   string
		entry *accountLock
	}
	seenLock := map[string]bool{}
	var foreign []string
	for _, st := range plan {
		if st.account == account || seenLock[st.account] {
			continue
		}
		seenLock[st.account] = true
		foreign = append(foreign, st.account)
	}
	sort.Strings(foreign)
	var locks []heldLock
	for _, acc := range foreign {
		locks = append(locks, heldLock{acc, l.acquireAccountLock(acc)})
	}
	defer func() {
		for i := len(locks) - 1; i >= 0; i-- {
			l.releaseAccountLock(locks[i].acc, locks[i].entry)
		}
	}()

	// Build every undo (NO store write yet) against running per-account chain
	// snapshots: seed each account's snapshot from the store on first touch, and
	// truncate as we go so several undos on one account see the previous build's
	// truncation (the plan is head-first within an account, so the next step's
	// block is the truncated tail). buildBlockUndo derives all balance inputs
	// from these snapshots, not the in-memory map, precisely so this ordering
	// works before anything is committed (#622).
	cascade := newCascadeBuild(newHash)
	snapshots := map[string]*AccountChain{}
	for _, st := range plan {
		snap, ok := snapshots[st.account]
		if !ok {
			s, serr := l.store.GetAccountChain(st.account)
			if serr != nil {
				return fmt.Errorf("SwapBlock: GetAccountChain(%s): %w", shortAddr(st.account), serr)
			}
			if s == nil {
				return fmt.Errorf("SwapBlock: account %s vanished under the cascade", shortAddr(st.account))
			}
			snap = s
			snapshots[st.account] = snap
		}
		undo, apply, berr := l.buildBlockUndo(st.account, st.b, snap)
		if berr != nil {
			return fmt.Errorf("SwapBlock: build undo for %s: %w", shortHash(st.b.Hash), berr)
		}
		cascade.addUndo(undo, apply)
		// Truncate the running snapshot to the post-undo chain so the next undo
		// on this account is built against it.
		snapshots[st.account] = undo.Chain
	}

	// Activate the overlay so the winner re-validation reads the post-undo state
	// (truncated chains, re-created pendings, reversed lease/keyset side effects).
	// Erroring here means a promotion was already active — impossible under the
	// quorum lock, so fail loudly rather than corrupt (#622).
	if err := l.activateCascade(cascade); err != nil {
		return fmt.Errorf("SwapBlock: %w", err)
	}

	// #570/C1 + #622: re-apply the winner through the exact live validation+commit
	// path (dispatchValidateAndAdd). prepareBlockWrite/commitBlockWrite read the
	// overlay, and commitBlockWrite intercepts THIS winner's commit to land the
	// whole cascade (undos + winner) in one CommitCascade transaction. Full
	// validation still runs, so the #614 guarantees hold: an equivocated
	// lease_settle minting XE, or a winning lease_accept leaving no Lease record,
	// are rejected/emitted exactly as on the live add path.
	if err := l.dispatchValidateAndAdd(newBlock, true); err != nil {
		// The winner failed full validation (e.g. the equivocated-mint attack), or
		// CommitCascade failed. NOTHING was written and NO in-memory state was
		// mutated (the undos' memApplies run only inside the successful commit
		// interception). The loser and its entire cascade therefore remain fully
		// intact on disk and in memory — so we simply deactivate the overlay and
		// refuse. (#622: this replaces the old unwind-loser-then-restore-loser
		// dance, which mutated the store before re-adding the loser and could
		// itself fail; the refusal now leaves pre-promotion state byte-identical.)
		l.deactivateCascade()
		return fmt.Errorf("SwapBlock: %w %s, loser kept: %w", ErrWinnerFullValidation, shortHash(newHash), err)
	}
	// On success the commit interception already committed the spanning txn,
	// applied every undo's in-memory deltas, and cleared the active cascade.
	// Deactivate defensively (idempotent) and release the foreign locks (defer).
	l.deactivateCascade()
	return nil
}

// GetBlockHeight returns the 1-based index of blockHash in the account's chain,
// or an error if the block is not found.
// GetAssetBalanceAtBlock walks the account's chain up to and including the
// block identified by blockHash, returning the most recent balance for the
// given asset. Returns 0 if no block with that asset exists before the target.
//
// #674: for XUSD it also adds back the lease_settle stake returns encountered
// along the way (they ride on XE blocks and are invisible to a plain balance
// walk), matching rebuildAssetBalances. The quorum conflict-resolution path uses
// this as the parent balance when validating a staged winner; without the stake
// re-add a winning XUSD block stacked above a settle is validated against a
// stake-short parent and wrongly refused.
func (l *Ledger) GetAssetBalanceAtBlock(account, asset, blockHash string) uint64 {
	chain, err := l.store.GetAccountChain(account)
	if err != nil || chain == nil {
		return 0
	}
	ls, hasLeases := l.store.(LeaseStore)
	xusd := asset == "XUSD"
	var bal uint64
	for _, b := range chain.Blocks {
		a := b.Asset
		if a == "" {
			a = "XE"
		}
		if a == asset {
			bal = b.Balance
		}
		if xusd && b.Type == BlockLeaseSettle && hasLeases {
			if lease, lerr := ls.GetLease(b.Source); lerr == nil && lease != nil {
				bal += lease.Stake
			}
		}
		if b.Hash == blockHash {
			break
		}
	}
	return bal
}

func (l *Ledger) GetBlockHeight(account, blockHash string) (uint64, error) {
	chain, err := l.store.GetAccountChain(account)
	if err != nil {
		return 0, fmt.Errorf("GetBlockHeight: GetAccountChain: %w", err)
	}
	if chain == nil {
		return 0, fmt.Errorf("GetBlockHeight: account %s not found", shortAddr(account))
	}
	for i, b := range chain.Blocks {
		if b.Hash == blockHash {
			return uint64(i + 1), nil
		}
	}
	return 0, fmt.Errorf("GetBlockHeight: block %s not found in account %s", shortHash(blockHash), shortAddr(account))
}

// FinalHeight returns the account's final-height watermark: the 1-based height
// up to and including which every block on the account's chain is finalized
// (irreversible). Returns 0 when nothing on the account is finalized. Because
// the watermark is a single integer, finalized history can never have gaps.
// See #525.
func (l *Ledger) FinalHeight(account string) uint64 {
	if l.finalStore == nil {
		return 0
	}
	h, err := l.finalStore.GetFinalHeight(account)
	if err != nil {
		return 0
	}
	return h
}

// IsFinalized reports whether the given block is finalized: its height is at or
// below its account's final-height watermark. A finalized block can never be
// reorged (see the finality wall in swapBlockLocked). Returns false if the block
// is not on the account's chain. See #525.
func (l *Ledger) IsFinalized(account, blockHash string) bool {
	h, err := l.GetBlockHeight(account, blockHash)
	if err != nil || h == 0 {
		return false
	}
	return h <= l.FinalHeight(account)
}

// FinalizedChildHash returns the hash of the on-chain child at (account, prev) —
// the block whose Previous is `prev` (or the height-1 block when prev is the open
// position "0"/"") — but only when that child is finalized (at or below the
// account's final-height watermark). Returns "" otherwise. Used to detect a
// conflict whose position has already been finalized so its lingering record can
// be cleaned even after the votes that would re-confirm it were deleted. (#707)
func (l *Ledger) FinalizedChildHash(account, prev string) string {
	chain, err := l.store.GetAccountChain(account)
	if err != nil || chain == nil {
		return ""
	}
	open := prev == "" || prev == "0"
	fh := l.FinalHeight(account)
	for i, b := range chain.Blocks {
		if b.Previous == prev || (open && i == 0) {
			if uint64(i+1) <= fh {
				return b.Hash
			}
			return ""
		}
	}
	return ""
}
