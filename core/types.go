package core

import "time"

// Conflict captures a detected equivocation: two or more blocks on the same
// account that share the same Previous hash (i.e. they compete to extend the
// same parent). The conflicting blocks are held in staging; only the original
// block that is already on the main chain is confirmed.
type Conflict struct {
	AccountAddress string            `json:"account_address"`
	PreviousHash   string            `json:"previous_hash"`
	BlockHashes    []string          `json:"block_hashes"`
	DetectedAt     time.Time         `json:"detected_at"`
	WeightSnapshot map[string]uint64 `json:"weight_snapshot,omitempty"`
	TotalWeight    uint64            `json:"total_weight,omitempty"`
}

// ConflictStore is an optional interface for stores that support persisting
// conflict (equivocation) records and staging conflicting blocks.
type ConflictStore interface {
	SaveConflict(c *Conflict) error
	GetConflict(account, previousHash string) (*Conflict, error)
	DeleteConflict(account, previousHash string) error
	GetConflictsForAccount(account string) ([]*Conflict, error)
	GetAllConflicts() ([]*Conflict, error)

	SaveStagedBlock(b *Block) error
	GetStagedBlock(hash string) (*Block, error)
	DeleteStagedBlock(hash string) error
}

type BlockType string

const (
	BlockSend             BlockType = "send"
	BlockReceive          BlockType = "receive"
	BlockMint             BlockType = "mint"
	BlockGenesis          BlockType = "genesis"
	BlockBurn             BlockType = "burn"
	BlockLease            BlockType = "lease"
	BlockLeaseAccept      BlockType = "lease_accept"
	BlockLeaseSettle      BlockType = "lease_settle"
	BlockLeaseCancel      BlockType = "lease_cancel"
	BlockLeaseForceSettle BlockType = "lease_force_settle"
	BlockMultisigOpen     BlockType = "multisig_open"
	BlockMultisigUpdate   BlockType = "multisig_update"
)

// validAssets is the allowlist of supported asset identifiers.
var validAssets = map[string]bool{
	"XE":   true,
	"XUSD": true,
}

// IsValidAsset reports whether the given asset identifier is supported.
func IsValidAsset(asset string) bool {
	return validAssets[asset]
}

// Keyset defines an M-of-N multisig key set.
type Keyset struct {
	Keys      []string `json:"keys"`      // hex-encoded ed25519 public keys
	Threshold int      `json:"threshold"` // minimum signatures required
}

// BlockSignature is a single signature from a multisig keyset member.
type BlockSignature struct {
	PublicKey string `json:"public_key"` // hex-encoded ed25519 pubkey
	Sig       string `json:"signature"`  // hex-encoded ed25519 signature
}

// Block lives on exactly one account's chain.
// Send blocks debit the sender; receive blocks credit the recipient.
type Block struct {
	Type      BlockType `json:"type"`
	Account   string    `json:"account"`   // account address: sha256("xe/account/v1" || pubkey), or the multisig keyset digest
	Previous  string    `json:"previous"`  // hash of previous block on this chain ("0" for open)
	Balance   uint64    `json:"balance"`   // balance AFTER this block
	Timestamp int64     `json:"timestamp"` // unix nanos
	Asset     string    `json:"asset"`     // asset identifier (e.g. "XE", "XUSD")

	// Delegation: the representative this account votes with.
	// Must be a 32-byte account address (64 hex chars) or "" for no delegation.
	Representative string `json:"representative,omitempty"`

	// Send fields
	Destination string `json:"destination,omitempty"` // recipient account address
	Amount      uint64 `json:"amount,omitempty"`      // tokens sent

	// Receive field
	Source string `json:"source,omitempty"` // hash of the send block being received

	// Lease fields
	VCPUs        uint64 `json:"vcpus,omitempty"`          // virtual CPUs
	MemoryMB     uint64 `json:"memory_mb,omitempty"`      // memory in megabytes
	DiskGB       uint64 `json:"disk_gb,omitempty"`        // disk in gigabytes
	Duration     uint64 `json:"duration,omitempty"`       // lease duration in seconds
	AccessPubKey string `json:"access_pub_key,omitempty"` // raw ed25519 public key for access auth (hex, 32 bytes)

	// Genesis lease-timing fields (#524, #662). Valid on the genesis block only;
	// they pin the network's lease timing so a compressed test network is a
	// different genesis, not a different binary. Each is OPTIONAL: a zero value
	// means "use the production default" (see DefaultLease* / DefaultMaxAttestationSkew).
	// When ALL are zero they add nothing to the canonical bytes, so a genesis that
	// omits them hashes identically to a pre-#524 genesis — existing networks are
	// unaffected. Units match the vars they feed: min-duration in seconds, the rest
	// in nanos. MaxAttestationSkewNs (#662) is consensus-critical — it gates
	// ValidateAttestations — and pinning it lets the force-settle gap shrink below
	// the production 20-minute floor (ValidateGenesisBlock enforces
	// LeaseForceSettleGap > 2×MaxAttestationSkew against the genesis-pinned skew).
	LeaseMinDurationSecs  uint64 `json:"lease_min_duration_secs,omitempty"`
	LeaseSettleGraceNs    int64  `json:"lease_settle_grace_ns,omitempty"`
	LeaseForceSettleGapNs int64  `json:"lease_force_settle_gap_ns,omitempty"`
	LeaseEscrowExpiryNs   int64  `json:"lease_escrow_expiry_ns,omitempty"`
	LeaseArchiveGapNs     int64  `json:"lease_archive_gap_ns,omitempty"`
	MaxAttestationSkewNs  int64  `json:"max_attestation_skew_ns,omitempty"`

	// Memo is an optional, clear-text annotation attached to user-initiated
	// transactions. Allowed on send and burn blocks only. Bounded at 64 bytes;
	// must be valid UTF-8. Hashed as part of canonical block bytes when
	// non-empty (see #412).
	Memo string `json:"memo,omitempty"`

	// Multisig fields
	MSKeyset   *Keyset          `json:"keyset,omitempty"`     // keyset for multisig_open / multisig_update
	Signatures []BlockSignature `json:"signatures,omitempty"` // multisig signatures (replaces Signature)

	// PubKey is the account's ed25519 public key, declared by the FIRST block on
	// a single-key account chain (Previous == "0") and by no other block (#829).
	// Since an address is sha256("xe/account/v1" || pubkey) the account field no
	// longer carries the verifying key, so the opening block must publish it:
	// validation asserts DeriveAddress(PubKey) == Account, the ledger persists
	// account → PubKey, and every later block on the chain verifies against the
	// STORED key. Bound into the block hash via MarshalBlockAux so it cannot be
	// rewritten in transit. Empty on multisig blocks (their credential is the
	// keyset, and their address commits to it via DeriveMultisigAddress).
	PubKey string `json:"pub_key,omitempty"` // hex-encoded ed25519 public key (open blocks only)

	Signature string `json:"signature,omitempty"` // hex-encoded ed25519 signature (single-key accounts)
	Hash      string `json:"hash"`                // hex-encoded SHA-256 of the block content

	// Anti-spam proof-of-work nonce. Excluded from Hash computation.
	PoWNonce uint64 `json:"pow_nonce,omitempty"`

	// Attestations from timekeepers for lease_accept and lease_settle blocks.
	// Excluded from Hash computation (attached after signing).
	Attestations []TimekeeperAttestation `json:"attestations,omitempty"`

	// CertificateHash references the provider's performance certificate.
	// Required on lease_accept blocks. Excluded from Hash computation.
	CertificateHash string `json:"certificate_hash,omitempty"`

	// Locked emission parameters, set by the provider on lease_accept blocks
	// from the epoch active at accept time. Unlike CertificateHash/Attestations
	// these ARE included in the canonical (signed, hashed) bytes — see
	// MarshalBlockCanonical — so every node records identical settle-rate inputs
	// regardless of which epoch it is in when it applies the accept (#501).
	// Settle emission is computed from the lease record's locked params (#434).
	LockedR         uint64 `json:"locked_r,omitempty"`          // R_effective at accept, ×1000
	LockedPayoutCap uint64 `json:"locked_payout_cap,omitempty"` // Hermite payout cap at accept, ×1000
	LockedTWAP      uint64 `json:"locked_twap_milli,omitempty"` // TWAP at accept, milli-USD
}

// TimekeeperAttestation is a signed timestamp from a trusted timekeeper node.
// The signed payload is sha256(lease_hash_bytes || timestamp_big_endian_8_bytes).
type TimekeeperAttestation struct {
	PublicKey string `json:"public_key"` // hex ed25519 pubkey of timekeeper
	Timestamp int64  `json:"timestamp"`  // unix nanos attested
	Signature string `json:"signature"`  // hex ed25519 sig over attestation payload
}

// TimekeeperConfig holds the set of trusted timekeeper public keys and
// the threshold of attestations required.
type TimekeeperConfig struct {
	Keys      []string `json:"keys"`      // hex ed25519 pubkeys
	Threshold int      `json:"threshold"` // required attestation count
}

// AccountChain is an ordered list of blocks for one account.
type AccountChain struct {
	Blocks []*Block
}

// Frontier returns the hash of the latest block, or "0" if the chain is empty.
func (c *AccountChain) Frontier() string {
	if len(c.Blocks) == 0 {
		return "0"
	}
	return c.Blocks[len(c.Blocks)-1].Hash
}

// LatestBalance returns the balance after the latest block, or 0 if empty.
func (c *AccountChain) LatestBalance() uint64 {
	if len(c.Blocks) == 0 {
		return 0
	}
	return c.Blocks[len(c.Blocks)-1].Balance
}

// PendingSend tracks an unreceived send block.
type PendingSend struct {
	SendHash    string
	Source      string // sender account
	Destination string
	Amount      uint64
	Asset       string // asset identifier (e.g. "XE", "XUSD")
}

// Vote represents a representative's vote for a block at a chain position
// (the root = ConflictAccount + ConflictPrev). Two-phase (#526): a converge vote
// (Final=false) is mutable — a rep may revote to follow the emerging leader — and
// a final vote (Final=true) is irrevocable, backed by the write-once commit-lock.
// Only final votes finalize a block; converge votes only establish the leader.
type Vote struct {
	RepPubKey       string // hex-encoded ed25519 public key of the representative
	BlockHash       string // hex-encoded hash of the block voted for
	ConflictAccount string // account address of the conflict
	ConflictPrev    string // previous hash of the conflict
	Timestamp       int64  // unix nanoseconds
	Final           bool   // true = final (irrevocable) vote; false = converge vote. Signed. (#526)
	Signature       []byte // ed25519 signature over voteSigningBytes
	Weight          uint64 // vote weight snapshot at cast time (not signed)
}

// VoteStore is an optional interface for stores that support persisting votes.
type VoteStore interface {
	PutVote(vote *Vote) error
	GetVotesByConflict(account, previous string) ([]*Vote, error)
	HasVoted(account, previous, repPubKey string) (bool, error)
	// GetVote returns the representative's current vote at a position, or nil if
	// none. Two-phase finalization keeps one evolving slot per rep: a converge
	// vote (Final=false, mutable) may be replaced or promoted to a final vote
	// (Final=true, irrevocable). Callers read this to enforce that a final vote
	// is never overwritten. (#526)
	GetVote(account, previous, repPubKey string) (*Vote, error)
}

type LeaseState string

const (
	LeaseCreated     LeaseState = "created"
	LeaseAccepted    LeaseState = "accepted"
	LeaseSettled     LeaseState = "settled"
	LeaseCancelled   LeaseState = "cancelled"
	LeaseUnfulfilled LeaseState = "unfulfilled"
	// LeaseExpired marks a lease whose escrow refund window closed with neither
	// party settling (#493, outcome #4). The escrow is burnt and the record
	// archived by a local node sweep. It is reputation-neutral: accountability
	// for abandonment is handled only via a resolved dispute (#506), never here.
	LeaseExpired LeaseState = "expired"
)

// Terminal reports whether the lease state is final (settled, cancelled,
// unfulfilled, or expired). Activity bucketing must use this rather than the
// legacy Settled bool, which stays false for cancelled leases (cancel sets
// only State) and so miscounts them as active (#755, #758).
//
// If you add a lease state, update BOTH this and isLiveLeaseEscrow
// (ledger.go) — over the valid states they are exact complements, verified by
// TestLeaseStatePartition (#763).
func (s LeaseState) Terminal() bool {
	switch s {
	case LeaseSettled, LeaseCancelled, LeaseUnfulfilled, LeaseExpired:
		return true
	}
	return false
}

var ValidLeaseStates = map[LeaseState]bool{
	LeaseCreated:     true,
	LeaseAccepted:    true,
	LeaseSettled:     true,
	LeaseCancelled:   true,
	LeaseUnfulfilled: true,
	LeaseExpired:     true,
}

// Lease tracks a compute lease between a consumer and provider.
type Lease struct {
	LeaseHash       string     `json:"lease_hash"` // hash of the lease block
	State           LeaseState `json:"state"`      // created, accepted, settled, cancelled, unfulfilled
	Consumer        string     `json:"consumer"`   // consumer account (lease block creator)
	Provider        string     `json:"provider"`   // provider account (lease block destination)
	VCPUs           uint64     `json:"vcpus"`
	MemoryMB        uint64     `json:"memory_mb"`
	DiskGB          uint64     `json:"disk_gb"`
	Duration        uint64     `json:"duration"`                   // seconds
	AccessPubKey    string     `json:"access_pub_key,omitempty"`   // raw ed25519 public key for access auth
	Cost            uint64     `json:"cost"`                       // XUSD paid by consumer
	Stake           uint64     `json:"stake"`                      // XUSD staked by provider
	StartTime       int64      `json:"start_time"`                 // unix nanos when lease was accepted
	CertificateHash string     `json:"certificate_hash,omitempty"` // provider's performance certificate
	Settled         bool       `json:"settled"`

	// Locked emission parameters captured at lease_accept time. Settle uses
	// these instead of current network state so the lease's XE emission is a
	// function of its own properties, not joint with whatever epoch is active
	// at settle time. Zero values indicate a pre-locking legacy lease, in
	// which case settle falls back to the current epoch (see #401).
	LockedR         uint64 `json:"locked_r,omitempty"`          // R_effective at accept, ×1000
	LockedPayoutCap uint64 `json:"locked_payout_cap,omitempty"` // Hermite cap at accept, ×1000
	LockedTWAP      uint64 `json:"locked_twap_milli,omitempty"` // TWAP at accept, milli-USD
}

// BackfillState sets State from the Settled bool for pre-#463 lease records.
func (l *Lease) BackfillState() {
	if l.State != "" {
		return
	}
	if l.Settled {
		l.State = LeaseSettled
	} else {
		l.State = LeaseAccepted
	}
}

// CertificateInfo is a minimal view of a performance certificate used
// by the ledger for lease and lease_accept validation. Avoids importing
// the perf package (which imports core).
type CertificateInfo struct {
	Provider             string // provider account (must match lease_accept creator)
	ExpiresAt            int64  // certificate expiry (must be after lease accept time)
	PriceMultiplierMilli uint64 // scales baseline lease cost, ×1000; zero = baseline (1000). See perf.Certificate.
}

// Now is a replaceable clock for testing.
var Now = func() time.Time { return time.Now() }
