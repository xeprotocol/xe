package core

import "time"

type Conflict struct {
	AccountAddress string            `json:"account_address"`
	PreviousHash   string            `json:"previous_hash"`
	BlockHashes    []string          `json:"block_hashes"`
	DetectedAt     time.Time         `json:"detected_at"`
	WeightSnapshot map[string]uint64 `json:"weight_snapshot,omitempty"`
	TotalWeight    uint64            `json:"total_weight,omitempty"`
}

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

var validAssets = map[string]bool{
	"XE":   true,
	"XUSD": true,
}

func IsValidAsset(asset string) bool {
	return validAssets[asset]
}

type Keyset struct {
	Keys      []string `json:"keys"`
	Threshold int      `json:"threshold"`
}

type BlockSignature struct {
	PublicKey string `json:"public_key"`
	Sig       string `json:"signature"`
}

type Block struct {
	Type      BlockType `json:"type"`
	Account   string    `json:"account"`
	Previous  string    `json:"previous"`
	Balance   uint64    `json:"balance"`
	Timestamp int64     `json:"timestamp"`
	Asset     string    `json:"asset"`

	Representative string `json:"representative,omitempty"`

	Destination string `json:"destination,omitempty"`
	Amount      uint64 `json:"amount,omitempty"`

	Source string `json:"source,omitempty"`

	VCPUs        uint64 `json:"vcpus,omitempty"`
	MemoryMB     uint64 `json:"memory_mb,omitempty"`
	DiskGB       uint64 `json:"disk_gb,omitempty"`
	Duration     uint64 `json:"duration,omitempty"`
	AccessPubKey string `json:"access_pub_key,omitempty"`

	LeaseMinDurationSecs  uint64 `json:"lease_min_duration_secs,omitempty"`
	LeaseSettleGraceNs    int64  `json:"lease_settle_grace_ns,omitempty"`
	LeaseForceSettleGapNs int64  `json:"lease_force_settle_gap_ns,omitempty"`
	LeaseEscrowExpiryNs   int64  `json:"lease_escrow_expiry_ns,omitempty"`
	LeaseArchiveGapNs     int64  `json:"lease_archive_gap_ns,omitempty"`
	MaxAttestationSkewNs  int64  `json:"max_attestation_skew_ns,omitempty"`

	Memo string `json:"memo,omitempty"`

	MSKeyset   *Keyset          `json:"keyset,omitempty"`
	Signatures []BlockSignature `json:"signatures,omitempty"`

	PubKey string `json:"pub_key,omitempty"`

	Signature string `json:"signature,omitempty"`
	Hash      string `json:"hash"`

	PoWNonce uint64 `json:"pow_nonce,omitempty"`

	Attestations []TimekeeperAttestation `json:"attestations,omitempty"`

	CertificateHash string `json:"certificate_hash,omitempty"`

	LockedR         uint64 `json:"locked_r,omitempty"`
	LockedPayoutCap uint64 `json:"locked_payout_cap,omitempty"`
	LockedTWAP      uint64 `json:"locked_twap_milli,omitempty"`
}

type TimekeeperAttestation struct {
	PublicKey string `json:"public_key"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

type TimekeeperConfig struct {
	Keys      []string `json:"keys"`
	Threshold int      `json:"threshold"`
}

type AccountChain struct {
	Blocks []*Block
}

func (c *AccountChain) Frontier() string {
	if len(c.Blocks) == 0 {
		return "0"
	}
	return c.Blocks[len(c.Blocks)-1].Hash
}

func (c *AccountChain) LatestBalance() uint64 {
	if len(c.Blocks) == 0 {
		return 0
	}
	return c.Blocks[len(c.Blocks)-1].Balance
}

type PendingSend struct {
	SendHash    string
	Source      string
	Destination string
	Amount      uint64
	Asset       string
}

type Vote struct {
	RepPubKey       string
	BlockHash       string
	ConflictAccount string
	ConflictPrev    string
	Timestamp       int64
	Final           bool
	Signature       []byte
	Weight          uint64
}

type VoteStore interface {
	PutVote(vote *Vote) error
	GetVotesByConflict(account, previous string) ([]*Vote, error)
	HasVoted(account, previous, repPubKey string) (bool, error)

	GetVote(account, previous, repPubKey string) (*Vote, error)
}

type LeaseState string

const (
	LeaseCreated     LeaseState = "created"
	LeaseAccepted    LeaseState = "accepted"
	LeaseSettled     LeaseState = "settled"
	LeaseCancelled   LeaseState = "cancelled"
	LeaseUnfulfilled LeaseState = "unfulfilled"

	LeaseExpired LeaseState = "expired"
)

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

type Lease struct {
	LeaseHash       string     `json:"lease_hash"`
	State           LeaseState `json:"state"`
	Consumer        string     `json:"consumer"`
	Provider        string     `json:"provider"`
	VCPUs           uint64     `json:"vcpus"`
	MemoryMB        uint64     `json:"memory_mb"`
	DiskGB          uint64     `json:"disk_gb"`
	Duration        uint64     `json:"duration"`
	AccessPubKey    string     `json:"access_pub_key,omitempty"`
	Cost            uint64     `json:"cost"`
	Stake           uint64     `json:"stake"`
	StartTime       int64      `json:"start_time"`
	CertificateHash string     `json:"certificate_hash,omitempty"`
	Settled         bool       `json:"settled"`

	LockedR         uint64 `json:"locked_r,omitempty"`
	LockedPayoutCap uint64 `json:"locked_payout_cap,omitempty"`
	LockedTWAP      uint64 `json:"locked_twap_milli,omitempty"`
}

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

type CertificateInfo struct {
	Provider             string
	ExpiresAt            int64
	PriceMultiplierMilli uint64
}

var Now = func() time.Time { return time.Now() }
