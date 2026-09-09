package core

import "errors"

type Store interface {
	GetBlock(hash string) (*Block, error)
	PutBlock(block *Block) error
	GetAccountChain(account string) (*AccountChain, error)
	PutAccountChain(account string, chain *AccountChain) error
	GetPendingSend(sendHash string) (*PendingSend, error)
	PutPendingSend(ps *PendingSend) error
	DeletePendingSend(sendHash string) error
	GetPendingByDest(account string) ([]*PendingSend, error)
	GetAllPending() ([]*PendingSend, error)
	PutFrontier(account string, blockHash string) error
	GetFrontier(account string) (string, error)

	CommitUndo(u *BlockUndo) error
	IsEmpty() (bool, error)
	Close() error
}

type QuorumStore interface {
	SetBlockStatus(hash string, status BlockStatus) error
	GetBlockStatus(hash string) (BlockStatus, error)
	SetFinalHeight(account string, height uint64) error
	GetFinalHeight(account string) (uint64, error)
	DeleteVotesForConflict(account, previous string) error
}

type FinalVoteStore interface {
	GetFinalVote(account, previous string) (hash string, ok bool, err error)

	PutFinalVoteIfAbsent(account, previous, hash string) (stored string, written bool, err error)
}

type Syncer interface {
	Sync() error
}

type DelegationStore interface {
	PutDelegation(account, representative string) error
	DeleteDelegation(account string) error
}

type DelegationIterator interface {
	IterateDelegations(fn func(account, representative string) error) error
}

type FrontierLister interface {
	AllFrontiers() map[string]string
}

type CertificateStore interface {
	PutCertificate(hash string, data []byte) error
	CertificateByHash(hash string) ([]byte, error)
	DeleteCertificate(hash string) error
	AllCertificates() (map[string][]byte, error)
}

type LeaseStore interface {
	PutLease(lease *Lease) error
	GetLease(leaseHash string) (*Lease, error)
	GetLeasesByProvider(provider string) ([]*Lease, error)
	GetLeasesByState(state LeaseState) ([]*Lease, error)
	GetAllLeases() ([]*Lease, error)
}

type ReputationStore interface {
	PutReputation(account string, agg *ReputationAggregate) error
	GetReputation(account string) (*ReputationAggregate, error)
	GetAllReputations() (map[string]*ReputationAggregate, error)
	DeleteReputation(account string) error
}

type KeysetStore interface {
	PutKeyset(account string, keyset *Keyset) error
	GetKeyset(account string) (*Keyset, error)
}

type AccountKeyStore interface {
	PutAccountKey(account, pubKey string) error
	GetAccountKey(account string) (string, error)
	DeleteAccountKey(account string) error
	AllAccountKeys() (map[string]string, error)
}

type BlockCommit struct {
	Block              *Block
	Account            string
	Chain              *AccountChain
	FrontierHash       string
	AddPending         *PendingSend
	DeletePendingID    string
	PutLease           *Lease
	SettleLeaseHash    string
	CancelLeaseHash    string
	UnfulfillLeaseHash string
	DelegationRep      string
	DeleteDelegation   bool
	PutKeyset          *Keyset

	PutAccountKey string

	ExpectLeaseHash  string
	ExpectLeaseState LeaseState

	AssetCredit *AssetDelta
}

type AssetDelta struct {
	Account string
	Asset   string
	Amount  uint64
}

var ErrLeaseStateConflict = errors.New("lease state conflict")

type AtomicBlockStore interface {
	CommitBlock(c *BlockCommit) error

	CommitCascade(undos []*BlockUndo, commit *BlockCommit) error
}

type BlockUndo struct {
	Account         string
	Chain           *AccountChain
	FrontierHash    string
	AddPending      *PendingSend
	DeletePendingID string
	RejectHash      string

	DeleteAccount bool

	RestoreDelegation bool
	PrevRep           string

	RestoreLease        *Lease
	DeleteLeaseHash     string
	DeleteKeysetAccount string

	DeleteAccountKeyAccount string

	AssetDebit *AssetDelta
}
