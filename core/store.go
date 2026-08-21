package core

import "errors"

// Store is the persistence interface for the block lattice.
// All Get methods return (nil, nil) on a cache miss (not found).
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
	GetFrontier(account string) (string, error) // empty string on miss
	// CommitUndo applies a block rollback — chain truncation, frontier,
	// pending add/delete, reject status, and delegation restore — in ONE
	// atomic transaction. Part of the required interface: separate writes
	// reopen the #570/H5 double-receive crash window, so there is
	// deliberately no non-atomic fallback (#597).
	CommitUndo(u *BlockUndo) error
	IsEmpty() (bool, error)
	Close() error
}

// QuorumStore is an optional interface for stores that support persisting
// block finalization status and per-account final heights (#525).
type QuorumStore interface {
	SetBlockStatus(hash string, status BlockStatus) error
	GetBlockStatus(hash string) (BlockStatus, error) // returns StatusPending if not found
	SetFinalHeight(account string, height uint64) error
	GetFinalHeight(account string) (uint64, error) // returns 0 if not found
	DeleteVotesForConflict(account, previous string) error
}

// FinalVoteStore persists the write-once finalization commit-lock: at most one
// finalized block hash per chain position (account, previous), ever. A record is
// written before a representative signs its final vote, and is NEVER deleted —
// persistence across conflict resolution, rollback, and restart is exactly what
// makes a final vote irrevocable (a rep can never final-vote two hashes at one
// position). See #526.
type FinalVoteStore interface {
	// GetFinalVote returns the locked hash for the position, ok=false if none.
	GetFinalVote(account, previous string) (hash string, ok bool, err error)
	// PutFinalVoteIfAbsent atomically records hash for the position iff no record
	// exists. Returns the stored hash (the pre-existing one if a record was
	// already present, otherwise hash) and written=true iff this call created it.
	PutFinalVoteIfAbsent(account, previous, hash string) (stored string, written bool, err error)
}

// Syncer is an optional interface for stores that can flush pending writes to
// stable storage. BadgerDB is opened with SyncWrites=false for throughput, so a
// caller that must guarantee durability before an externally-visible,
// irrevocable side effect — gossiping a final vote — calls Sync first. Without
// it, a crash after the gossip but before the OS flushes the write-once
// commit-lock + final vote loses them; on restart the rep no longer has its
// local final vote (the #566 re-affirm needs it) and could final-vote the other
// sibling → two conflicting irrevocable final votes → #538-class divergent
// finalization. (#570/H1)
type Syncer interface {
	Sync() error
}

// DelegationStore is an optional interface for stores that support persisting
// delegation data (account → representative mappings).
type DelegationStore interface {
	PutDelegation(account, representative string) error
	DeleteDelegation(account string) error
}

// DelegationIterator is an optional interface that stores may implement to
// allow the Ledger to rebuild its in-memory delegation map on startup.
type DelegationIterator interface {
	IterateDelegations(fn func(account, representative string) error) error
}

// FrontierLister is an optional interface for stores that can enumerate all
// account frontiers. Used by Ledger.Frontiers().
type FrontierLister interface {
	AllFrontiers() map[string]string
}

// CertificateStore is an optional interface for stores that persist provider
// performance certificates (raw JSON, keyed by CERTIFICATE HASH). Since #596
// binds the certificate hash into lease block hashes, certificates are chain
// data: a node must be able to serve them to cold-syncing peers long after
// the original gossip stopped (#630). Memory-only caching loses them on the
// first full-network restart.
//
// The keyspace is the certificate hash rather than the provider account
// (#816). A provider re-issues its certificate at expiry and on every restart,
// but the lease blocks written under the old certificate keep pinning the old
// hash forever. Keying by provider retains exactly one certificate per
// provider, so the first rotation silently discards the certificate that all
// of that provider's earlier lease history depends on, and any node replaying
// that history stalls on a block it can no longer validate.
type CertificateStore interface {
	PutCertificate(hash string, data []byte) error
	CertificateByHash(hash string) ([]byte, error)
	DeleteCertificate(hash string) error
	AllCertificates() (map[string][]byte, error)
}

// LeaseStore is an optional interface for stores that support persisting
// compute lease records.
type LeaseStore interface {
	PutLease(lease *Lease) error
	GetLease(leaseHash string) (*Lease, error)
	GetLeasesByProvider(provider string) ([]*Lease, error)
	GetLeasesByState(state LeaseState) ([]*Lease, error)
	GetAllLeases() ([]*Lease, error)
}

// ReputationStore is an optional interface for stores that support persisting
// per-account reputation aggregates. See core/reputation.go and #380/#402.
type ReputationStore interface {
	PutReputation(account string, agg *ReputationAggregate) error
	GetReputation(account string) (*ReputationAggregate, error) // nil, nil on miss
	GetAllReputations() (map[string]*ReputationAggregate, error)
	DeleteReputation(account string) error // drop a record reverted to no counters (#681)
}

// KeysetStore is an optional interface for stores that support persisting
// multisig keysets.
type KeysetStore interface {
	PutKeyset(account string, keyset *Keyset) error
	GetKeyset(account string) (*Keyset, error) // nil, nil on miss
}

// AccountKeyStore is an optional interface for stores that persist the
// single-key credential registry: account address → hex ed25519 public key
// (#829). The mapping is declared by the first block on an account chain and is
// what every later block on that chain is verified against, now that the
// address is sha256("xe/account/v1" || pubkey) rather than the key itself.
//
// PutAccountKey deliberately REPLACES any existing record rather than
// insert-only. Replacement is the whole point of decoupling identity from
// credential: #424 key rotation is a follow-up block type that swaps the stored
// key while the address, balance and chain continuity are preserved — exactly
// what multisig_update already does with PutKeyset. The consensus rule that a
// non-open block may not redeclare a key lives in ValidatePubKeyDeclaration,
// not in the storage layer, so rotation needs no storage change.
type AccountKeyStore interface {
	PutAccountKey(account, pubKey string) error
	GetAccountKey(account string) (string, error) // "" on miss
	DeleteAccountKey(account string) error
	AllAccountKeys() (map[string]string, error)
}

// BlockCommit represents the complete set of writes for adding a block to the
// ledger. These writes must be applied atomically to prevent partial-write
// corruption on crash.
type BlockCommit struct {
	Block              *Block
	Account            string
	Chain              *AccountChain
	FrontierHash       string
	AddPending         *PendingSend // non-nil for send blocks
	DeletePendingID    string       // non-empty sendHash for receive blocks
	PutLease           *Lease       // non-nil for lease and lease_accept blocks
	SettleLeaseHash    string       // non-empty for lease_settle blocks
	CancelLeaseHash    string       // non-empty for lease_cancel blocks
	UnfulfillLeaseHash string       // non-empty for lease_force_settle blocks (#488)
	DelegationRep      string       // non-empty: persist account→rep delegation
	DeleteDelegation   bool         // true: delete delegation for account
	PutKeyset          *Keyset      // non-nil: store keyset for multisig account

	// PutAccountKey (#829): non-empty when this block declares the account's
	// ed25519 public key (the first block on a single-key chain). Written in the
	// same transaction as the block itself so the credential registry can never
	// disagree with the chain that declared it.
	PutAccountKey string

	// ExpectLeaseHash/ExpectLeaseState (#570/C3): when ExpectLeaseHash is
	// non-empty, the commit must fail with ErrLeaseStateConflict unless the
	// stored lease exists and is in ExpectLeaseState — checked inside the
	// commit transaction. Lease-state transitions validate the state outside
	// the commit and on different account chains (accept on the provider's,
	// cancel on the consumer's); this compare-and-swap is the last line
	// against a lost update on any path that bypasses the per-lease lock.
	ExpectLeaseHash  string
	ExpectLeaseState LeaseState

	// AssetCredit (#674): an extra in-memory asset-balance credit applied
	// atomically with this commit — the provider's XUSD stake return on
	// lease_settle. The settle block's own Balance tracks XE only, so the stake
	// return is not expressible through it; folding it onto the commit (with its
	// inverse AssetDebit on BlockUndo) keeps it inside the commit/undo boundary
	// so a reorg reverses it and a rebuild-from-store agrees by construction.
	// Applied in commitBlockWrite, not by the store backend (asset balances are
	// in-memory derived state, rebuilt each boot — never persisted).
	AssetCredit *AssetDelta
}

// AssetDelta is a single account+asset balance delta carried on a commit/undo
// for a side effect not expressible through the block's own Balance field. The
// sole user is the lease_settle XUSD stake return, which rides on an XE block
// (#674).
type AssetDelta struct {
	Account string
	Asset   string
	Amount  uint64
}

// ErrLeaseStateConflict is returned by CommitBlock when ExpectLeaseHash is set
// and the stored lease is missing or not in ExpectLeaseState (#570/C3).
var ErrLeaseStateConflict = errors.New("lease state conflict")

// AtomicBlockStore is an optional interface for stores that support committing
// a block and all its side effects (chain update, frontier, pending send
// create/delete) in a single atomic operation.
type AtomicBlockStore interface {
	CommitBlock(c *BlockCommit) error

	// CommitCascade applies all undos (in order) then the winner commit in ONE
	// atomic transaction. This is the #622 crash-atomicity boundary for conflict
	// promotion: a winner is promoted by unwinding the on-chain loser and its
	// cross-account cascade (the undos) and re-applying the winner (the commit),
	// and a crash between those writes — the pre-#622 demote-then-readd path used
	// a separate transaction per step — stranded the account half-promoted.
	//
	// The cascade is NEVER silently split: an ErrTxnTooBig-class failure (the
	// whole set exceeds one store transaction) MUST surface loudly rather than
	// degrade to per-block transactions and reopen the crash window.
	CommitCascade(undos []*BlockUndo, commit *BlockCommit) error
}

// BlockUndo is the complete set of store writes for rolling back one frontier
// block: the truncated chain + new frontier for the account, the pending send
// it must delete (an undone send's own pending) or re-create (the source of an
// undone receive), and marking the block rejected. These MUST be applied in a
// single store transaction (#570/H5) — applied as separate transactions, a
// crash between them can leave a half-rolled-back block (e.g. the source
// pending re-created but the consuming receive still on chain → the same send
// receivable twice → double credit).
type BlockUndo struct {
	Account         string
	Chain           *AccountChain // truncated chain (frontier block removed)
	FrontierHash    string        // new frontier hash ("0" if the chain is now empty)
	AddPending      *PendingSend  // re-create the source pending of an undone receive
	DeletePendingID string        // delete the pending an undone send created
	RejectHash      string        // mark this block StatusRejected

	// DeleteAccount (#701): the undo emptied the account's chain (the rolled-back
	// block was its only/last block). Delete the now-chainless account record —
	// chain + frontier keys — instead of persisting an empty chain with a "0"
	// frontier, so the live account map matches a fresh rebuild-from-chain (which
	// omits chainless accounts). Without this a cascade that unwinds a recipient's
	// only receive leaves a ghost account (block_count=0) in /accounts, diverging
	// the per-account census from a node that never built the rolled-back cone. A
	// later first-receive re-creates the account normally (open block, previous
	// "0"). When the same transaction re-adds a block to this account (the winner
	// commit in a CommitCascade for an open-conflict swap), the subsequent commit
	// re-creates the keys, so the net effect is correct.
	DeleteAccount bool

	// RestoreDelegation persists the account's delegation pointer in the SAME
	// transaction: PrevRep is the representative in effect before the undone
	// block ("" deletes the entry). #586 made rollback restore the prior rep
	// with persistent DelegationStore writes; issued outside this transaction,
	// a crash between CommitUndo and that write left the chain rolled back
	// with the delegation still pointing at the rolled-back rep — and
	// rebuildDelegation reads the persisted entries, so the restart diverged
	// consensus weights from a clean replay (#597).
	RestoreDelegation bool
	PrevRep           string

	// Lease/keyset side-effect reversal (#570/C1): when a conflict loser that
	// carried lease or multisig side effects is unwound to promote the winner,
	// the same transaction must reverse those side effects. RestoreLease writes
	// the reconstructed prior lease record (e.g. settle→accepted, accept→created);
	// DeleteLeaseHash removes a lease record created by an unwound lease block;
	// DeleteKeysetAccount removes a keyset created by an unwound multisig_open.
	RestoreLease        *Lease
	DeleteLeaseHash     string
	DeleteKeysetAccount string

	// DeleteAccountKeyAccount (#829) removes the account→pubkey record declared
	// by an unwound opening block, mirroring DeleteKeysetAccount. Without it a
	// reorged-out open block would leave a credential registered for an account
	// with no chain, so a rebuild-from-store would disagree with a cold sync.
	DeleteAccountKeyAccount string

	// AssetDebit (#674): inverse of the unwound block's AssetCredit — the
	// lease_settle XUSD stake return. Subtracted from the in-memory balance when
	// the settle is undone. Guarded to lease_settle (force_settle never returns
	// the stake). Applied in the buildBlockUndo apply closure, not by the store
	// backend (asset balances are in-memory derived state, never persisted).
	AssetDebit *AssetDelta
}
