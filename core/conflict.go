package core

import "sync"

// conflictRWMu guards any concurrent access to package-level conflict helpers
// that iterate over ConflictStore entries. Upgraded to RWMutex for concurrent read support.
var conflictRWMu sync.RWMutex

// GetConflictForBlock scans all conflicts in cs and returns the first one that
// contains blockHash in its BlockHashes slice. Returns (nil, false) if not found.
func GetConflictForBlock(cs ConflictStore, blockHash string) (*Conflict, bool) {
	conflictRWMu.RLock()
	defer conflictRWMu.RUnlock()

	conflicts, err := cs.GetAllConflicts()
	if err != nil {
		return nil, false
	}
	for _, c := range conflicts {
		for _, h := range c.BlockHashes {
			if h == blockHash {
				return c, true
			}
		}
	}
	return nil, false
}

// RemoveConflict deletes the conflict record for (account, previous) from cs.
func RemoveConflict(cs ConflictStore, account, previous string) {
	conflictRWMu.Lock()
	defer conflictRWMu.Unlock()
	_ = cs.DeleteConflict(account, previous)
}

// NewConflict creates a new Conflict for the given account and previous hash,
// seeded with the two block hashes that caused the equivocation.
func NewConflict(account, previousHash string, hashA, hashB string) *Conflict {
	return &Conflict{
		AccountAddress: account,
		PreviousHash:   previousHash,
		BlockHashes:    []string{hashA, hashB},
		DetectedAt:     Now(),
	}
}

// detectConflictSibling reports the hash of a block already on chain that
// occupies the same (account, previous) slot as b — i.e. the sibling b would
// equivocate against — or "" if there is none. For open blocks, Previous is "0",
// so two competing opens match here. Read-only: it records nothing.
//
// Detection is split from recording (recordConflict) deliberately: the caller
// must VALIDATE the incoming block (ValidateStagedBlock) BEFORE recording a
// conflict, so a semantically-invalid block can never seed or extend a conflict
// record. Recording an unvalidated sibling would leave a phantom hash in the
// record whose body was never staged, freezing the account behind the
// unresolved-conflict guard until a quorum sweep evicts it (a cheap, remotely
// triggerable wedge on a shared/public-keyed account such as the faucet minter).
// The caller must hold the account lock.
func detectConflictSibling(chain *AccountChain, b *Block) string {
	if chain == nil {
		return ""
	}
	for _, existing := range chain.Blocks {
		if existing.Previous == b.Previous {
			return existing.Hash
		}
	}
	return ""
}

// recordConflict creates or extends the conflict record for (account, previous),
// seeding a new record with existingHash (the on-chain sibling) and newHash.
// Returns isNew=true only when the record first reaches size 2, so the caller
// fires the detection callback exactly once.
//
// The caller MUST have already validated the incoming block (asset + semantics
// via ValidateStagedBlock) — recordConflict assumes the equivocation is
// legitimate. See detectConflictSibling for why. The caller must hold the
// account lock.
func recordConflict(cs ConflictStore, account, previous, existingHash, newHash string) (isNew bool, err error) {
	record, err := cs.GetConflict(account, previous)
	if err != nil {
		return false, err
	}
	if record == nil {
		// First time we see a second block at this (account, previous).
		record = NewConflict(account, previous, existingHash, newHash)
		if err := cs.SaveConflict(record); err != nil {
			return false, err
		}
		return true, nil
	}
	// Record already exists; append the new hash if not already present.
	if containsConflictHash(record.BlockHashes, newHash) {
		return false, nil // idempotent
	}
	// Cap conflict set size to prevent unbounded growth from an attacker
	// generating unlimited equivocating blocks.
	const maxConflictHashes = 10
	if len(record.BlockHashes) >= maxConflictHashes {
		return false, nil // conflict tracked, but reject further equivocations
	}
	record.BlockHashes = append(record.BlockHashes, newHash)
	if err := cs.SaveConflict(record); err != nil {
		return false, err
	}
	// isNew=false: callback already fired when size reached 2.
	return false, nil
}

// containsConflictHash reports whether hash is in the slice.
func containsConflictHash(hashes []string, hash string) bool {
	for _, h := range hashes {
		if h == hash {
			return true
		}
	}
	return false
}
