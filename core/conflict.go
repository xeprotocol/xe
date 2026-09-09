package core

import "sync"

var conflictRWMu sync.RWMutex

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

func RemoveConflict(cs ConflictStore, account, previous string) {
	conflictRWMu.Lock()
	defer conflictRWMu.Unlock()
	_ = cs.DeleteConflict(account, previous)
}

func NewConflict(account, previousHash string, hashA, hashB string) *Conflict {
	return &Conflict{
		AccountAddress: account,
		PreviousHash:   previousHash,
		BlockHashes:    []string{hashA, hashB},
		DetectedAt:     Now(),
	}
}

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

func recordConflict(cs ConflictStore, account, previous, existingHash, newHash string) (isNew bool, err error) {
	record, err := cs.GetConflict(account, previous)
	if err != nil {
		return false, err
	}
	if record == nil {

		record = NewConflict(account, previous, existingHash, newHash)
		if err := cs.SaveConflict(record); err != nil {
			return false, err
		}
		return true, nil
	}

	if containsConflictHash(record.BlockHashes, newHash) {
		return false, nil
	}

	const maxConflictHashes = 10
	if len(record.BlockHashes) >= maxConflictHashes {
		return false, nil
	}
	record.BlockHashes = append(record.BlockHashes, newHash)
	if err := cs.SaveConflict(record); err != nil {
		return false, err
	}

	return false, nil
}

func containsConflictHash(hashes []string, hash string) bool {
	for _, h := range hashes {
		if h == hash {
			return true
		}
	}
	return false
}
