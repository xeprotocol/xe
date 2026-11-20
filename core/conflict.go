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

func recordConflict(cs ConflictStore, account, previous, existingHash, newHash string, snapshotWeights func() map[string]uint64) (isNew bool, record *Conflict, err error) {
	conflictRWMu.Lock()
	defer conflictRWMu.Unlock()

	rec, err := cs.GetConflict(account, previous)
	if err != nil {
		return false, nil, err
	}
	if rec == nil {
		rec = NewConflict(account, previous, existingHash, newHash)
		if snapshotWeights != nil {
			rec.WeightSnapshot = snapshotWeights()
			var total uint64
			for _, w := range rec.WeightSnapshot {
				total += w
			}
			rec.TotalWeight = total
		}
		if err := cs.SaveConflict(rec); err != nil {
			return false, nil, err
		}
		return true, rec, nil
	}

	if containsConflictHash(rec.BlockHashes, newHash) {
		return false, rec, nil
	}

	const maxConflictHashes = 10
	if len(rec.BlockHashes) >= maxConflictHashes {
		return false, rec, nil
	}
	rec.BlockHashes = append(rec.BlockHashes, newHash)
	if err := cs.SaveConflict(rec); err != nil {
		return false, nil, err
	}

	return false, rec, nil
}

func trimConflictHashes(cs ConflictStore, account, previous string, deadPhantoms []string) error {
	conflictRWMu.Lock()
	defer conflictRWMu.Unlock()

	current, err := cs.GetConflict(account, previous)
	if err != nil {
		return err
	}
	if current == nil {
		return nil
	}

	deadSet := make(map[string]bool, len(deadPhantoms))
	for _, h := range deadPhantoms {
		deadSet[h] = true
	}

	var newHashes []string
	for _, h := range current.BlockHashes {
		if !deadSet[h] {
			newHashes = append(newHashes, h)
		}
	}

	if len(newHashes) != len(current.BlockHashes) {
		current.BlockHashes = newHashes
		return cs.SaveConflict(current)
	}
	return nil
}

func containsConflictHash(hashes []string, hash string) bool {
	for _, h := range hashes {
		if h == hash {
			return true
		}
	}
	return false
}
