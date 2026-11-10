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
	_, isNew, err = recordConflictWithSnapshot(cs, account, previous, existingHash, newHash, nil)
	return isNew, err
}

func recordConflictWithSnapshot(cs ConflictStore, account, previous, existingHash, newHash string, snapshotFn func() map[string]uint64) (saved *Conflict, isNew bool, err error) {
	conflictRWMu.Lock()
	defer conflictRWMu.Unlock()

	record, err := cs.GetConflict(account, previous)
	if err != nil {
		return nil, false, err
	}
	if record == nil {
		record = NewConflict(account, previous, existingHash, newHash)
		if snapshotFn != nil {
			record.WeightSnapshot = snapshotFn()
			var total uint64
			for _, w := range record.WeightSnapshot {
				total += w
			}
			record.TotalWeight = total
		}
		if err := cs.SaveConflict(record); err != nil {
			return nil, false, err
		}
		cp := *record
		cp.BlockHashes = append([]string(nil), record.BlockHashes...)
		return &cp, true, nil
	}

	if containsConflictHash(record.BlockHashes, newHash) {
		cp := *record
		cp.BlockHashes = append([]string(nil), record.BlockHashes...)
		return &cp, false, nil
	}

	const maxConflictHashes = 10
	if len(record.BlockHashes) >= maxConflictHashes {
		cp := *record
		cp.BlockHashes = append([]string(nil), record.BlockHashes...)
		return &cp, false, nil
	}
	record.BlockHashes = append(record.BlockHashes, newHash)
	if err := cs.SaveConflict(record); err != nil {
		return nil, false, err
	}

	cp := *record
	cp.BlockHashes = append([]string(nil), record.BlockHashes...)
	return &cp, false, nil
}

func trimConflictHashes(cs ConflictStore, account, previous string, drop map[string]bool) (*Conflict, error) {
	conflictRWMu.Lock()
	defer conflictRWMu.Unlock()

	latest, err := cs.GetConflict(account, previous)
	if err != nil || latest == nil {
		return nil, err
	}
	filtered := make([]string, 0, len(latest.BlockHashes))
	changed := false
	for _, h := range latest.BlockHashes {
		if drop[h] {
			changed = true
			continue
		}
		filtered = append(filtered, h)
	}
	if !changed {
		return latest, nil
	}
	if len(filtered) == 0 {
		_ = cs.DeleteConflict(account, previous)
		return nil, nil
	}
	latest.BlockHashes = filtered
	if err := cs.SaveConflict(latest); err != nil {
		return nil, err
	}
	return latest, nil
}

func containsConflictHash(hashes []string, hash string) bool {
	for _, h := range hashes {
		if h == hash {
			return true
		}
	}
	return false
}
