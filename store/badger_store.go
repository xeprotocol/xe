package store

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/statechain"
)

const (
	prefixBlock       = byte(0x01)
	prefixChain       = byte(0x02)
	prefixPending     = byte(0x03)
	prefixPendingDst  = byte(0x04)
	prefixFrontier    = byte(0x05)
	prefixDelegation  = byte(0x06)
	prefixWeight      = byte(0x07)
	prefixConflict    = byte(0x08)
	prefixStaged      = byte(0x09)
	prefixVote        = byte(0x0a)
	prefixBlockStatus = byte(0x0b)
	prefixFinalHeight = byte(0x0c)
	prefixLease       = byte(0x0d)
	prefixStateBlock  = byte(0x0e)
	prefixKeyset      = byte(0x0f)
	prefixReputation  = byte(0x10)
	prefixFinalVote   = byte(0x11)
	prefixCertificate = byte(0x12)
	prefixAccountKey  = byte(0x13)
)

type BadgerStore struct {
	db        *badger.DB
	gcQuit    chan struct{}
	gcDone    chan struct{}
	closeOnce sync.Once
}

func NewBadgerStore(dir string) (*BadgerStore, error) {
	opts := badger.DefaultOptions(dir).WithLogger(nil)
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}
	s := &BadgerStore{db: db, gcQuit: make(chan struct{}), gcDone: make(chan struct{})}
	go s.runGC()
	return s, nil
}

func (s *BadgerStore) Sync() error {
	return s.db.Sync()
}

func (s *BadgerStore) runGC() {
	defer close(s.gcDone)
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.gcQuit:
			return
		case <-ticker.C:
			for {
				if err := s.db.RunValueLogGC(0.5); err != nil {
					break
				}
			}
		}
	}
}

func (s *BadgerStore) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.gcQuit)
		<-s.gcDone
		err = s.db.Close()
	})
	return err
}

func prefixedKey(prefix byte, key string) []byte {
	b := make([]byte, 1+len(key))
	b[0] = prefix
	copy(b[1:], key)
	return b
}

func (s *BadgerStore) GetBlock(hash string) (*core.Block, error) {
	var block core.Block
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(prefixedKey(prefixBlock, hash))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &block)
		})
	})
	if err == badger.ErrKeyNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &block, nil
}

func (s *BadgerStore) PutBlock(block *core.Block) error {
	data, err := json.Marshal(block)
	if err != nil {
		return err
	}
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(prefixedKey(prefixBlock, block.Hash), data)
	})
}

func (s *BadgerStore) GetAccountChain(account string) (*core.AccountChain, error) {
	var chain *core.AccountChain
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(prefixedKey(prefixChain, account))
		if err != nil {
			return err
		}
		var hashes []string
		if err := item.Value(func(val []byte) error {
			return json.Unmarshal(val, &hashes)
		}); err != nil {
			return err
		}

		chain = &core.AccountChain{
			Blocks: make([]*core.Block, 0, len(hashes)),
		}
		for _, h := range hashes {
			blockItem, err := txn.Get(prefixedKey(prefixBlock, h))
			if err != nil {
				return fmt.Errorf("chain references missing block %s: %w", h, err)
			}
			var b core.Block
			if err := blockItem.Value(func(val []byte) error {
				return json.Unmarshal(val, &b)
			}); err != nil {
				return fmt.Errorf("unmarshal block %s: %w", h, err)
			}
			chain.Blocks = append(chain.Blocks, &b)
		}
		return nil
	})
	if err == badger.ErrKeyNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return chain, nil
}

func (s *BadgerStore) PutAccountChain(account string, chain *core.AccountChain) error {
	hashes := make([]string, len(chain.Blocks))
	for i, b := range chain.Blocks {
		hashes[i] = b.Hash
	}
	data, err := json.Marshal(hashes)
	if err != nil {
		return err
	}
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(prefixedKey(prefixChain, account), data)
	})
}

func (s *BadgerStore) GetPendingSend(sendHash string) (*core.PendingSend, error) {
	var ps core.PendingSend
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(prefixedKey(prefixPending, sendHash))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &ps)
		})
	})
	if err == badger.ErrKeyNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &ps, nil
}

func (s *BadgerStore) PutPendingSend(ps *core.PendingSend) error {
	psData, err := json.Marshal(ps)
	if err != nil {
		return err
	}

	return s.db.Update(func(txn *badger.Txn) error {

		if err := txn.Set(prefixedKey(prefixPending, ps.SendHash), psData); err != nil {
			return err
		}

		destKey := prefixedKey(prefixPendingDst, ps.Destination)
		var hashes []string
		item, err := txn.Get(destKey)
		if err != nil && err != badger.ErrKeyNotFound {
			return err
		}
		if err == nil {
			if err := item.Value(func(val []byte) error {
				return json.Unmarshal(val, &hashes)
			}); err != nil {
				return err
			}
		}
		hashes = append(hashes, ps.SendHash)
		destData, err := json.Marshal(hashes)
		if err != nil {
			return err
		}
		return txn.Set(destKey, destData)
	})
}

func (s *BadgerStore) DeletePendingSend(sendHash string) error {
	return s.db.Update(func(txn *badger.Txn) error {

		pendingKey := prefixedKey(prefixPending, sendHash)
		item, err := txn.Get(pendingKey)
		if err == badger.ErrKeyNotFound {
			return nil
		}
		if err != nil {
			return err
		}

		var ps core.PendingSend
		if err := item.Value(func(val []byte) error {
			return json.Unmarshal(val, &ps)
		}); err != nil {
			return err
		}

		if err := txn.Delete(pendingKey); err != nil {
			return err
		}

		destKey := prefixedKey(prefixPendingDst, ps.Destination)
		var hashes []string
		item2, err := txn.Get(destKey)
		if err != nil && err != badger.ErrKeyNotFound {
			return err
		}
		if err == nil {
			if err := item2.Value(func(val []byte) error {
				return json.Unmarshal(val, &hashes)
			}); err != nil {
				return err
			}
		}

		filtered := hashes[:0]
		for _, h := range hashes {
			if h != sendHash {
				filtered = append(filtered, h)
			}
		}

		if len(filtered) == 0 {
			return txn.Delete(destKey)
		}
		destData, err := json.Marshal(filtered)
		if err != nil {
			return err
		}
		return txn.Set(destKey, destData)
	})
}

func (s *BadgerStore) GetPendingByDest(account string) ([]*core.PendingSend, error) {
	var hashes []string
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(prefixedKey(prefixPendingDst, account))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &hashes)
		})
	})
	if err == badger.ErrKeyNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	out := make([]*core.PendingSend, 0, len(hashes))
	for _, h := range hashes {
		ps, err := s.GetPendingSend(h)
		if err != nil {
			return nil, err
		}
		if ps != nil {
			out = append(out, ps)
		}
	}
	return out, nil
}

func (s *BadgerStore) GetAllPending() ([]*core.PendingSend, error) {
	out := make([]*core.PendingSend, 0)
	err := s.db.View(func(txn *badger.Txn) error {
		prefix := []byte{prefixPending}
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			var ps core.PendingSend
			if err := item.Value(func(val []byte) error {
				return json.Unmarshal(val, &ps)
			}); err != nil {
				return err
			}
			out = append(out, &ps)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *BadgerStore) PutFrontier(account string, blockHash string) error {
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(prefixedKey(prefixFrontier, account), []byte(blockHash))
	})
}

func (s *BadgerStore) GetFrontier(account string) (string, error) {
	var frontier string
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(prefixedKey(prefixFrontier, account))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			frontier = string(val)
			return nil
		})
	})
	if err == badger.ErrKeyNotFound {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return frontier, nil
}

func (s *BadgerStore) AllFrontiers() map[string]string {
	out := make(map[string]string)
	if err := s.db.View(func(txn *badger.Txn) error {
		prefix := []byte{prefixFrontier}
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			k := item.KeyCopy(nil)
			account := string(k[1:])
			if err := item.Value(func(val []byte) error {
				out[account] = string(val)
				return nil
			}); err != nil {
				return fmt.Errorf("AllFrontiers: read value for %s: %w", account[:12], err)
			}
		}
		return nil
	}); err != nil {
		log.Printf("AllFrontiers: %v", err)
	}
	return out
}

func (s *BadgerStore) IsEmpty() (bool, error) {
	empty := true
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		prefix := []byte{prefixBlock}
		it.Seek(prefix)
		if it.ValidForPrefix(prefix) {
			empty = false
		}
		return nil
	})
	return empty, err
}

func (s *BadgerStore) PutCertificate(hash string, data []byte) error {
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(prefixedKey(prefixCertificate, hash), data)
	})
}

func (s *BadgerStore) CertificateByHash(hash string) ([]byte, error) {
	var data []byte
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(prefixedKey(prefixCertificate, hash))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			data = append([]byte(nil), val...)
			return nil
		})
	})
	if err == badger.ErrKeyNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (s *BadgerStore) DeleteCertificate(hash string) error {
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(prefixedKey(prefixCertificate, hash))
	})
}

func (s *BadgerStore) AllCertificates() (map[string][]byte, error) {
	out := map[string][]byte{}
	err := s.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		prefix := []byte{prefixCertificate}
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			hash := string(item.Key()[1:])
			if err := item.Value(func(val []byte) error {
				out[hash] = append([]byte(nil), val...)
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *BadgerStore) PutDelegation(account, representative string) error {
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(prefixedKey(prefixDelegation, account), []byte(representative))
	})
}

func (s *BadgerStore) GetDelegation(account string) (string, error) {
	var rep string
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(prefixedKey(prefixDelegation, account))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			rep = string(val)
			return nil
		})
	})
	if err == badger.ErrKeyNotFound {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return rep, nil
}

func (s *BadgerStore) DeleteDelegation(account string) error {
	return s.db.Update(func(txn *badger.Txn) error {
		err := txn.Delete(prefixedKey(prefixDelegation, account))
		if err == badger.ErrKeyNotFound {
			return nil
		}
		return err
	})
}

func (s *BadgerStore) IterateDelegations(fn func(account, representative string) error) error {
	return s.db.View(func(txn *badger.Txn) error {
		prefix := []byte{prefixDelegation}
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()

			k := item.KeyCopy(nil)
			account := string(k[1:])
			var rep string
			if err := item.Value(func(val []byte) error {
				rep = string(val)
				return nil
			}); err != nil {
				return err
			}
			if err := fn(account, rep); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *BadgerStore) PutKeyset(account string, keyset *core.Keyset) error {
	data, err := json.Marshal(keyset)
	if err != nil {
		return fmt.Errorf("marshal keyset: %w", err)
	}
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(prefixedKey(prefixKeyset, account), data)
	})
}

func (s *BadgerStore) GetKeyset(account string) (*core.Keyset, error) {
	var ks core.Keyset
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(prefixedKey(prefixKeyset, account))
		if err == badger.ErrKeyNotFound {
			return nil
		}
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &ks)
		})
	})
	if err != nil {
		return nil, err
	}
	if len(ks.Keys) == 0 {
		return nil, nil
	}
	return &ks, nil
}

func (s *BadgerStore) PutAccountKey(account, pubKey string) error {
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(prefixedKey(prefixAccountKey, account), []byte(pubKey))
	})
}

func (s *BadgerStore) GetAccountKey(account string) (string, error) {
	var out string
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(prefixedKey(prefixAccountKey, account))
		if err == badger.ErrKeyNotFound {
			return nil
		}
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			out = string(val)
			return nil
		})
	})
	if err != nil {
		return "", err
	}
	return out, nil
}

func (s *BadgerStore) DeleteAccountKey(account string) error {
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(prefixedKey(prefixAccountKey, account))
	})
}

func (s *BadgerStore) AllAccountKeys() (map[string]string, error) {
	out := make(map[string]string)
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		prefix := []byte{prefixAccountKey}
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			account := string(item.Key()[1:])
			if err := item.Value(func(val []byte) error {
				out[account] = string(val)
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *BadgerStore) PutWeight(representative string, weight *big.Int) error {
	var val []byte
	if weight == nil || weight.Sign() <= 0 {
		val = []byte{}
	} else {
		val = weight.Bytes()
	}
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(prefixedKey(prefixWeight, representative), val)
	})
}

func (s *BadgerStore) GetWeight(representative string) (*big.Int, error) {
	w := new(big.Int)
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(prefixedKey(prefixWeight, representative))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			if len(val) > 0 {
				w.SetBytes(val)
			}
			return nil
		})
	})
	if err == badger.ErrKeyNotFound {
		return new(big.Int), nil
	}
	if err != nil {
		return nil, err
	}
	return w, nil
}

func (s *BadgerStore) CommitBlock(c *core.BlockCommit) error {
	return s.db.Update(func(txn *badger.Txn) error {
		return applyCommitTxn(txn, c)
	})
}

func applyCommitTxn(txn *badger.Txn, c *core.BlockCommit) error {
	blockData, err := json.Marshal(c.Block)
	if err != nil {
		return fmt.Errorf("CommitBlock: marshal block: %w", err)
	}
	hashes := make([]string, len(c.Chain.Blocks))
	for i, b := range c.Chain.Blocks {
		hashes[i] = b.Hash
	}
	chainData, err := json.Marshal(hashes)
	if err != nil {
		return fmt.Errorf("CommitBlock: marshal chain: %w", err)
	}

	{

		if c.ExpectLeaseHash != "" {
			item, err := txn.Get(prefixedKey(prefixLease, c.ExpectLeaseHash))
			if err == badger.ErrKeyNotFound {
				return fmt.Errorf("CommitBlock: %w: lease %s not found", core.ErrLeaseStateConflict, c.ExpectLeaseHash[:12])
			}
			if err != nil {
				return fmt.Errorf("CommitBlock: lease CAS read: %w", err)
			}
			var lease core.Lease
			if err := item.Value(func(val []byte) error {
				return json.Unmarshal(val, &lease)
			}); err != nil {
				return err
			}
			if lease.State != c.ExpectLeaseState {
				return fmt.Errorf("CommitBlock: %w: lease %s is %s, want %s",
					core.ErrLeaseStateConflict, c.ExpectLeaseHash[:12], lease.State, c.ExpectLeaseState)
			}
		}

		if err := txn.Set(prefixedKey(prefixBlock, c.Block.Hash), blockData); err != nil {
			return err
		}

		if err := txn.Set(prefixedKey(prefixChain, c.Account), chainData); err != nil {
			return err
		}

		if c.FrontierHash != "" {
			if err := txn.Set(prefixedKey(prefixFrontier, c.Account), []byte(c.FrontierHash)); err != nil {
				return err
			}
		}

		if c.AddPending != nil {
			psData, err := json.Marshal(c.AddPending)
			if err != nil {
				return err
			}
			if err := txn.Set(prefixedKey(prefixPending, c.AddPending.SendHash), psData); err != nil {
				return err
			}

			destKey := prefixedKey(prefixPendingDst, c.AddPending.Destination)
			var destHashes []string
			item, err := txn.Get(destKey)
			if err != nil && err != badger.ErrKeyNotFound {
				return err
			}
			if err == nil {
				if err := item.Value(func(val []byte) error {
					return json.Unmarshal(val, &destHashes)
				}); err != nil {
					return err
				}
			}
			destHashes = append(destHashes, c.AddPending.SendHash)
			destData, err := json.Marshal(destHashes)
			if err != nil {
				return err
			}
			if err := txn.Set(destKey, destData); err != nil {
				return err
			}
		}

		if c.PutLease != nil {
			leaseData, err := json.Marshal(c.PutLease)
			if err != nil {
				return err
			}
			if err := txn.Set(prefixedKey(prefixLease, c.PutLease.LeaseHash), leaseData); err != nil {
				return err
			}
		}

		if c.SettleLeaseHash != "" {
			leaseKey := prefixedKey(prefixLease, c.SettleLeaseHash)
			item, err := txn.Get(leaseKey)
			if err != nil {
				return fmt.Errorf("CommitBlock: settle lease %s: %w", c.SettleLeaseHash[:12], err)
			}
			var lease core.Lease
			if err := item.Value(func(val []byte) error {
				return json.Unmarshal(val, &lease)
			}); err != nil {
				return err
			}
			lease.Settled = true
			lease.State = core.LeaseSettled
			settledData, err := json.Marshal(&lease)
			if err != nil {
				return err
			}
			if err := txn.Set(leaseKey, settledData); err != nil {
				return err
			}
		}

		if c.CancelLeaseHash != "" {
			leaseKey := prefixedKey(prefixLease, c.CancelLeaseHash)
			item, err := txn.Get(leaseKey)
			if err != nil {
				return fmt.Errorf("CommitBlock: cancel lease %s: %w", c.CancelLeaseHash[:12], err)
			}
			var lease core.Lease
			if err := item.Value(func(val []byte) error {
				return json.Unmarshal(val, &lease)
			}); err != nil {
				return err
			}
			lease.State = core.LeaseCancelled
			cancelData, err := json.Marshal(&lease)
			if err != nil {
				return err
			}
			if err := txn.Set(leaseKey, cancelData); err != nil {
				return err
			}
		}

		if c.UnfulfillLeaseHash != "" {
			leaseKey := prefixedKey(prefixLease, c.UnfulfillLeaseHash)
			item, err := txn.Get(leaseKey)
			if err != nil {
				return fmt.Errorf("CommitBlock: force-settle lease %s: %w", c.UnfulfillLeaseHash[:12], err)
			}
			var lease core.Lease
			if err := item.Value(func(val []byte) error {
				return json.Unmarshal(val, &lease)
			}); err != nil {
				return err
			}
			lease.Settled = true
			lease.State = core.LeaseUnfulfilled
			unfulfilledData, err := json.Marshal(&lease)
			if err != nil {
				return err
			}
			if err := txn.Set(leaseKey, unfulfilledData); err != nil {
				return err
			}
		}

		if c.DeletePendingID != "" {
			pendingKey := prefixedKey(prefixPending, c.DeletePendingID)
			item, err := txn.Get(pendingKey)
			if err != nil && err != badger.ErrKeyNotFound {
				return err
			}
			if err == nil {
				var ps core.PendingSend
				if err := item.Value(func(val []byte) error {
					return json.Unmarshal(val, &ps)
				}); err != nil {
					return err
				}
				if err := txn.Delete(pendingKey); err != nil {
					return err
				}

				destKey := prefixedKey(prefixPendingDst, ps.Destination)
				var destHashes []string
				item2, err := txn.Get(destKey)
				if err != nil && err != badger.ErrKeyNotFound {
					return err
				}
				if err == nil {
					if err := item2.Value(func(val []byte) error {
						return json.Unmarshal(val, &destHashes)
					}); err != nil {
						return err
					}
				}
				filtered := destHashes[:0]
				for _, h := range destHashes {
					if h != c.DeletePendingID {
						filtered = append(filtered, h)
					}
				}
				if len(filtered) == 0 {
					if err := txn.Delete(destKey); err != nil {
						return err
					}
				} else {
					destData, err := json.Marshal(filtered)
					if err != nil {
						return err
					}
					if err := txn.Set(destKey, destData); err != nil {
						return err
					}
				}
			}
		}

		if c.DeleteDelegation {
			if err := txn.Delete(prefixedKey(prefixDelegation, c.Account)); err != nil && err != badger.ErrKeyNotFound {
				return err
			}
		} else if c.DelegationRep != "" {
			if err := txn.Set(prefixedKey(prefixDelegation, c.Account), []byte(c.DelegationRep)); err != nil {
				return err
			}
		}

		if c.PutKeyset != nil {
			ksJSON, err := json.Marshal(c.PutKeyset)
			if err != nil {
				return fmt.Errorf("marshal keyset: %w", err)
			}
			if err := txn.Set(prefixedKey(prefixKeyset, c.Account), ksJSON); err != nil {
				return err
			}
		}

		if c.PutAccountKey != "" {
			if err := txn.Set(prefixedKey(prefixAccountKey, c.Account), []byte(c.PutAccountKey)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *BadgerStore) CommitUndo(u *core.BlockUndo) error {
	return s.db.Update(func(txn *badger.Txn) error {
		return applyUndoTxn(txn, u)
	})
}

func applyUndoTxn(txn *badger.Txn, u *core.BlockUndo) error {
	hashes := make([]string, len(u.Chain.Blocks))
	for i, b := range u.Chain.Blocks {
		hashes[i] = b.Hash
	}
	chainData, err := json.Marshal(hashes)
	if err != nil {
		return fmt.Errorf("CommitUndo: marshal chain: %w", err)
	}

	{
		if u.DeleteAccount {

			if err := txn.Delete(prefixedKey(prefixChain, u.Account)); err != nil {
				return err
			}
			if err := txn.Delete(prefixedKey(prefixFrontier, u.Account)); err != nil {
				return err
			}
		} else {

			if err := txn.Set(prefixedKey(prefixChain, u.Account), chainData); err != nil {
				return err
			}

			if err := txn.Set(prefixedKey(prefixFrontier, u.Account), []byte(u.FrontierHash)); err != nil {
				return err
			}
		}

		if u.DeletePendingID != "" {
			pendingKey := prefixedKey(prefixPending, u.DeletePendingID)
			item, err := txn.Get(pendingKey)
			if err != nil && err != badger.ErrKeyNotFound {
				return err
			}
			if err == nil {
				var ps core.PendingSend
				if err := item.Value(func(val []byte) error {
					return json.Unmarshal(val, &ps)
				}); err != nil {
					return err
				}
				if err := txn.Delete(pendingKey); err != nil {
					return err
				}
				destKey := prefixedKey(prefixPendingDst, ps.Destination)
				var destHashes []string
				if it, err := txn.Get(destKey); err == nil {
					if err := it.Value(func(val []byte) error {
						return json.Unmarshal(val, &destHashes)
					}); err != nil {
						return err
					}
				} else if err != badger.ErrKeyNotFound {
					return err
				}
				filtered := destHashes[:0]
				for _, h := range destHashes {
					if h != u.DeletePendingID {
						filtered = append(filtered, h)
					}
				}
				if len(filtered) == 0 {
					if err := txn.Delete(destKey); err != nil {
						return err
					}
				} else {
					fd, err := json.Marshal(filtered)
					if err != nil {
						return err
					}
					if err := txn.Set(destKey, fd); err != nil {
						return err
					}
				}
			}
		}

		if u.AddPending != nil {
			psData, err := json.Marshal(u.AddPending)
			if err != nil {
				return err
			}
			if err := txn.Set(prefixedKey(prefixPending, u.AddPending.SendHash), psData); err != nil {
				return err
			}
			destKey := prefixedKey(prefixPendingDst, u.AddPending.Destination)
			var destHashes []string
			if it, err := txn.Get(destKey); err == nil {
				if err := it.Value(func(val []byte) error {
					return json.Unmarshal(val, &destHashes)
				}); err != nil {
					return err
				}
			} else if err != badger.ErrKeyNotFound {
				return err
			}
			destHashes = append(destHashes, u.AddPending.SendHash)
			dd, err := json.Marshal(destHashes)
			if err != nil {
				return err
			}
			if err := txn.Set(destKey, dd); err != nil {
				return err
			}
		}

		if u.RejectHash != "" {
			if err := txn.Set(prefixedKey(prefixBlockStatus, u.RejectHash), []byte{byte(core.StatusRejected)}); err != nil {
				return err
			}
		}

		if u.RestoreDelegation {
			delKey := prefixedKey(prefixDelegation, u.Account)
			if u.PrevRep == "" {
				if err := txn.Delete(delKey); err != nil {
					return err
				}
			} else {
				if err := txn.Set(delKey, []byte(u.PrevRep)); err != nil {
					return err
				}
			}
		}

		if u.RestoreLease != nil {
			leaseData, err := json.Marshal(u.RestoreLease)
			if err != nil {
				return err
			}
			if err := txn.Set(prefixedKey(prefixLease, u.RestoreLease.LeaseHash), leaseData); err != nil {
				return err
			}
		}
		if u.DeleteLeaseHash != "" {
			if err := txn.Delete(prefixedKey(prefixLease, u.DeleteLeaseHash)); err != nil {
				return err
			}
		}
		if u.DeleteKeysetAccount != "" {
			if err := txn.Delete(prefixedKey(prefixKeyset, u.DeleteKeysetAccount)); err != nil {
				return err
			}
		}
		if u.DeleteAccountKeyAccount != "" {
			if err := txn.Delete(prefixedKey(prefixAccountKey, u.DeleteAccountKeyAccount)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *BadgerStore) CommitCascade(undos []*core.BlockUndo, commit *core.BlockCommit) error {
	err := s.db.Update(func(txn *badger.Txn) error {
		for i, u := range undos {
			if err := applyUndoTxn(txn, u); err != nil {
				return fmt.Errorf("undo %d/%d (%s): %w", i+1, len(undos), shortStr(u.Account), err)
			}
		}
		if commit != nil {
			if err := applyCommitTxn(txn, commit); err != nil {
				return fmt.Errorf("winner commit: %w", err)
			}
		}
		return nil
	})
	if err != nil {

		return fmt.Errorf("CommitCascade: %d undo(s) + winner: %w", len(undos), err)
	}
	return nil
}

func shortStr(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func conflictKey(account, previousHash string) []byte {
	suffix := account + ":" + previousHash
	b := make([]byte, 1+len(suffix))
	b[0] = prefixConflict
	copy(b[1:], suffix)
	return b
}

func conflictAccountPrefix(account string) []byte {
	suffix := account + ":"
	b := make([]byte, 1+len(suffix))
	b[0] = prefixConflict
	copy(b[1:], suffix)
	return b
}

func (s *BadgerStore) SaveConflict(c *core.Conflict) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(conflictKey(c.AccountAddress, c.PreviousHash), data)
	})
}

func (s *BadgerStore) GetConflict(account, previousHash string) (*core.Conflict, error) {
	var c core.Conflict
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(conflictKey(account, previousHash))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &c)
		})
	})
	if err == badger.ErrKeyNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *BadgerStore) DeleteConflict(account, previousHash string) error {
	return s.db.Update(func(txn *badger.Txn) error {
		err := txn.Delete(conflictKey(account, previousHash))
		if err == badger.ErrKeyNotFound {
			return nil
		}
		return err
	})
}

func (s *BadgerStore) GetConflictsForAccount(account string) ([]*core.Conflict, error) {
	prefix := conflictAccountPrefix(account)
	conflicts := make([]*core.Conflict, 0)
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			var c core.Conflict
			if err := item.Value(func(val []byte) error {
				return json.Unmarshal(val, &c)
			}); err != nil {
				return err
			}
			conflicts = append(conflicts, &c)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return conflicts, nil
}

func (s *BadgerStore) GetAllConflicts() ([]*core.Conflict, error) {
	prefix := []byte{prefixConflict}
	conflicts := make([]*core.Conflict, 0)
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			var c core.Conflict
			if err := item.Value(func(val []byte) error {
				return json.Unmarshal(val, &c)
			}); err != nil {
				return err
			}
			conflicts = append(conflicts, &c)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return conflicts, nil
}

func (s *BadgerStore) SaveStagedBlock(b *core.Block) error {
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(prefixedKey(prefixStaged, b.Hash), data)
	})
}

func (s *BadgerStore) DeleteStagedBlock(hash string) error {
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(prefixedKey(prefixStaged, hash))
	})
}

func (s *BadgerStore) GetStagedBlock(hash string) (*core.Block, error) {
	var b core.Block
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(prefixedKey(prefixStaged, hash))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &b)
		})
	})
	if err == badger.ErrKeyNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &b, nil
}

func voteKey(conflictAccount, conflictPrev, repPubKey string) ([]byte, error) {
	accountBytes, err := hex.DecodeString(conflictAccount)
	if err != nil {
		return nil, fmt.Errorf("voteKey: invalid conflictAccount hex: %w", err)
	}
	if len(accountBytes) != 32 {
		return nil, fmt.Errorf("voteKey: conflictAccount must be 32 bytes, got %d", len(accountBytes))
	}

	var prevBytes []byte
	if conflictPrev == "0" {
		prevBytes = make([]byte, 32)
	} else {
		prevBytes, err = hex.DecodeString(conflictPrev)
		if err != nil {
			return nil, fmt.Errorf("voteKey: invalid conflictPrev hex: %w", err)
		}
		if len(prevBytes) != 32 {
			return nil, fmt.Errorf("voteKey: conflictPrev must be 32 bytes, got %d", len(prevBytes))
		}
	}

	repBytes, err := hex.DecodeString(repPubKey)
	if err != nil {
		return nil, fmt.Errorf("voteKey: invalid repPubKey hex: %w", err)
	}
	if len(repBytes) != 32 {
		return nil, fmt.Errorf("voteKey: repPubKey must be 32 bytes, got %d", len(repBytes))
	}

	key := make([]byte, 1+32+32+32)
	key[0] = prefixVote
	copy(key[1:33], accountBytes)
	copy(key[33:65], prevBytes)
	copy(key[65:97], repBytes)
	return key, nil
}

func voteConflictPrefix(conflictAccount, conflictPrev string) ([]byte, error) {
	accountBytes, err := hex.DecodeString(conflictAccount)
	if err != nil {
		return nil, fmt.Errorf("voteConflictPrefix: invalid conflictAccount hex: %w", err)
	}
	if len(accountBytes) != 32 {
		return nil, fmt.Errorf("voteConflictPrefix: conflictAccount must be 32 bytes, got %d", len(accountBytes))
	}

	var prevBytes []byte
	if conflictPrev == "0" {
		prevBytes = make([]byte, 32)
	} else {
		prevBytes, err = hex.DecodeString(conflictPrev)
		if err != nil {
			return nil, fmt.Errorf("voteConflictPrefix: invalid conflictPrev hex: %w", err)
		}
		if len(prevBytes) != 32 {
			return nil, fmt.Errorf("voteConflictPrefix: conflictPrev must be 32 bytes, got %d", len(prevBytes))
		}
	}

	prefix := make([]byte, 1+32+32)
	prefix[0] = prefixVote
	copy(prefix[1:33], accountBytes)
	copy(prefix[33:65], prevBytes)
	return prefix, nil
}

func (s *BadgerStore) PutVote(vote *core.Vote) error {
	key, err := voteKey(vote.ConflictAccount, vote.ConflictPrev, vote.RepPubKey)
	if err != nil {
		return err
	}
	data, err := json.Marshal(vote)
	if err != nil {
		return err
	}
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(key, data)
	})
}

func (s *BadgerStore) GetVote(account, previous, repPubKey string) (*core.Vote, error) {
	key, err := voteKey(account, previous, repPubKey)
	if err != nil {
		return nil, err
	}
	var v *core.Vote
	err = s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err == badger.ErrKeyNotFound {
			return nil
		}
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			var vv core.Vote
			if err := json.Unmarshal(val, &vv); err != nil {
				return err
			}
			v = &vv
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (s *BadgerStore) GetVotesByConflict(account, previous string) ([]*core.Vote, error) {
	prefix, err := voteConflictPrefix(account, previous)
	if err != nil {
		return nil, err
	}

	votes := make([]*core.Vote, 0)
	err = s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			var v core.Vote
			if err := item.Value(func(val []byte) error {
				return json.Unmarshal(val, &v)
			}); err != nil {
				return err
			}
			votes = append(votes, &v)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return votes, nil
}

func (s *BadgerStore) HasVoted(account, previous, repPubKey string) (bool, error) {
	key, err := voteKey(account, previous, repPubKey)
	if err != nil {
		return false, err
	}
	err = s.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get(key)
		return err
	})
	if err == badger.ErrKeyNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *BadgerStore) SetBlockStatus(hash string, status core.BlockStatus) error {
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(prefixedKey(prefixBlockStatus, hash), []byte{byte(status)})
	})
}

func (s *BadgerStore) GetBlockStatus(hash string) (core.BlockStatus, error) {
	var status core.BlockStatus
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(prefixedKey(prefixBlockStatus, hash))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			if len(val) > 0 {
				status = core.BlockStatus(val[0])
			}
			return nil
		})
	})
	if err == badger.ErrKeyNotFound {
		return core.StatusPending, nil
	}
	if err != nil {
		return core.StatusPending, err
	}
	return status, nil
}

func (s *BadgerStore) SetFinalHeight(account string, height uint64) error {
	val := make([]byte, 8)
	binary.BigEndian.PutUint64(val, height)
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(prefixedKey(prefixFinalHeight, account), val)
	})
}

func (s *BadgerStore) GetFinalHeight(account string) (uint64, error) {
	var height uint64
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(prefixedKey(prefixFinalHeight, account))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			if len(val) >= 8 {
				height = binary.BigEndian.Uint64(val)
			}
			return nil
		})
	})
	if err == badger.ErrKeyNotFound {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return height, nil
}

func (s *BadgerStore) GetFinalVote(account, previous string) (string, bool, error) {
	var hash string
	var ok bool
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(prefixedKey(prefixFinalVote, account+"|"+previous))
		if err == badger.ErrKeyNotFound {
			return nil
		}
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			hash = string(val)
			ok = true
			return nil
		})
	})
	if err != nil {
		return "", false, err
	}
	return hash, ok, nil
}

func (s *BadgerStore) PutFinalVoteIfAbsent(account, previous, hash string) (string, bool, error) {
	var stored string
	var written bool
	err := s.db.Update(func(txn *badger.Txn) error {
		key := prefixedKey(prefixFinalVote, account+"|"+previous)
		item, err := txn.Get(key)
		if err == nil {
			return item.Value(func(val []byte) error {
				stored = string(val)
				written = false
				return nil
			})
		}
		if err != badger.ErrKeyNotFound {
			return err
		}
		if err := txn.Set(key, []byte(hash)); err != nil {
			return err
		}
		stored = hash
		written = true
		return nil
	})
	if err != nil {
		return "", false, err
	}
	return stored, written, nil
}

func (s *BadgerStore) PutLease(lease *core.Lease) error {
	data, err := json.Marshal(lease)
	if err != nil {
		return err
	}
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(prefixedKey(prefixLease, lease.LeaseHash), data)
	})
}

func (s *BadgerStore) GetLease(leaseHash string) (*core.Lease, error) {
	var lease core.Lease
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(prefixedKey(prefixLease, leaseHash))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &lease)
		})
	})
	if err == badger.ErrKeyNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &lease, nil
}

func (s *BadgerStore) GetLeasesByProvider(provider string) ([]*core.Lease, error) {
	out := make([]*core.Lease, 0)
	err := s.db.View(func(txn *badger.Txn) error {
		prefix := []byte{prefixLease}
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			var l core.Lease
			if err := item.Value(func(val []byte) error {
				return json.Unmarshal(val, &l)
			}); err != nil {
				return err
			}
			if l.Provider == provider {
				out = append(out, &l)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *BadgerStore) GetLeasesByState(state core.LeaseState) ([]*core.Lease, error) {
	out := make([]*core.Lease, 0)
	err := s.db.View(func(txn *badger.Txn) error {
		prefix := []byte{prefixLease}
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			var l core.Lease
			if err := item.Value(func(val []byte) error {
				return json.Unmarshal(val, &l)
			}); err != nil {
				return err
			}
			if l.State == state {
				out = append(out, &l)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *BadgerStore) GetAllLeases() ([]*core.Lease, error) {
	out := make([]*core.Lease, 0)
	err := s.db.View(func(txn *badger.Txn) error {
		prefix := []byte{prefixLease}
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			var l core.Lease
			if err := item.Value(func(val []byte) error {
				return json.Unmarshal(val, &l)
			}); err != nil {
				return err
			}
			out = append(out, &l)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *BadgerStore) PutReputation(account string, agg *core.ReputationAggregate) error {
	data, err := json.Marshal(agg)
	if err != nil {
		return err
	}
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(prefixedKey(prefixReputation, account), data)
	})
}

func (s *BadgerStore) DeleteReputation(account string) error {
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(prefixedKey(prefixReputation, account))
	})
}

func (s *BadgerStore) GetReputation(account string) (*core.ReputationAggregate, error) {
	var agg core.ReputationAggregate
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(prefixedKey(prefixReputation, account))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &agg)
		})
	})
	if err == badger.ErrKeyNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &agg, nil
}

func (s *BadgerStore) GetAllReputations() (map[string]*core.ReputationAggregate, error) {
	out := make(map[string]*core.ReputationAggregate)
	err := s.db.View(func(txn *badger.Txn) error {
		prefix := []byte{prefixReputation}
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			account := string(item.Key()[1:])
			var agg core.ReputationAggregate
			if err := item.Value(func(val []byte) error {
				return json.Unmarshal(val, &agg)
			}); err != nil {
				return err
			}
			cp := agg
			out[account] = &cp
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func stateBlockKey(index uint64) []byte {
	key := make([]byte, 9)
	key[0] = prefixStateBlock
	binary.BigEndian.PutUint64(key[1:], index)
	return key
}

func (s *BadgerStore) PutStateBlock(block *statechain.Block) error {
	data, err := json.Marshal(block)
	if err != nil {
		return err
	}
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(stateBlockKey(block.Index), data)
	})
}

func (s *BadgerStore) GetStateBlock(index uint64) (*statechain.Block, error) {
	var block statechain.Block
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(stateBlockKey(index))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &block)
		})
	})
	if err == badger.ErrKeyNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &block, nil
}

func (s *BadgerStore) GetStateTip() (*statechain.Block, error) {
	var tip *statechain.Block
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Reverse = true
		it := txn.NewIterator(opts)
		defer it.Close()

		seekKey := make([]byte, 9)
		seekKey[0] = prefixStateBlock + 1
		it.Seek(seekKey)
		if it.ValidForPrefix([]byte{prefixStateBlock}) {
			item := it.Item()
			var b statechain.Block
			if err := item.Value(func(val []byte) error {
				return json.Unmarshal(val, &b)
			}); err != nil {
				return err
			}
			tip = &b
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return tip, nil
}

func (s *BadgerStore) GetStateBlockRange(start, count uint64) ([]*statechain.Block, error) {
	var blocks []*statechain.Block
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()

		prefix := []byte{prefixStateBlock}
		seekKey := stateBlockKey(start)
		var n uint64
		for it.Seek(seekKey); it.ValidForPrefix(prefix) && n < count; it.Next() {
			item := it.Item()
			var b statechain.Block
			if err := item.Value(func(val []byte) error {
				return json.Unmarshal(val, &b)
			}); err != nil {
				return err
			}
			blocks = append(blocks, &b)
			n++
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return blocks, nil
}

func (s *BadgerStore) StateBlockCount() (uint64, error) {
	var count uint64
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		prefix := []byte{prefixStateBlock}
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			count++
		}
		return nil
	})
	return count, err
}

func (s *BadgerStore) DeleteVotesForConflict(account, previous string) error {
	prefix, err := voteConflictPrefix(account, previous)
	if err != nil {
		return err
	}

	return s.db.Update(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)

		var keys [][]byte
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			keys = append(keys, it.Item().KeyCopy(nil))
		}
		it.Close()

		for _, k := range keys {
			if err := txn.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}
