package store

import (
	"encoding/json"
	"math/big"
	"sync"

	"github.com/dgraph-io/badger/v4"
	"github.com/xeprotocol/xe/core"
)

type pendingTally struct {
	gate sync.RWMutex

	mu      sync.Mutex
	built   bool
	byAsset map[string]*pendingSum
}

type pendingSum struct {
	count  int
	amount big.Int
}

type pendingDelta map[string]*pendingSum

func (d pendingDelta) change(ps *core.PendingSend, sign int) {
	sum := d[ps.Asset]
	if sum == nil {
		sum = &pendingSum{}
		d[ps.Asset] = sum
	}
	sum.count += sign
	amount := new(big.Int).SetUint64(ps.Amount)
	if sign < 0 {
		amount.Neg(amount)
	}
	sum.amount.Add(&sum.amount, amount)
}

func (d pendingDelta) added(ps *core.PendingSend) { d.change(ps, 1) }

func (d pendingDelta) removed(ps *core.PendingSend) { d.change(ps, -1) }

func (t *pendingTally) apply(d pendingDelta) {
	if len(d) == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.built {
		return
	}
	for asset, c := range d {
		sum := t.byAsset[asset]
		if sum == nil {
			sum = &pendingSum{}
			t.byAsset[asset] = sum
		}
		sum.count += c.count
		sum.amount.Add(&sum.amount, &c.amount)
		if sum.count == 0 && sum.amount.Sign() == 0 {
			delete(t.byAsset, asset)
		}
	}
}

func (s *BadgerStore) updatePending(fn func(txn *badger.Txn, d pendingDelta) error) error {
	s.pending.gate.RLock()
	defer s.pending.gate.RUnlock()
	d := pendingDelta{}
	if err := s.db.Update(func(txn *badger.Txn) error { return fn(txn, d) }); err != nil {
		return err
	}
	s.pending.apply(d)
	return nil
}

func putPendingTxn(txn *badger.Txn, d pendingDelta, ps *core.PendingSend, data []byte) error {
	key := prefixedKey(prefixPending, ps.SendHash)
	item, err := txn.Get(key)
	if err != nil && err != badger.ErrKeyNotFound {
		return err
	}
	if err == nil {
		var old core.PendingSend
		if err := item.Value(func(val []byte) error { return json.Unmarshal(val, &old) }); err != nil {
			return err
		}
		d.removed(&old)
	}
	if err := txn.Set(key, data); err != nil {
		return err
	}
	d.added(ps)
	return nil
}

func (s *BadgerStore) PendingTotals() (map[string]core.PendingTotal, error) {
	t := &s.pending
	t.gate.Lock()
	defer t.gate.Unlock()
	if !t.built {
		byAsset := map[string]*pendingSum{}
		err := s.db.View(func(txn *badger.Txn) error {
			prefix := []byte{prefixPending}
			opts := badger.DefaultIteratorOptions
			opts.Prefix = prefix
			it := txn.NewIterator(opts)
			defer it.Close()
			d := pendingDelta(byAsset)
			for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
				var ps core.PendingSend
				if err := it.Item().Value(func(val []byte) error { return json.Unmarshal(val, &ps) }); err != nil {
					return err
				}
				d.added(&ps)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		t.byAsset, t.built = byAsset, true
	}
	out := make(map[string]core.PendingTotal, len(t.byAsset))
	for asset, sum := range t.byAsset {
		out[asset] = core.PendingTotal{Count: sum.count, Amount: new(big.Int).Set(&sum.amount)}
	}
	return out, nil
}
