package directory

import (
	"fmt"
	"sync"
	"time"
)

var clock = time.Now

type Registration struct {
	Account string `json:"account"`

	PubKey    string `json:"pub_key"`
	NodePeer  string `json:"node_peer"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

type Directory struct {
	mu            sync.RWMutex
	registrations map[string]*Registration
	ttl           time.Duration
}

const DefaultTTL = 30 * time.Minute

func New(ttl time.Duration) *Directory {
	if ttl == 0 {
		ttl = DefaultTTL
	}
	return &Directory{
		registrations: make(map[string]*Registration),
		ttl:           ttl,
	}
}

const MaxRegistrations = 50_000

func (d *Directory) Register(reg *Registration) error {
	if err := VerifyRegistration(reg); err != nil {
		return err
	}
	now := clock().UnixNano()
	if d.expired(reg.Timestamp, now) {
		return fmt.Errorf("timestamp older than the directory TTL")
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	existing, ok := d.registrations[reg.Account]
	if ok && existing.Timestamp >= reg.Timestamp {
		return nil
	}
	if !ok && len(d.registrations) >= MaxRegistrations {
		d.prune(now)
		if len(d.registrations) >= MaxRegistrations {
			return fmt.Errorf("directory full")
		}
	}

	d.registrations[reg.Account] = reg
	return nil
}

func (d *Directory) expired(ts, now int64) bool {
	return ts < now-int64(d.ttl)
}

func (d *Directory) Lookup(account string) (*Registration, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	reg, ok := d.registrations[account]
	if !ok {
		return nil, false
	}

	if d.expired(reg.Timestamp, clock().UnixNano()) {
		return nil, false
	}

	return reg, true
}

func (d *Directory) Remove(account string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.registrations, account)
}

func (d *Directory) List() []*Registration {
	d.mu.RLock()
	defer d.mu.RUnlock()

	now := clock().UnixNano()
	out := make([]*Registration, 0, len(d.registrations))
	for _, reg := range d.registrations {
		if !d.expired(reg.Timestamp, now) {
			out = append(out, reg)
		}
	}
	return out
}

func (d *Directory) HasNodePeer(nodePeer string) bool {
	if d == nil || nodePeer == "" {
		return false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()

	now := time.Now().UnixNano()
	for _, reg := range d.registrations {
		if reg.NodePeer == nodePeer && now-reg.Timestamp <= int64(d.ttl) {
			return true
		}
	}
	return false
}

func (d *Directory) Prune() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.prune(clock().UnixNano())
}

func (d *Directory) prune(now int64) int {
	pruned := 0
	for account, reg := range d.registrations {
		if d.expired(reg.Timestamp, now) {
			delete(d.registrations, account)
			pruned++
		}
	}
	return pruned
}

func (d *Directory) TTL() time.Duration {
	return d.ttl
}
