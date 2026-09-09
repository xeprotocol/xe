package directory

import (
	"sync"
	"time"
)

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

func (d *Directory) Register(reg *Registration) error {
	if err := VerifyRegistration(reg); err != nil {
		return err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	existing, ok := d.registrations[reg.Account]
	if ok && existing.Timestamp >= reg.Timestamp {
		return nil
	}

	d.registrations[reg.Account] = reg
	return nil
}

func (d *Directory) Lookup(account string) (*Registration, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	reg, ok := d.registrations[account]
	if !ok {
		return nil, false
	}

	if time.Since(time.Unix(0, reg.Timestamp)) > d.ttl {
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

	now := time.Now().UnixNano()
	out := make([]*Registration, 0, len(d.registrations))
	for _, reg := range d.registrations {
		if now-reg.Timestamp <= int64(d.ttl) {
			out = append(out, reg)
		}
	}
	return out
}

func (d *Directory) Prune() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now().UnixNano()
	pruned := 0
	for account, reg := range d.registrations {
		if now-reg.Timestamp > int64(d.ttl) {
			delete(d.registrations, account)
			pruned++
		}
	}
	return pruned
}

func (d *Directory) TTL() time.Duration {
	return d.ttl
}
