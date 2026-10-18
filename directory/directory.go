package directory

import (
	"fmt"
	"sync"
	"time"

	"github.com/xeprotocol/xe/core"
)

type Registration struct {
	Account string `json:"account"`

	PubKey    string `json:"pub_key"`
	NodePeer  string `json:"node_peer"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

const (
	DefaultTTL              = 30 * time.Minute
	DefaultMaxRegistrations = 10_000
)

type Directory struct {
	mu            sync.RWMutex
	registrations map[string]*Registration
	ttl           time.Duration
	maxEntries    int
}

func New(ttl time.Duration) *Directory {
	if ttl == 0 {
		ttl = DefaultTTL
	}
	return &Directory{
		registrations: make(map[string]*Registration),
		ttl:           ttl,
		maxEntries:    DefaultMaxRegistrations,
	}
}

func (d *Directory) isExpired(reg *Registration, now int64) bool {
	if reg == nil || reg.Timestamp <= 0 {
		return true
	}
	if reg.Timestamp > now+int64(MaxRegistrationClockSkew) {
		return true
	}
	if now > reg.Timestamp && now-reg.Timestamp > int64(d.ttl) {
		return true
	}
	return false
}

func (d *Directory) Register(reg *Registration) error {
	if err := VerifyRegistration(reg); err != nil {
		return err
	}

	now := core.Now().UnixNano()
	if d.isExpired(reg, now) {
		return fmt.Errorf("registration expired")
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	existing, ok := d.registrations[reg.Account]
	if ok && !d.isExpired(existing, now) && existing.Timestamp >= reg.Timestamp {
		return nil
	}

	limit := d.maxEntries
	if limit <= 0 {
		limit = DefaultMaxRegistrations
	}
	if !ok && len(d.registrations) >= limit {
		for acc, r := range d.registrations {
			if d.isExpired(r, now) {
				delete(d.registrations, acc)
			}
		}
		if len(d.registrations) >= limit {
			var oldestAcc string
			var oldestTs int64
			for acc, r := range d.registrations {
				if oldestAcc == "" || r.Timestamp < oldestTs {
					oldestAcc = acc
					oldestTs = r.Timestamp
				}
			}
			if oldestAcc == "" || reg.Timestamp <= oldestTs {
				return fmt.Errorf("directory capacity reached")
			}
			delete(d.registrations, oldestAcc)
		}
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

	if d.isExpired(reg, core.Now().UnixNano()) {
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

	now := core.Now().UnixNano()
	out := make([]*Registration, 0, len(d.registrations))
	for _, reg := range d.registrations {
		if !d.isExpired(reg, now) {
			out = append(out, reg)
		}
	}
	return out
}

func (d *Directory) Prune() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := core.Now().UnixNano()
	pruned := 0
	for account, reg := range d.registrations {
		if d.isExpired(reg, now) {
			delete(d.registrations, account)
			pruned++
		}
	}
	return pruned
}

func (d *Directory) TTL() time.Duration {
	return d.ttl
}
