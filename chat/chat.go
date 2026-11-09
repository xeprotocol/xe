package chat

import (
	"sort"
	"sync"
	"time"

	"github.com/xeprotocol/xe/core"
)

const maxSeenIDs = 100_000

const defaultMaxAccounts = 10_000

const defaultRetention = 2 * MaxEnvelopeSkew

type ChatStore struct {
	mu            sync.RWMutex
	messages      map[string][]*Envelope
	seen          map[string]int64
	lastActive    map[string]int64
	maxPerAccount int
	maxAccounts   int
	retention     time.Duration
	listeners     []chan *Envelope
	listenerMu    sync.Mutex
}

func NewChatStore(maxPerAccount int) *ChatStore {
	return NewChatStoreWithLimits(maxPerAccount, defaultMaxAccounts, defaultRetention)
}

func NewChatStoreWithLimits(maxPerAccount, maxAccounts int, retention time.Duration) *ChatStore {
	if maxAccounts <= 0 {
		maxAccounts = defaultMaxAccounts
	}
	if retention <= 0 {
		retention = defaultRetention
	}
	return &ChatStore{
		messages:      make(map[string][]*Envelope),
		seen:          make(map[string]int64),
		lastActive:    make(map[string]int64),
		maxPerAccount: maxPerAccount,
		maxAccounts:   maxAccounts,
		retention:     retention,
		listeners:     make([]chan *Envelope, 0),
	}
}

func (s *ChatStore) Store(env *Envelope) bool {
	s.mu.Lock()
	if _, dup := s.seen[env.ID]; dup {
		s.mu.Unlock()
		return false
	}
	if len(s.seen) >= maxSeenIDs {
		s.pruneSeenLocked()
		if len(s.seen) >= maxSeenIDs {
			toEvict := maxSeenIDs / 10
			if toEvict < 1 {
				toEvict = 1
			}
			s.evictOldestSeenLocked(toEvict)
		}
	}
	s.seen[env.ID] = env.Timestamp

	// Ensure accounts capacity before storing
	s.ensureAccountCapacityLocked(env.To, env.From)

	s.storeFor(env.To, env)

	if env.From != env.To {
		s.storeFor(env.From, env)
	}
	s.mu.Unlock()

	s.listenerMu.Lock()
	for _, ch := range s.listeners {
		select {
		case ch <- env:
		default:
		}
	}
	s.listenerMu.Unlock()
	return true
}

func (s *ChatStore) pruneSeenLocked() {
	cutoff := core.Now().Add(-s.retention).UnixNano()
	for id, ts := range s.seen {
		if ts < cutoff {
			delete(s.seen, id)
		}
	}
}

func (s *ChatStore) evictOldestSeenLocked(n int) {
	if n <= 0 || len(s.seen) == 0 {
		return
	}
	type seenEntry struct {
		id string
		ts int64
	}
	entries := make([]seenEntry, 0, len(s.seen))
	for id, ts := range s.seen {
		entries = append(entries, seenEntry{id: id, ts: ts})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ts < entries[j].ts
	})
	if n > len(entries) {
		n = len(entries)
	}
	for i := 0; i < n; i++ {
		delete(s.seen, entries[i].id)
	}
}

func (s *ChatStore) Prune() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneSeenLocked()
	s.pruneMessagesLocked()
}

func (s *ChatStore) pruneMessagesLocked() {
	cutoff := core.Now().Add(-s.retention).UnixNano()
	for account, msgs := range s.messages {
		var active []*Envelope
		for _, env := range msgs {
			if env.Timestamp >= cutoff {
				active = append(active, env)
			}
		}
		if len(active) == 0 {
			delete(s.messages, account)
			delete(s.lastActive, account)
		} else {
			s.messages[account] = active
			s.lastActive[account] = active[len(active)-1].Timestamp
		}
	}
}

func (s *ChatStore) ensureAccountCapacityLocked(to, from string) {
	needed := 0
	if _, ok := s.messages[to]; !ok {
		needed++
	}
	if from != to {
		if _, ok := s.messages[from]; !ok {
			needed++
		}
	}
	if needed == 0 {
		return
	}

	if len(s.messages)+needed > s.maxAccounts {
		s.pruneMessagesLocked()
	}

	if excess := len(s.messages) + needed - s.maxAccounts; excess > 0 {
		s.evictOldestAccountsLocked(excess)
	}
}

func (s *ChatStore) evictOldestAccountsLocked(n int) {
	if n <= 0 || len(s.messages) == 0 {
		return
	}
	type acctTS struct {
		account string
		ts      int64
	}
	items := make([]acctTS, 0, len(s.lastActive))
	for acct, ts := range s.lastActive {
		items = append(items, acctTS{account: acct, ts: ts})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].ts < items[j].ts
	})
	if n > len(items) {
		n = len(items)
	}
	for i := 0; i < n; i++ {
		delete(s.messages, items[i].account)
		delete(s.lastActive, items[i].account)
	}
}

func (s *ChatStore) storeFor(account string, env *Envelope) {
	msgs := s.messages[account]
	if len(msgs) >= s.maxPerAccount {

		newMsgs := make([]*Envelope, s.maxPerAccount)
		copy(newMsgs, msgs[1:])
		newMsgs[s.maxPerAccount-1] = env
		s.messages[account] = newMsgs
	} else {
		s.messages[account] = append(msgs, env)
	}
	s.lastActive[account] = env.Timestamp
}

func (s *ChatStore) Messages(account string, since int64) []*Envelope {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Envelope, 0)
	for _, env := range s.messages[account] {
		if env.Timestamp > since {
			result = append(result, env)
		}
	}
	return result
}

func (s *ChatStore) Accounts() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]string, 0, len(s.messages))
	for account := range s.messages {
		out = append(out, account)
	}

	sort.Strings(out)
	return out
}

func (s *ChatStore) Contacts(account string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	set := make(map[string]bool)
	for _, env := range s.messages[account] {
		other := env.To
		if env.To == account {
			other = env.From
		}
		if other != account {
			set[other] = true
		}
	}
	out := make([]string, 0, len(set))
	for contact := range set {
		out = append(out, contact)
	}
	sort.Strings(out)
	return out
}

func (s *ChatStore) Subscribe() (chan *Envelope, func()) {
	ch := make(chan *Envelope, 64)
	s.listenerMu.Lock()
	s.listeners = append(s.listeners, ch)
	s.listenerMu.Unlock()

	return ch, func() {
		s.listenerMu.Lock()
		defer s.listenerMu.Unlock()
		for i, l := range s.listeners {
			if l == ch {
				s.listeners = append(s.listeners[:i], s.listeners[i+1:]...)
				close(ch)
				return
			}
		}
	}
}
