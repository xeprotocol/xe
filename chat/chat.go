package chat

import (
	"sort"
	"sync"
	"time"

	"github.com/xeprotocol/xe/core"
)

const (
	maxSeenIDs  = 100_000
	maxAccounts = 10_000
)

type ChatStore struct {
	mu            sync.RWMutex
	messages      map[string][]*Envelope
	seen          map[string]int64
	seenOrder     []string
	accountOrder  []string
	lastPrune     time.Time
	maxPerAccount int
	maxAccounts   int
	maxSeen       int
	listeners     []chan *Envelope
	listenerMu    sync.Mutex
}

func NewChatStore(maxPerAccount int) *ChatStore {
	return NewChatStoreWithLimits(maxPerAccount, maxAccounts, maxSeenIDs)
}

func NewChatStoreWithLimits(maxPerAccount, maxAccts, maxSeen int) *ChatStore {
	return &ChatStore{
		messages:      make(map[string][]*Envelope),
		seen:          make(map[string]int64),
		seenOrder:     make([]string, 0),
		accountOrder:  make([]string, 0),
		maxPerAccount: maxPerAccount,
		maxAccounts:   maxAccts,
		maxSeen:       maxSeen,
		listeners:     make([]chan *Envelope, 0),
	}
}

func (s *ChatStore) maxSeenCap() int {
	if s.maxSeen <= 0 {
		return maxSeenIDs
	}
	return s.maxSeen
}

func (s *ChatStore) maxAccountsCap() int {
	if s.maxAccounts <= 0 {
		return maxAccounts
	}
	return s.maxAccounts
}

func (s *ChatStore) Store(env *Envelope) bool {
	if env == nil || env.ID == "" {
		return false
	}
	s.mu.Lock()
	if _, dup := s.seen[env.ID]; dup {
		s.mu.Unlock()
		return false
	}

	maxSeen := s.maxSeenCap()
	if len(s.seen) >= maxSeen {
		now := core.Now()
		if s.lastPrune.IsZero() || now.Sub(s.lastPrune) >= 10*time.Second {
			s.lastPrune = now
			s.pruneSeenLocked(now)
		}
		for len(s.seen) >= maxSeen {
			if !s.evictOldestSeenLocked() {
				break
			}
		}
	}
	s.seen[env.ID] = env.Timestamp
	s.seenOrder = append(s.seenOrder, env.ID)
	s.compactSeenOrderLocked()

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

func (s *ChatStore) pruneSeenLocked(now time.Time) {
	cutoff := now.Add(-2 * MaxEnvelopeSkew).UnixNano()
	for id, ts := range s.seen {
		if ts < cutoff {
			delete(s.seen, id)
		}
	}
	s.compactSeenOrderLocked()
}

func (s *ChatStore) evictOldestSeenLocked() bool {
	for len(s.seenOrder) > 0 {
		id := s.seenOrder[0]
		s.seenOrder = s.seenOrder[1:]
		if _, ok := s.seen[id]; ok {
			delete(s.seen, id)
			return true
		}
	}
	return false
}

func (s *ChatStore) compactSeenOrderLocked() {
	maxSeen := s.maxSeenCap()
	if len(s.seenOrder) <= 2*maxSeen {
		return
	}
	compacted := make([]string, 0, len(s.seen))
	for _, id := range s.seenOrder {
		if _, ok := s.seen[id]; ok {
			compacted = append(compacted, id)
		}
	}
	s.seenOrder = compacted
}

func (s *ChatStore) storeFor(account string, env *Envelope) {
	if account == "" {
		return
	}
	msgs, exists := s.messages[account]
	if !exists {
		maxAccts := s.maxAccountsCap()
		for len(s.messages) >= maxAccts {
			if !s.evictOldestAccountLocked() {
				break
			}
		}
	}

	maxPerAcct := s.maxPerAccount
	if maxPerAcct <= 0 {
		maxPerAcct = 1000
	}

	if len(msgs) >= maxPerAcct {
		newMsgs := make([]*Envelope, maxPerAcct)
		copy(newMsgs, msgs[1:])
		newMsgs[maxPerAcct-1] = env
		s.messages[account] = newMsgs
	} else {
		s.messages[account] = append(msgs, env)
	}

	s.accountOrder = append(s.accountOrder, account)
	s.compactAccountOrderLocked()
}

func (s *ChatStore) evictOldestAccountLocked() bool {
	for len(s.accountOrder) > 0 {
		acct := s.accountOrder[0]
		s.accountOrder = s.accountOrder[1:]
		if _, ok := s.messages[acct]; ok {
			delete(s.messages, acct)
			return true
		}
	}
	return false
}

func (s *ChatStore) compactAccountOrderLocked() {
	maxAccts := s.maxAccountsCap()
	if len(s.accountOrder) <= 2*maxAccts {
		return
	}
	compacted := make([]string, 0, len(s.messages))
	seen := make(map[string]bool, len(s.messages))
	for i := len(s.accountOrder) - 1; i >= 0; i-- {
		acct := s.accountOrder[i]
		if _, ok := s.messages[acct]; ok && !seen[acct] {
			seen[acct] = true
			compacted = append(compacted, acct)
		}
	}
	for i, j := 0, len(compacted)-1; i < j; i, j = i+1, j-1 {
		compacted[i], compacted[j] = compacted[j], compacted[i]
	}
	s.accountOrder = compacted
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
