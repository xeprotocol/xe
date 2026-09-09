package chat

import (
	"sort"
	"sync"

	"github.com/xeprotocol/xe/core"
)

const maxSeenIDs = 100_000

type ChatStore struct {
	mu            sync.RWMutex
	messages      map[string][]*Envelope
	seen          map[string]int64
	maxPerAccount int
	listeners     []chan *Envelope
	listenerMu    sync.Mutex
}

func NewChatStore(maxPerAccount int) *ChatStore {
	return &ChatStore{
		messages:      make(map[string][]*Envelope),
		seen:          make(map[string]int64),
		maxPerAccount: maxPerAccount,
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
			s.mu.Unlock()
			return false
		}
	}
	s.seen[env.ID] = env.Timestamp

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
	cutoff := core.Now().Add(-2 * MaxEnvelopeSkew).UnixNano()
	for id, ts := range s.seen {
		if ts < cutoff {
			delete(s.seen, id)
		}
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
