package node

import (
	"sort"
	"sync"

	"github.com/xeprotocol/xe/perf"
)

const certRetentionPerProvider = 256

type certSet struct {
	mu         sync.RWMutex
	byHash     map[string]*perf.Certificate
	byProvider map[string][]*perf.Certificate
}

func newCertSet() *certSet {
	return &certSet{
		byHash:     make(map[string]*perf.Certificate),
		byProvider: make(map[string][]*perf.Certificate),
	}
}

func (cs *certSet) put(cert *perf.Certificate) (added bool, evicted []string) {
	if cert == nil {
		return false, nil
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if _, ok := cs.byHash[cert.Hash]; ok {
		return false, nil
	}

	list := cs.byProvider[cert.Provider]

	if len(list) >= certRetentionPerProvider && cert.IssuedAt <= list[0].IssuedAt {
		return false, nil
	}

	cs.byHash[cert.Hash] = cert
	list = append(list, cert)
	sort.SliceStable(list, func(i, j int) bool { return list[i].IssuedAt < list[j].IssuedAt })

	for len(list) > certRetentionPerProvider {
		oldest := list[0]
		delete(cs.byHash, oldest.Hash)
		evicted = append(evicted, oldest.Hash)
		list = list[1:]
	}
	cs.byProvider[cert.Provider] = list
	return true, evicted
}

func (cs *certSet) get(hash string) *perf.Certificate {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.byHash[hash]
}

func (cs *certSet) current(provider string) *perf.Certificate {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	list := cs.byProvider[provider]
	if len(list) == 0 {
		return nil
	}
	return list[len(list)-1]
}

func (cs *certSet) currentValid(provider string, now int64) *perf.Certificate {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	list := cs.byProvider[provider]
	for i := len(list) - 1; i >= 0; i-- {
		if list[i].ExpiresAt > now {
			return list[i]
		}
	}
	return nil
}

func (cs *certSet) all() []*perf.Certificate {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	var current, history []*perf.Certificate
	for _, list := range cs.byProvider {
		if len(list) == 0 {
			continue
		}
		current = append(current, list[len(list)-1])
		for i := len(list) - 2; i >= 0; i-- {
			history = append(history, list[i])
		}
	}
	sort.SliceStable(current, func(i, j int) bool { return current[i].Provider < current[j].Provider })
	return append(current, history...)
}

func (cs *certSet) len() int {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return len(cs.byHash)
}
