package node

import (
	"sort"
	"sync"

	"github.com/xeprotocol/xe/perf"
)

const (
	certRetentionPerProvider = 256
	maxTrackedCertProviders  = 1024
)

type certSet struct {
	mu           sync.RWMutex
	byHash       map[string]*perf.Certificate
	byProvider   map[string][]*perf.Certificate
	maxProviders int
}

func newCertSet() *certSet {
	return &certSet{
		byHash:       make(map[string]*perf.Certificate),
		byProvider:   make(map[string][]*perf.Certificate),
		maxProviders: maxTrackedCertProviders,
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

	list, exists := cs.byProvider[cert.Provider]
	limit := cs.maxProviders
	if limit <= 0 {
		limit = maxTrackedCertProviders
	}
	if !exists && len(cs.byProvider) >= limit {
		var oldestProvider string
		var oldestLatestIssued int64
		for prov, plist := range cs.byProvider {
			if len(plist) == 0 {
				oldestProvider = prov
				oldestLatestIssued = -1
				break
			}
			latestIssued := plist[len(plist)-1].IssuedAt
			if oldestProvider == "" || latestIssued < oldestLatestIssued {
				oldestProvider = prov
				oldestLatestIssued = latestIssued
			}
		}
		if oldestProvider == "" || (oldestLatestIssued >= 0 && cert.IssuedAt <= oldestLatestIssued) {
			return false, nil
		}
		for _, oldCert := range cs.byProvider[oldestProvider] {
			delete(cs.byHash, oldCert.Hash)
			evicted = append(evicted, oldCert.Hash)
		}
		delete(cs.byProvider, oldestProvider)
	}

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
