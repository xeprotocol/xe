package node

import (
	"math"
	"sort"
	"sync"

	"github.com/xeprotocol/xe/perf"
)

const (
	DefaultCertRetentionPerProvider = 256
	DefaultCertRetentionGlobal      = 4096
)

var (
	CertRetentionPerProvider = DefaultCertRetentionPerProvider
	CertRetentionGlobal      = DefaultCertRetentionGlobal
)

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

	if len(list) >= CertRetentionPerProvider && cert.IssuedAt <= list[0].IssuedAt {
		return false, nil
	}

	if len(cs.byHash) >= CertRetentionGlobal {
		var minIssued int64 = math.MaxInt64
		for _, plist := range cs.byProvider {
			if len(plist) > 0 && plist[0].IssuedAt < minIssued {
				minIssued = plist[0].IssuedAt
			}
		}
		if cert.IssuedAt <= minIssued {
			return false, nil
		}
	}

	cs.byHash[cert.Hash] = cert
	list = append(list, cert)
	sort.SliceStable(list, func(i, j int) bool { return list[i].IssuedAt < list[j].IssuedAt })

	for len(list) > CertRetentionPerProvider {
		oldest := list[0]
		delete(cs.byHash, oldest.Hash)
		evicted = append(evicted, oldest.Hash)
		list = list[1:]
	}
	if len(list) == 0 {
		delete(cs.byProvider, cert.Provider)
	} else {
		cs.byProvider[cert.Provider] = list
	}

	for len(cs.byHash) > CertRetentionGlobal {
		var (
			oldestProv string
			oldestCert *perf.Certificate
		)
		for prov, plist := range cs.byProvider {
			if len(plist) > 0 {
				if oldestCert == nil || plist[0].IssuedAt < oldestCert.IssuedAt ||
					(plist[0].IssuedAt == oldestCert.IssuedAt && prov < oldestProv) {
					oldestCert = plist[0]
					oldestProv = prov
				}
			}
		}
		if oldestCert == nil {
			break
		}
		delete(cs.byHash, oldestCert.Hash)
		evicted = append(evicted, oldestCert.Hash)
		plist := cs.byProvider[oldestProv][1:]
		if len(plist) == 0 {
			delete(cs.byProvider, oldestProv)
		} else {
			cs.byProvider[oldestProv] = plist
		}
	}

	return true, evicted
}

func (cs *certSet) pruneExpired(now int64) (evicted []string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	for prov, list := range cs.byProvider {
		n := 0
		for _, cert := range list {
			if cert.ExpiresAt <= now {
				delete(cs.byHash, cert.Hash)
				evicted = append(evicted, cert.Hash)
			} else {
				list[n] = cert
				n++
			}
		}
		for i := n; i < len(list); i++ {
			list[i] = nil
		}
		list = list[:n]
		if len(list) == 0 {
			delete(cs.byProvider, prov)
		} else {
			cs.byProvider[prov] = list
		}
	}
	return evicted
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
		if (list[i].IssuedAt == 0 || list[i].IssuedAt <= now) && list[i].ExpiresAt > now {
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
