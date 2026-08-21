package node

import (
	"sort"
	"sync"

	"github.com/xeprotocol/xe/perf"
)

// certRetentionPerProvider bounds how many certificates are kept for any one
// provider. Certificates cost one signature to mint (#817), so retention must
// be bounded or a provider could grow every peer's store without limit.
//
// The bound is deliberately far above any legitimate need: providers re-issue
// at most once per 7-day validity window plus once per restart, so 256 covers
// years of normal operation. A provider that deliberately rotates past the
// bound evicts its OWN oldest certificates, which makes its OWN old lease
// blocks unvalidatable for nodes that have not yet synced them — a real but
// self-inflicted denial of service, and a sub-case of #817 (certificates carry
// no proof of work done, so they are free to mint). Making retention exact
// requires pinning certificates referenced by stored lease blocks; that is
// tracked as follow-up on #816 and is not attempted here.
const certRetentionPerProvider = 256

// certSet holds the performance certificates a node knows about.
//
// It is keyed by certificate HASH, not by provider (#816). Lease blocks pin
// the hash of the certificate that was current when they were written, and the
// ledger must resolve that exact hash to validate the block — forever, long
// after the provider has rotated. Keying by provider retains one certificate
// and silently discards the history, which permanently stalls any node
// replaying lease blocks that pin an evicted hash.
//
// A per-provider index tracks the newest certificate, which is what offer and
// accept paths want ("this provider's current certificate").
type certSet struct {
	mu         sync.RWMutex
	byHash     map[string]*perf.Certificate
	byProvider map[string][]*perf.Certificate // ascending IssuedAt; last is current
}

func newCertSet() *certSet {
	return &certSet{
		byHash:     make(map[string]*perf.Certificate),
		byProvider: make(map[string][]*perf.Certificate),
	}
}

// put retains a certificate. It returns added=false if the certificate was
// already held or was dropped by the retention bound, and returns the hashes
// of any certificates evicted to stay within the bound so the caller can drop
// them from persistent storage too.
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

	// At the bound, an incoming certificate older than everything retained is
	// dropped rather than evicting newer history.
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

// get returns the certificate with the given hash, or nil.
func (cs *certSet) get(hash string) *perf.Certificate {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.byHash[hash]
}

// current returns the newest certificate held for a provider, or nil. It does
// not filter on expiry — callers that need a usable certificate check that
// themselves, since "the newest one we have" and "a valid one" are different
// questions and conflating them is what #816 was.
func (cs *certSet) current(provider string) *perf.Certificate {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	list := cs.byProvider[provider]
	if len(list) == 0 {
		return nil
	}
	return list[len(list)-1]
}

// currentValid returns the newest certificate held for a provider that has not
// expired as of now, or nil. This is the "can I quote or accept a lease
// against this provider" question, and is deliberately distinct from current():
// retention keeps expired certificates for historical validation, but they must
// never be offered as a certificate to write a new lease against.
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

// all returns every retained certificate, each provider's current certificate
// first, then history newest-first. Ordering matters because a peer serving a
// pull truncates at a response cap: current certificates — the ones needed to
// accept new leases — must never be the entries that get cut.
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

// len reports how many certificates are retained.
func (cs *certSet) len() int {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return len(cs.byHash)
}
