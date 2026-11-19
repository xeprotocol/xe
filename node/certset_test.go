package node

import (
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/perf"
)

func newTestKeyPair(t *testing.T) *core.KeyPair {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	return kp
}

func makeTestCert(t *testing.T, kp *core.KeyPair, issuedAt, expiresAt int64) *perf.Certificate {
	if kp == nil {
		kp = newTestKeyPair(t)
	}
	startMedian := issuedAt
	endMedian := startMedian + 1_000_000_000
	score := 1.0
	zeroRoot := "0000000000000000000000000000000000000000000000000000000000000000"
	dummyHex := "1111111111111111111111111111111111111111111111111111111111111111"

	cert := &perf.Certificate{
		Provider:             kp.Address(),
		ProviderPubKey:       kp.PubKeyHex(),
		Seed:                 perf.SeedHex(perf.DeriveSeed(startMedian, kp.Public)),
		WorkloadVersion:      perf.WorkloadVersion,
		Puzzles:              perf.PoWPuzzles,
		WorkProof:            dummyHex,
		CPUHash:              dummyHex,
		Score:                score,
		StartAttestationRoot: zeroRoot,
		EndAttestationRoot:   zeroRoot,
		StartMedian:          startMedian,
		EndMedian:            endMedian,
		IssuedAt:             issuedAt,
		ExpiresAt:            expiresAt,
		PriceMultiplierMilli: 1000,
	}
	if err := perf.SignCertificate(cert, kp); err != nil {
		t.Fatalf("SignCertificate failed: %v", err)
	}
	return cert
}

func TestCertSet_PerProviderRetention(t *testing.T) {
	defer func(origProv, origGlobal int) {
		CertRetentionPerProvider = origProv
		CertRetentionGlobal = origGlobal
	}(CertRetentionPerProvider, CertRetentionGlobal)

	CertRetentionPerProvider = 3
	CertRetentionGlobal = 100

	cs := newCertSet()
	kp, _ := core.GenerateKeyPair()
	base := time.Now().UnixNano()

	var hashes []string
	for i := 1; i <= 5; i++ {
		cert := makeTestCert(t, kp, base+int64(i)*1_000_000_000, base+int64(i+10)*1_000_000_000)
		hashes = append(hashes, cert.Hash)
		added, _ := cs.put(cert)
		if !added {
			t.Fatalf("failed to add cert %d", i)
		}
	}

	if cs.len() != 3 {
		t.Fatalf("expected certSet len 3, got %d", cs.len())
	}

	// First two should have been evicted
	if cs.get(hashes[0]) != nil || cs.get(hashes[1]) != nil {
		t.Errorf("expected hashes[0] and hashes[1] to be evicted")
	}

	// Last three should be present
	for i := 2; i < 5; i++ {
		if cs.get(hashes[i]) == nil {
			t.Errorf("expected hash %d to be retained", i)
		}
	}
}

func TestCertSet_GlobalRetentionAcrossProviders(t *testing.T) {
	defer func(origProv, origGlobal int) {
		CertRetentionPerProvider = origProv
		CertRetentionGlobal = origGlobal
	}(CertRetentionPerProvider, CertRetentionGlobal)

	CertRetentionPerProvider = 10
	CertRetentionGlobal = 5

	cs := newCertSet()
	base := int64(1_000_000_000)

	var certs []*perf.Certificate
	for i := 0; i < 10; i++ {
		kp, _ := core.GenerateKeyPair()
		cert := makeTestCert(t, kp, base+int64(i)*100_000_000, base+int64(i+10)*100_000_000)
		certs = append(certs, cert)
		added, _ := cs.put(cert)
		if !added {
			t.Fatalf("failed to add cert %d", i)
		}
	}

	if cs.len() != 5 {
		t.Fatalf("expected global retention cap 5, got %d", cs.len())
	}

	// Check that byProvider map only has 5 keys (empty slices deleted)
	if len(cs.byProvider) != 5 {
		t.Fatalf("expected byProvider map to have 5 keys, got %d", len(cs.byProvider))
	}

	// First 5 certs (oldest) should have been evicted
	for i := 0; i < 5; i++ {
		if cs.get(certs[i].Hash) != nil {
			t.Errorf("expected cert %d to be evicted", i)
		}
		if _, ok := cs.byProvider[certs[i].Provider]; ok {
			t.Errorf("expected provider %d to be pruned from byProvider", i)
		}
	}

	// Last 5 certs should be present
	for i := 5; i < 10; i++ {
		if cs.get(certs[i].Hash) == nil {
			t.Errorf("expected cert %d to be retained", i)
		}
	}

	// Adding a cert older than the global oldest (certs[5].IssuedAt) must be rejected
	oldKp, _ := core.GenerateKeyPair()
	oldCert := makeTestCert(t, oldKp, certs[5].IssuedAt-10, base+int64(20)*100_000_000)
	added, _ := cs.put(oldCert)
	if added {
		t.Errorf("expected cert older than global oldest to be rejected, but it was added")
	}

	// Adding a newer cert should succeed and evict certs[5]
	newKp, _ := core.GenerateKeyPair()
	newCert := makeTestCert(t, newKp, certs[9].IssuedAt+100_000_000, base+int64(30)*100_000_000)
	added, evicted := cs.put(newCert)
	if !added {
		t.Fatalf("expected newer cert to be added")
	}
	if len(evicted) != 1 || evicted[0] != certs[5].Hash {
		t.Errorf("expected evicted to be certs[5].Hash (%s), got %v", certs[5].Hash, evicted)
	}
	if cs.get(certs[5].Hash) != nil {
		t.Errorf("expected certs[5] to be evicted")
	}
	if cs.get(newCert.Hash) == nil {
		t.Errorf("expected newCert to be retained")
	}
	if cs.len() != 5 {
		t.Fatalf("expected global cap 5, got %d", cs.len())
	}
}

func TestCertSet_PruneExpired(t *testing.T) {
	cs := newCertSet()
	now := int64(2_000_000_000)

	kp1, _ := core.GenerateKeyPair()
	kp2, _ := core.GenerateKeyPair()

	// cert1: expired
	cert1 := makeTestCert(t, kp1, 1_000_000_000, now-100)
	// cert2: valid
	cert2 := makeTestCert(t, kp1, 1_500_000_000, now+1_000_000_000)
	// cert3: expired (only cert for kp2)
	cert3 := makeTestCert(t, kp2, 1_000_000_000, now-50)

	cs.put(cert1)
	cs.put(cert2)
	cs.put(cert3)

	if cs.len() != 3 {
		t.Fatalf("expected 3 certs, got %d", cs.len())
	}

	evicted := cs.pruneExpired(now)
	if len(evicted) != 2 {
		t.Fatalf("expected 2 evicted certs, got %d (%v)", len(evicted), evicted)
	}

	if cs.len() != 1 {
		t.Fatalf("expected 1 remaining cert, got %d", cs.len())
	}
	if cs.get(cert2.Hash) == nil {
		t.Errorf("expected cert2 to remain")
	}
	if cs.get(cert1.Hash) != nil || cs.get(cert3.Hash) != nil {
		t.Errorf("expected cert1 and cert3 to be deleted from byHash")
	}
	if _, ok := cs.byProvider[kp2.Address()]; ok {
		t.Errorf("expected kp2 to be pruned from byProvider")
	}
}

func TestCertSet_CurrentValid(t *testing.T) {
	cs := newCertSet()
	now := int64(2_000_000_000)
	kp, _ := core.GenerateKeyPair()

	// cert1: expired
	cert1 := makeTestCert(t, kp, 1_000_000_000, now-100)
	cs.put(cert1)

	if cs.currentValid(kp.Address(), now) != nil {
		t.Errorf("expected nil for expired cert")
	}

	// cert2: valid
	cert2 := makeTestCert(t, kp, 1_500_000_000, now+1_000_000_000)
	cs.put(cert2)

	curr := cs.currentValid(kp.Address(), now)
	if curr == nil || curr.Hash != cert2.Hash {
		t.Errorf("expected cert2, got %v", curr)
	}

	// cert3: future issued (IssuedAt > now)
	cert3 := makeTestCert(t, kp, now+500_000_000, now+2_000_000_000)
	cs.put(cert3)

	// currentValid at `now` should still be cert2
	curr = cs.currentValid(kp.Address(), now)
	if curr == nil || curr.Hash != cert2.Hash {
		t.Errorf("expected cert2 at now, got %v", curr)
	}

	// currentValid at `now + 600_000_000` should be cert3
	curr = cs.currentValid(kp.Address(), now+600_000_000)
	if curr == nil || curr.Hash != cert3.Hash {
		t.Errorf("expected cert3 at future time, got %v", curr)
	}
}
