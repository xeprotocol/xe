package node

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/xeprotocol/xe/perf"
	"github.com/xeprotocol/xe/store"
)

func TestNode_IngestCertificate(t *testing.T) {
	s := store.NewMemStore()
	n := &Node{store: s}

	now := time.Now().UnixNano()
	kp := newTestKeyPair(t)

	// 1. Expired certificate must be rejected
	expiredCert := makeTestCert(t, kp, now-2_000_000_000, now-1_000_000_000)
	if n.ingestCertificate(expiredCert) {
		t.Error("expected expired certificate to be rejected by ingestCertificate")
	}
	all, _ := s.AllCertificates()
	if len(all) != 0 {
		t.Errorf("expected store to be empty, got %d items", len(all))
	}

	// 2. Valid certificate must be accepted and persisted
	validCert := makeTestCert(t, kp, now, now+int64(perf.CertificateValidity))
	if !n.ingestCertificate(validCert) {
		t.Error("expected valid certificate to be accepted by ingestCertificate")
	}
	all, _ = s.AllCertificates()
	if len(all) != 1 {
		t.Fatalf("expected 1 cert in store, got %d", len(all))
	}
	if _, ok := all[validCert.Hash]; !ok {
		t.Errorf("expected validCert.Hash to be persisted in store")
	}
}

func TestNode_LoadPersistedCertificates(t *testing.T) {
	defer func(origProv, origGlobal int) {
		CertRetentionPerProvider = origProv
		CertRetentionGlobal = origGlobal
	}(CertRetentionPerProvider, CertRetentionGlobal)

	CertRetentionPerProvider = 10
	CertRetentionGlobal = 3

	s := store.NewMemStore()
	n := &Node{store: s}

	now := time.Now().UnixNano()

	// Add 1 expired certificate
	kpExpired := newTestKeyPair(t)
	expCert := makeTestCert(t, kpExpired, now-3_000_000_000, now-1_000_000_000)
	expData, _ := json.Marshal(expCert)
	s.PutCertificate(expCert.Hash, expData)

	// Add 1 malformed json entry
	s.PutCertificate("badhex1234", []byte("invalid json data"))

	// Add 5 valid certificates from different providers
	var validHashes []string
	base := now - int64(time.Hour)
	for i := 0; i < 5; i++ {
		kp := newTestKeyPair(t)
		issued := base + int64(i)*1_000_000_000
		cert := makeTestCert(t, kp, issued, issued+int64(perf.CertificateValidity))
		validHashes = append(validHashes, cert.Hash)
		data, _ := json.Marshal(cert)
		s.PutCertificate(cert.Hash, data)
	}

	allBefore, _ := s.AllCertificates()
	if len(allBefore) != 7 {
		t.Fatalf("expected 7 items in store before boot, got %d", len(allBefore))
	}

	n.loadPersistedCertificates()

	// Should have loaded CertRetentionGlobal = 3 certs into memory
	if n.CertificateCount() != 3 {
		t.Fatalf("expected 3 certs loaded into RAM, got %d", n.CertificateCount())
	}

	allAfter, _ := s.AllCertificates()

	// The expired cert and corrupt cert must be deleted from store
	if _, ok := allAfter[expCert.Hash]; ok {
		t.Errorf("expected expired cert to be pruned from store on load")
	}
	if _, ok := allAfter["badhex1234"]; ok {
		t.Errorf("expected corrupt cert to be pruned from store on load")
	}

	// The store should only retain the 3 newest certs (indices 2, 3, 4)
	if len(allAfter) != 3 {
		t.Fatalf("expected store to contain exactly 3 certs, got %d", len(allAfter))
	}
	for i := 0; i < 2; i++ {
		if _, ok := allAfter[validHashes[i]]; ok {
			t.Errorf("expected excess old cert %d (%s) to be evicted from store", i, validHashes[i])
		}
	}
	for i := 2; i < 5; i++ {
		if _, ok := allAfter[validHashes[i]]; !ok {
			t.Errorf("expected newest cert %d (%s) to be retained in store", i, validHashes[i])
		}
	}
}

func TestNode_PruneExpiredCertificates(t *testing.T) {
	s := store.NewMemStore()
	n := &Node{store: s}

	now := time.Now().UnixNano()
	kp1 := newTestKeyPair(t)
	kp2 := newTestKeyPair(t)

	// cert1: expired
	cert1 := makeTestCert(t, kp1, now-2_000_000_000, now-500_000_000)
	// cert2: unexpired
	cert2 := makeTestCert(t, kp2, now-1_000_000_000, now+int64(perf.CertificateValidity))

	n.certs().put(cert1)
	n.certs().put(cert2)
	data1, _ := json.Marshal(cert1)
	data2, _ := json.Marshal(cert2)
	s.PutCertificate(cert1.Hash, data1)
	s.PutCertificate(cert2.Hash, data2)

	all, _ := s.AllCertificates()
	if n.CertificateCount() != 2 || len(all) != 2 {
		t.Fatalf("setup failed")
	}

	pruned := n.PruneExpiredCertificates()
	if pruned != 1 {
		t.Fatalf("expected 1 pruned cert, got %d", pruned)
	}

	if n.CertificateCount() != 1 {
		t.Fatalf("expected 1 cert in RAM, got %d", n.CertificateCount())
	}
	all, _ = s.AllCertificates()
	if len(all) != 1 {
		t.Fatalf("expected 1 cert in store, got %d", len(all))
	}
	if _, ok := all[cert1.Hash]; ok {
		t.Errorf("expected cert1 to be deleted from store")
	}
	if _, ok := all[cert2.Hash]; !ok {
		t.Errorf("expected cert2 to remain in store")
	}
}
