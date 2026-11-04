package node

import (
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/perf"
)

func createNodeTestCert(t *testing.T, issuedAt, expiresAt int64) (*perf.Certificate, *core.KeyPair) {
	t.Helper()
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	addr, err := core.DeriveAddress(kp.PubKeyHex())
	if err != nil {
		t.Fatalf("DeriveAddress failed: %v", err)
	}

	cert := &perf.Certificate{
		Provider:             addr,
		ProviderPubKey:       kp.PubKeyHex(),
		WorkloadVersion:      perf.WorkloadVersion,
		Puzzles:              perf.PoWPuzzles,
		CPUHash:              strings.Repeat("a", 64),
		PriceMultiplierMilli: perf.PriceMultiplierDefault,
		Score:                100.0,
		IssuedAt:             issuedAt,
		ExpiresAt:            expiresAt,
	}
	if err := perf.SignCertificate(cert, kp); err != nil {
		t.Fatalf("SignCertificate failed: %v", err)
	}
	return cert, kp
}

func TestNode_IngestCertificateRejectsExpired(t *testing.T) {
	oldNow := core.Now
	defer func() { core.Now = oldNow }()

	fixedNow := int64(3_000_000_000_000)
	core.Now = func() time.Time { return time.Unix(0, fixedNow) }

	n := &Node{}

	// Expired cert
	expiredCert, _ := createNodeTestCert(t, fixedNow-2000, fixedNow-1000)
	if n.ingestCertificate(expiredCert) {
		t.Fatalf("expected ingestCertificate to reject expired cert")
	}

	// Valid cert
	validCert, _ := createNodeTestCert(t, fixedNow-1000, fixedNow+int64(time.Hour))
	if !n.ingestCertificate(validCert) {
		t.Fatalf("expected ingestCertificate to accept valid cert")
	}
}

func TestNode_CollectCertificatesFiltersExpired(t *testing.T) {
	oldNow := core.Now
	defer func() { core.Now = oldNow }()

	initialNow := int64(4_000_000_000_000)
	core.Now = func() time.Time { return time.Unix(0, initialNow) }

	n := &Node{}

	// Cert 1 expires soon (+ 100 nanos)
	certExpiringSoon, _ := createNodeTestCert(t, initialNow-1000, initialNow+100)
	// Cert 2 expires much later (+ 1 hour)
	certLongLived, _ := createNodeTestCert(t, initialNow-1000, initialNow+int64(time.Hour))

	if !n.ingestCertificate(certExpiringSoon) || !n.ingestCertificate(certLongLived) {
		t.Fatalf("failed to ingest test certs")
	}

	// Advance time past certExpiringSoon
	core.Now = func() time.Time { return time.Unix(0, initialNow+500) }

	collected := n.collectCertificates()
	if len(collected) != 1 {
		t.Fatalf("expected 1 unexpired collected cert, got %d", len(collected))
	}
	if collected[0].Hash != certLongLived.Hash {
		t.Fatalf("expected %s, got %s", certLongLived.Hash, collected[0].Hash)
	}
}
