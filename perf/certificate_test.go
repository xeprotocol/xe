package perf

import (
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
)

func newTestKeyPair(t *testing.T) *core.KeyPair {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	return kp
}

func newTestCertificate(t *testing.T, kp *core.KeyPair, issuedAt, expiresAt int64) *Certificate {
	if kp == nil {
		kp = newTestKeyPair(t)
	}
	startMedian := issuedAt
	endMedian := startMedian + 1_000_000_000 // 1 sec
	score := 1.0
	zeroRoot := "0000000000000000000000000000000000000000000000000000000000000000"
	dummyHex := "1111111111111111111111111111111111111111111111111111111111111111"

	cert := &Certificate{
		Provider:             kp.Address(),
		ProviderPubKey:       kp.PubKeyHex(),
		Seed:                 SeedHex(DeriveSeed(startMedian, kp.Public)),
		WorkloadVersion:      WorkloadVersion,
		Puzzles:              PoWPuzzles,
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
	if err := SignCertificate(cert, kp); err != nil {
		t.Fatalf("SignCertificate failed: %v", err)
	}
	return cert
}

func TestVerifyCertificateContent_Valid(t *testing.T) {
	kp := newTestKeyPair(t)
	now := time.Now().UnixNano()
	cert := newTestCertificate(t, kp, now, now+int64(CertificateValidity))

	if err := VerifyCertificateContent(cert); err != nil {
		t.Fatalf("expected valid cert, got error: %v", err)
	}
}

func TestVerifyCertificateContent_WorkProof(t *testing.T) {
	kp := newTestKeyPair(t)
	now := time.Now().UnixNano()

	badProofs := []string{
		"",                                                                 // empty
		"111111111111111111111111111111111111111111111111111111111111111",  // 63 chars
		"11111111111111111111111111111111111111111111111111111111111111111", // 65 chars
		"111111111111111111111111111111111111111111111111111111111111111G", // non-hex
		"111111111111111111111111111111111111111111111111111111111111111A", // uppercase
	}

	for _, bad := range badProofs {
		cert := newTestCertificate(t, kp, now, now+int64(CertificateValidity))
		cert.WorkProof = bad
		_ = SignCertificate(cert, kp)
		if err := VerifyCertificateContent(cert); err == nil {
			t.Errorf("expected error for bad work_proof %q, got nil", bad)
		}
	}
}

func TestVerifyCertificateContent_AttestationRoots(t *testing.T) {
	kp := newTestKeyPair(t)
	now := time.Now().UnixNano()

	badRoots := []string{
		"",
		"00000000",
		"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
	}

	for _, bad := range badRoots {
		cert := newTestCertificate(t, kp, now, now+int64(CertificateValidity))
		cert.StartAttestationRoot = bad
		_ = SignCertificate(cert, kp)
		if err := VerifyCertificateContent(cert); err == nil {
			t.Errorf("expected error for bad StartAttestationRoot %q, got nil", bad)
		}

		cert2 := newTestCertificate(t, kp, now, now+int64(CertificateValidity))
		cert2.EndAttestationRoot = bad
		_ = SignCertificate(cert2, kp)
		if err := VerifyCertificateContent(cert2); err == nil {
			t.Errorf("expected error for bad EndAttestationRoot %q, got nil", bad)
		}
	}
}

func TestVerifyCertificateContent_ExpiryAndIssuedAt(t *testing.T) {
	kp := newTestKeyPair(t)
	now := time.Now().UnixNano()

	// IssuedAt <= 0
	cert0 := newTestCertificate(t, kp, 0, now+int64(CertificateValidity))
	if err := VerifyCertificateContent(cert0); err == nil {
		t.Error("expected error for IssuedAt <= 0, got nil")
	}

	// ExpiresAt <= IssuedAt
	cert1 := newTestCertificate(t, kp, now, now)
	if err := VerifyCertificateContent(cert1); err == nil {
		t.Error("expected error for ExpiresAt <= IssuedAt, got nil")
	}

	cert2 := newTestCertificate(t, kp, now, now-1000)
	if err := VerifyCertificateContent(cert2); err == nil {
		t.Error("expected error for ExpiresAt < IssuedAt, got nil")
	}

	// Duration exceeds CertificateValidity + 24h
	tooLong := now + int64(CertificateValidity+25*time.Hour)
	cert3 := newTestCertificate(t, kp, now, tooLong)
	if err := VerifyCertificateContent(cert3); err == nil {
		t.Error("expected error for duration > CertificateValidity + 24h, got nil")
	}
}
