package perf_test

import (
	"encoding/hex"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/perf"
)

func makeValidCertificate(t *testing.T, kp *core.KeyPair, startMedian int64) *perf.Certificate {
	t.Helper()
	endMedian := startMedian + int64(2*time.Second)
	pubBytes, err := hex.DecodeString(kp.PubKeyHex())
	if err != nil {
		t.Fatalf("DecodeString pubkey: %v", err)
	}
	seed := perf.DeriveSeed(startMedian, pubBytes)
	elapsedSecs := float64(endMedian-startMedian) / 1e9
	score := 1.0 / elapsedSecs

	cert := &perf.Certificate{
		Provider:             kp.Address(),
		Seed:                 perf.SeedHex(seed),
		WorkloadVersion:      perf.WorkloadVersion,
		Puzzles:              perf.PoWPuzzles,
		WorkProof:            strings.Repeat("ab", 32),
		CPUHash:              strings.Repeat("cd", 32),
		Score:                score,
		StartAttestationRoot: strings.Repeat("11", 32),
		EndAttestationRoot:   strings.Repeat("22", 32),
		StartMedian:          startMedian,
		EndMedian:            endMedian,
		IssuedAt:             startMedian,
		ExpiresAt:            startMedian + int64(perf.CertificateValidity),
		PriceMultiplierMilli: perf.PriceMultiplierDefault,
	}
	if err := perf.SignCertificate(cert, kp); err != nil {
		t.Fatalf("SignCertificate: %v", err)
	}
	return cert
}

func TestCertificateVerificationRejectsForgedScoreSeedAndInfiniteExpiry(t *testing.T) {
	kp, _ := core.GenerateKeyPair()
	now := core.Now().UnixNano()

	valid := makeValidCertificate(t, kp, now)
	if err := perf.VerifyCertificate(valid, now); err != nil {
		t.Fatalf("expected valid certificate to pass VerifyCertificate, got: %v", err)
	}

	// 1. Infinite / NaN score must be rejected.
	infCert := *valid
	infCert.Score = math.Inf(1)
	_ = perf.SignCertificate(&infCert, kp)
	if err := perf.VerifyCertificateContent(&infCert); err == nil {
		t.Fatalf("expected +Inf score certificate to be rejected")
	}

	// 2. Forged inflated score inconsistent with EndMedian - StartMedian must be rejected.
	forgedScore := *valid
	forgedScore.Score = 999999.0
	_ = perf.SignCertificate(&forgedScore, kp)
	if err := perf.VerifyCertificateContent(&forgedScore); err == nil {
		t.Fatalf("expected certificate with forged score inconsistent with elapsed median time to be rejected")
	}

	// 3. Forged seed not derived from (StartMedian, ProviderPubKey) must be rejected.
	forgedSeed := *valid
	forgedSeed.Seed = strings.Repeat("ff", 32)
	_ = perf.SignCertificate(&forgedSeed, kp)
	if err := perf.VerifyCertificateContent(&forgedSeed); err == nil {
		t.Fatalf("expected certificate with forged seed to be rejected")
	}

	// 4. Missing/zero attestation roots or work proof must be rejected.
	noAtt := *valid
	noAtt.StartAttestationRoot = ""
	_ = perf.SignCertificate(&noAtt, kp)
	if err := perf.VerifyCertificateContent(&noAtt); err == nil {
		t.Fatalf("expected certificate with empty start_attestation_root to be rejected")
	}

	// 5. 100-year expiry (ExpiresAt = math.MaxInt64) exceeding CertificateValidity must be rejected.
	infiniteExpiry := *valid
	infiniteExpiry.ExpiresAt = math.MaxInt64
	_ = perf.SignCertificate(&infiniteExpiry, kp)
	if err := perf.VerifyCertificateContent(&infiniteExpiry); err == nil {
		t.Fatalf("expected certificate with ExpiresAt=MaxInt64 (> CertificateValidity) to be rejected")
	}

	// 6. Far-future IssuedAt must be rejected by VerifyCertificate(c, now).
	futureStart := now + int64(24*time.Hour)
	futureCert := makeValidCertificate(t, kp, futureStart)
	if err := perf.VerifyCertificate(futureCert, now); err == nil {
		t.Fatalf("expected far-future certificate to be rejected by VerifyCertificate")
	}
}
