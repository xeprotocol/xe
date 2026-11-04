package net

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/perf"
)

func makeCertMsg(c *perf.Certificate) *pubsub.Message {
	data, _ := json.Marshal(c)
	return &pubsub.Message{
		Message: &pb.Message{
			Data: data,
		},
	}
}

func createTestCert(t *testing.T, issuedAt, expiresAt int64) (*perf.Certificate, *core.KeyPair) {
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

func TestCertificateValidator_RejectsExpiredCertificate(t *testing.T) {
	oldNow := core.Now
	defer func() { core.Now = oldNow }()

	fixedNow := int64(1_000_000_000_000)
	core.Now = func() time.Time { return time.Unix(0, fixedNow) }

	// Expired: expired 1000 nanos before fixedNow
	cert, _ := createTestCert(t, fixedNow-2_000_000, fixedNow-1000)
	msg := makeCertMsg(cert)

	val := certificateValidator()
	res := val(context.Background(), peer.ID(""), msg)
	if res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for expired certificate, got %v", res)
	}
}

func TestCertificateValidator_AcceptsUnexpiredCertificate(t *testing.T) {
	oldNow := core.Now
	defer func() { core.Now = oldNow }()

	fixedNow := int64(1_000_000_000_000)
	core.Now = func() time.Time { return time.Unix(0, fixedNow) }

	// Valid: expires 1 hour in the future
	cert, _ := createTestCert(t, fixedNow-1000, fixedNow+int64(time.Hour))
	msg := makeCertMsg(cert)

	val := certificateValidator()
	res := val(context.Background(), peer.ID(""), msg)
	if res != pubsub.ValidationAccept {
		t.Fatalf("expected ValidationAccept for unexpired certificate, got %v", res)
	}
}

func TestCertificateValidator_RejectsTamperedCertificate(t *testing.T) {
	oldNow := core.Now
	defer func() { core.Now = oldNow }()

	fixedNow := int64(1_000_000_000_000)
	core.Now = func() time.Time { return time.Unix(0, fixedNow) }

	cert, _ := createTestCert(t, fixedNow-1000, fixedNow+int64(time.Hour))
	cert.Score = 999.0 // tampering with score without resigning
	msg := makeCertMsg(cert)

	val := certificateValidator()
	res := val(context.Background(), peer.ID(""), msg)
	if res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for tampered certificate, got %v", res)
	}
}

func TestCertificateValidator_RejectsMalformedMessage(t *testing.T) {
	val := certificateValidator()
	malformed := &pubsub.Message{
		Message: &pb.Message{
			Data: []byte("not valid json"),
		},
	}
	res := val(context.Background(), peer.ID(""), malformed)
	if res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for malformed message, got %v", res)
	}
}
