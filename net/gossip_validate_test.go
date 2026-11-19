package net

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pubsub_pb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/perf"
)

func makeGossipTestCert(t *testing.T, issuedAt, expiresAt int64) *perf.Certificate {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
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

func testPubsubMsg(data []byte) *pubsub.Message {
	return &pubsub.Message{
		Message: &pubsub_pb.Message{
			Data: data,
		},
	}
}

func TestCertificateValidator(t *testing.T) {
	val := certificateValidator()
	ctx := context.Background()
	p := peer.ID("test-peer-1")

	now := time.Now().UnixNano()

	// 1. Valid certificate should be accepted
	validCert := makeGossipTestCert(t, now, now+int64(perf.CertificateValidity))
	validBytes, _ := json.Marshal(validCert)
	res := val(ctx, p, testPubsubMsg(validBytes))
	if res != pubsub.ValidationAccept {
		t.Fatalf("expected ValidationAccept for valid cert, got %v", res)
	}

	// 2. Expired certificate should be ignored (not relayed, not accepted)
	expiredCert := makeGossipTestCert(t, now-2_000_000_000, now-1_000_000_000)
	expiredBytes, _ := json.Marshal(expiredCert)
	res = val(ctx, p, testPubsubMsg(expiredBytes))
	if res != pubsub.ValidationIgnore {
		t.Fatalf("expected ValidationIgnore for expired cert, got %v", res)
	}

	// 3. Malformed certificate should be rejected
	res = val(ctx, p, testPubsubMsg([]byte("not json")))
	if res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for corrupt cert, got %v", res)
	}

	// 4. Rate-limiting check: flooding messages from same peer should get ValidationIgnore
	floodPeer := peer.ID("flooding-peer")
	// Burst is 10. Send 30 messages in quick succession.
	deniedCount := 0
	for i := 0; i < 30; i++ {
		cert := makeGossipTestCert(t, now, now+int64(perf.CertificateValidity))
		data, _ := json.Marshal(cert)
		r := val(ctx, floodPeer, testPubsubMsg(data))
		if r == pubsub.ValidationIgnore {
			deniedCount++
		}
	}
	if deniedCount == 0 {
		t.Fatalf("expected rate-limiting to deny messages from floodPeer")
	}
}
