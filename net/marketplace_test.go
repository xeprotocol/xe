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
)

func newTestPubsubMessage(t *testing.T, mm *MarketplaceMsg) *pubsub.Message {
	t.Helper()
	data, err := json.Marshal(mm)
	if err != nil {
		t.Fatalf("failed to marshal marketplace message: %v", err)
	}
	return &pubsub.Message{
		Message: &pubsub_pb.Message{
			Data: data,
		},
		ReceivedFrom: peer.ID("test-peer"),
	}
}

func newSignedTestRequest(t *testing.T, kp *core.KeyPair, timestamp int64) *ResourceRequest {
	t.Helper()
	req := &ResourceRequest{
		Consumer:  kp.Address(),
		RequestID: "test-req-12345",
		VCPUs:     4,
		MemoryMB:  8192,
		DiskGB:    50,
		Duration:  3600,
		Timestamp: timestamp,
	}
	SignRequest(req, kp.Private)
	return req
}

func TestMarketplaceValidator_FreshRequest(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	validator := marketplaceValidator()
	now := time.Now().Unix()
	req := newSignedTestRequest(t, kp, now)

	msg := newTestPubsubMessage(t, &MarketplaceMsg{
		Type:    "request",
		Request: req,
	})

	res := validator(context.Background(), "", msg)
	if res != pubsub.ValidationAccept {
		t.Fatalf("expected ValidationAccept for fresh request, got %v", res)
	}
}

func TestMarketplaceValidator_StaleRequest_Year2020(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	validator := marketplaceValidator()
	// Unix timestamp for 2020-01-01 00:00:00 UTC
	ts2020 := int64(1577836800)
	req := newSignedTestRequest(t, kp, ts2020)

	msg := newTestPubsubMessage(t, &MarketplaceMsg{
		Type:    "request",
		Request: req,
	})

	res := validator(context.Background(), "", msg)
	if res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for 2020 stale request, got %v", res)
	}
}

func TestMarketplaceValidator_StaleRequest_PastExpiry(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	validator := marketplaceValidator()
	staleTs := time.Now().Unix() - int64(RequestMaxAge.Seconds()) - 5
	req := newSignedTestRequest(t, kp, staleTs)

	msg := newTestPubsubMessage(t, &MarketplaceMsg{
		Type:    "request",
		Request: req,
	})

	res := validator(context.Background(), "", msg)
	if res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for request older than RequestMaxAge, got %v", res)
	}
}

func TestMarketplaceValidator_FarFutureRequest(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	validator := marketplaceValidator()
	futureTs := time.Now().Unix() + int64(RequestMaxFutureDrift.Seconds()) + 10
	req := newSignedTestRequest(t, kp, futureTs)

	msg := newTestPubsubMessage(t, &MarketplaceMsg{
		Type:    "request",
		Request: req,
	})

	res := validator(context.Background(), "", msg)
	if res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for far-future request, got %v", res)
	}
}

func TestMarketplaceValidator_NanosecondTimestamps(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	validator := marketplaceValidator()

	// Fresh nanosecond timestamp
	freshNano := time.Now().UnixNano()
	reqFresh := newSignedTestRequest(t, kp, freshNano)
	msgFresh := newTestPubsubMessage(t, &MarketplaceMsg{
		Type:    "request",
		Request: reqFresh,
	})
	if res := validator(context.Background(), "", msgFresh); res != pubsub.ValidationAccept {
		t.Fatalf("expected ValidationAccept for fresh nanosecond request, got %v", res)
	}

	// Stale nanosecond timestamp (5 minutes ago)
	staleNano := time.Now().Add(-5 * time.Minute).UnixNano()
	reqStale := newSignedTestRequest(t, kp, staleNano)
	msgStale := newTestPubsubMessage(t, &MarketplaceMsg{
		Type:    "request",
		Request: reqStale,
	})
	if res := validator(context.Background(), "", msgStale); res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for stale nanosecond request, got %v", res)
	}

	// Far-future nanosecond timestamp (5 minutes in future)
	futureNano := time.Now().Add(5 * time.Minute).UnixNano()
	reqFuture := newSignedTestRequest(t, kp, futureNano)
	msgFuture := newTestPubsubMessage(t, &MarketplaceMsg{
		Type:    "request",
		Request: reqFuture,
	})
	if res := validator(context.Background(), "", msgFuture); res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for future nanosecond request, got %v", res)
	}
}

func TestVerifyRequest_FreshnessAndExpiry(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	// Fresh request in seconds
	now := time.Now().Unix()
	freshReq := newSignedTestRequest(t, kp, now)
	if err := VerifyRequest(freshReq); err != nil {
		t.Fatalf("expected nil error for fresh request, got: %v", err)
	}

	// Stale request from 2020
	staleReq2020 := newSignedTestRequest(t, kp, 1577836800)
	if err := VerifyRequest(staleReq2020); err == nil {
		t.Fatalf("expected error for 2020 stale request, got nil")
	}

	// Stale request > 60s ago
	staleReq := newSignedTestRequest(t, kp, now-int64(RequestMaxAge.Seconds())-10)
	if err := VerifyRequest(staleReq); err == nil {
		t.Fatalf("expected error for stale request, got nil")
	}

	// Far-future request
	futureReq := newSignedTestRequest(t, kp, now+int64(RequestMaxFutureDrift.Seconds())-10)
	if err := VerifyRequest(futureReq); err != nil {
		t.Fatalf("expected nil error for request within drift tolerance, got: %v", err)
	}

	driftExceededReq := newSignedTestRequest(t, kp, now+int64(RequestMaxFutureDrift.Seconds())+10)
	if err := VerifyRequest(driftExceededReq); err == nil {
		t.Fatalf("expected error for far-future request, got nil")
	}
}

func TestVerifyRequest_TamperedTimestampFailsSignature(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	// Create and sign a request in 2020
	req := newSignedTestRequest(t, kp, 1577836800)

	// Attacker tampers timestamp to current time to try bypassing freshness check
	req.Timestamp = time.Now().Unix()

	// VerifyRequest must fail due to cryptographic signature mismatch
	if err := VerifyRequest(req); err == nil {
		t.Fatalf("expected signature verification failure for tampered timestamp, got nil")
	}

	// Gossip validator must also reject it
	validator := marketplaceValidator()
	msg := newTestPubsubMessage(t, &MarketplaceMsg{
		Type:    "request",
		Request: req,
	})
	if res := validator(context.Background(), "", msg); res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for tampered request, got %v", res)
	}
}
