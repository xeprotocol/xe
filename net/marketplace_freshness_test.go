package net

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
)

func genTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	kp := &core.KeyPair{Public: pub, Private: priv}
	return pub, priv, kp.Address()
}

func TestVerifyAdvertisement_Freshness(t *testing.T) {
	_, priv, addr := genTestKey(t)

	// 1. Fresh advertisement
	freshAd := &ResourceAdvertisement{
		Provider:            addr,
		VCPUs:               16,
		MemoryMB:            65536,
		DiskGB:              1000,
		MaxConcurrentLeases: 10,
		Timestamp:           time.Now().UnixNano(),
	}
	SignAdvertisement(freshAd, priv)
	if err := VerifyAdvertisement(freshAd); err != nil {
		t.Fatalf("expected fresh advertisement to pass, got: %v", err)
	}

	// 2. Stale advertisement (e.g. 90 days old)
	staleAd := &ResourceAdvertisement{
		Provider:            addr,
		VCPUs:               16,
		MemoryMB:            65536,
		DiskGB:              1000,
		MaxConcurrentLeases: 10,
		Timestamp:           time.Now().Add(-90 * 24 * time.Hour).UnixNano(),
	}
	SignAdvertisement(staleAd, priv)
	err := VerifyAdvertisement(staleAd)
	if err == nil {
		t.Fatal("expected stale advertisement to be rejected, got nil")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected error mentioning expired, got: %v", err)
	}

	// 3. Future-dated advertisement (e.g. 90 days ahead)
	futureAd := &ResourceAdvertisement{
		Provider:            addr,
		VCPUs:               16,
		MemoryMB:            65536,
		DiskGB:              1000,
		MaxConcurrentLeases: 10,
		Timestamp:           time.Now().Add(90 * 24 * time.Hour).UnixNano(),
	}
	SignAdvertisement(futureAd, priv)
	err = VerifyAdvertisement(futureAd)
	if err == nil {
		t.Fatal("expected future advertisement to be rejected, got nil")
	}
	if !strings.Contains(err.Error(), "too far in future") {
		t.Fatalf("expected error mentioning future, got: %v", err)
	}

	// 4. Missing/zero timestamp
	zeroAd := &ResourceAdvertisement{
		Provider: addr,
		VCPUs:    16,
	}
	SignAdvertisement(zeroAd, priv)
	if err := VerifyAdvertisement(zeroAd); err == nil {
		t.Fatal("expected zero timestamp advertisement to be rejected")
	}
}

func TestVerifyRequest_Freshness(t *testing.T) {
	_, priv, addr := genTestKey(t)

	// 1. Fresh request
	freshReq := &ResourceRequest{
		Consumer:  addr,
		RequestID: "req-12345",
		VCPUs:     4,
		MemoryMB:  8192,
		DiskGB:    50,
		Duration:  3600,
		Timestamp: time.Now().UnixNano(),
	}
	SignRequest(freshReq, priv)
	if err := VerifyRequest(freshReq); err != nil {
		t.Fatalf("expected fresh request to pass, got: %v", err)
	}

	// 2. Stale request
	staleReq := &ResourceRequest{
		Consumer:  addr,
		RequestID: "req-12345",
		VCPUs:     4,
		MemoryMB:  8192,
		DiskGB:    50,
		Duration:  3600,
		Timestamp: time.Now().Add(-2 * time.Hour).UnixNano(),
	}
	SignRequest(staleReq, priv)
	err := VerifyRequest(staleReq)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected request expired error, got: %v", err)
	}

	// 3. Future request
	futureReq := &ResourceRequest{
		Consumer:  addr,
		RequestID: "req-12345",
		VCPUs:     4,
		MemoryMB:  8192,
		DiskGB:    50,
		Duration:  3600,
		Timestamp: time.Now().Add(30 * time.Minute).UnixNano(),
	}
	SignRequest(futureReq, priv)
	err = VerifyRequest(futureReq)
	if err == nil || !strings.Contains(err.Error(), "too far in future") {
		t.Fatalf("expected request future error, got: %v", err)
	}
}

func TestVerifyOffer_Freshness(t *testing.T) {
	_, priv, addr := genTestKey(t)

	// 1. Fresh offer
	freshOffer := &ResourceOffer{
		Provider:  addr,
		RequestID: "req-12345",
		VCPUs:     4,
		MemoryMB:  8192,
		DiskGB:    50,
		Duration:  3600,
		TotalCost: 500000,
		Timestamp: time.Now().UnixNano(),
	}
	SignOffer(freshOffer, priv)
	if err := VerifyOffer(freshOffer); err != nil {
		t.Fatalf("expected fresh offer to pass, got: %v", err)
	}

	// 2. Stale offer
	staleOffer := &ResourceOffer{
		Provider:  addr,
		RequestID: "req-12345",
		VCPUs:     4,
		MemoryMB:  8192,
		DiskGB:    50,
		Duration:  3600,
		TotalCost: 500000,
		Timestamp: time.Now().Add(-1 * time.Hour).UnixNano(),
	}
	SignOffer(staleOffer, priv)
	err := VerifyOffer(staleOffer)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected offer expired error, got: %v", err)
	}

	// 3. Future offer
	futureOffer := &ResourceOffer{
		Provider:  addr,
		RequestID: "req-12345",
		VCPUs:     4,
		MemoryMB:  8192,
		DiskGB:    50,
		Duration:  3600,
		TotalCost: 500000,
		Timestamp: time.Now().Add(10 * time.Minute).UnixNano(),
	}
	SignOffer(futureOffer, priv)
	err = VerifyOffer(futureOffer)
	if err == nil || !strings.Contains(err.Error(), "too far in future") {
		t.Fatalf("expected offer future error, got: %v", err)
	}
}
