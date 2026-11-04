package net

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/xeprotocol/xe/core"
)

func TestMarketplaceFreshnessAndSignatures(t *testing.T) {
	refNow := time.Date(2026, 10, 23, 18, 1, 0, 0, time.UTC)
	core.Now = func() time.Time { return refNow }
	defer func() { core.Now = func() time.Time { return time.Now() } }()

	providerKP := core.KeyPairFromSeed(bytes.Repeat([]byte{0x11}, 32))
	consumerKP := core.KeyPairFromSeed(bytes.Repeat([]byte{0x22}, 32))

	validator := marketplaceValidator()

	validateGossip := func(mm *MarketplaceMsg) pubsub.ValidationResult {
		raw, err := json.Marshal(mm)
		if err != nil {
			t.Fatalf("marshal MarketplaceMsg: %v", err)
		}
		msg := &pubsub.Message{Message: &pb.Message{Data: raw}}
		return validator(context.Background(), "", msg)
	}

	t.Run("fresh advertisement accepted", func(t *testing.T) {
		ad := &ResourceAdvertisement{
			Provider:            providerKP.Address(),
			VCPUs:               64,
			MemoryMB:            262144,
			DiskGB:              4096,
			MaxConcurrentLeases: 99,
			Timestamp:           refNow.UnixNano(),
		}
		SignAdvertisement(ad, providerKP.Private)
		if err := VerifyAdvertisement(ad); err != nil {
			t.Fatalf("expected fresh advertisement to pass, got: %v", err)
		}
		if got := validateGossip(&MarketplaceMsg{Type: "advertisement", Ad: ad}); got != pubsub.ValidationAccept {
			t.Fatalf("expected ValidationAccept, got %v", got)
		}
	})

	t.Run("90-day-old advertisement rejected", func(t *testing.T) {
		ad := &ResourceAdvertisement{
			Provider:            providerKP.Address(),
			VCPUs:               64,
			MemoryMB:            262144,
			DiskGB:              4096,
			MaxConcurrentLeases: 99,
			Timestamp:           refNow.Add(-90 * 24 * time.Hour).UnixNano(),
		}
		SignAdvertisement(ad, providerKP.Private)
		if err := VerifyAdvertisement(ad); err == nil {
			t.Fatalf("expected 90-day-old advertisement to fail verification")
		}
		if got := validateGossip(&MarketplaceMsg{Type: "advertisement", Ad: ad}); got != pubsub.ValidationReject {
			t.Fatalf("expected ValidationReject for stale advertisement, got %v", got)
		}
	})

	t.Run("future-dated advertisement rejected", func(t *testing.T) {
		ad := &ResourceAdvertisement{
			Provider:            providerKP.Address(),
			VCPUs:               64,
			MemoryMB:            262144,
			DiskGB:              4096,
			MaxConcurrentLeases: 99,
			Timestamp:           refNow.Add(90 * 24 * time.Hour).UnixNano(),
		}
		SignAdvertisement(ad, providerKP.Private)
		if err := VerifyAdvertisement(ad); err == nil {
			t.Fatalf("expected future-dated advertisement to fail verification")
		}
		if got := validateGossip(&MarketplaceMsg{Type: "advertisement", Ad: ad}); got != pubsub.ValidationReject {
			t.Fatalf("expected ValidationReject for future-dated advertisement, got %v", got)
		}
	})

	t.Run("fresh request accepted and stale/future request rejected", func(t *testing.T) {
		req := &ResourceRequest{
			Consumer:  consumerKP.Address(),
			RequestID: "req-1",
			VCPUs:     4,
			MemoryMB:  8192,
			DiskGB:    100,
			Duration:  3600,
			Timestamp: refNow.UnixNano(),
		}
		SignRequest(req, consumerKP.Private)
		if err := VerifyRequest(req); err != nil {
			t.Fatalf("expected fresh request to pass, got: %v", err)
		}
		if got := validateGossip(&MarketplaceMsg{Type: "request", Request: req}); got != pubsub.ValidationAccept {
			t.Fatalf("expected ValidationAccept, got %v", got)
		}

		staleReq := *req
		staleReq.Timestamp = refNow.Add(-MaxRequestAge - time.Second).UnixNano()
		SignRequest(&staleReq, consumerKP.Private)
		if err := VerifyRequest(&staleReq); err == nil {
			t.Fatalf("expected stale request to fail verification")
		}
		if got := validateGossip(&MarketplaceMsg{Type: "request", Request: &staleReq}); got != pubsub.ValidationReject {
			t.Fatalf("expected ValidationReject for stale request, got %v", got)
		}

		futureReq := *req
		futureReq.Timestamp = refNow.Add(MaxMarketplaceFutureSkew + time.Second).UnixNano()
		SignRequest(&futureReq, consumerKP.Private)
		if err := VerifyRequest(&futureReq); err == nil {
			t.Fatalf("expected future request to fail verification")
		}
	})

	t.Run("fresh offer accepted and stale/future offer rejected", func(t *testing.T) {
		offer := &ResourceOffer{
			Provider:        providerKP.Address(),
			RequestID:       "req-1",
			VCPUs:           4,
			MemoryMB:        8192,
			DiskGB:          100,
			Duration:        3600,
			TotalCost:       1000,
			CertificateHash: "abcd",
			Timestamp:       refNow.UnixNano(),
		}
		SignOffer(offer, providerKP.Private)
		if err := VerifyOffer(offer); err != nil {
			t.Fatalf("expected fresh offer to pass, got: %v", err)
		}
		if got := validateGossip(&MarketplaceMsg{Type: "offer", Offer: offer}); got != pubsub.ValidationAccept {
			t.Fatalf("expected ValidationAccept, got %v", got)
		}

		staleOffer := *offer
		staleOffer.Timestamp = refNow.Add(-MaxOfferAge - time.Second).UnixNano()
		SignOffer(&staleOffer, providerKP.Private)
		if err := VerifyOffer(&staleOffer); err == nil {
			t.Fatalf("expected stale offer to fail verification")
		}

		futureOffer := *offer
		futureOffer.Timestamp = refNow.Add(MaxMarketplaceFutureSkew + time.Second).UnixNano()
		SignOffer(&futureOffer, providerKP.Private)
		if err := VerifyOffer(&futureOffer); err == nil {
			t.Fatalf("expected future offer to fail verification")
		}
	})
}
