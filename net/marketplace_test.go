package net

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pubsub_pb "github.com/libp2p/go-libp2p-pubsub/pb"

	"github.com/xeprotocol/xe/core"
)

func createSignedAdvertisement(t *testing.T, timestamp int64) (*ResourceAdvertisement, *core.KeyPair) {
	t.Helper()
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	ad := &ResourceAdvertisement{
		Provider:            kp.Address(),
		VCPUs:               8,
		MemoryMB:            16384,
		DiskGB:              200,
		MaxConcurrentLeases: 5,
		Timestamp:           timestamp,
	}
	SignAdvertisement(ad, kp.Private)
	return ad, kp
}

func makeMarketplacePubsubMessage(t *testing.T, mm *MarketplaceMsg) *pubsub.Message {
	t.Helper()
	data, err := json.Marshal(mm)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	return &pubsub.Message{
		Message: &pubsub_pb.Message{
			Data: data,
		},
	}
}

func TestMarketplaceValidator_FreshAdvertisement_Seconds(t *testing.T) {
	ad, _ := createSignedAdvertisement(t, time.Now().Unix())
	msg := makeMarketplacePubsubMessage(t, &MarketplaceMsg{
		Type: "advertisement",
		Ad:   ad,
	})

	val := marketplaceValidator()
	result := val(context.Background(), "", msg)
	if result != pubsub.ValidationAccept {
		t.Fatalf("expected ValidationAccept for fresh advertisement (seconds), got %v", result)
	}
}

func TestMarketplaceValidator_FreshAdvertisement_Nanoseconds(t *testing.T) {
	ad, _ := createSignedAdvertisement(t, time.Now().UnixNano())
	msg := makeMarketplacePubsubMessage(t, &MarketplaceMsg{
		Type: "advertisement",
		Ad:   ad,
	})

	val := marketplaceValidator()
	result := val(context.Background(), "", msg)
	if result != pubsub.ValidationAccept {
		t.Fatalf("expected ValidationAccept for fresh advertisement (nanoseconds), got %v", result)
	}
}

func TestMarketplaceValidator_StaleAdvertisement(t *testing.T) {
	val := marketplaceValidator()

	testCases := []struct {
		name      string
		timestamp int64
	}{
		{
			name:      "1 hour ago seconds",
			timestamp: time.Now().Unix() - 3600,
		},
		{
			name:      "1 hour ago nanoseconds",
			timestamp: time.Now().Add(-1 * time.Hour).UnixNano(),
		},
		{
			name:      "past AdMaxAge seconds",
			timestamp: time.Now().Unix() - int64(AdMaxAge.Seconds()) - 10,
		},
		{
			name:      "past AdMaxAge nanoseconds",
			timestamp: time.Now().Add(-AdMaxAge - 10*time.Second).UnixNano(),
		},
		{
			name:      "zero timestamp",
			timestamp: 0,
		},
		{
			name:      "negative timestamp",
			timestamp: -100,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ad, _ := createSignedAdvertisement(t, tc.timestamp)
			msg := makeMarketplacePubsubMessage(t, &MarketplaceMsg{
				Type: "advertisement",
				Ad:   ad,
			})

			result := val(context.Background(), "", msg)
			if result != pubsub.ValidationReject {
				t.Fatalf("expected ValidationReject for stale advertisement (%s), got %v", tc.name, result)
			}
		})
	}
}

func TestMarketplaceValidator_FarFutureAdvertisement(t *testing.T) {
	val := marketplaceValidator()

	testCases := []struct {
		name      string
		timestamp int64
	}{
		{
			name:      "exceeds 60s future drift seconds",
			timestamp: time.Now().Unix() + int64(AdMaxFutureDrift.Seconds()) + 10,
		},
		{
			name:      "1 hour in future seconds",
			timestamp: time.Now().Unix() + 3600,
		},
		{
			name:      "exceeds future drift nanoseconds",
			timestamp: time.Now().Add(AdMaxFutureDrift + 10*time.Second).UnixNano(),
		},
		{
			name:      "1 hour in future nanoseconds",
			timestamp: time.Now().Add(1 * time.Hour).UnixNano(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ad, _ := createSignedAdvertisement(t, tc.timestamp)
			msg := makeMarketplacePubsubMessage(t, &MarketplaceMsg{
				Type: "advertisement",
				Ad:   ad,
			})

			result := val(context.Background(), "", msg)
			if result != pubsub.ValidationReject {
				t.Fatalf("expected ValidationReject for far-future advertisement (%s), got %v", tc.name, result)
			}
		})
	}
}

func TestMarketplaceValidator_MalformedAndInvalid(t *testing.T) {
	val := marketplaceValidator()

	// Malformed JSON
	badMsg := &pubsub.Message{
		Message: &pubsub_pb.Message{
			Data: []byte("not-json"),
		},
	}
	if res := val(context.Background(), "", badMsg); res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for malformed json, got %v", res)
	}

	// Empty type
	emptyTypeMsg := makeMarketplacePubsubMessage(t, &MarketplaceMsg{
		Type: "",
	})
	if res := val(context.Background(), "", emptyTypeMsg); res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for empty type, got %v", res)
	}

	// Unknown type
	unknownTypeMsg := makeMarketplacePubsubMessage(t, &MarketplaceMsg{
		Type: "unknown_future_type",
	})
	if res := val(context.Background(), "", unknownTypeMsg); res != pubsub.ValidationIgnore {
		t.Fatalf("expected ValidationIgnore for unknown type, got %v", res)
	}

	// Nil ad
	nilAdMsg := makeMarketplacePubsubMessage(t, &MarketplaceMsg{
		Type: "advertisement",
		Ad:   nil,
	})
	if res := val(context.Background(), "", nilAdMsg); res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for nil ad, got %v", res)
	}

	// Fresh ad with invalid signature
	ad, _ := createSignedAdvertisement(t, time.Now().Unix())
	ad.Signature = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	invalidSigMsg := makeMarketplacePubsubMessage(t, &MarketplaceMsg{
		Type: "advertisement",
		Ad:   ad,
	})
	if res := val(context.Background(), "", invalidSigMsg); res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for invalid signature, got %v", res)
	}
}

func TestVerifyAdvertisement(t *testing.T) {
	// Fresh advertisement (seconds)
	adSeconds, _ := createSignedAdvertisement(t, time.Now().Unix())
	if err := VerifyAdvertisement(adSeconds); err != nil {
		t.Fatalf("expected fresh advertisement (seconds) to verify cleanly, got: %v", err)
	}

	// Fresh advertisement (nanoseconds)
	adNanos, _ := createSignedAdvertisement(t, time.Now().UnixNano())
	if err := VerifyAdvertisement(adNanos); err != nil {
		t.Fatalf("expected fresh advertisement (nanoseconds) to verify cleanly, got: %v", err)
	}

	// Stale advertisement
	adStale, _ := createSignedAdvertisement(t, time.Now().Unix()-3600)
	if err := VerifyAdvertisement(adStale); err == nil {
		t.Fatalf("expected stale advertisement to fail verification")
	}

	// Far-future advertisement
	adFuture, _ := createSignedAdvertisement(t, time.Now().Unix()+3600)
	if err := VerifyAdvertisement(adFuture); err == nil {
		t.Fatalf("expected far-future advertisement to fail verification")
	}

	// Missing provider
	adMissingProvider, _ := createSignedAdvertisement(t, time.Now().Unix())
	adMissingProvider.Provider = ""
	if err := VerifyAdvertisement(adMissingProvider); err == nil {
		t.Fatalf("expected missing provider to fail verification")
	}
}

func TestNormalizeTimestamp(t *testing.T) {
	nowSec := time.Now().Unix()

	// Seconds
	if got := NormalizeTimestamp(nowSec); got != nowSec {
		t.Fatalf("expected %d, got %d", nowSec, got)
	}

	// Milliseconds
	millis := nowSec * 1000
	if got := NormalizeTimestamp(millis); got != nowSec {
		t.Fatalf("expected %d, got %d", nowSec, got)
	}

	// Nanoseconds
	nanos := nowSec * 1_000_000_000
	if got := NormalizeTimestamp(nanos); got != nowSec {
		t.Fatalf("expected %d, got %d", nowSec, got)
	}

	// Zero
	if got := NormalizeTimestamp(0); got != 0 {
		t.Fatalf("expected 0, got %d", got)
	}

	// Negative
	if got := NormalizeTimestamp(-500); got != -500 {
		t.Fatalf("expected -500, got %d", got)
	}
}

func TestVerifyAdvertisement_TamperedTimestampFailsSignature(t *testing.T) {
	// Attacker has an old advertisement from 2020
	ts2020 := int64(1577836800)
	ad, _ := createSignedAdvertisement(t, ts2020)

	// Untampered old ad fails verification due to expiry
	if err := VerifyAdvertisement(ad); err == nil {
		t.Fatalf("expected stale 2020 advertisement to fail verification")
	}

	// Attacker modifies the timestamp to current time to bypass freshness check
	ad.Timestamp = time.Now().Unix()

	// Verification must fail due to cryptographic signature mismatch
	if err := VerifyAdvertisement(ad); err == nil {
		t.Fatalf("expected tampered timestamp advertisement to fail signature verification")
	}

	// Gossip validator must also reject it
	val := marketplaceValidator()
	msg := makeMarketplacePubsubMessage(t, &MarketplaceMsg{
		Type: "advertisement",
		Ad:   ad,
	})
	if res := val(context.Background(), "", msg); res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for tampered advertisement, got %v", res)
	}
}

func TestFreshnessConstants(t *testing.T) {
	if AdMaxAge != 60*time.Second {
		t.Fatalf("expected AdMaxAge to be 60s, got %v", AdMaxAge)
	}
	if AdMaxFutureDrift != 60*time.Second {
		t.Fatalf("expected AdMaxFutureDrift to be 60s, got %v", AdMaxFutureDrift)
	}
	if RequestMaxAge != 60*time.Second {
		t.Fatalf("expected RequestMaxAge to be 60s, got %v", RequestMaxAge)
	}
}
