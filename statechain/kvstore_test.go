package statechain

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateEpochValue_Valid(t *testing.T) {
	// Phase 1: factor=950, s_milli=0, twap=250 -> expected RCollusion = 950 * 1000 / 250 = 3800
	// RVolume=1500, RPriceFloor=1000 -> supportive=1500
	// RCollusion (3800) >= supportive (1500) -> REffective = 1500, RSource = "volume"
	ev := EpochValue{
		Epoch:        1,
		StartNS:      1000,
		EndNS:        2000,
		TWAPMilliUSD: 250,
		RVolume:      1500,
		RPriceFloor:  1000,
		RCollusion:   3800,
		REffective:   1500,
		RSource:      "volume",
		Phase:        1,
		SMilli:       0,
		PayoutCap:    1500,
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	kv := NewKVStore()
	if err := validateEpochValue(raw, kv); err != nil {
		t.Fatalf("expected valid epoch, got error: %v", err)
	}
}

func TestValidateEpochValue_RejectZeroTWAP(t *testing.T) {
	ev := EpochValue{
		Epoch:        1,
		StartNS:      1000,
		EndNS:        2000,
		TWAPMilliUSD: 0,
		RVolume:      1500,
		RPriceFloor:  1000,
		RCollusion:   0,
		REffective:   1500,
		RSource:      "volume",
		Phase:        1,
		SMilli:       0,
		PayoutCap:    1500,
	}
	raw, _ := json.Marshal(ev)

	err := validateEpochValue(raw, nil)
	if err == nil {
		t.Fatalf("expected error for TWAPMilliUSD == 0, got nil")
	}
	if !strings.Contains(err.Error(), "twap_milli_usd must be > 0") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestValidateEpochValue_RejectZeroRCollusion(t *testing.T) {
	ev := EpochValue{
		Epoch:        1,
		StartNS:      1000,
		EndNS:        2000,
		TWAPMilliUSD: 250,
		RVolume:      1500,
		RPriceFloor:  1000,
		RCollusion:   0,
		REffective:   1500,
		RSource:      "volume",
		Phase:        1,
		SMilli:       0,
		PayoutCap:    1500,
	}
	raw, _ := json.Marshal(ev)

	err := validateEpochValue(raw, nil)
	if err == nil {
		t.Fatalf("expected error for RCollusion == 0, got nil")
	}
	if !strings.Contains(err.Error(), "r_collusion must be > 0") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestValidateEpochValue_RejectZeroREffective(t *testing.T) {
	ev := EpochValue{
		Epoch:        1,
		StartNS:      1000,
		EndNS:        2000,
		TWAPMilliUSD: 250,
		RVolume:      0,
		RPriceFloor:  0,
		RCollusion:   3800,
		REffective:   0,
		RSource:      "tied",
		Phase:        1,
		SMilli:       0,
		PayoutCap:    1500,
	}
	raw, _ := json.Marshal(ev)

	err := validateEpochValue(raw, nil)
	if err == nil {
		t.Fatalf("expected error for REffective == 0, got nil")
	}
	if !strings.Contains(err.Error(), "r_effective must be > 0") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestValidateEpochValue_RejectUnboundedR_Issue372(t *testing.T) {
	// The malicious epoch from Issue #372 PoC:
	// {"epoch":1,"start_ns":0,"end_ns":1000000000,"twap_milli_usd":0,
	//  "r_volume":1000000000,"r_price_floor":100,"r_collusion":0,
	//  "r_effective":1000000000,"r_source":"volume","phase":1,"payout_cap":1502}
	malicious := []byte(`{
		"epoch": 1,
		"start_ns": 0,
		"end_ns": 1000000000,
		"twap_milli_usd": 0,
		"r_volume": 1000000000,
		"r_price_floor": 100,
		"r_collusion": 0,
		"r_effective": 1000000000,
		"r_source": "volume",
		"phase": 1,
		"payout_cap": 1502
	}`)

	err := validateEpochValue(malicious, nil)
	if err == nil {
		t.Fatalf("expected rejection of malicious unbounded epoch, but was accepted")
	}

	// Even if twap is set > 0, r_volume = 1e9 and r_effective = 1e9 must be rejected
	maliciousWithTWAP := []byte(`{
		"epoch": 1,
		"start_ns": 0,
		"end_ns": 1000000000,
		"twap_milli_usd": 250,
		"r_volume": 1000000000,
		"r_price_floor": 100,
		"r_collusion": 3800,
		"r_effective": 1000000000,
		"r_source": "volume",
		"phase": 1,
		"payout_cap": 1502
	}`)

	err2 := validateEpochValue(maliciousWithTWAP, nil)
	if err2 == nil {
		t.Fatalf("expected rejection of r_volume=1e9 epoch, but was accepted")
	}
	if !strings.Contains(err2.Error(), "exceeds r_init") {
		t.Fatalf("expected error mentioning exceeds r_init, got: %v", err2)
	}
}

func TestValidateEpochValue_RejectUnboundedRPriceFloor(t *testing.T) {
	ev := EpochValue{
		Epoch:        1,
		StartNS:      1000,
		EndNS:        2000,
		TWAPMilliUSD: 250,
		RVolume:      1000,
		RPriceFloor:  999999,
		RCollusion:   3800,
		REffective:   3800,
		RSource:      "collusion",
		Phase:        1,
		SMilli:       0,
		PayoutCap:    1500,
	}
	raw, _ := json.Marshal(ev)

	err := validateEpochValue(raw, nil)
	if err == nil {
		t.Fatalf("expected error for RPriceFloor exceeding ceiling, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds r_price_floor_tier_1") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestValidateEpochValue_CollusionSource(t *testing.T) {
	// TWAP=500, s=0, factor=950 -> expected RCollusion = 950000 / 500 = 1900
	// supportive = max(2000, 1500) = 2000. RCollusion (1900) < 2000 -> REffective = 1900, source = "collusion"
	ev := EpochValue{
		Epoch:        1,
		StartNS:      1000,
		EndNS:        2000,
		TWAPMilliUSD: 500,
		RVolume:      2000,
		RPriceFloor:  1500,
		RCollusion:   1900,
		REffective:   1900,
		RSource:      "collusion",
		Phase:        1,
		SMilli:       0,
		PayoutCap:    1500,
	}
	raw, _ := json.Marshal(ev)

	if err := validateEpochValue(raw, nil); err != nil {
		t.Fatalf("expected valid collusion epoch, got error: %v", err)
	}
}

func TestExpectedRCollusion(t *testing.T) {
	if got := expectedRCollusion(0, 0, 950); got != 0 {
		t.Errorf("expected 0 for twap=0, got %d", got)
	}
	if got := expectedRCollusion(250, 1000, 950); got != 0 {
		t.Errorf("expected 0 for s=1000, got %d", got)
	}
	if got := expectedRCollusion(250, 0, 950); got != 3800 {
		t.Errorf("expected 3800, got %d", got)
	}
	if got := expectedRCollusion(250, 300, 950); got != 2660 {
		t.Errorf("expected 2660, got %d", got)
	}
	// Very high TWAP should floor at 1
	if got := expectedRCollusion(10_000_000, 0, 950); got != 1 {
		t.Errorf("expected floor 1 for huge TWAP, got %d", got)
	}
}
