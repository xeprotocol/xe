package core

import (
	"testing"
)

func TestValidateLeaseDimensionsMinimums(t *testing.T) {
	// Rejects 0 vcpus
	if err := ValidateLeaseDimensions(0, 512, 5, LeaseMinDuration); err == nil {
		t.Fatalf("expected error for 0 vcpus, got nil")
	}

	// Rejects memory below 512 MB
	if err := ValidateLeaseDimensions(1, 511, 5, LeaseMinDuration); err == nil {
		t.Fatalf("expected error for memory < 512 MB, got nil")
	}

	// Rejects disk below 5 GB
	if err := ValidateLeaseDimensions(1, 512, 4, LeaseMinDuration); err == nil {
		t.Fatalf("expected error for disk < 5 GB, got nil")
	}

	// Accepts minimum valid dimensions
	if err := ValidateLeaseDimensions(1, 512, 5, LeaseMinDuration); err != nil {
		t.Fatalf("expected valid dimensions to pass, got: %v", err)
	}

	// Accepts larger dimensions
	if err := ValidateLeaseDimensions(4, 4096, 50, LeaseMinDuration); err != nil {
		t.Fatalf("expected larger dimensions to pass, got: %v", err)
	}
}

func TestLeaseCostMinimumDimensions(t *testing.T) {
	const mult = uint64(1000)
	cost, err := LeaseCost(LeaseMinVCPUs, LeaseMinMemoryMB, LeaseMinDiskGB, LeaseMinDuration, mult)
	if err != nil {
		t.Fatalf("LeaseCost failed for minimum dimensions: %v", err)
	}
	if cost == 0 {
		t.Fatalf("expected non-zero cost for minimum dimensions, got 0")
	}
}
