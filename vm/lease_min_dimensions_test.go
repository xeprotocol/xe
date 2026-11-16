package vm

import (
	"testing"
)

func TestMockManagerEffectiveResources(t *testing.T) {
	mgr := NewMockManager()
	info, err := mgr.Provision("testhash12345678", Resources{VCPUs: 0, MemoryMB: 1, DiskGB: 0}, "dummy-key")
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	if info.Resources == nil {
		t.Fatalf("expected non-nil resources")
	}

	if info.Resources.VCPUs < 1 {
		t.Fatalf("expected VCPUs >= 1, got %d", info.Resources.VCPUs)
	}
	if info.Resources.MemoryMB < 512 {
		t.Fatalf("expected MemoryMB >= 512, got %d", info.Resources.MemoryMB)
	}
	if info.Resources.DiskGB < 5 {
		t.Fatalf("expected DiskGB >= 5, got %d", info.Resources.DiskGB)
	}
}
