package directory

import (
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
)

func TestDirectory_HasNodePeer(t *testing.T) {
	d := New(30 * time.Minute)
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	nodePeer := "12D3KooWTestDirectoryPeer1111111111111111111"
	if d.HasNodePeer(nodePeer) {
		t.Fatalf("expected HasNodePeer to return false for empty directory")
	}

	now := time.Now().UnixNano()
	reg := NewRegistration(nodePeer, now, kp)
	if err := d.Register(reg); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if !d.HasNodePeer(nodePeer) {
		t.Fatalf("expected HasNodePeer to return true for registered nodePeer")
	}

	if d.HasNodePeer("12D3KooWUnknownPeer2222222222222222222") {
		t.Fatalf("expected HasNodePeer to return false for unregistered nodePeer")
	}

	// Test expired registration
	dExpired := New(10 * time.Millisecond)
	expiredReg := NewRegistration(nodePeer, now-int64(1*time.Hour), kp)
	// Manually inject expired reg into map
	dExpired.mu.Lock()
	dExpired.registrations[expiredReg.Account] = expiredReg
	dExpired.mu.Unlock()

	if dExpired.HasNodePeer(nodePeer) {
		t.Fatalf("expected HasNodePeer to return false for expired registration")
	}
}
