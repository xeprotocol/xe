package directory

import (
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
)

const validTestPeerID = "12D3KooWGgkhY5EXnz9xCVEee4UNAMFPMVe8SzqpQNgwwdn4ChMs"

func TestVerifyRegistrationRejectsShortAndInvalidNodePeer(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	now := time.Now().UnixNano()
	d := New(DefaultTTL)

	for _, invalidPeer := range []string{"", "A", "abc", "shortpeer", "not-a-valid-libp2p-peer-id-1234567890"} {
		reg := NewRegistration(invalidPeer, now, kp)
		if err := VerifyRegistration(reg); err == nil {
			t.Fatalf("expected VerifyRegistration to reject node_peer %q, got nil", invalidPeer)
		}
		if err := d.Register(reg); err == nil {
			t.Fatalf("expected Directory.Register to reject node_peer %q, got nil", invalidPeer)
		}
	}

	validReg := NewRegistration(validTestPeerID, now, kp)
	if err := VerifyRegistration(validReg); err != nil {
		t.Fatalf("expected valid peer ID to pass VerifyRegistration, got %v", err)
	}
	if err := d.Register(validReg); err != nil {
		t.Fatalf("expected valid peer ID to pass Directory.Register, got %v", err)
	}
	got, ok := d.Lookup(kp.Address())
	if !ok || got.NodePeer != validTestPeerID {
		t.Fatalf("expected registered entry for %s with peer %s, got ok=%v reg=%+v", kp.Address(), validTestPeerID, ok, got)
	}
}
