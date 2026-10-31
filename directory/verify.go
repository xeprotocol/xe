package directory

import (
	"errors"
	"strings"
)

// MinimumNodePeerLen is the number of characters required from a node peer ID
// before it can be safely abbreviated for display/logging. A shorter value would
// panic on the unguarded NodePeer[:12] slice used throughout the codebase.
const MinimumNodePeerLen = 12

// ErrNodePeerTooShort is returned when a registration's node_peer is too short
// to be a valid peer identifier.
var ErrNodePeerTooShort = errors.New("node_peer must be at least 12 characters")

// VerifyRegistration validates an incoming directory registration. It rejects
// empty and too-short node_peer values so that no downstream consumer can
// panic on an unguarded NodePeer[:12] slice.
func VerifyRegistration(reg *Registration, networkID string) error {
	if reg == nil {
		return errors.New("nil registration")
	}
	if strings.TrimSpace(reg.NodePeer) == "" {
		return errors.New("node_peer is required")
	}
	if len(reg.NodePeer) < MinimumNodePeerLen {
		return ErrNodePeerTooShort
	}
	if reg.NetworkID != "" && reg.NetworkID != networkID {
		return errors.New("network_id mismatch")
	}
	// Signature verification is performed by the caller; this function only
	// enforces structural invariants that prevent panics.
	return nil
}