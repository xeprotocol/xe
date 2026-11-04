package core

import "fmt"

// SignDeliveryAttestation signs a consumer delivery/uptime attestation for a lease.
// It produces a TimekeeperAttestation signed by the consumer's keypair over the
// canonical attestation payload for (leaseHash, timestamp).
func SignDeliveryAttestation(leaseHash string, timestamp int64, consumerKP *KeyPair) (*TimekeeperAttestation, error) {
	if consumerKP == nil {
		return nil, fmt.Errorf("nil consumer keypair")
	}
	return SignAttestation(leaseHash, timestamp, consumerKP)
}

// VerifyDeliveryAttestation verifies that an attestation was signed by the lease consumer
// for the given leaseHash at a timestamp >= minTimestamp.
func VerifyDeliveryAttestation(a *TimekeeperAttestation, leaseHash, consumerAddr string, minTimestamp int64) error {
	if a == nil {
		return fmt.Errorf("nil delivery attestation")
	}
	if consumerAddr == "" {
		return fmt.Errorf("empty consumer address")
	}
	if a.Timestamp < minTimestamp {
		return fmt.Errorf("delivery attestation timestamp %d before minimum %d", a.Timestamp, minTimestamp)
	}
	if err := VerifyPayloadKey(a.PublicKey, consumerAddr); err != nil {
		return fmt.Errorf("delivery attestation key mismatch: %w", err)
	}
	return VerifyAttestation(a, leaseHash)
}

// HasDeliveryAttestation reports whether attestations contain at least one valid
// consumer-signed delivery attestation for leaseHash with timestamp >= minTimestamp.
func HasDeliveryAttestation(attestations []TimekeeperAttestation, leaseHash, consumerAddr string, minTimestamp int64) bool {
	for i := range attestations {
		if VerifyDeliveryAttestation(&attestations[i], leaseHash, consumerAddr, minTimestamp) == nil {
			return true
		}
	}
	return false
}
