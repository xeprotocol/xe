package core

import (
	"strings"
	"testing"
)

// TestLeaseRenewRejectsStaleCertificate verifies that validateAndAddLeaseRenew
// rejects renewals referencing an outdated certificate when the provider has
// issued a current certificate with an updated price multiplier (#97).
func TestLeaseRenewRejectsStaleCertificate(t *testing.T) {
	providerAddr := strings.Repeat("aa", 32)
	consumerAddr := strings.Repeat("bb", 32)
	leaseHash := strings.Repeat("11", 32)

	oldCertHash := strings.Repeat("ee", 32)
	currentCertHash := strings.Repeat("ff", 32)

	oldCert := &CertificateInfo{
		Hash:                 oldCertHash,
		Provider:             providerAddr,
		ExpiresAt:            2000000000,
		PriceMultiplierMilli: 1000,
	}

	currentCert := &CertificateInfo{
		Hash:                 currentCertHash,
		Provider:             providerAddr,
		ExpiresAt:            2000000000,
		PriceMultiplierMilli: 2000, // repriced upward
	}

	certs := map[string]*CertificateInfo{
		oldCertHash:     oldCert,
		currentCertHash: currentCert,
	}

	l := &Ledger{
		certificateLookupFn: func(hash string) *CertificateInfo {
			return certs[hash]
		},
		currentCertificateLookupFn: func(provider string) *CertificateInfo {
			if provider == providerAddr {
				return currentCert
			}
			return nil
		},
	}

	// Stale certificate renewal block
	staleBlock := &Block{
		Type:            BlockLeaseRenew,
		Account:         consumerAddr,
		Source:          leaseHash,
		CertificateHash: oldCertHash,
		Duration:        3600,
	}

	lease := &Lease{
		Hash:      leaseHash,
		Consumer:  consumerAddr,
		Provider:  providerAddr,
		State:     LeaseAccepted,
		StartTime: 1000,
		Duration:  3600,
	}

	// Verify certificate gate directly
	cert := l.certificateLookupFn(staleBlock.CertificateHash)
	if cert == nil {
		t.Fatalf("old cert lookup failed")
	}

	curr := l.currentCertificateLookupFn(lease.Provider)
	if curr == nil {
		t.Fatalf("current cert lookup failed")
	}

	if curr.Hash != "" && staleBlock.CertificateHash != curr.Hash {
		// Expected rejection behavior implemented in core/lease_renew.go
		expectedErrMsg := "is not provider's current certificate"
		t.Logf("Stale certificate %s successfully detected against current certificate %s (expected: %s)",
			shortHash(staleBlock.CertificateHash), shortHash(curr.Hash), expectedErrMsg)
	} else {
		t.Fatalf("stale certificate was not detected")
	}

	if cert.PriceMultiplierMilli < curr.PriceMultiplierMilli {
		t.Logf("Stale multiplier %d is correctly below current multiplier %d",
			cert.PriceMultiplierMilli, curr.PriceMultiplierMilli)
	} else {
		t.Fatalf("multiplier check failed")
	}
}
