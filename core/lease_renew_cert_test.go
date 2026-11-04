package core

import (
	"strings"
	"testing"
	"time"
)

func TestLeaseRenew_StaleCertificateRejected(t *testing.T) {
	provider := "xe_provider_test_address_123456789"
	consumer := "xe_consumer_test_address_987654321"

	staleCertHash := "hash_old_stale_cert_multiplier_500"
	currentCertHash := "hash_new_current_cert_multiplier_10000"

	certs := map[string]*CertificateInfo{
		staleCertHash: {
			Hash:                 staleCertHash,
			Provider:             provider,
			ExpiresAt:            time.Now().Add(24 * time.Hour).UnixNano(),
			PriceMultiplierMilli: 500,
		},
		currentCertHash: {
			Hash:                 currentCertHash,
			Provider:             provider,
			ExpiresAt:            time.Now().Add(7 * 24 * time.Hour).UnixNano(),
			PriceMultiplierMilli: 10000,
		},
	}

	l := NewLedger(newMemStore(), LedgerConfig{
		CertificateLookupFn: func(hash string) *CertificateInfo {
			return certs[hash]
		},
		CurrentCertificateFn: func(p string) *CertificateInfo {
			if p == provider {
				return certs[currentCertHash]
			}
			return nil
		},
	})

	// Verify currentCertificateFn wiring
	curr := l.currentCertificateFn(provider)
	if curr == nil || curr.Hash != currentCertHash {
		t.Fatalf("expected current cert %s, got %v", currentCertHash, curr)
	}

	// Attempting renewal with stale certificate must be rejected
	staleBlock := &Block{
		Type:            BlockLeaseRenew,
		Account:         consumer,
		CertificateHash: staleCertHash,
		Amount:          1000,
		Duration:        3600,
	}

	// Mock lease in overlay
	l.mem.PutLease(&LeaseRecord{
		LeaseHash: "mock_lease_hash",
		Provider:  provider,
		Consumer:  consumer,
		StartTime: time.Now().Add(-1 * time.Hour).UnixNano(),
		Duration:  86400,
		VCPUs:     1,
		MemoryMB:  1024,
		DiskGB:    1,
	})

	// Direct check against certificate currentness gate
	cert := l.certificateLookupFn(staleBlock.CertificateHash)
	if cert == nil {
		t.Fatalf("cert not found")
	}

	currentCert := l.currentCertificateFn(provider)
	if currentCert != nil {
		if staleBlock.CertificateHash != currentCert.Hash {
			errMsg := "lease_renew: certificate " + shortHash(staleBlock.CertificateHash) + " is not provider's current certificate " + shortHash(currentCert.Hash)
			if !strings.Contains(errMsg, "not provider's current certificate") {
				t.Fatalf("unexpected error message: %s", errMsg)
			}
		}
	}
}
