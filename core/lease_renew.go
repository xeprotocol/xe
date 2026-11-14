package core

import "fmt"

func (l *Ledger) validateAndAddLeaseRenew(b *Block, skipSkew bool) error {
	if b.Asset != "XUSD" {
		return fmt.Errorf("lease_renew block must have asset=XUSD")
	}
	if b.Source == "" {
		return fmt.Errorf("lease_renew must reference a source lease hash")
	}

	lease, ok, err := l.getLeaseOverlay(b.Source)
	if !ok {
		return fmt.Errorf("store does not support leases")
	}
	if err != nil {
		return fmt.Errorf("GetLease: %w", err)
	}
	if lease == nil {
		return fmt.Errorf("lease not found: %s", shortHash(b.Source))
	}
	if lease.Settled {
		return fmt.Errorf("lease already settled")
	}
	if lease.State != LeaseAccepted {

		if lease.State == LeaseCreated {
			return fmt.Errorf("lease not yet accepted for renewal (state %s): retry after accept", lease.State)
		}
		return fmt.Errorf("lease_renew: lease not renewable in %s state", lease.State)
	}
	if lease.Consumer != b.Account {
		return fmt.Errorf("lease_renew: only the consumer can renew a lease")
	}

	if b.Duration < LeaseMinDuration {
		return fmt.Errorf("lease_renew duration must be >= %d seconds, got %d", LeaseMinDuration, b.Duration)
	}
	newEffective, ok := safeAdd(lease.EffectiveDurationSecs(), b.Duration)
	if !ok || newEffective > LeaseMaxDuration {
		return fmt.Errorf("lease_renew: cumulative duration %d + %d exceeds max %d", lease.EffectiveDurationSecs(), b.Duration, LeaseMaxDuration)
	}

	if l.timekeeperConfigFn == nil {
		return fmt.Errorf("lease_renew: timekeepers not configured")
	}
	tkConfig := l.timekeeperConfigFn()
	if tkConfig == nil {
		return fmt.Errorf("lease_renew: timekeepers not configured")
	}
	renewTime, err := ValidateAttestationsForOp(b.Attestations, b.Source, string(BlockLeaseRenew), tkConfig, skipSkew)
	if err != nil {
		return fmt.Errorf("lease_renew attestation: %w", err)
	}

	expiry := lease.EffectiveExpiry()
	if renewTime <= lease.StartTime {
		return fmt.Errorf("lease_renew: renewal time %d must be strictly after lease start %d", renewTime, lease.StartTime)
	}
	if len(lease.Renewals) > 0 {
		lastStart := lease.Renewals[len(lease.Renewals)-1].StartTime
		if renewTime <= lastStart {
			return fmt.Errorf("lease_renew: renewal time %d must be strictly after previous renewal start %d", renewTime, lastStart)
		}
	}
	if renewTime >= expiry {
		return fmt.Errorf("lease_renew: lease no longer live (renewal time %d >= effective expiry %d)", renewTime, expiry)
	}

	if b.CertificateHash == "" {
		return fmt.Errorf("lease_renew: performance certificate required")
	}
	if l.certificateLookupFn == nil {
		return fmt.Errorf("lease_renew: certificate lookup not configured")
	}
	cert := l.certificateLookupFn(b.CertificateHash)
	if cert == nil {
		return fmt.Errorf("lease_renew: certificate %s not found", shortHash(b.CertificateHash))
	}
	if cert.Provider != lease.Provider {
		return fmt.Errorf("lease_renew: certificate %s belongs to %s, not the lease provider %s",
			shortHash(b.CertificateHash), shortHash(cert.Provider), shortHash(lease.Provider))
	}
	if cert.ExpiresAt != 0 && renewTime > cert.ExpiresAt {
		return fmt.Errorf("lease_renew: certificate %s expired at %d, renewal time %d",
			shortHash(b.CertificateHash), cert.ExpiresAt, renewTime)
	}

	expectedCost, err := LeaseCost(lease.VCPUs, lease.MemoryMB, lease.DiskGB, b.Duration, cert.PriceMultiplierMilli)
	if err != nil {
		return fmt.Errorf("lease_renew cost %w", err)
	}
	if b.Amount != expectedCost {
		return fmt.Errorf("lease_renew cost mismatch: expected %d (multiplier %d), got %d", expectedCost, cert.PriceMultiplierMilli, b.Amount)
	}

	if b.LockedR == 0 {
		return fmt.Errorf("lease_renew missing locked emission params: locked_r must be set")
	}
	if err := l.validateLockedEmissionAt(renewTime, b.LockedR, b.LockedPayoutCap, b.LockedTWAP, skipSkew, "lease_renew"); err != nil {
		return err
	}

	escrow, err := l.getPendingSendOverlay(b.Source)
	if err != nil {
		return fmt.Errorf("GetPendingSend: %w", err)
	}
	if escrow == nil {
		return fmt.Errorf("lease_renew: no live escrow for lease %s", shortHash(b.Source))
	}

	chain, err := l.getAccountChainOverlay(b.Account)
	if err != nil {
		return fmt.Errorf("GetAccountChain: %w", err)
	}
	if chain == nil {
		return fmt.Errorf("lease_renew from unopened account")
	}
	if b.Previous != chain.Frontier() {
		return fmt.Errorf("previous mismatch: got %s, want %s", shortHash(b.Previous), shortHash(chain.Frontier()))
	}
	if len(chain.Blocks) > 0 {
		lastTs := chain.Blocks[len(chain.Blocks)-1].Timestamp
		if b.Timestamp < lastTs {
			return fmt.Errorf("block timestamp %d is before previous block timestamp %d", b.Timestamp, lastTs)
		}
	}

	oldBal := l.getAssetBalanceOverlay(b.Account, "XUSD")
	if b.Amount > oldBal {
		return fmt.Errorf("insufficient XUSD balance for renewal: have %d, need %d", oldBal, b.Amount)
	}
	if b.Balance != oldBal-b.Amount {
		return fmt.Errorf("balance mismatch: expected %d, got %d", oldBal-b.Amount, b.Balance)
	}

	commit, prevBalance, err := l.prepareBlockWrite(b)
	if err != nil {
		return err
	}

	commit.TopUpPendingID = b.Source
	commit.TopUpPendingAmount = b.Amount

	renewed := *lease
	renewed.Renewals = append(append([]LeaseSegment(nil), lease.Renewals...), LeaseSegment{
		RenewHash:       b.Hash,
		Duration:        b.Duration,
		Cost:            b.Amount,
		StartTime:       renewTime,
		CertificateHash: b.CertificateHash,
		LockedR:         b.LockedR,
		LockedPayoutCap: b.LockedPayoutCap,
		LockedTWAP:      b.LockedTWAP,
	})
	commit.PutLease = &renewed

	commit.ExpectLeaseHash = b.Source
	commit.ExpectLeaseState = LeaseAccepted
	commit.ExpectLeaseEffectiveDurationSecs = lease.EffectiveDurationSecs()

	return l.commitBlockWrite(commit, prevBalance)
}
