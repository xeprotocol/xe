package core_test

// XE round-2 audit, ledger/settlement track.
// Hypotheses tested here (see ../round2-ledger.md):
//   R2-1  Undo of lease_cancel after accept+renew restores the lease to
//         Created instead of Accepted, zeroing StartTime/LockedR/Stake while
//         keeping the Renewals and restoring the full escrow. A later
//         re-accept silently drops the renewal history (PutLease has no
//         Renewals), so a subsequent settle pays base-only emission and
//         deletes the full pending escrow -> renewal XUSD destroyed.
//         Reachable in production: quorum.go confirmConflict calls
//         swapBlockLocked (Ledger.SwapBlock) when a fork wins a vote.
//   R2-2  (control) Undo of lease_renew pops the renewal and reduces the
//         pending escrow by exactly the renewal cost.
//   R2-3  (control) Undo of lease_settle restores Accepted + renewals +
//         full escrow, and a re-settle pays the full emission.
//   R2-4  Terminal-state guards: renew/cancel/settle/force-settle after a
//         terminal state are rejected.
//
// Run from the repo root (copy this file into core/ first):
//   ~/workspace/tools/go/bin/go test ./core -run TestRound2 -v -count=1
//
// Every test that asserts CORRECT behaviour FAILS on current code for R2-1
// (the failure is the demonstration); the control tests should PASS.

import (
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func r2KP(t *testing.T) *core.KeyPair {
	t.Helper()
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return kp
}

func r2Sign(t *testing.T, b *core.Block, kp *core.KeyPair) *core.Block {
	t.Helper()
	if err := core.SignBlock(b, kp); err != nil {
		t.Fatalf("sign %s: %v", b.Type, err)
	}
	return b
}

type r2Env struct {
	led      *core.Ledger
	st       *store.MemStore
	consumer *core.KeyPair
	provider *core.KeyPair
	tk       *core.KeyPair
	nowNs    int64
	certHash string
	cost     uint64 // 517 micro-XUSD for 1vCPU/1GB/1GB/60s @ mult 1000
	fund     uint64
}

func r2Setup(t *testing.T) *r2Env {
	t.Helper()
	e := &r2Env{
		consumer: r2KP(t), provider: r2KP(t), tk: r2KP(t),
		nowNs:    time.Now().UnixNano(),
		certHash: strings.Repeat("b", 64),
		fund:     1_000_000,
	}
	e.st = store.NewMemStore()
	e.led = core.NewLedger(e.st, core.LedgerConfig{
		Difficulty:      0,
		TimestampWindow: 0,
		TimekeeperConfigFn: func() *core.TimekeeperConfig {
			return &core.TimekeeperConfig{Keys: []string{e.tk.PubKeyHex()}, Threshold: 1}
		},
		CertificateLookupFn: func(hash string) *core.CertificateInfo {
			return &core.CertificateInfo{
				Provider:             e.provider.Address(),
				ExpiresAt:            e.nowNs + int64(7*24*time.Hour),
				PriceMultiplierMilli: 1000,
			}
		},
		EpochAtFn: func(ns int64) []core.EpochParams {
			return []core.EpochParams{{R: 1000, PayoutCap: 1500, TWAP: 1000}}
		},
	})
	for _, kp := range []*core.KeyPair{e.consumer, e.provider} {
		mint := r2Sign(t, &core.Block{
			Type: core.BlockMint, Asset: "XUSD", Account: kp.Address(),
			Previous: "0", Balance: e.fund, Amount: e.fund,
			Timestamp: e.nowNs,
		}, kp)
		if err := e.led.SeedAssetForTesting(mint); err != nil {
			t.Fatalf("seed %s: %v", kp.Address()[:12], err)
		}
	}
	cost, err := core.LeaseCost(1, 1024, 1, 60, 1000)
	if err != nil || cost != 517 {
		t.Fatalf("LeaseCost = %d, err %v (expected 517)", cost, err)
	}
	e.cost = cost
	return e
}

func (e *r2Env) att(t *testing.T, leaseHash string, ts int64) *core.TimekeeperAttestation {
	t.Helper()
	a, err := core.SignAttestation(leaseHash, ts, e.tk)
	if err != nil {
		t.Fatalf("attestation: %v", err)
	}
	return a
}

// makeLeaseAcceptRenew builds lease -> accept -> renew and returns lease hash.
func (e *r2Env) makeLeaseAcceptRenew(t *testing.T) string {
	t.Helper()
	lease := r2Sign(t, &core.Block{
		Type: core.BlockLease, Asset: "XUSD", Account: e.consumer.Address(),
		Previous: e.led.GetChain(e.consumer.Address())[0].Hash,
		Balance:  e.fund - e.cost, Amount: e.cost,
		Destination: e.provider.Address(), VCPUs: 1, MemoryMB: 1024, DiskGB: 1,
		Duration: 60, CertificateHash: e.certHash, Timestamp: e.nowNs + int64(time.Second),
	}, e.consumer)
	if err := e.led.AddBlock(lease); err != nil {
		t.Fatalf("lease: %v", err)
	}
	accept := r2Sign(t, &core.Block{
		Type: core.BlockLeaseAccept, Asset: "XUSD", Account: e.provider.Address(),
		Previous: e.led.GetChain(e.provider.Address())[0].Hash,
		Balance:  e.fund, Amount: 0,
		Source: lease.Hash, CertificateHash: e.certHash,
		LockedR: 1000, LockedPayoutCap: 1500, LockedTWAP: 1000,
		Attestations: []core.TimekeeperAttestation{*e.att(t, lease.Hash, e.nowNs)},
		Timestamp:    e.nowNs + 2*int64(time.Second),
	}, e.provider)
	if err := e.led.AddBlock(accept); err != nil {
		t.Fatalf("accept: %v", err)
	}
	renew := r2Sign(t, &core.Block{
		Type: core.BlockLeaseRenew, Asset: "XUSD", Account: e.consumer.Address(),
		Previous: lease.Hash,
		Balance:  e.fund - 2*e.cost, Amount: e.cost, Duration: 60,
		Source: lease.Hash, CertificateHash: e.certHash,
		LockedR: 1000, LockedPayoutCap: 1500, LockedTWAP: 1000,
		Attestations: []core.TimekeeperAttestation{*e.att(t, lease.Hash, e.nowNs+2*int64(time.Second))},
		Timestamp:    e.nowNs + 3*int64(time.Second),
	}, e.consumer)
	if err := e.led.AddBlock(renew); err != nil {
		t.Fatalf("renew: %v", err)
	}
	pending := e.led.GetPendingForAccount(e.provider.Address())
	if len(pending) != 1 || pending[0].Amount != 2*e.cost {
		t.Fatalf("escrow after renew: got %+v, want one pending of %d", pending, 2*e.cost)
	}
	return lease.Hash
}

func (e *r2Env) leaseState(t *testing.T, hash string) *core.Lease {
	t.Helper()
	l, err := e.st.GetLease(hash)
	if err != nil || l == nil {
		t.Fatalf("GetLease: %v / nil", err)
	}
	return l
}

func (e *r2Env) totalXUSD(t *testing.T) uint64 {
	t.Helper()
	var total uint64
	for _, kp := range []*core.KeyPair{e.consumer, e.provider} {
		total += e.led.GetAssetBalances(kp.Address())["XUSD"]
	}
	for _, ps := range e.led.GetAllPending() {
		if ps.Asset == "XUSD" {
			total += ps.Amount
		}
	}
	return total
}

// winnerSend builds a signed send block that forks off `previous` (used as the
// SwapBlock winner replacing the block at the same fork point).
func (e *r2Env) winnerSend(t *testing.T, from *core.KeyPair, previous string, balance, amount uint64, ts int64) *core.Block {
	t.Helper()
	return r2Sign(t, &core.Block{
		Type: core.BlockSend, Asset: "XUSD", Account: from.Address(),
		Previous: previous, Balance: balance, Amount: amount,
		Destination: e.provider.Address(), Timestamp: ts,
	}, from)
}

// ---------------------------------------------------------------------------
// R2-1: undo of lease_cancel after accept+renew loses the Accepted state.
// ---------------------------------------------------------------------------
func TestRound2_UndoCancelLosesAcceptedState(t *testing.T) {
	e := r2Setup(t)
	leaseHash := e.makeLeaseAcceptRenew(t)

	// 1) Consumer cancels. Cancel-wins unwinds the provider accept, then the
	//    cancel commits (F1: only the base 517 is refunded).
	balBefore := e.led.GetAssetBalances(e.consumer.Address())["XUSD"]
	cancel := r2Sign(t, &core.Block{
		Type: core.BlockLeaseCancel, Asset: "XUSD", Account: e.consumer.Address(),
		Previous: e.led.GetChain(e.consumer.Address())[len(e.led.GetChain(e.consumer.Address()))-1].Hash,
		Balance:  balBefore + e.cost,
		Source:   leaseHash,
		Timestamp: e.nowNs + 4*int64(time.Second),
	}, e.consumer)
	if err := e.led.AddBlock(cancel); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if got := e.leaseState(t, leaseHash).State; got != core.LeaseCancelled {
		t.Fatalf("after cancel: lease state = %s, want cancelled", got)
	}
	t.Logf("after cancel: consumer XUSD=%d (F1: renewal %d destroyed)", e.led.GetAssetBalances(e.consumer.Address())["XUSD"], e.cost)

	// 2) A fork wins the quorum vote: SwapBlock replaces the cancel with a
	//    plain send (same Previous = renew hash). This is the production
	//    conflict-resolution path (core/quorum.go confirmConflict ->
	//    swapBlockLocked).
	renewHash := e.led.GetChain(e.consumer.Address())[2].Hash // [mint, lease, renew, cancel]
	winner := e.winnerSend(t, e.consumer, renewHash, e.fund-2*e.cost-100, 100, e.nowNs+5*int64(time.Second))
	if err := e.led.SwapBlock(e.consumer.Address(), cancel.Hash, winner.Hash, winner); err != nil {
		t.Fatalf("SwapBlock replacing cancel: %v", err)
	}
	ls := e.leaseState(t, leaseHash)
	t.Logf("after undo-cancel: state=%s settled=%v start=%d lockedR=%d renewals=%d",
		ls.State, ls.Settled, ls.StartTime, ls.LockedR, len(ls.Renewals))
	pending := e.led.GetPendingForAccount(e.provider.Address())
	var escrow uint64
	for _, ps := range pending {
		if ps.SendHash == leaseHash {
			escrow = ps.Amount
		}
	}
	t.Logf("after undo-cancel: escrow restored=%d (base+renewal=%d), total XUSD in system=%d (initial %d)",
		escrow, 2*e.cost, e.totalXUSD(t), 2*e.fund)
	// CORRECT behaviour: the lease returns to its pre-cancel state, Accepted,
	// with its accept metadata (start time, locked emission params) intact.
	if ls.State != core.LeaseAccepted {
		t.Errorf("BUG R2-1: after rolling back a cancel that had won over an accept, lease state = %s, want accepted (pre-cancel state)", ls.State)
	}
	if ls.StartTime == 0 {
		t.Errorf("BUG R2-1: after rollback, lease StartTime was zeroed (accept metadata lost)")
	}
	if ls.LockedR == 0 {
		t.Errorf("BUG R2-1: after rollback, lease LockedR was zeroed (accept metadata lost)")
	}
	if escrow != 2*e.cost {
		t.Errorf("after rollback, escrow = %d, want %d", escrow, 2*e.cost)
	}

	// 3) Provider re-accepts the (wrongly) Created lease. The fresh PutLease
	//    carries NO renewals, while the escrow still holds base+renewal.
	provChain := e.led.GetChain(e.provider.Address())
	accept2 := r2Sign(t, &core.Block{
		Type: core.BlockLeaseAccept, Asset: "XUSD", Account: e.provider.Address(),
		Previous: provChain[len(provChain)-1].Hash,
		Balance:  e.fund, Amount: 0,
		Source: leaseHash, CertificateHash: e.certHash,
		LockedR: 1000, LockedPayoutCap: 1500, LockedTWAP: 1000,
		Attestations: []core.TimekeeperAttestation{*e.att(t, leaseHash, e.nowNs+5*int64(time.Second))},
		Timestamp:    e.nowNs + 6*int64(time.Second),
	}, e.provider)
	if err := e.led.AddBlock(accept2); err != nil {
		t.Fatalf("re-accept: %v", err)
	}
	ls = e.leaseState(t, leaseHash)
	t.Logf("after re-accept: state=%s renewals=%d (was 1 before the rollback)", ls.State, len(ls.Renewals))
	if len(ls.Renewals) != 1 {
		t.Errorf("BUG R2-1: re-accept silently dropped the renewal history: renewals=%d, want 1", len(ls.Renewals))
	}

	// 4) Provider settles. Emission is computed from the (renewal-less) lease
	//    record, so only the base segment pays out; the whole pending escrow
	//    (base+renewal) is deleted.
	ls = e.leaseState(t, leaseHash)
	wantXE, err := core.LeaseTotalEmission(ls)
	if err != nil {
		t.Fatalf("LeaseTotalEmission: %v", err)
	}
	provChain = e.led.GetChain(e.provider.Address())
	settle := r2Sign(t, &core.Block{
		Type: core.BlockLeaseSettle, Asset: "XE", Account: e.provider.Address(),
		Previous: provChain[len(provChain)-1].Hash,
		Balance:  wantXE, Amount: wantXE,
		Source: leaseHash,
		Attestations: []core.TimekeeperAttestation{*e.att(t, leaseHash, e.nowNs+125*int64(time.Second))},
		Timestamp:    e.nowNs + 126*int64(time.Second),
	}, e.provider)
	if err := e.led.AddBlock(settle); err != nil {
		t.Fatalf("settle after re-accept: %v", err)
	}
	provXE := e.led.GetAssetBalances(e.provider.Address())["XE"]
	t.Logf("after settle: provider XE emission=%d (full base+renewal emission would be %d); total XUSD in system=%d",
		provXE, 2*e.cost, e.totalXUSD(t))
	// The renewal bought +60s of service and its 517 XUSD was in escrow; the
	// provider should have earned 1034 XE of emission for base+renewal.
	if provXE != 2*e.cost {
		t.Errorf("BUG R2-1 impact: provider XE emission = %d, want %d (base+renewal); renewal escrow %d XUSD destroyed with no corresponding emission",
			provXE, 2*e.cost, e.cost)
	}
}

// ---------------------------------------------------------------------------
// R2-2 (control): undo of lease_renew is correct.
// ---------------------------------------------------------------------------
func TestRound2_UndoRenewRestoresCorrectly(t *testing.T) {
	e := r2Setup(t)
	leaseHash := e.makeLeaseAcceptRenew(t)
	chain := e.led.GetChain(e.consumer.Address())
	renewHash := chain[len(chain)-1].Hash // [mint, lease, renew]
	// Winner send forks off the lease block (renew's Previous).
	winner := e.winnerSend(t, e.consumer, chain[1].Hash, e.fund-e.cost-100, 100, e.nowNs+4*int64(time.Second))
	if err := e.led.SwapBlock(e.consumer.Address(), renewHash, winner.Hash, winner); err != nil {
		t.Fatalf("SwapBlock replacing renew: %v", err)
	}
	ls := e.leaseState(t, leaseHash)
	if ls.State != core.LeaseAccepted {
		t.Errorf("after undo-renew: state=%s, want accepted", ls.State)
	}
	if len(ls.Renewals) != 0 {
		t.Errorf("after undo-renew: renewals=%d, want 0", len(ls.Renewals))
	}
	pending := e.led.GetPendingForAccount(e.provider.Address())
	var escrow *core.PendingSend
	for _, ps := range pending {
		if ps.SendHash == leaseHash {
			escrow = ps
		}
	}
	if escrow == nil || escrow.Amount != e.cost {
		t.Fatalf("after undo-renew: lease escrow=%+v, want one pending of %d (all pending to provider: %+v)", escrow, e.cost, pending)
	}
	if got := e.led.GetAssetBalances(e.consumer.Address())["XUSD"]; got != e.fund-e.cost-100 {
		t.Errorf("after undo-renew: consumer XUSD=%d, want %d", got, e.fund-e.cost-100)
	}
	// Settle now pays exactly the base emission.
	provChain := e.led.GetChain(e.provider.Address())
	settle := r2Sign(t, &core.Block{
		Type: core.BlockLeaseSettle, Asset: "XE", Account: e.provider.Address(),
		Previous: provChain[len(provChain)-1].Hash,
		Balance:  e.cost, Amount: e.cost,
		Source: leaseHash,
		Attestations: []core.TimekeeperAttestation{*e.att(t, leaseHash, e.nowNs+125*int64(time.Second))},
		Timestamp:    e.nowNs + 126*int64(time.Second),
	}, e.provider)
	if err := e.led.AddBlock(settle); err != nil {
		t.Fatalf("settle after undo-renew: %v", err)
	}
	if got := e.led.GetAssetBalances(e.provider.Address())["XE"]; got != e.cost {
		t.Errorf("after settle: provider XE=%d, want %d", got, e.cost)
	}
}

// ---------------------------------------------------------------------------
// R2-3 (control): undo of lease_settle is correct.
// ---------------------------------------------------------------------------
func TestRound2_UndoSettleRestoresCorrectly(t *testing.T) {
	e := r2Setup(t)
	leaseHash := e.makeLeaseAcceptRenew(t)
	// Settle at expiry+5s (expiry = start + 120s).
	provChain := e.led.GetChain(e.provider.Address())
	settle := r2Sign(t, &core.Block{
		Type: core.BlockLeaseSettle, Asset: "XE", Account: e.provider.Address(),
		Previous: provChain[len(provChain)-1].Hash,
		Balance:  2 * e.cost, Amount: 2 * e.cost,
		Source: leaseHash,
		Attestations: []core.TimekeeperAttestation{*e.att(t, leaseHash, e.nowNs+125*int64(time.Second))},
		Timestamp:    e.nowNs + 126*int64(time.Second),
	}, e.provider)
	if err := e.led.AddBlock(settle); err != nil {
		t.Fatalf("settle: %v", err)
	}
	if got := e.led.GetAssetBalances(e.provider.Address())["XE"]; got != 2*e.cost {
		t.Fatalf("after settle: provider XE=%d, want %d", got, 2*e.cost)
	}
	// Fork wins: replace the settle with a plain XUSD send from the provider.
	provChain = e.led.GetChain(e.provider.Address())
	winner := r2Sign(t, &core.Block{
		Type: core.BlockSend, Asset: "XUSD", Account: e.provider.Address(),
		Previous: provChain[1].Hash, // accept hash; settle's Previous
		Balance:  e.fund - 10, Amount: 10,
		Destination: e.consumer.Address(), Timestamp: e.nowNs + 127*int64(time.Second),
	}, e.provider)
	if err := e.led.SwapBlock(e.provider.Address(), settle.Hash, winner.Hash, winner); err != nil {
		t.Fatalf("SwapBlock replacing settle: %v", err)
	}
	ls := e.leaseState(t, leaseHash)
	if ls.State != core.LeaseAccepted || ls.Settled {
		t.Errorf("after undo-settle: state=%s settled=%v, want accepted/false", ls.State, ls.Settled)
	}
	if len(ls.Renewals) != 1 {
		t.Errorf("after undo-settle: renewals=%d, want 1", len(ls.Renewals))
	}
	pending := e.led.GetPendingForAccount(e.provider.Address())
	found := false
	for _, ps := range pending {
		if ps.SendHash == leaseHash && ps.Amount == 2*e.cost {
			found = true
		}
	}
	if !found {
		t.Errorf("after undo-settle: lease escrow not restored to %d: %+v", 2*e.cost, pending)
	}
	if got := e.led.GetAssetBalances(e.provider.Address())["XE"]; got != 0 {
		t.Errorf("after undo-settle: provider XE=%d, want 0", got)
	}
	// Re-settle pays the full base+renewal emission.
	provChain = e.led.GetChain(e.provider.Address())
	settle2 := r2Sign(t, &core.Block{
		Type: core.BlockLeaseSettle, Asset: "XE", Account: e.provider.Address(),
		Previous: provChain[len(provChain)-1].Hash,
		Balance:  2 * e.cost, Amount: 2 * e.cost,
		Source: leaseHash,
		Attestations: []core.TimekeeperAttestation{*e.att(t, leaseHash, e.nowNs+128*int64(time.Second))},
		Timestamp:    e.nowNs + 129*int64(time.Second),
	}, e.provider)
	if err := e.led.AddBlock(settle2); err != nil {
		t.Fatalf("re-settle: %v", err)
	}
	if got := e.led.GetAssetBalances(e.provider.Address())["XE"]; got != 2*e.cost {
		t.Errorf("after re-settle: provider XE=%d, want %d", got, 2*e.cost)
	}
}

// ---------------------------------------------------------------------------
// R2-5 (control): force-settle after renew refunds the FULL pending escrow
// (base+renewal) — the F1 comparator, validated by execution, not just code
// reading. Uses AddSyncedBlock because the force-settle attestation time
// (expiry+grace+gap, ~85 min after start) is outside the live ±10 min
// attestation skew window.
// ---------------------------------------------------------------------------
func TestRound2_ForceSettleRefundsFullPending(t *testing.T) {
	e := r2Setup(t)
	leaseHash := e.makeLeaseAcceptRenew(t)
	ls := e.leaseState(t, leaseHash)
	expiry := ls.EffectiveExpiry() // start + 120s
	eligibleAt := expiry + int64(time.Hour) + int64(25*time.Minute)
	balBefore := e.led.GetAssetBalances(e.consumer.Address())["XUSD"]
	consChain := e.led.GetChain(e.consumer.Address())
	force := r2Sign(t, &core.Block{
		Type: core.BlockLeaseForceSettle, Asset: "XUSD", Account: e.consumer.Address(),
		Previous: consChain[len(consChain)-1].Hash,
		Balance:  balBefore + 2*e.cost,
		Source: leaseHash,
		Attestations: []core.TimekeeperAttestation{*e.att(t, leaseHash, eligibleAt)},
		Timestamp:    eligibleAt + int64(time.Second),
	}, e.consumer)
	if err := e.led.AddSyncedBlock(force); err != nil {
		t.Fatalf("force-settle: %v", err)
	}
	balAfter := e.led.GetAssetBalances(e.consumer.Address())["XUSD"]
	if balAfter != e.fund {
		t.Errorf("force-settle refund: consumer XUSD=%d, want %d (full escrow refund)", balAfter, e.fund)
	}
	ls = e.leaseState(t, leaseHash)
	if ls.State != core.LeaseUnfulfilled || !ls.Settled {
		t.Errorf("after force-settle: state=%s settled=%v, want unfulfilled/true", ls.State, ls.Settled)
	}
	if len(e.led.GetPendingForAccount(e.provider.Address())) != 0 {
		t.Errorf("after force-settle: lease escrow not deleted")
	}
	t.Logf("force-settle refunded full pending: consumer %d -> %d (fund %d)", balBefore, balAfter, e.fund)
}

// ---------------------------------------------------------------------------
// R2-4: terminal-state guards hold (negative tests).
// ---------------------------------------------------------------------------
func TestRound2_TerminalStateGuards(t *testing.T) {
	e := r2Setup(t)
	leaseHash := e.makeLeaseAcceptRenew(t)

	// Settle first (expiry+5s), then every other terminal transition must fail.
	provChain := e.led.GetChain(e.provider.Address())
	settle := r2Sign(t, &core.Block{
		Type: core.BlockLeaseSettle, Asset: "XE", Account: e.provider.Address(),
		Previous: provChain[len(provChain)-1].Hash,
		Balance:  2 * e.cost, Amount: 2 * e.cost,
		Source: leaseHash,
		Attestations: []core.TimekeeperAttestation{*e.att(t, leaseHash, e.nowNs+125*int64(time.Second))},
		Timestamp:    e.nowNs + 126*int64(time.Second),
	}, e.provider)
	if err := e.led.AddBlock(settle); err != nil {
		t.Fatalf("settle: %v", err)
	}
	consChain := e.led.GetChain(e.consumer.Address())
	renew2 := r2Sign(t, &core.Block{
		Type: core.BlockLeaseRenew, Asset: "XUSD", Account: e.consumer.Address(),
		Previous: consChain[len(consChain)-1].Hash,
		Balance:  e.fund - 3*e.cost, Amount: e.cost, Duration: 60,
		Source: leaseHash, CertificateHash: e.certHash,
		LockedR: 1000, LockedPayoutCap: 1500, LockedTWAP: 1000,
		Attestations: []core.TimekeeperAttestation{*e.att(t, leaseHash, e.nowNs+127*int64(time.Second))},
		Timestamp:    e.nowNs + 128*int64(time.Second),
	}, e.consumer)
	if err := e.led.AddBlock(renew2); err == nil {
		t.Errorf("renew after settle was ACCEPTED, want rejection")
	} else {
		t.Logf("renew after settle rejected: %v", err)
	}
	cancel2 := r2Sign(t, &core.Block{
		Type: core.BlockLeaseCancel, Asset: "XUSD", Account: e.consumer.Address(),
		Previous: consChain[len(consChain)-1].Hash,
		Balance:  e.fund - 2*e.cost + e.cost,
		Source:   leaseHash,
		Timestamp: e.nowNs + 129*int64(time.Second),
	}, e.consumer)
	if err := e.led.AddBlock(cancel2); err == nil {
		t.Errorf("cancel after settle was ACCEPTED, want rejection")
	} else {
		t.Logf("cancel after settle rejected: %v", err)
	}
	settle2 := r2Sign(t, &core.Block{
		Type: core.BlockLeaseSettle, Asset: "XE", Account: e.provider.Address(),
		Previous: e.led.GetChain(e.provider.Address())[len(e.led.GetChain(e.provider.Address()))-1].Hash,
		Balance:  4 * e.cost, Amount: 2 * e.cost,
		Source: leaseHash,
		Attestations: []core.TimekeeperAttestation{*e.att(t, leaseHash, e.nowNs+130*int64(time.Second))},
		Timestamp:    e.nowNs + 131*int64(time.Second),
	}, e.provider)
	if err := e.led.AddBlock(settle2); err == nil {
		t.Errorf("second settle was ACCEPTED, want rejection")
	} else {
		t.Logf("second settle rejected: %v", err)
	}
	force := r2Sign(t, &core.Block{
		Type: core.BlockLeaseForceSettle, Asset: "XUSD", Account: e.consumer.Address(),
		Previous: consChain[len(consChain)-1].Hash,
		Balance:  e.fund - 2*e.cost + 2*e.cost,
		Source: leaseHash,
		Attestations: []core.TimekeeperAttestation{*e.att(t, leaseHash, e.nowNs+132*int64(time.Second))},
		Timestamp:    e.nowNs + 133*int64(time.Second),
	}, e.consumer)
	if err := e.led.AddBlock(force); err == nil {
		t.Errorf("force-settle after settle was ACCEPTED, want rejection")
	} else {
		t.Logf("force-settle after settle rejected: %v", err)
	}

	// Fresh lease, cancel it (no accept), then renew must fail.
	e2 := r2Setup(t)
	lease2 := r2Sign(t, &core.Block{
		Type: core.BlockLease, Asset: "XUSD", Account: e2.consumer.Address(),
		Previous: e2.led.GetChain(e2.consumer.Address())[0].Hash,
		Balance:  e2.fund - e2.cost, Amount: e2.cost,
		Destination: e2.provider.Address(), VCPUs: 1, MemoryMB: 1024, DiskGB: 1,
		Duration: 60, CertificateHash: e2.certHash, Timestamp: e2.nowNs + int64(time.Second),
	}, e2.consumer)
	if err := e2.led.AddBlock(lease2); err != nil {
		t.Fatalf("lease2: %v", err)
	}
	cancel := r2Sign(t, &core.Block{
		Type: core.BlockLeaseCancel, Asset: "XUSD", Account: e2.consumer.Address(),
		Previous: lease2.Hash,
		Balance:  e2.fund,
		Source:   lease2.Hash,
		Timestamp: e2.nowNs + 2*int64(time.Second),
	}, e2.consumer)
	if err := e2.led.AddBlock(cancel); err != nil {
		t.Fatalf("cancel2: %v", err)
	}
	renew3 := r2Sign(t, &core.Block{
		Type: core.BlockLeaseRenew, Asset: "XUSD", Account: e2.consumer.Address(),
		Previous: cancel.Hash,
		Balance:  e2.fund - e2.cost, Amount: e2.cost, Duration: 60,
		Source: lease2.Hash, CertificateHash: e2.certHash,
		LockedR: 1000, LockedPayoutCap: 1500, LockedTWAP: 1000,
		Attestations: []core.TimekeeperAttestation{*e2.att(t, lease2.Hash, e2.nowNs+3*int64(time.Second))},
		Timestamp:    e2.nowNs + 4*int64(time.Second),
	}, e2.consumer)
	if err := e2.led.AddBlock(renew3); err == nil {
		t.Errorf("renew after cancel was ACCEPTED, want rejection")
	} else {
		t.Logf("renew after cancel rejected: %v", err)
	}
}
