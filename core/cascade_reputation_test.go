package core

import (
	"errors"
	"sync"
	"testing"
)

type miniMemStore struct {
	mu          sync.RWMutex
	blocks      map[string]*Block
	chains      map[string]*AccountChain
	pending     map[string]*PendingSend
	frontiers   map[string]string
	leases      map[string]*Lease
	delegations map[string]string
	keysets     map[string]*Keyset
	accountKeys map[string]string
}

func newMiniMemStore() *miniMemStore {
	return &miniMemStore{
		blocks:      make(map[string]*Block),
		chains:      make(map[string]*AccountChain),
		pending:     make(map[string]*PendingSend),
		frontiers:   make(map[string]string),
		leases:      make(map[string]*Lease),
		delegations: make(map[string]string),
		keysets:     make(map[string]*Keyset),
		accountKeys: make(map[string]string),
	}
}

func (m *miniMemStore) GetBlock(hash string) (*Block, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if b, ok := m.blocks[hash]; ok {
		cp := *b
		return &cp, nil
	}
	return nil, nil
}

func (m *miniMemStore) PutBlock(b *Block) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *b
	m.blocks[b.Hash] = &cp
	return nil
}

func (m *miniMemStore) GetAccountChain(account string) (*AccountChain, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ch := m.chains[account]
	if ch == nil {
		return nil, nil
	}
	out := &AccountChain{Blocks: make([]*Block, len(ch.Blocks))}
	copy(out.Blocks, ch.Blocks)
	return out, nil
}

func (m *miniMemStore) PutAccountChain(account string, chain *AccountChain) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := &AccountChain{Blocks: make([]*Block, len(chain.Blocks))}
	copy(out.Blocks, chain.Blocks)
	m.chains[account] = out
	return nil
}

func (m *miniMemStore) GetPendingSend(sendHash string) (*PendingSend, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if ps, ok := m.pending[sendHash]; ok {
		cp := *ps
		return &cp, nil
	}
	return nil, nil
}

func (m *miniMemStore) PutPendingSend(ps *PendingSend) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *ps
	m.pending[ps.SendHash] = &cp
	return nil
}

func (m *miniMemStore) DeletePendingSend(sendHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.pending, sendHash)
	return nil
}

func (m *miniMemStore) GetPendingByDest(account string) ([]*PendingSend, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*PendingSend
	for _, ps := range m.pending {
		if ps.Destination == account {
			cp := *ps
			res = append(res, &cp)
		}
	}
	return res, nil
}

func (m *miniMemStore) GetAllPending() ([]*PendingSend, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*PendingSend
	for _, ps := range m.pending {
		cp := *ps
		res = append(res, &cp)
	}
	return res, nil
}

func (m *miniMemStore) PutFrontier(account, hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.frontiers[account] = hash
	return nil
}

func (m *miniMemStore) GetFrontier(account string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.frontiers[account], nil
}

func (m *miniMemStore) AllFrontiers() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]string, len(m.frontiers))
	for k, v := range m.frontiers {
		out[k] = v
	}
	return out
}

func (m *miniMemStore) IsEmpty() (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.blocks) == 0, nil
}

func (m *miniMemStore) Close() error { return nil }

func (m *miniMemStore) PutLease(lease *Lease) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *lease
	if lease.Renewals != nil {
		cp.Renewals = append([]LeaseSegment(nil), lease.Renewals...)
	}
	m.leases[lease.LeaseHash] = &cp
	return nil
}

func (m *miniMemStore) GetLease(leaseHash string) (*Lease, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if l, ok := m.leases[leaseHash]; ok {
		cp := *l
		if l.Renewals != nil {
			cp.Renewals = append([]LeaseSegment(nil), l.Renewals...)
		}
		return &cp, nil
	}
	return nil, nil
}

func (m *miniMemStore) GetLeasesByProvider(provider string) ([]*Lease, error) { return nil, nil }
func (m *miniMemStore) GetLeasesByState(state LeaseState) ([]*Lease, error)  { return nil, nil }
func (m *miniMemStore) GetAllLeases() ([]*Lease, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*Lease
	for _, l := range m.leases {
		cp := *l
		if l.Renewals != nil {
			cp.Renewals = append([]LeaseSegment(nil), l.Renewals...)
		}
		res = append(res, &cp)
	}
	return res, nil
}

func (m *miniMemStore) CommitUndo(u *BlockUndo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.applyUndoLocked(u)
	return nil
}

func (m *miniMemStore) applyUndoLocked(u *BlockUndo) {
	if u.RejectHash != "" {
		delete(m.blocks, u.RejectHash)
	}
	if u.DeleteAccount {
		delete(m.chains, u.Account)
		delete(m.frontiers, u.Account)
	} else if u.Chain != nil {
		out := &AccountChain{Blocks: make([]*Block, len(u.Chain.Blocks))}
		copy(out.Blocks, u.Chain.Blocks)
		m.chains[u.Account] = out
		m.frontiers[u.Account] = u.FrontierHash
	}
	if u.DeletePendingID != "" {
		delete(m.pending, u.DeletePendingID)
	}
	if u.AddPending != nil {
		cp := *u.AddPending
		m.pending[cp.SendHash] = &cp
	}
	if u.RestoreLease != nil {
		cp := *u.RestoreLease
		if u.RestoreLease.Renewals != nil {
			cp.Renewals = append([]LeaseSegment(nil), u.RestoreLease.Renewals...)
		}
		m.leases[cp.LeaseHash] = &cp
	}
	if u.DeleteLeaseHash != "" {
		delete(m.leases, u.DeleteLeaseHash)
	}
}

func (m *miniMemStore) CommitBlock(c *BlockCommit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.applyCommitLocked(c)
	return nil
}

func (m *miniMemStore) applyCommitLocked(c *BlockCommit) {
	cp := *c.Block
	m.blocks[c.Block.Hash] = &cp
	out := &AccountChain{Blocks: make([]*Block, len(c.Chain.Blocks))}
	copy(out.Blocks, c.Chain.Blocks)
	m.chains[c.Account] = out
	m.frontiers[c.Account] = c.FrontierHash
	if c.AddPending != nil {
		p := *c.AddPending
		m.pending[p.SendHash] = &p
	}
	if c.DeletePendingID != "" {
		delete(m.pending, c.DeletePendingID)
	}
	if c.PutLease != nil {
		l := *c.PutLease
		m.leases[l.LeaseHash] = &l
	}
}

func (m *miniMemStore) CommitCascade(undos []*BlockUndo, commit *BlockCommit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range undos {
		m.applyUndoLocked(u)
	}
	if commit != nil {
		m.applyCommitLocked(commit)
	}
	return nil
}

func TestCascadeOverlayStaleStoreReadsInUndoAndXUSDBalance(t *testing.T) {
	store := newMiniMemStore()
	l := NewLedger(store, LedgerConfig{})

	consumer, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair consumer: %v", err)
	}
	provider, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair provider: %v", err)
	}

	leaseHash := "aaaa000000000000000000000000000000000000000000000000000000000001"
	leaseBlock := &Block{
		Type:        BlockLease,
		Account:     consumer.Address(),
		Previous:    "0",
		Balance:     900_000,
		Timestamp:   1000,
		Asset:       "XUSD",
		Destination: provider.Address(),
		Amount:      100_000,
		Duration:    3600,
		PubKey:      consumer.PubKeyHex(),
		Hash:        leaseHash,
	}
	if err := store.PutBlock(leaseBlock); err != nil {
		t.Fatalf("PutBlock leaseBlock: %v", err)
	}

	// Store has an accepted, renewed, and settled lease (stake=10_000, base=100_000, renewal=50_000)
	storedLease := &Lease{
		LeaseHash:       leaseHash,
		State:           LeaseSettled,
		Consumer:        consumer.Address(),
		Provider:        provider.Address(),
		Duration:        3600,
		Cost:            100_000,
		Stake:           10_000,
		StartTime:       2000,
		Settled:         true,
		LockedR:         1000,
		LockedPayoutCap: 1000,
		LockedTWAP:      1000,
		Renewals: []LeaseSegment{
			{Duration: 1800, Cost: 50_000, LockedR: 1000, LockedPayoutCap: 1000, LockedTWAP: 1000},
		},
	}
	if err := store.PutLease(storedLease); err != nil {
		t.Fatalf("PutLease: %v", err)
	}

	// Provider chain has: [0] mint 50_000 XUSD, [1] lease_accept (stake 10_000 -> bal 40_000), [2] lease_settle (XE 150 + XUSD stake refund 10_000)
	pMint := &Block{
		Type:      BlockMint,
		Account:   provider.Address(),
		Previous:  "0",
		Balance:   50_000,
		Amount:    50_000,
		Timestamp: 1500,
		Asset:     "XUSD",
		PubKey:    provider.PubKeyHex(),
		Hash:      "bbbb000000000000000000000000000000000000000000000000000000000001",
	}
	pAccept := &Block{
		Type:      BlockLeaseAccept,
		Account:   provider.Address(),
		Previous:  pMint.Hash,
		Balance:   40_000,
		Amount:    10_000,
		Source:    leaseHash,
		Timestamp: 2000,
		Asset:     "XUSD",
		Hash:      "bbbb000000000000000000000000000000000000000000000000000000000002",
	}
	pSettle := &Block{
		Type:      BlockLeaseSettle,
		Account:   provider.Address(),
		Previous:  pAccept.Hash,
		Balance:   150,
		Amount:    150,
		Source:    leaseHash,
		Timestamp: 6000,
		Asset:     "XE",
		Hash:      "bbbb000000000000000000000000000000000000000000000000000000000003",
	}
	pChain := &AccountChain{Blocks: []*Block{pMint, pAccept, pSettle}}

	cascade := newCascadeBuild("winner_hash")

	// Step 1: Unwind BlockLeaseSettle -> restores lease to LeaseAccepted (still has 1 renewal) and restores pending escrow (150_000)
	u1, apply1, err := l.buildBlockUndoWithCascade(provider.Address(), pSettle, pChain, cascade)
	if err != nil {
		t.Fatalf("buildBlockUndoWithCascade settle: %v", err)
	}
	cascade.addUndo(u1, apply1)
	if u1.AddPending == nil || u1.AddPending.Amount != 150_000 {
		t.Fatalf("expected restored pending escrow 150_000 after settle undo, got %+v", u1.AddPending)
	}

	// Step 2: Unwind consumer's BlockLeaseRenew -> pops renewal from overlay lease
	cRenew := &Block{
		Type:      BlockLeaseRenew,
		Account:   consumer.Address(),
		Previous:  leaseBlock.Hash,
		Balance:   850_000,
		Amount:    50_000,
		Duration:  1800,
		Source:    leaseHash,
		Timestamp: 3000,
		Asset:     "XUSD",
		Hash:      "aaaa000000000000000000000000000000000000000000000000000000000002",
	}
	cChain := &AccountChain{Blocks: []*Block{leaseBlock, cRenew}}
	u2, apply2, err := l.buildBlockUndoWithCascade(consumer.Address(), cRenew, cChain, cascade)
	if err != nil {
		t.Fatalf("buildBlockUndoWithCascade renew: %v", err)
	}
	cascade.addUndo(u2, apply2)
	if u2.RestoreLease == nil || len(u2.RestoreLease.Renewals) != 0 || u2.RestoreLease.State != LeaseAccepted {
		t.Fatalf("expected overlay lease to have 0 renewals and State=LeaseAccepted, got %+v", u2.RestoreLease)
	}

	// Step 3: Unwind provider's BlockLeaseAccept -> restores lease to LeaseCreated (Stake=0, 0 renewals in overlay)
	u3, apply3, err := l.buildBlockUndoWithCascade(provider.Address(), pAccept, u1.Chain, cascade)
	if err != nil {
		t.Fatalf("buildBlockUndoWithCascade accept: %v", err)
	}
	cascade.addUndo(u3, apply3)
	if u3.RestoreLease == nil || u3.RestoreLease.State != LeaseCreated || u3.RestoreLease.Stake != 0 || len(u3.RestoreLease.Renewals) != 0 {
		t.Fatalf("expected LeaseCreated with Stake=0 and 0 renewals, got %+v", u3.RestoreLease)
	}

	// Verify escrowPendingOfWithCascade reads the overlay lease (0 renewals -> 100_000, NOT stale store 150_000)
	ps := l.escrowPendingOfWithCascade(leaseHash, cascade)
	if ps == nil || ps.Amount != 100_000 {
		t.Fatalf("expected escrowPendingOfWithCascade to return 100_000 after renewal pop in overlay, got %+v", ps)
	}

	// Verify xusdBalanceOnChainWithCascade reads Stake=0 from the overlay when LeaseCreated is in overlay
	chainWithStaleSettle := &AccountChain{Blocks: []*Block{pMint, pSettle}}
	if got := l.xusdBalanceOnChainWithCascade(chainWithStaleSettle, cascade); got != 50_000 {
		t.Fatalf("expected xusdBalanceOnChainWithCascade to read Stake=0 from overlay (50_000), got %d", got)
	}
}

func TestRenewedLeaseReputationDurationAndFallbackTimestamps(t *testing.T) {
	store := newMiniMemStore()
	l := NewLedger(store, LedgerConfig{})

	consumer := "1111111111111111111111111111111111111111111111111111111111111111"
	provider := "2222222222222222222222222222222222222222222222222222222222222222"
	leaseHash := "3333333333333333333333333333333333333333333333333333333333333333"

	// Base duration = 3600s, two renewals of 3600s and 7200s -> total EffectiveDurationSecs = 14400s
	startTime := int64(1_000_000_000_000)
	lease := &Lease{
		LeaseHash: leaseHash,
		State:     LeaseSettled,
		Consumer:  consumer,
		Provider:  provider,
		Duration:  3600,
		Cost:      100_000,
		Stake:     10_000,
		StartTime: startTime,
		Settled:   true,
		Renewals: []LeaseSegment{
			{Duration: 3600, Cost: 100_000},
			{Duration: 7200, Cost: 200_000},
		},
	}
	if err := store.PutLease(lease); err != nil {
		t.Fatalf("PutLease: %v", err)
	}

	// Rebuild reputation from store when provider chain has no settle block (tests fallback timestamp + EffectiveDurationSecs)
	l.rebuildReputation()

	pRep := l.GetReputation(provider)
	cRep := l.GetReputation(consumer)
	if pRep.LeaseHoursSettledAsProvider != 14400 {
		t.Fatalf("expected provider LeaseHoursSettledAsProvider=14400 (including renewals), got %d", pRep.LeaseHoursSettledAsProvider)
	}
	if cRep.LeaseHoursSettledAsConsumer != 14400 {
		t.Fatalf("expected consumer LeaseHoursSettledAsConsumer=14400 (including renewals), got %d", cRep.LeaseHoursSettledAsConsumer)
	}
	expectedExpiry := lease.EffectiveExpiry()
	if pRep.LastActivityAt != expectedExpiry {
		t.Fatalf("expected fallback LastActivityAt=%d (EffectiveExpiry), got %d", expectedExpiry, pRep.LastActivityAt)
	}

	// Now test undo of BlockLeaseSettle reverts the full 14400s (EffectiveDurationSecs), not just 3600s
	settleBlock := &Block{
		Type:      BlockLeaseSettle,
		Account:   provider,
		Previous:  "0",
		Balance:   500,
		Amount:    500,
		Source:    leaseHash,
		Timestamp: expectedExpiry,
		Asset:     "XE",
		Hash:      "4444444444444444444444444444444444444444444444444444444444444444",
	}
	pChain := &AccountChain{Blocks: []*Block{settleBlock}}
	_, applyUndo, err := l.buildBlockUndo(provider, settleBlock, pChain)
	if err != nil {
		t.Fatalf("buildBlockUndo settle: %v", err)
	}
	applyUndo()

	pRepAfter := l.GetReputation(provider)
	cRepAfter := l.GetReputation(consumer)
	if pRepAfter.LeaseHoursSettledAsProvider != 0 {
		t.Fatalf("expected provider LeaseHoursSettledAsProvider=0 after settle undo, got %d", pRepAfter.LeaseHoursSettledAsProvider)
	}
	if cRepAfter.LeaseHoursSettledAsConsumer != 0 {
		t.Fatalf("expected consumer LeaseHoursSettledAsConsumer=0 after settle undo, got %d", cRepAfter.LeaseHoursSettledAsConsumer)
	}
}

func TestSwapBlockCredentialVerificationAndOverlayKeyset(t *testing.T) {
	store := newMiniMemStore()
	l := NewLedger(store, LedgerConfig{})

	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair kp1: %v", err)
	}
	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair kp2: %v", err)
	}
	dest, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair dest: %v", err)
	}

	// Seed kp1 with 1000 XE (block 1: open mint, block 2: send 100 XE)
	mint := &Block{
		Type:      BlockMint,
		Account:   kp1.Address(),
		Previous:  "0",
		Balance:   1000,
		Amount:    1000,
		Timestamp: 1000,
		Asset:     "XE",
	}
	if err := SignBlock(mint, kp1); err != nil {
		t.Fatalf("SignBlock mint: %v", err)
	}
	if err := l.SeedAssetForTesting(mint); err != nil {
		t.Fatalf("SeedAssetForTesting: %v", err)
	}

	loserSend := &Block{
		Type:        BlockSend,
		Account:     kp1.Address(),
		Previous:    mint.Hash,
		Balance:     900,
		Amount:      100,
		Destination: dest.Address(),
		Timestamp:   2000,
		Asset:       "XE",
	}
	if err := SignBlock(loserSend, kp1); err != nil {
		t.Fatalf("SignBlock loserSend: %v", err)
	}
	if err := l.AddBlock(loserSend); err != nil {
		t.Fatalf("AddBlock loserSend: %v", err)
	}

	// Forged replacement block signed by kp2 (wrong private key for kp1's account)
	forgedWinner := &Block{
		Type:        BlockSend,
		Account:     kp1.Address(),
		Previous:    mint.Hash,
		Balance:     800,
		Amount:      200,
		Destination: dest.Address(),
		Timestamp:   2001,
		Asset:       "XE",
	}
	if err := SignBlock(forgedWinner, kp2); err != nil {
		t.Fatalf("SignBlock forgedWinner: %v", err)
	}

	err = l.SwapBlock(kp1.Address(), loserSend.Hash, forgedWinner.Hash, forgedWinner)
	if err == nil || !errors.Is(err, ErrWinnerFullValidation) {
		t.Fatalf("expected SwapBlock to reject forged winner with ErrWinnerFullValidation, got: %v", err)
	}
	// Ensure loserSend is still the frontier
	chain := l.GetChain(kp1.Address())
	if len(chain) != 2 || chain[1].Hash != loserSend.Hash {
		t.Fatalf("expected loserSend to remain on chain after failed SwapBlock")
	}
}
