package core

import (
	"testing"
)

type testLeaseStore struct {
	blocks   map[string]*Block
	chains   map[string]*AccountChain
	pending  map[string]*PendingSend
	leases   map[string]*Lease
	staged   map[string]*Block
	statuses map[string]BlockStatus
}

func newTestLeaseStore() *testLeaseStore {
	return &testLeaseStore{
		blocks:   make(map[string]*Block),
		chains:   make(map[string]*AccountChain),
		pending:  make(map[string]*PendingSend),
		leases:   make(map[string]*Lease),
		staged:   make(map[string]*Block),
		statuses: make(map[string]BlockStatus),
	}
}

func (s *testLeaseStore) GetBlock(hash string) (*Block, error) {
	return s.blocks[hash], nil
}
func (s *testLeaseStore) PutBlock(b *Block) error {
	s.blocks[b.Hash] = b
	return nil
}
func (s *testLeaseStore) GetAccountChain(account string) (*AccountChain, error) {
	return s.chains[account], nil
}
func (s *testLeaseStore) PutAccountChain(account string, chain *AccountChain) error {
	s.chains[account] = chain
	return nil
}
func (s *testLeaseStore) GetPendingSend(sendHash string) (*PendingSend, error) {
	return s.pending[sendHash], nil
}
func (s *testLeaseStore) PutPendingSend(ps *PendingSend) error {
	s.pending[ps.SendHash] = ps
	return nil
}
func (s *testLeaseStore) DeletePendingSend(sendHash string) error {
	delete(s.pending, sendHash)
	return nil
}
func (s *testLeaseStore) GetPendingByDest(account string) ([]*PendingSend, error) {
	return nil, nil
}
func (s *testLeaseStore) GetAllPending() ([]*PendingSend, error) {
	return nil, nil
}
func (s *testLeaseStore) PutFrontier(account string, blockHash string) error {
	return nil
}
func (s *testLeaseStore) GetFrontier(account string) (string, error) {
	if c := s.chains[account]; c != nil && len(c.Blocks) > 0 {
		return c.Frontier(), nil
	}
	return "0", nil
}
func (s *testLeaseStore) CommitUndo(u *BlockUndo) error {
	return nil
}
func (s *testLeaseStore) IsEmpty() (bool, error) {
	return len(s.blocks) == 0, nil
}
func (s *testLeaseStore) Close() error {
	return nil
}
func (s *testLeaseStore) CommitBlock(c *BlockCommit) error {
	if c.Block != nil {
		s.blocks[c.Block.Hash] = c.Block
	}
	if c.Chain != nil {
		s.chains[c.Account] = c.Chain
	}
	return nil
}
func (s *testLeaseStore) CommitCascade(undos []*BlockUndo, commit *BlockCommit) error {
	return nil
}
func (s *testLeaseStore) PutLease(lease *Lease) error {
	s.leases[lease.LeaseHash] = lease
	return nil
}
func (s *testLeaseStore) GetLease(leaseHash string) (*Lease, error) {
	return s.leases[leaseHash], nil
}
func (s *testLeaseStore) GetLeasesByProvider(provider string) ([]*Lease, error) {
	return nil, nil
}
func (s *testLeaseStore) GetLeasesByState(state LeaseState) ([]*Lease, error) {
	return nil, nil
}
func (s *testLeaseStore) GetAllLeases() ([]*Lease, error) {
	return nil, nil
}
func (s *testLeaseStore) SaveConflict(c *Conflict) error {
	return nil
}
func (s *testLeaseStore) GetConflict(account, previousHash string) (*Conflict, error) {
	return nil, nil
}
func (s *testLeaseStore) DeleteConflict(account, previousHash string) error {
	return nil
}
func (s *testLeaseStore) GetConflictsForAccount(account string) ([]*Conflict, error) {
	return nil, nil
}
func (s *testLeaseStore) GetAllConflicts() ([]*Conflict, error) {
	return nil, nil
}
func (s *testLeaseStore) SaveStagedBlock(b *Block) error {
	s.staged[b.Hash] = b
	return nil
}
func (s *testLeaseStore) GetStagedBlock(hash string) (*Block, error) {
	return s.staged[hash], nil
}
func (s *testLeaseStore) DeleteStagedBlock(hash string) error {
	delete(s.staged, hash)
	return nil
}
func (s *testLeaseStore) SetBlockStatus(hash string, status BlockStatus) error {
	s.statuses[hash] = status
	return nil
}
func (s *testLeaseStore) GetBlockStatus(hash string) (BlockStatus, error) {
	return s.statuses[hash], nil
}
func (s *testLeaseStore) SetFinalHeight(account string, height uint64) error {
	return nil
}
func (s *testLeaseStore) GetFinalHeight(account string) (uint64, error) {
	return 0, nil
}
func (s *testLeaseStore) DeleteVotesForConflict(account, previous string) error {
	return nil
}

func TestDefaultAssetForBlock(t *testing.T) {
	leaseTypes := []BlockType{
		BlockLease,
		BlockLeaseAccept,
		BlockLeaseSettle,
		BlockLeaseCancel,
		BlockLeaseForceSettle,
		BlockLeaseRenew,
	}

	for _, lt := range leaseTypes {
		if !IsLeaseBlock(lt) {
			t.Errorf("expected %s to be recognized as lease block", lt)
		}
		if got := DefaultAssetForBlock(lt, ""); got != "XUSD" {
			t.Errorf("expected empty asset for %s to default to XUSD, got %q", lt, got)
		}
		if got := DefaultAssetForBlock(lt, "XUSD"); got != "XUSD" {
			t.Errorf("expected explicit XUSD for %s to remain XUSD, got %q", lt, got)
		}
	}

	if got := DefaultAssetForBlock(BlockMint, ""); got != "XUSD" {
		t.Errorf("expected empty asset for mint to default to XUSD, got %q", got)
	}

	nonLeaseTypes := []BlockType{
		BlockSend,
		BlockReceive,
		BlockBurn,
		BlockGenesis,
		BlockMultisigOpen,
		BlockMultisigUpdate,
	}

	for _, nlt := range nonLeaseTypes {
		if IsLeaseBlock(nlt) {
			t.Errorf("expected %s NOT to be recognized as lease block", nlt)
		}
		if got := DefaultAssetForBlock(nlt, ""); got != "XE" {
			t.Errorf("expected empty asset for %s to default to XE, got %q", nlt, got)
		}
		if got := DefaultAssetForBlock(nlt, "XUSD"); got != "XUSD" {
			t.Errorf("expected explicit asset to be preserved, got %q", got)
		}
	}
}

func TestValidateStagedBlock_LeaseAssetEnforcement(t *testing.T) {
	store := newTestLeaseStore()
	ledger := NewLedger(store, LedgerConfig{})

	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	account := kp.Address()
	ledger.setAccountKey(account, kp.PubKeyHex())
	dest := "0202020202020202020202020202020202020202020202020202020202020202"
	prev := "0101010101010101010101010101010101010101010101010101010101010101"
	source := "0303030303030303030303030303030303030303030303030303030303030303"

	// 1. Lease block with explicit XE asset must fail validation
	badLease := &Block{
		Type:        BlockLease,
		Account:     account,
		Previous:    prev,
		Destination: dest,
		Amount:      50,
		Balance:     50,
		Asset:       "XE",
	}
	MustSignBlock(badLease, kp)
	if err := ledger.ValidateStagedBlock(badLease, 100); err == nil {
		t.Fatalf("expected error validating staged lease with Asset=XE, got nil")
	}

	// 2. Lease block with XUSD asset must pass validation
	goodLease := &Block{
		Type:        BlockLease,
		Account:     account,
		Previous:    prev,
		Destination: dest,
		Amount:      50,
		Balance:     50,
		Asset:       "XUSD",
	}
	MustSignBlock(goodLease, kp)
	if err := ledger.ValidateStagedBlock(goodLease, 100); err != nil {
		t.Fatalf("unexpected error validating staged lease with Asset=XUSD: %v", err)
	}

	// 3. Lease renew block with XE asset must fail validation
	badRenew := &Block{
		Type:     BlockLeaseRenew,
		Account:  account,
		Previous: prev,
		Source:   source,
		Amount:   20,
		Balance:  80,
		Asset:    "XE",
	}
	MustSignBlock(badRenew, kp)
	if err := ledger.ValidateStagedBlock(badRenew, 100); err == nil {
		t.Fatalf("expected error validating staged lease_renew with Asset=XE, got nil")
	}

	// 4. Lease renew block with XUSD asset must pass validation
	goodRenew := &Block{
		Type:     BlockLeaseRenew,
		Account:  account,
		Previous: prev,
		Source:   source,
		Amount:   20,
		Balance:  80,
		Asset:    "XUSD",
	}
	MustSignBlock(goodRenew, kp)
	if err := ledger.ValidateStagedBlock(goodRenew, 100); err != nil {
		t.Fatalf("unexpected error validating staged lease_renew with Asset=XUSD: %v", err)
	}
}

func TestQuorumPromotable_LeaseEmptyAsset_RequiresXUSDBalance(t *testing.T) {
	store := newTestLeaseStore()
	ledger := NewLedger(store, LedgerConfig{})
	qm := NewQuorumManager(store, store, nil, ledger)

	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	account := kp.Address()
	ledger.setAccountKey(account, kp.PubKeyHex())

	dest := "0202020202020202020202020202020202020202020202020202020202020202"
	prevHash := "0101010101010101010101010101010101010101010101010101010101010101"
	xusdHash := "0404040404040404040404040404040404040404040404040404040404040404"

	// Create a chain where account has 1000 XE, but 0 XUSD at prevHash
	chain := &AccountChain{
		Blocks: []*Block{
			{
				Hash:    prevHash,
				Account: account,
				Asset:   "XE",
				Balance: 1000,
			},
		},
	}
	store.chains[account] = chain

	// Staged lease block with empty asset ("") requesting 100
	stagedBlock := &Block{
		Type:        BlockLease,
		Account:     account,
		Destination: dest,
		Previous:    prevHash,
		Amount:      100,
		Balance:     0,
		Asset:       "", // empty asset
	}
	MustSignBlock(stagedBlock, kp)
	store.staged[stagedBlock.Hash] = stagedBlock

	// In the unpatched code, promotable defaulted asset="" to "XE", saw 1000 XE,
	// and incorrectly reported promotable = true.
	// In the fixed code, promotable uses DefaultAssetForBlock, looks up XUSD balance (0),
	// and correctly rejects promotion (false).
	if qm.promotable(account, prevHash, stagedBlock.Hash) {
		t.Fatalf("promotable returned true for staged lease with empty asset when account has 0 XUSD (even with 1000 XE)")
	}

	// Now add a block providing 100 XUSD to the chain before prevHash
	chain.Blocks = []*Block{
		{
			Hash:    xusdHash,
			Account: account,
			Asset:   "XUSD",
			Balance: 100,
		},
		{
			Hash:     prevHash,
			Account:  account,
			Previous: xusdHash,
			Asset:    "XE",
			Balance:  1000,
		},
	}

	// With 100 XUSD parent balance, the staged block (Amount: 100, Balance: 0) is now valid!
	if !qm.promotable(account, prevHash, stagedBlock.Hash) {
		t.Fatalf("promotable returned false for staged lease when account has sufficient 100 XUSD")
	}
}

func TestGetAssetBalanceAtBlock_LeaseSettleStakeIncluded(t *testing.T) {
	store := newTestLeaseStore()
	ledger := NewLedger(store, LedgerConfig{})

	account := "0101010101010101010101010101010101010101010101010101010101010101"
	leaseHash := "0202020202020202020202020202020202020202020202020202020202020202"
	settleHash := "0303030303030303030303030303030303030303030303030303030303030303"

	store.leases[leaseHash] = &Lease{
		LeaseHash: leaseHash,
		Stake:     500,
	}

	// Chain with settled lease: balance was 100 XUSD, and 500 stake was returned
	chain := &AccountChain{
		Blocks: []*Block{
			{
				Hash:    settleHash,
				Type:    BlockLeaseSettle,
				Account: account,
				Source:  leaseHash,
				Asset:   "XUSD",
				Balance: 100,
			},
		},
	}
	store.chains[account] = chain

	bal := ledger.GetAssetBalanceAtBlock(account, "XUSD", settleHash)
	expected := uint64(100 + 500)
	if bal != expected {
		t.Fatalf("GetAssetBalanceAtBlock returned %d, want %d (including returned stake)", bal, expected)
	}
}
