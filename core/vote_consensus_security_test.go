package core

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type testVoteConflictStore struct {
	*testFullStore
}

type testFullStore struct {
	blocks      map[string]*Block
	chains      map[string]*AccountChain
	frontiers   map[string]string
	pending     map[string]*PendingSend
	leases      map[string]*Lease
	delegations map[string]string
	conflicts   map[string]*Conflict
	staged      map[string]*Block
	votes       map[string]*Vote
	status      map[string]BlockStatus
	finalHeight map[string]uint64
	finalVotes  map[string]string
	keysets     map[string]*Keyset
	accountKeys map[string]string
}

func newTestFullStore() *testFullStore {
	return &testFullStore{
		blocks:      make(map[string]*Block),
		chains:      make(map[string]*AccountChain),
		frontiers:   make(map[string]string),
		pending:     make(map[string]*PendingSend),
		leases:      make(map[string]*Lease),
		delegations: make(map[string]string),
		conflicts:   make(map[string]*Conflict),
		staged:      make(map[string]*Block),
		votes:       make(map[string]*Vote),
		status:      make(map[string]BlockStatus),
		finalHeight: make(map[string]uint64),
		finalVotes:  make(map[string]string),
		keysets:     make(map[string]*Keyset),
		accountKeys: make(map[string]string),
	}
}

func (s *testFullStore) PutBlock(b *Block) error {
	cp := *b
	s.blocks[b.Hash] = &cp
	return nil
}
func (s *testFullStore) GetBlock(hash string) (*Block, error) {
	b, ok := s.blocks[strings.ToLower(hash)]
	if !ok {
		b, ok = s.blocks[hash]
	}
	if !ok {
		return nil, nil
	}
	cp := *b
	return &cp, nil
}
func (s *testFullStore) GetAccountChain(account string) (*AccountChain, error) {
	ch, ok := s.chains[account]
	if !ok || ch == nil {
		return nil, nil
	}
	out := &AccountChain{Blocks: make([]*Block, len(ch.Blocks))}
	for i, b := range ch.Blocks {
		cp := *b
		out.Blocks[i] = &cp
	}
	return out, nil
}
func (s *testFullStore) PutAccountChain(account string, chain *AccountChain) error {
	out := &AccountChain{Blocks: make([]*Block, len(chain.Blocks))}
	for i, b := range chain.Blocks {
		cp := *b
		out.Blocks[i] = &cp
	}
	s.chains[account] = out
	return nil
}
func (s *testFullStore) PutPendingSend(ps *PendingSend) error {
	cp := *ps
	s.pending[ps.SendHash] = &cp
	return nil
}
func (s *testFullStore) GetPendingSend(sendHash string) (*PendingSend, error) {
	ps, ok := s.pending[sendHash]
	if !ok {
		return nil, nil
	}
	cp := *ps
	return &cp, nil
}
func (s *testFullStore) DeletePendingSend(sendHash string) error {
	delete(s.pending, sendHash)
	return nil
}
func (s *testFullStore) GetPendingByDest(dest string) ([]*PendingSend, error) {
	var out []*PendingSend
	for _, ps := range s.pending {
		if ps.Destination == dest {
			cp := *ps
			out = append(out, &cp)
		}
	}
	return out, nil
}
func (s *testFullStore) GetAllPending() ([]*PendingSend, error) {
	var out []*PendingSend
	for _, ps := range s.pending {
		cp := *ps
		out = append(out, &cp)
	}
	return out, nil
}
func (s *testFullStore) PutFrontier(account, blockHash string) error {
	s.frontiers[account] = blockHash
	return nil
}
func (s *testFullStore) GetFrontier(account string) (string, error) {
	return s.frontiers[account], nil
}
func (s *testFullStore) AllFrontiers() map[string]string {
	out := make(map[string]string, len(s.frontiers))
	for k, v := range s.frontiers {
		out[k] = v
	}
	return out
}
func (s *testFullStore) IsEmpty() (bool, error) { return len(s.blocks) == 0, nil }
func (s *testFullStore) Close() error           { return nil }

func (s *testFullStore) CommitBlock(c *BlockCommit) error {
	_ = s.PutBlock(c.Block)
	_ = s.PutAccountChain(c.Account, c.Chain)
	_ = s.PutFrontier(c.Account, c.FrontierHash)
	if c.AddPending != nil {
		_ = s.PutPendingSend(c.AddPending)
	}
	if c.TopUpPendingID != "" {
		if ps, ok := s.pending[c.TopUpPendingID]; ok {
			ps.Amount += c.TopUpPendingAmount
		}
	}
	if c.DeletePendingID != "" {
		delete(s.pending, c.DeletePendingID)
	}
	if c.DeleteDelegation {
		delete(s.delegations, c.Account)
	} else if c.DelegationRep != "" {
		s.delegations[c.Account] = c.DelegationRep
	}
	if c.PutLease != nil {
		cp := *c.PutLease
		s.leases[cp.LeaseHash] = &cp
	}
	if c.SettleLeaseHash != "" {
		if l, ok := s.leases[c.SettleLeaseHash]; ok {
			l.Settled = true
			l.State = LeaseSettled
		}
	}
	if c.CancelLeaseHash != "" {
		if l, ok := s.leases[c.CancelLeaseHash]; ok {
			l.State = LeaseCancelled
		}
	}
	if c.UnfulfillLeaseHash != "" {
		if l, ok := s.leases[c.UnfulfillLeaseHash]; ok {
			l.State = LeaseUnfulfilled
		}
	}
	if c.PutKeyset != nil {
		s.keysets[c.Account] = c.PutKeyset
	}
	if c.PutAccountKey != "" {
		s.accountKeys[c.Account] = c.PutAccountKey
	}
	return nil
}

func (s *testFullStore) CommitUndo(u *BlockUndo) error {
	if u.DeleteAccount {
		delete(s.chains, u.Account)
		delete(s.frontiers, u.Account)
	} else {
		_ = s.PutAccountChain(u.Account, u.Chain)
		s.frontiers[u.Account] = u.FrontierHash
	}
	if u.ReducePendingID != "" {
		if ps, ok := s.pending[u.ReducePendingID]; ok {
			ps.Amount -= u.ReducePendingAmount
		}
	}
	if u.DeletePendingID != "" {
		delete(s.pending, u.DeletePendingID)
	}
	if u.AddPending != nil {
		_ = s.PutPendingSend(u.AddPending)
	}
	if u.RejectHash != "" {
		s.status[strings.ToLower(u.RejectHash)] = StatusRejected
	}
	if u.RestoreDelegation {
		if u.PrevRep == "" {
			delete(s.delegations, u.Account)
		} else {
			s.delegations[u.Account] = u.PrevRep
		}
	}
	if u.RestoreLease != nil {
		cp := *u.RestoreLease
		s.leases[cp.LeaseHash] = &cp
	}
	if u.DeleteLeaseHash != "" {
		delete(s.leases, u.DeleteLeaseHash)
	}
	if u.DeleteKeysetAccount != "" {
		delete(s.keysets, u.DeleteKeysetAccount)
	}
	if u.DeleteAccountKeyAccount != "" {
		delete(s.accountKeys, u.DeleteAccountKeyAccount)
	}
	return nil
}

func (s *testFullStore) CommitCascade(undos []*BlockUndo, winner *BlockCommit) error {
	for _, u := range undos {
		if err := s.CommitUndo(u); err != nil {
			return err
		}
	}
	if winner != nil {
		return s.CommitBlock(winner)
	}
	return nil
}

func (s *testFullStore) PutLease(l *Lease) error {
	cp := *l
	s.leases[l.LeaseHash] = &cp
	return nil
}
func (s *testFullStore) GetLease(hash string) (*Lease, error) {
	l, ok := s.leases[hash]
	if !ok {
		return nil, nil
	}
	cp := *l
	return &cp, nil
}
func (s *testFullStore) SettleLease(hash string) error {
	if l, ok := s.leases[hash]; ok {
		l.Settled = true
		l.State = LeaseSettled
	}
	return nil
}
func (s *testFullStore) CancelLease(hash string) error {
	if l, ok := s.leases[hash]; ok {
		l.State = LeaseCancelled
	}
	return nil
}
func (s *testFullStore) UnfulfillLease(hash string) error {
	if l, ok := s.leases[hash]; ok {
		l.State = LeaseUnfulfilled
	}
	return nil
}
func (s *testFullStore) ExpireLease(hash string) error {
	if l, ok := s.leases[hash]; ok {
		l.State = LeaseExpired
	}
	return nil
}
func (s *testFullStore) DeleteLease(hash string) error {
	delete(s.leases, hash)
	return nil
}
func (s *testFullStore) GetLeasesByProvider(provider string) ([]*Lease, error) { return nil, nil }
func (s *testFullStore) GetLeasesByState(state LeaseState) ([]*Lease, error)   { return nil, nil }
func (s *testFullStore) GetAllLeases() ([]*Lease, error)                       { return nil, nil }

func (s *testFullStore) SaveConflict(c *Conflict) error {
	cp := *c
	cp.BlockHashes = append([]string(nil), c.BlockHashes...)
	s.conflicts[c.AccountAddress+"|"+c.PreviousHash] = &cp
	return nil
}
func (s *testFullStore) GetConflict(account, previousHash string) (*Conflict, error) {
	c, ok := s.conflicts[account+"|"+previousHash]
	if !ok {
		return nil, nil
	}
	cp := *c
	cp.BlockHashes = append([]string(nil), c.BlockHashes...)
	return &cp, nil
}
func (s *testFullStore) DeleteConflict(account, previousHash string) error {
	delete(s.conflicts, account+"|"+previousHash)
	return nil
}
func (s *testFullStore) GetConflictsForAccount(account string) ([]*Conflict, error) {
	var out []*Conflict
	prefix := account + "|"
	for k, c := range s.conflicts {
		if strings.HasPrefix(k, prefix) {
			cp := *c
			out = append(out, &cp)
		}
	}
	return out, nil
}
func (s *testFullStore) GetAllConflicts() ([]*Conflict, error) {
	var out []*Conflict
	for _, c := range s.conflicts {
		cp := *c
		out = append(out, &cp)
	}
	return out, nil
}
func (s *testFullStore) SaveStagedBlock(b *Block) error {
	cp := *b
	s.staged[b.Hash] = &cp
	return nil
}
func (s *testFullStore) GetStagedBlock(hash string) (*Block, error) {
	b, ok := s.staged[strings.ToLower(hash)]
	if !ok {
		b, ok = s.staged[hash]
	}
	if !ok {
		return nil, nil
	}
	cp := *b
	return &cp, nil
}
func (s *testFullStore) DeleteStagedBlock(hash string) error {
	delete(s.staged, strings.ToLower(hash))
	delete(s.staged, hash)
	return nil
}

func (s *testFullStore) PutVote(v *Vote) error {
	cp := *v
	s.votes[v.ConflictAccount+"|"+v.ConflictPrev+"|"+v.RepPubKey] = &cp
	return nil
}
func (s *testFullStore) GetVotesByConflict(account, previous string) ([]*Vote, error) {
	var out []*Vote
	prefix := account + "|" + previous + "|"
	for k, v := range s.votes {
		if strings.HasPrefix(k, prefix) {
			cp := *v
			out = append(out, &cp)
		}
	}
	return out, nil
}
func (s *testFullStore) HasVoted(account, previous, repPubKey string) (bool, error) {
	_, ok := s.votes[account+"|"+previous+"|"+repPubKey]
	return ok, nil
}
func (s *testFullStore) GetVote(account, previous, repPubKey string) (*Vote, error) {
	v, ok := s.votes[account+"|"+previous+"|"+repPubKey]
	if !ok {
		return nil, nil
	}
	cp := *v
	return &cp, nil
}
func (s *testFullStore) SetBlockStatus(hash string, status BlockStatus) error {
	s.status[strings.ToLower(hash)] = status
	return nil
}
func (s *testFullStore) GetBlockStatus(hash string) (BlockStatus, error) {
	st, ok := s.status[strings.ToLower(hash)]
	if !ok {
		return StatusPending, nil
	}
	return st, nil
}
func (s *testFullStore) SetFinalHeight(account string, height uint64) error {
	s.finalHeight[account] = height
	return nil
}
func (s *testFullStore) GetFinalHeight(account string) (uint64, error) {
	return s.finalHeight[account], nil
}
func (s *testFullStore) DeleteVotesForConflict(account, previous string) error {
	prefix := account + "|" + previous + "|"
	for k := range s.votes {
		if strings.HasPrefix(k, prefix) {
			delete(s.votes, k)
		}
	}
	return nil
}
func (s *testFullStore) GetFinalVote(account, previous string) (string, bool, error) {
	h, ok := s.finalVotes[account+"|"+previous]
	return h, ok, nil
}
func (s *testFullStore) PutFinalVoteIfAbsent(account, previous, hash string) (string, bool, error) {
	k := account + "|" + previous
	if existing, ok := s.finalVotes[k]; ok {
		return existing, false, nil
	}
	s.finalVotes[k] = hash
	return hash, true, nil
}
func (s *testFullStore) IterateDelegations(fn func(account, representative string) error) error {
	for a, r := range s.delegations {
		if err := fn(a, r); err != nil {
			return err
		}
	}
	return nil
}

func makeTestGenesis(t *testing.T, kp *KeyPair) *Block {
	t.Helper()
	b := &Block{
		Type:           BlockGenesis,
		Account:        kp.Address(),
		Previous:       "0",
		Balance:        GenesisSupply,
		Timestamp:      0,
		Asset:          "XE",
		Representative: kp.Address(),
		PubKey:         kp.PubKeyHex(),
	}
	savedID := GetNetworkID()
	SetNetworkID("")
	if err := SignBlock(b, kp); err != nil {
		SetNetworkID(savedID)
		t.Fatal(err)
	}
	SetNetworkID(savedID)
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := SetGenesisJSON(raw); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ClearGenesisOverride)
	return b
}

func setupTestLedgerWithRep(t *testing.T) (*Ledger, *testFullStore, *KeyPair, *KeyPair) {
	t.Helper()
	genKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	repKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	genBlock := makeTestGenesis(t, genKP)

	st := newTestFullStore()
	ledger := NewLedger(st, LedgerConfig{})

	// Delegate genesis supply to repKP
	send := &Block{
		Type:           BlockSend,
		Account:        genKP.Address(),
		Previous:       genBlock.Hash,
		Balance:        GenesisSupply - 1000,
		Amount:         1000,
		Destination:    repKP.Address(),
		Representative: repKP.Address(),
		Asset:          "XE",
		Timestamp:      Now().UnixNano(),
	}
	if err := SignBlock(send, genKP); err != nil {
		t.Fatal(err)
	}
	if err := ledger.AddBlock(send); err != nil {
		t.Fatal(err)
	}
	return ledger, st, genKP, repKP
}

func TestVoteCanonicalHexRejectsCaseVariantQuorumForgery(t *testing.T) {
	ledger, st, genKP, repKP := setupTestLedgerWithRep(t)
	rep2KP, _ := GenerateKeyPair()

	// Create a second representative with 90% weight so repKP only has ~10% weight
	chain := ledger.GetChain(genKP.Address())
	tip := chain[len(chain)-1]
	ninetyPct := (GenesisSupply - 1000) * 9 / 10
	sendToRep2 := &Block{
		Type:           BlockSend,
		Account:        genKP.Address(),
		Previous:       tip.Hash,
		Balance:        tip.Balance - ninetyPct,
		Amount:         ninetyPct,
		Destination:    rep2KP.Address(),
		Representative: repKP.Address(),
		Asset:          "XE",
		Timestamp:      Now().UnixNano(),
	}
	if err := SignBlock(sendToRep2, genKP); err != nil {
		t.Fatal(err)
	}
	if err := ledger.AddBlock(sendToRep2); err != nil {
		t.Fatal(err)
	}
	recvRep2 := &Block{
		Type:           BlockReceive,
		Account:        rep2KP.Address(),
		Previous:       "0",
		Balance:        ninetyPct,
		Source:         sendToRep2.Hash,
		Representative: rep2KP.Address(),
		Asset:          "XE",
		Timestamp:      Now().UnixNano(),
	}
	if err := SignBlock(recvRep2, rep2KP); err != nil {
		t.Fatal(err)
	}
	if err := ledger.AddBlock(recvRep2); err != nil {
		t.Fatal(err)
	}

	// Create a conflict on genKP's chain
	b1 := &Block{
		Type:        BlockSend,
		Account:     genKP.Address(),
		Previous:    sendToRep2.Hash,
		Balance:     sendToRep2.Balance - 100,
		Amount:      100,
		Destination: repKP.Address(),
		Asset:       "XE",
		Timestamp:   Now().UnixNano(),
	}
	b2 := &Block{
		Type:        BlockSend,
		Account:     genKP.Address(),
		Previous:    sendToRep2.Hash,
		Balance:     sendToRep2.Balance - 200,
		Amount:      200,
		Destination: repKP.Address(),
		Asset:       "XE",
		Timestamp:   Now().UnixNano() + 1,
	}
	_ = SignBlock(b1, genKP)
	_ = SignBlock(b2, genKP)
	if err := ledger.AddBlock(b1); err != nil {
		t.Fatal(err)
	}
	if err := ledger.AddBlock(b2); err != nil {
		t.Fatal(err)
	}

	vm := NewVoteManager(st, repKP, ledger)
	qm := NewQuorumManager(st, st, st, ledger)
	vm.SetQuorumManager(qm)

	// Sign a valid Final vote from repKP (who only holds ~10% of total weight)
	validVote := vm.buildVote(genKP.Address(), sendToRep2.Hash, b2.Hash, true)
	if validVote == nil {
		t.Fatal("expected valid signed vote")
	}

	// Mutate RepPubKey, BlockHash, ConflictAccount, ConflictPrev to uppercase:
	// VerifyVoteSignature and ValidateVote MUST reject all non-canonical hex permutations!
	upperRepVote := *validVote
	upperRepVote.RepPubKey = strings.ToUpper(validVote.RepPubKey)
	if upperRepVote.RepPubKey == validVote.RepPubKey {
		upperRepVote.RepPubKey = "A" + validVote.RepPubKey[1:]
	}
	if VerifyVoteSignature(&upperRepVote) {
		t.Fatal("VerifyVoteSignature accepted non-canonical uppercase RepPubKey")
	}
	if err := vm.ValidateVote(&upperRepVote); err == nil {
		t.Fatal("ValidateVote accepted non-canonical uppercase RepPubKey")
	}

	upperBlockVote := *validVote
	upperBlockVote.BlockHash = strings.ToUpper(validVote.BlockHash)
	if upperBlockVote.BlockHash == validVote.BlockHash {
		upperBlockVote.BlockHash = "A" + validVote.BlockHash[1:]
	}
	if VerifyVoteSignature(&upperBlockVote) {
		t.Fatal("VerifyVoteSignature accepted non-canonical uppercase BlockHash")
	}
	if err := vm.ReceiveVote(&upperBlockVote); err == nil {
		t.Fatal("ReceiveVote accepted non-canonical uppercase BlockHash")
	}

	// Defense-in-depth: even if 10 case-variant votes from 10%-weight repKP are injected directly into store,
	// finalTally must deduplicate by RepAccount() and NOT reach 67% quorum!
	for i := 0; i < 10; i++ {
		mut := *validVote
		mut.RepPubKey = strings.ToUpper(validVote.RepPubKey[:i+1]) + validVote.RepPubKey[i+1:]
		mut.Weight = ledger.GetVoteWeight(repKP.Address()).Uint64()
		_ = st.PutVote(&mut)
	}
	res, err := qm.finalTally(genKP.Address(), sendToRep2.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if res != nil {
		t.Fatalf("expected nil quorum result from 10%% rep case-variant votes, got winner %s", res.WinnerHash)
	}
}

func TestReceiveVoteRejectsStaleNonFinalVoteReplay(t *testing.T) {
	ledger, st, genKP, repKP := setupTestLedgerWithRep(t)
	chain := ledger.GetChain(genKP.Address())
	tip := chain[len(chain)-1]

	b1 := &Block{
		Type:        BlockSend,
		Account:     genKP.Address(),
		Previous:    tip.Hash,
		Balance:     tip.Balance - 100,
		Amount:      100,
		Destination: repKP.Address(),
		Asset:       "XE",
		Timestamp:   Now().UnixNano(),
	}
	b2 := &Block{
		Type:        BlockSend,
		Account:     genKP.Address(),
		Previous:    tip.Hash,
		Balance:     tip.Balance - 200,
		Amount:      200,
		Destination: repKP.Address(),
		Asset:       "XE",
		Timestamp:   Now().UnixNano() + 1,
	}
	_ = SignBlock(b1, genKP)
	_ = SignBlock(b2, genKP)
	_ = ledger.AddBlock(b1)
	_ = ledger.AddBlock(b2)

	vm := NewVoteManager(st, repKP, ledger)
	now := Now().UnixNano()

	olderVote := &Vote{
		RepPubKey:       repKP.PubKeyHex(),
		BlockHash:       b1.Hash,
		ConflictAccount: genKP.Address(),
		ConflictPrev:    tip.Hash,
		Timestamp:       now - 1000,
		Final:           false,
	}
	sb1, _ := voteSigningBytes(olderVote)
	olderVote.Signature = ed25519.Sign(repKP.Private, sb1)

	newerVote := &Vote{
		RepPubKey:       repKP.PubKeyHex(),
		BlockHash:       b2.Hash,
		ConflictAccount: genKP.Address(),
		ConflictPrev:    tip.Hash,
		Timestamp:       now,
		Final:           false,
	}
	sb2, _ := voteSigningBytes(newerVote)
	newerVote.Signature = ed25519.Sign(repKP.Private, sb2)

	if err := vm.receiveVoteInner(newerVote); err != nil {
		t.Fatal(err)
	}
	// Replaying the older non-final vote must NOT overwrite newerVote
	if err := vm.receiveVoteInner(olderVote); err != nil {
		t.Fatal(err)
	}
	stored, err := st.GetVote(genKP.Address(), tip.Hash, repKP.PubKeyHex())
	if err != nil || stored == nil {
		t.Fatal("expected stored vote")
	}
	if stored.BlockHash != b2.Hash {
		t.Fatalf("stale non-final vote overwrote newer vote: got %s, want %s", stored.BlockHash, b2.Hash)
	}
}

func TestCompetingReceiveAndLeaseCancelConflictStagingAndSwap(t *testing.T) {
	ledger, st, genKP, repKP := setupTestLedgerWithRep(t)
	chain := ledger.GetChain(genKP.Address())
	sendHash := chain[len(chain)-1].Hash

	// Two competing BlockReceive blocks on repKP consuming the same sendHash
	recv1 := &Block{
		Type:           BlockReceive,
		Account:        repKP.Address(),
		Previous:       "0",
		Balance:        1000,
		Source:         sendHash,
		Representative: repKP.Address(),
		Asset:          "XE",
		Timestamp:      Now().UnixNano(),
	}
	recv2 := &Block{
		Type:           BlockReceive,
		Account:        repKP.Address(),
		Previous:       "0",
		Balance:        1000,
		Source:         sendHash,
		Representative: genKP.Address(),
		Asset:          "XE",
		Timestamp:      Now().UnixNano() + 1,
	}
	_ = SignBlock(recv1, repKP)
	_ = SignBlock(recv2, repKP)

	if err := ledger.AddBlock(recv1); err != nil {
		t.Fatal(err)
	}
	// Competing recv2 consuming the same sendHash must be staged as a conflict, NOT rejected!
	if err := ledger.AddBlock(recv2); err != nil {
		t.Fatalf("competing BlockReceive rejected instead of staged: %v", err)
	}
	conflict := ledger.GetConflict(repKP.Address(), "0")
	if conflict == nil || len(conflict.BlockHashes) != 2 {
		t.Fatalf("expected conflict with 2 candidates, got %+v", conflict)
	}

	// Wrong asset on staged receive must be rejected by ValidateStagedBlock
	badAssetRecv := *recv2
	badAssetRecv.Asset = "XUSD"
	if err := ledger.ValidateStagedBlock(&badAssetRecv, 0); err == nil {
		t.Fatal("expected ValidateStagedBlock to reject mismatched asset on BlockReceive")
	}

	// Promoting recv2 via SwapBlock must succeed and decrement/increment blockCount accurately
	countBefore := ledger.BlockCount()
	if err := ledger.SwapBlock(repKP.Address(), recv1.Hash, recv2.Hash, recv2); err != nil {
		t.Fatalf("SwapBlock failed for competing BlockReceive: %v", err)
	}
	if ledger.BlockCount() != countBefore {
		t.Fatalf("BlockCount drifted across SwapBlock: got %d, want %d", ledger.BlockCount(), countBefore)
	}
	_ = st
}

func TestSwapBlockUnwindsAcceptedLeaseAndRestoresProviderStake(t *testing.T) {
	genKP, _ := GenerateKeyPair()
	providerKP, _ := GenerateKeyPair()
	tk1, _ := GenerateKeyPair()
	tk2, _ := GenerateKeyPair()

	genBlock := makeTestGenesis(t, genKP)

	certHash := strings.Repeat("ab", 32)
	st := newTestFullStore()
	ledger := NewLedger(st, LedgerConfig{
		MinterConfigFn: func() *MinterConfig {
			return &MinterConfig{Keys: []string{genKP.Address()}}
		},
		TimekeeperConfigFn: func() *TimekeeperConfig {
			return &TimekeeperConfig{Keys: []string{tk1.PubKeyHex(), tk2.PubKeyHex()}, Threshold: 2}
		},
		CertificateLookupFn: func(hash string) *CertificateInfo {
			if hash == certHash {
				return &CertificateInfo{
					Provider:             providerKP.Address(),
					ExpiresAt:            Now().Add(24 * time.Hour).UnixNano(),
					PriceMultiplierMilli: 1000,
				}
			}
			return nil
		},
	})

	// Mint XUSD to genKP and send XUSD to providerKP so providerKP can stake
	mintAmount := 10_000 * AssetXUSD.UnitsPerToken
	mint := &Block{
		Type:      BlockMint,
		Account:   genKP.Address(),
		Previous:  genBlock.Hash,
		Balance:   mintAmount,
		Amount:    mintAmount,
		Asset:     "XUSD",
		Timestamp: Now().UnixNano(),
	}
	_ = SignBlock(mint, genKP)
	if err := ledger.AddBlock(mint); err != nil {
		t.Fatal(err)
	}

	sendXUSD := &Block{
		Type:        BlockSend,
		Account:     genKP.Address(),
		Previous:    mint.Hash,
		Balance:     mintAmount / 2,
		Amount:      mintAmount / 2,
		Destination: providerKP.Address(),
		Asset:       "XUSD",
		Timestamp:   Now().UnixNano(),
	}
	_ = SignBlock(sendXUSD, genKP)
	if err := ledger.AddBlock(sendXUSD); err != nil {
		t.Fatal(err)
	}
	recvXUSD := &Block{
		Type:           BlockReceive,
		Account:        providerKP.Address(),
		Previous:       "0",
		Balance:        mintAmount / 2,
		Source:         sendXUSD.Hash,
		Representative: genKP.Address(),
		Asset:          "XUSD",
		Timestamp:      Now().UnixNano(),
	}
	_ = SignBlock(recvXUSD, providerKP)
	if err := ledger.AddBlock(recvXUSD); err != nil {
		t.Fatal(err)
	}

	// Consumer creates a lease block (oldBlock) and a competing XUSD send block (newBlock) at the same Previous
	cost, err := LeaseCost(2, 4096, 50, 3600, 1000)
	if err != nil {
		t.Fatal(err)
	}
	leaseBlk := &Block{
		Type:            BlockLease,
		Account:         genKP.Address(),
		Previous:        sendXUSD.Hash,
		Balance:         sendXUSD.Balance - cost,
		Amount:          cost,
		Destination:     providerKP.Address(),
		VCPUs:           2,
		MemoryMB:        4096,
		DiskGB:          50,
		Duration:        3600,
		CertificateHash: certHash,
		Asset:           "XUSD",
		Timestamp:       Now().UnixNano(),
	}
	_ = SignBlock(leaseBlk, genKP)
	if err := ledger.AddBlock(leaseBlk); err != nil {
		t.Fatal(err)
	}

	// Provider accepts the lease
	now := Now().UnixNano()
	att1, _ := SignAttestation(leaseBlk.Hash, now, tk1)
	att2, _ := SignAttestation(leaseBlk.Hash, now, tk2)
	stake := LeaseStake(cost)
	acceptBlk := &Block{
		Type:            BlockLeaseAccept,
		Account:         providerKP.Address(),
		Previous:        recvXUSD.Hash,
		Balance:         recvXUSD.Balance - stake,
		Amount:          stake,
		Source:          leaseBlk.Hash,
		CertificateHash: certHash,
		LockedR:         RFallback,
		Asset:           "XUSD",
		Timestamp:       now,
		Attestations:    []TimekeeperAttestation{*att1, *att2},
	}
	_ = SignBlock(acceptBlk, providerKP)
	if err := ledger.AddBlock(acceptBlk); err != nil {
		t.Fatal(err)
	}

	// Competing block on consumer replacing leaseBlk
	competingSend := &Block{
		Type:        BlockSend,
		Account:     genKP.Address(),
		Previous:        sendXUSD.Hash,
		Balance:     sendXUSD.Balance - 100,
		Amount:      100,
		Destination: providerKP.Address(),
		Asset:       "XUSD",
		Timestamp:   now + 1,
	}
	_ = SignBlock(competingSend, genKP)

	if err := ledger.SwapBlock(genKP.Address(), leaseBlk.Hash, competingSend.Hash, competingSend); err != nil {
		t.Fatalf("SwapBlock failed to unwind accepted lease: %v", err)
	}

	// Provider's acceptBlk must have been unwound and provider's staked XUSD restored!
	pChain := ledger.GetChain(providerKP.Address())
	if len(pChain) != 1 || pChain[0].Hash != recvXUSD.Hash {
		t.Fatalf("expected provider chain unwound to recvXUSD, got len=%d", len(pChain))
	}
	if got := ledger.getAssetBalance(providerKP.Address(), "XUSD"); got != recvXUSD.Balance {
		t.Fatalf("provider XUSD stake not restored: got %d, want %d", got, recvXUSD.Balance)
	}
}

func TestZeroAddressRepresentativeRejectedAndAllowlistCaseNormalized(t *testing.T) {
	ledger, _, genKP, repKP := setupTestLedgerWithRep(t)
	chain := ledger.GetChain(genKP.Address())
	tip := chain[len(chain)-1]

	// Legitimate block signed with Representative == ""
	legit := &Block{
		Type:           BlockSend,
		Account:        genKP.Address(),
		Previous:       tip.Hash,
		Balance:        tip.Balance - 100,
		Amount:         100,
		Destination:    repKP.Address(),
		Representative: "",
		Asset:          "XE",
		Timestamp:      Now().UnixNano(),
	}
	if err := SignBlock(legit, genKP); err != nil {
		t.Fatal(err)
	}

	// Attacker mutates Representative from "" to ZeroAddress without private key
	mutated := *legit
	mutated.Representative = ZeroAddress
	if err := VerifyBlock(&mutated); err == nil {
		t.Fatal("VerifyBlock accepted ZeroAddress Representative collision")
	}
	if err := ledger.AddBlock(&mutated); err == nil {
		t.Fatal("AddBlock accepted ZeroAddress Representative collision")
	}

	// Verify RepresentativeConfig allowlist normalizes uppercase hex addresses
	upperRepAddr := strings.ToUpper(repKP.Address())
	ledger.SetRepresentativeConfigFn(func() *RepresentativeConfig {
		return &RepresentativeConfig{
			Mode:      RepModeAllowlist,
			Addresses: []string{upperRepAddr},
		}
	})
	if ledger.RepEligibilityFailedOpen() {
		t.Fatal("expected allowlist with uppercase hex address not to fail open")
	}
	if w := ledger.GetVoteWeight(repKP.Address()); w.Sign() <= 0 {
		t.Fatalf("expected positive vote weight for allowlisted rep, got %s", w.String())
	}
}
