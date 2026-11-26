package core

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

func TestRepresentativesAllowlistCaseInsensitive(t *testing.T) {
	repA := "a2673b1cb92518fbcd2c578ef297ce79e90bd1e6e0fca13a50af1485b86f435d"
	repB := "b3673b1cb92518fbcd2c578ef297ce79e90bd1e6e0fca13a50af1485b86f435d"
	upperB := strings.ToUpper(repB)

	l := &Ledger{
		delegation: map[string]string{},
		weights: map[string]*big.Int{
			repA: big.NewInt(1000),
			repB: big.NewInt(1000),
		},
	}

	// 1. Partial uppercase allowlist: repB configured with uppercase should match lowercase weight
	l.SetRepresentativeConfigFn(func() *RepresentativeConfig {
		return &RepresentativeConfig{Mode: RepModeAllowlist, Addresses: []string{repA, upperB}}
	})

	if !l.RepEligibilityRestricted() {
		t.Fatalf("expected allowlist to be restricted")
	}
	if w := l.GetVoteWeight(repB); w.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("expected repB weight 1000 regardless of case in allowlist, got %s", w)
	}
	if total := l.GetTotalDelegatedWeight(); total.Cmp(big.NewInt(2000)) != 0 {
		t.Fatalf("expected total delegated weight 2000, got %s", total)
	}

	// 3. Uppercase weight key: allowlist with lowercase address should match and not fail-open
	lUpperWeights := &Ledger{
		delegation: map[string]string{},
		weights: map[string]*big.Int{
			strings.ToUpper(repA): big.NewInt(1500),
		},
	}
	lUpperWeights.SetRepresentativeConfigFn(func() *RepresentativeConfig {
		return &RepresentativeConfig{Mode: RepModeAllowlist, Addresses: []string{repA}}
	})
	if !lUpperWeights.RepEligibilityRestricted() {
		t.Fatalf("expected allowlist to be restricted when weight key is uppercase")
	}
	if lUpperWeights.RepEligibilityFailedOpen() {
		t.Fatalf("expected RepEligibilityFailedOpen() to be false when weight key is uppercase")
	}
	if w := lUpperWeights.GetVoteWeight(repA); w.Cmp(big.NewInt(1500)) != 0 {
		t.Fatalf("expected repA weight 1500, got %s", w)
	}
	if w := lUpperWeights.GetVoteWeight(strings.ToUpper(repA)); w.Cmp(big.NewInt(1500)) != 0 {
		t.Fatalf("expected uppercase repA weight 1500, got %s", w)
	}
	if inelig := lUpperWeights.GetIneligibleWeight(); inelig.Sign() != 0 {
		t.Fatalf("expected ineligible weight 0, got %s", inelig)
	}
	if total := lUpperWeights.GetTotalDelegatedWeight(); total.Cmp(big.NewInt(1500)) != 0 {
		t.Fatalf("expected total delegated weight 1500, got %s", total)
	}
}

type mockGenesisStore struct {
	chains map[string]*AccountChain
}

func (m *mockGenesisStore) GetBlock(hash string) (*Block, error)               { return nil, nil }
func (m *mockGenesisStore) PutBlock(block *Block) error                         { return nil }
func (m *mockGenesisStore) GetAccountChain(account string) (*AccountChain, error) {
	if m.chains == nil {
		return nil, nil
	}
	return m.chains[account], nil
}
func (m *mockGenesisStore) PutAccountChain(account string, chain *AccountChain) error {
	if m.chains == nil {
		m.chains = make(map[string]*AccountChain)
	}
	m.chains[account] = chain
	return nil
}
func (m *mockGenesisStore) GetPendingSend(sendHash string) (*PendingSend, error) { return nil, nil }
func (m *mockGenesisStore) PutPendingSend(ps *PendingSend) error                 { return nil }
func (m *mockGenesisStore) DeletePendingSend(sendHash string) error              { return nil }
func (m *mockGenesisStore) GetPendingByDest(account string) ([]*PendingSend, error) {
	return nil, nil
}
func (m *mockGenesisStore) GetAllPending() ([]*PendingSend, error) { return nil, nil }
func (m *mockGenesisStore) PutFrontier(account string, blockHash string) error {
	return nil
}
func (m *mockGenesisStore) GetFrontier(account string) (string, error) { return "", nil }
func (m *mockGenesisStore) CommitUndo(u *BlockUndo) error             { return nil }
func (m *mockGenesisStore) IsEmpty() (bool, error)                    { return len(m.chains) == 0, nil }
func (m *mockGenesisStore) Close() error                              { return nil }
func (m *mockGenesisStore) CommitBlock(c *BlockCommit) error {
	if m.chains == nil {
		m.chains = make(map[string]*AccountChain)
	}
	m.chains[c.Account] = c.Chain
	return nil
}
func (m *mockGenesisStore) CommitCascade(undos []*BlockUndo, commit *BlockCommit) error {
	return nil
}

func TestNewLedgerGenesisUppercaseRepresentative(t *testing.T) {
	raw := EmbeddedGenesisJSON()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal genesis: %v", err)
	}

	origRep, ok := doc["representative"].(string)
	if !ok || origRep == "" {
		t.Fatalf("invalid embedded genesis representative")
	}

	// Set representative to uppercase in genesis document
	doc["representative"] = strings.ToUpper(origRep)
	customJSON, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal custom genesis: %v", err)
	}

	if err := SetGenesisJSON(customJSON); err != nil {
		t.Fatalf("SetGenesisJSON with uppercase representative failed: %v", err)
	}
	defer ClearGenesisOverride()

	store := &mockGenesisStore{}
	l := NewLedger(store, LedgerConfig{})

	// Verify that NewLedger normalized the representative in l.weights to lowercase
	l.delegationMu.RLock()
	lowerRep := strings.ToLower(origRep)
	upperRep := strings.ToUpper(origRep)
	wLower := l.weights[lowerRep]
	wUpper := l.weights[upperRep]
	l.delegationMu.RUnlock()

	if wLower == nil || wLower.Sign() <= 0 {
		t.Fatalf("expected l.weights[%s] to have positive delegated weight, got %v", lowerRep, wLower)
	}
	if wUpper != nil && lowerRep != upperRep {
		t.Fatalf("expected l.weights[%s] to be nil after normalization, but had %v", upperRep, wUpper)
	}

	// Configure allowlist specifying the representative in lowercase
	l.SetRepresentativeConfigFn(func() *RepresentativeConfig {
		return &RepresentativeConfig{
			Mode:      RepModeAllowlist,
			Addresses: []string{lowerRep},
		}
	})

	if !l.RepEligibilityRestricted() {
		t.Fatalf("expected allowlist to be restricted")
	}
	if l.RepEligibilityFailedOpen() {
		t.Fatalf("expected RepEligibilityFailedOpen() to be false, but failed open")
	}
	if w := l.GetVoteWeight(lowerRep); w.Sign() <= 0 {
		t.Fatalf("expected positive vote weight for %s, got %s", lowerRep, w)
	}
	if w := l.GetVoteWeight(upperRep); w.Sign() <= 0 {
		t.Fatalf("expected positive vote weight when queried with uppercase %s, got %s", upperRep, w)
	}

	// Configure allowlist specifying the representative in uppercase
	l.SetRepresentativeConfigFn(func() *RepresentativeConfig {
		return &RepresentativeConfig{
			Mode:      RepModeAllowlist,
			Addresses: []string{upperRep},
		}
	})

	if !l.RepEligibilityRestricted() {
		t.Fatalf("expected allowlist to remain restricted with uppercase address")
	}
	if l.RepEligibilityFailedOpen() {
		t.Fatalf("expected RepEligibilityFailedOpen() to be false with uppercase address, but failed open")
	}
	if w := l.GetVoteWeight(lowerRep); w.Sign() <= 0 {
		t.Fatalf("expected positive vote weight for %s, got %s", lowerRep, w)
	}
	if w := l.GetVoteWeight(upperRep); w.Sign() <= 0 {
		t.Fatalf("expected positive vote weight when queried with uppercase %s, got %s", upperRep, w)
	}
}

func TestNewLedgerGenesisUppercasePubKeyPreservesHash(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	repKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair rep: %v", err)
	}
	upperPub := strings.ToUpper(kp.PubKeyHex())
	upperRep := strings.ToUpper(repKP.Address())
	lowerRep := strings.ToLower(upperRep)

	b := Block{
		Type:           BlockGenesis,
		Account:        kp.Address(),
		Previous:       "0",
		Balance:        GenesisSupply,
		Asset:          "XE",
		Representative: upperRep,
		PubKey:         upperPub,
		Timestamp:      0,
	}

	savedID := GetNetworkID()
	SetNetworkID("")
	h, err := HashBlock(&b)
	if err != nil {
		SetNetworkID(savedID)
		t.Fatalf("HashBlock: %v", err)
	}
	b.Hash = h
	hashBytes, err := DecodeHash(h)
	if err != nil {
		SetNetworkID(savedID)
		t.Fatalf("DecodeHash: %v", err)
	}
	b.Signature = hex.EncodeToString(ed25519.Sign(kp.Private, hashBytes))
	SetNetworkID(savedID)

	customJSON, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal custom genesis: %v", err)
	}
	if err := SetGenesisJSON(customJSON); err != nil {
		t.Fatalf("SetGenesisJSON failed: %v", err)
	}
	defer ClearGenesisOverride()

	store := &mockGenesisStore{}
	l := NewLedger(store, LedgerConfig{})

	chain := store.chains[b.Account]
	if chain == nil || len(chain.Blocks) == 0 {
		t.Fatalf("expected persisted genesis block in store")
	}
	stored := chain.Blocks[0]
	if stored.PubKey != upperPub {
		t.Fatalf("expected persisted genesis PubKey %q to preserve case, got %q", upperPub, stored.PubKey)
	}

	SetNetworkID("")
	errVerify := VerifyBlock(stored)
	recomputedHash, errHash := HashBlock(stored)
	SetNetworkID(savedID)
	if errHash != nil {
		t.Fatalf("HashBlock(stored): %v", errHash)
	}
	if recomputedHash != stored.Hash {
		t.Fatalf("persisted genesis hash mismatch after normalization: got %s, want %s", recomputedHash, stored.Hash)
	}
	if errVerify != nil {
		t.Fatalf("VerifyBlock(stored) failed: %v", errVerify)
	}

	l.SetRepresentativeConfigFn(func() *RepresentativeConfig {
		return &RepresentativeConfig{
			Mode:      RepModeAllowlist,
			Addresses: []string{upperRep},
		}
	})
	if l.RepEligibilityFailedOpen() {
		t.Fatalf("expected RepEligibilityFailedOpen() to be false")
	}
	if w := l.GetVoteWeight(lowerRep); w.Sign() <= 0 {
		t.Fatalf("expected positive vote weight for %s, got %s", lowerRep, w)
	}
}
