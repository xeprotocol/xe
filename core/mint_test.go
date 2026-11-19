package core

import (
	"strings"
	"testing"
)

type mockMintStore struct {
	blocks  map[string]*Block
	chains  map[string]*AccountChain
	pending map[string]*PendingSend
}

func newMockMintStore() *mockMintStore {
	return &mockMintStore{
		blocks:  make(map[string]*Block),
		chains:  make(map[string]*AccountChain),
		pending: make(map[string]*PendingSend),
	}
}

func (m *mockMintStore) GetBlock(hash string) (*Block, error) {
	return m.blocks[hash], nil
}

func (m *mockMintStore) PutBlock(block *Block) error {
	m.blocks[block.Hash] = block
	return nil
}

func (m *mockMintStore) GetAccountChain(account string) (*AccountChain, error) {
	return m.chains[account], nil
}

func (m *mockMintStore) PutAccountChain(account string, chain *AccountChain) error {
	m.chains[account] = chain
	return nil
}

func (m *mockMintStore) GetPendingSend(sendHash string) (*PendingSend, error) {
	return m.pending[sendHash], nil
}

func (m *mockMintStore) PutPendingSend(ps *PendingSend) error {
	m.pending[ps.SendHash] = ps
	return nil
}

func (m *mockMintStore) DeletePendingSend(sendHash string) error {
	delete(m.pending, sendHash)
	return nil
}

func (m *mockMintStore) GetPendingByDest(account string) ([]*PendingSend, error) {
	return nil, nil
}

func (m *mockMintStore) GetAllPending() ([]*PendingSend, error) {
	return nil, nil
}

func (m *mockMintStore) PutFrontier(account string, blockHash string) error {
	return nil
}

func (m *mockMintStore) GetFrontier(account string) (string, error) {
	return "", nil
}

func (m *mockMintStore) CommitUndo(u *BlockUndo) error {
	return nil
}

func (m *mockMintStore) IsEmpty() (bool, error) {
	return len(m.blocks) == 0, nil
}

func (m *mockMintStore) Close() error {
	return nil
}

func (m *mockMintStore) CommitBlock(c *BlockCommit) error {
	if c.Block != nil {
		m.blocks[c.Block.Hash] = c.Block
	}
	if c.Chain != nil {
		m.chains[c.Account] = c.Chain
	}
	return nil
}

func (m *mockMintStore) CommitCascade(undos []*BlockUndo, commit *BlockCommit) error {
	return m.CommitBlock(commit)
}

func TestIsMinter_SupportsAddressAndPublicKey(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	pubKey := kp.PubKeyHex()
	address := kp.Address()

	store := newMockMintStore()

	// 1. Configured with derived address (standard)
	ledgerWithAddr := NewLedger(store, LedgerConfig{
		MinterConfigFn: func() *MinterConfig {
			return &MinterConfig{
				Keys: []string{address},
			}
		},
	})

	if !ledgerWithAddr.isMinter(address) {
		t.Fatalf("expected isMinter(address) to be true when configured with address")
	}
	if !ledgerWithAddr.isMinter(strings.ToUpper(address)) {
		t.Fatalf("expected isMinter to be case-insensitive for address")
	}

	// 2. Configured with public key (fixes issue #379: silent mint lockout)
	ledgerWithPubKey := NewLedger(store, LedgerConfig{
		MinterConfigFn: func() *MinterConfig {
			return &MinterConfig{
				Keys: []string{pubKey},
			}
		},
	})

	if !ledgerWithPubKey.isMinter(address) {
		t.Fatalf("expected isMinter(address) to be true when configured with public key")
	}
	if !ledgerWithPubKey.isMinter(strings.ToUpper(address)) {
		t.Fatalf("expected isMinter to be case-insensitive when configured with public key")
	}
	// Uppercase public key in config
	ledgerWithUpperPubKey := NewLedger(store, LedgerConfig{
		MinterConfigFn: func() *MinterConfig {
			return &MinterConfig{
				Keys: []string{strings.ToUpper(pubKey)},
			}
		},
	})
	if !ledgerWithUpperPubKey.isMinter(address) {
		t.Fatalf("expected isMinter(address) to be true when config contains uppercase public key")
	}

	// 3. Configured with Addresses field
	ledgerWithAddresses := NewLedger(store, LedgerConfig{
		MinterConfigFn: func() *MinterConfig {
			return &MinterConfig{
				Addresses: []string{pubKey},
			}
		},
	})
	if !ledgerWithAddresses.isMinter(address) {
		t.Fatalf("expected isMinter(address) to be true when configured via Addresses field with public key")
	}

	// 4. Unauthorized account
	otherKp, _ := GenerateKeyPair()
	if ledgerWithPubKey.isMinter(otherKp.Address()) {
		t.Fatalf("unauthorized account should not be accepted as minter")
	}

	// 5. Nil config or nil config function
	ledgerNil := NewLedger(store, LedgerConfig{})
	if ledgerNil.isMinter(address) {
		t.Fatalf("isMinter should be false when minterConfigFn is nil")
	}
}

func TestValidateAndAddMint_PubkeyAndAddressMinter(t *testing.T) {
	minterKp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	pubKey := minterKp.PubKeyHex()
	address := minterKp.Address()

	// Test minting when sys.minter is configured with public key
	store := newMockMintStore()
	ledger := NewLedger(store, LedgerConfig{
		MinterConfigFn: func() *MinterConfig {
			return &MinterConfig{
				Keys: []string{pubKey}, // operator configured public key!
			}
		},
	})

	mintAmount := uint64(5000)
	mintBlock := &Block{
		Type:      BlockMint,
		Account:   address,
		Previous:  "0",
		Amount:    mintAmount,
		Balance:   mintAmount,
		Asset:     "XCU",
		Timestamp: 1000,
	}

	err = ledger.validateAndAddMint(mintBlock)
	if err != nil {
		t.Fatalf("expected mint block to succeed when sys.minter configured with public key, got: %v", err)
	}

	// Verify unauthorized minter rejected
	unauthorizedKp, _ := GenerateKeyPair()
	unauthorizedBlock := &Block{
		Type:      BlockMint,
		Account:   unauthorizedKp.Address(),
		Previous:  "0",
		Amount:    mintAmount,
		Balance:   mintAmount,
		Asset:     "XCU",
		Timestamp: 1001,
	}
	err = ledger.validateAndAddMint(unauthorizedBlock)
	if err == nil || !strings.Contains(err.Error(), "not an authorized minter") {
		t.Fatalf("expected unauthorized minter error, got: %v", err)
	}
}
