package core_test

import (
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func setupTestLedger(t *testing.T, window int64) (*core.Ledger, *store.MemStore) {
	t.Helper()
	s := store.NewMemStore()
	l := core.NewLedger(s, core.LedgerConfig{
		Difficulty:      0,
		TimestampWindow: window,
	})
	return l, s
}

func createMintBlock(account string, amount uint64, ts int64, kp *core.KeyPair) *core.Block {
	b := &core.Block{
		Type:      core.BlockMint,
		Account:   account,
		Previous:  "0",
		Amount:    amount,
		Balance:   amount,
		Asset:     "XE",
		Timestamp: ts,
	}
	_ = core.SignBlock(b, kp)
	return b
}

func createSendBlock(account, prev string, amount, balance uint64, dest string, ts int64, kp *core.KeyPair) *core.Block {
	b := &core.Block{
		Type:        core.BlockSend,
		Account:     account,
		Previous:    prev,
		Amount:      amount,
		Balance:     balance,
		Asset:       "XE",
		Destination: dest,
		Timestamp:   ts,
	}
	_ = core.SignBlock(b, kp)
	return b
}

func createReceiveBlock(account, prev string, amount, balance uint64, source string, ts int64, kp *core.KeyPair) *core.Block {
	b := &core.Block{
		Type:      core.BlockReceive,
		Account:   account,
		Previous:  prev,
		Amount:    amount,
		Balance:   balance,
		Asset:     "XE",
		Source:    source,
		Timestamp: ts,
	}
	_ = core.SignBlock(b, kp)
	return b
}

func TestReceiveBlockTimestampSkewValidation(t *testing.T) {
	l, _ := setupTestLedger(t, core.DefaultTimestampWindow)

	senderKp, _ := core.GenerateKeyPair()
	receiverKp, _ := core.GenerateKeyPair()
	senderAddr := senderKp.Address()
	receiverAddr := receiverKp.Address()

	now := core.Now().UnixNano()

	// Seed sender
	mint := createMintBlock(senderAddr, 10_000_000, now, senderKp)
	if err := l.SeedAssetForTesting(mint); err != nil {
		t.Fatalf("SeedAssetForTesting: %v", err)
	}

	// Legitimate send at now
	send1 := createSendBlock(senderAddr, mint.Hash, 1_000_000, 9_000_000, receiverAddr, now, senderKp)
	if err := l.AddBlock(send1); err != nil {
		t.Fatalf("AddBlock(send1): %v", err)
	}

	// 1. Receive block with future timestamp beyond skew window (+28h) must be rejected
	futureTs := core.Now().Add(28 * time.Hour).UnixNano()
	recvFuture := createReceiveBlock(receiverAddr, "0", 1_000_000, 1_000_000, send1.Hash, futureTs, receiverKp)
	err := l.AddBlock(recvFuture)
	if err == nil {
		t.Fatalf("expected receive block with +28h timestamp to be rejected, got nil")
	}
	if !strings.Contains(err.Error(), "timestamp out of range") {
		t.Errorf("expected 'timestamp out of range' error, got: %v", err)
	}

	// 2. Receive block with past timestamp beyond skew window (-25h) must be rejected
	pastTs := core.Now().Add(-25 * time.Hour).UnixNano()
	recvPast := createReceiveBlock(receiverAddr, "0", 1_000_000, 1_000_000, send1.Hash, pastTs, receiverKp)
	err = l.AddBlock(recvPast)
	if err == nil {
		t.Fatalf("expected receive block with -25h timestamp to be rejected, got nil")
	}
	if !strings.Contains(err.Error(), "timestamp out of range") {
		t.Errorf("expected 'timestamp out of range' error, got: %v", err)
	}

	// 3. Receive block with negative timestamp must be rejected
	recvNeg := createReceiveBlock(receiverAddr, "0", 1_000_000, 1_000_000, send1.Hash, -1, receiverKp)
	err = l.AddBlock(recvNeg)
	if err == nil {
		t.Fatalf("expected receive block with negative timestamp to be rejected, got nil")
	}
	if !strings.Contains(err.Error(), "must not be negative") {
		t.Errorf("expected 'must not be negative' error, got: %v", err)
	}

	// 4. Valid receive block at current time must succeed
	recvValid := createReceiveBlock(receiverAddr, "0", 1_000_000, 1_000_000, send1.Hash, now, receiverKp)
	if err := l.AddBlock(recvValid); err != nil {
		t.Fatalf("expected valid receive block to succeed, got: %v", err)
	}
}

func TestReceiveBlockTimestampBeforeSourceSend(t *testing.T) {
	// Ledger with disabled window to specifically isolate the causal check
	l, _ := setupTestLedger(t, -1)

	senderKp, _ := core.GenerateKeyPair()
	receiverKp, _ := core.GenerateKeyPair()
	senderAddr := senderKp.Address()
	receiverAddr := receiverKp.Address()

	baseTime := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC).UnixNano()

	// Seed sender
	mint := createMintBlock(senderAddr, 10_000_000, baseTime, senderKp)
	if err := l.SeedAssetForTesting(mint); err != nil {
		t.Fatalf("SeedAssetForTesting: %v", err)
	}

	// Send at baseTime + 1 hour
	sendTime := baseTime + int64(time.Hour)
	send := createSendBlock(senderAddr, mint.Hash, 1_000_000, 9_000_000, receiverAddr, sendTime, senderKp)
	if err := l.AddBlock(send); err != nil {
		t.Fatalf("AddBlock(send): %v", err)
	}

	// Open receive with timestamp before sendTime (e.g. sendTime - 10 minutes) must be rejected
	recvBeforeSend := createReceiveBlock(receiverAddr, "0", 1_000_000, 1_000_000, send.Hash, sendTime-int64(10*time.Minute), receiverKp)
	err := l.AddBlock(recvBeforeSend)
	if err == nil {
		t.Fatalf("expected receive block timestamp before send timestamp to be rejected, got nil")
	}
	if !strings.Contains(err.Error(), "before source send timestamp") {
		t.Errorf("expected 'before source send timestamp' error, got: %v", err)
	}

	// Valid receive at sendTime + 1 minute succeeds
	recvValid := createReceiveBlock(receiverAddr, "0", 1_000_000, 1_000_000, send.Hash, sendTime+int64(time.Minute), receiverKp)
	if err := l.AddBlock(recvValid); err != nil {
		t.Fatalf("AddBlock(recvValid): %v", err)
	}

	// Second send at sendTime + 2 hours
	send2Time := sendTime + int64(2*time.Hour)
	send2 := createSendBlock(senderAddr, send.Hash, 1_000_000, 8_000_000, receiverAddr, send2Time, senderKp)
	if err := l.AddBlock(send2); err != nil {
		t.Fatalf("AddBlock(send2): %v", err)
	}

	// Second receive on existing chain with timestamp before send2Time must be rejected
	recv2BeforeSend := createReceiveBlock(receiverAddr, recvValid.Hash, 1_000_000, 2_000_000, send2.Hash, send2Time-int64(5*time.Minute), receiverKp)
	err = l.AddBlock(recv2BeforeSend)
	if err == nil {
		t.Fatalf("expected receive block on existing chain before send timestamp to be rejected, got nil")
	}
	if !strings.Contains(err.Error(), "before source send timestamp") {
		t.Errorf("expected 'before source send timestamp' error, got: %v", err)
	}
}

func TestValidateStagedBlockReceiveTimestamp(t *testing.T) {
	l, s := setupTestLedger(t, -1)

	senderKp, _ := core.GenerateKeyPair()
	receiverKp, _ := core.GenerateKeyPair()
	senderAddr := senderKp.Address()
	receiverAddr := receiverKp.Address()

	baseTime := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC).UnixNano()
	mint := createMintBlock(senderAddr, 10_000_000, baseTime, senderKp)
	if err := l.SeedAssetForTesting(mint); err != nil {
		t.Fatalf("SeedAssetForTesting: %v", err)
	}

	sendTime := baseTime + int64(time.Hour)
	send := createSendBlock(senderAddr, mint.Hash, 1_000_000, 9_000_000, receiverAddr, sendTime, senderKp)
	if err := l.AddBlock(send); err != nil {
		t.Fatalf("AddBlock(send): %v", err)
	}

	_ = s
	// Staged receive block before sendTime must be rejected by ValidateStagedBlock
	recvBeforeSend := createReceiveBlock(receiverAddr, "0", 1_000_000, 1_000_000, send.Hash, sendTime-int64(10*time.Minute), receiverKp)
	err := l.ValidateStagedBlock(recvBeforeSend, 0)
	if err == nil {
		t.Fatalf("expected ValidateStagedBlock to reject receive before send timestamp, got nil")
	}
	if !strings.Contains(err.Error(), "before source send timestamp") {
		t.Errorf("expected 'before source send timestamp' error, got: %v", err)
	}
}

func TestNewLedgerDefaultTimestampWindow(t *testing.T) {
	// When TimestampWindow is 0 in config, NewLedger must default to DefaultTimestampWindow
	s := store.NewMemStore()
	l := core.NewLedger(s, core.LedgerConfig{
		Difficulty:      0,
		TimestampWindow: 0,
	})

	senderKp, _ := core.GenerateKeyPair()
	receiverKp, _ := core.GenerateKeyPair()
	senderAddr := senderKp.Address()
	receiverAddr := receiverKp.Address()

	now := core.Now().UnixNano()
	mint := createMintBlock(senderAddr, 10_000_000, now, senderKp)
	if err := l.SeedAssetForTesting(mint); err != nil {
		t.Fatalf("SeedAssetForTesting: %v", err)
	}

	send := createSendBlock(senderAddr, mint.Hash, 1_000_000, 9_000_000, receiverAddr, now, senderKp)
	if err := l.AddBlock(send); err != nil {
		t.Fatalf("AddBlock(send): %v", err)
	}

	// +28h receive block must be rejected even though TimestampWindow was 0 in config
	futureTs := core.Now().Add(28 * time.Hour).UnixNano()
	recvFuture := createReceiveBlock(receiverAddr, "0", 1_000_000, 1_000_000, send.Hash, futureTs, receiverKp)
	err := l.AddBlock(recvFuture)
	if err == nil {
		t.Fatalf("expected receive block with +28h to be rejected with default window, got nil")
	}
	if !strings.Contains(err.Error(), "timestamp out of range") {
		t.Errorf("expected 'timestamp out of range' error, got: %v", err)
	}

	// +28h send block must also be rejected
	sendFuture := createSendBlock(senderAddr, send.Hash, 1_000_000, 8_000_000, receiverAddr, futureTs, senderKp)
	err = l.AddBlock(sendFuture)
	if err == nil {
		t.Fatalf("expected send block with +28h to be rejected with default window, got nil")
	}
	if !strings.Contains(err.Error(), "timestamp out of range") {
		t.Errorf("expected 'timestamp out of range' error, got: %v", err)
	}
}
