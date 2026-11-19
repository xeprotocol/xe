package core_test

import (
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/store"
)

func newTestLedger(ms core.Store, minters ...string) *core.Ledger {
	return core.NewLedger(ms, core.LedgerConfig{
		TimekeeperConfigFn: func() *core.TimekeeperConfig { return &core.TimekeeperConfig{} },
		MinterConfigFn:     func() *core.MinterConfig { return &core.MinterConfig{Keys: minters} },
		FeatureActiveFn:    func(f string) bool { return true },
	})
}

func createFundedAccount(t *testing.T, ledger *core.Ledger, kp *core.KeyPair, balance uint64) {
	t.Helper()
	addr := kp.Address()
	p := &core.Block{
		Type:      core.BlockMint,
		Account:   addr,
		Previous:  "0",
		Balance:   balance,
		Amount:    balance,
		Asset:     "XCU",
		Timestamp: time.Now().UnixNano(),
	}
	if err := core.SignBlock(p, kp); err != nil {
		t.Fatalf("sign mint block: %v", err)
	}
	if err := ledger.AddBlock(p); err != nil {
		t.Fatalf("add mint block failed: %v", err)
	}
}

func sendBlock(t *testing.T, ledger *core.Ledger, mem core.Store, sender *core.KeyPair, dest string, amount uint64, ts int64) *core.Block {
	t.Helper()
	chain, err := mem.GetAccountChain(sender.Address())
	if err != nil || chain == nil || len(chain.Blocks) == 0 {
		t.Fatalf("get sender chain: %v", err)
	}
	frontier := chain.Frontier()
	lastBlock := chain.Blocks[len(chain.Blocks)-1]
	if lastBlock.Balance < amount {
		t.Fatalf("insufficient balance: have %d, want %d", lastBlock.Balance, amount)
	}

	b := &core.Block{
		Type:        core.BlockSend,
		Account:     sender.Address(),
		Previous:    frontier,
		Balance:     lastBlock.Balance - amount,
		Timestamp:   ts,
		Asset:       "XCU",
		Amount:      amount,
		Destination: dest,
	}
	if err := core.SignBlock(b, sender); err != nil {
		t.Fatalf("sign send block: %v", err)
	}
	if err := ledger.AddBlock(b); err != nil {
		t.Fatalf("add send block failed: %v", err)
	}
	return b
}

func receiveBlock(t *testing.T, ledger *core.Ledger, mem core.Store, receiver *core.KeyPair, send *core.Block, ts int64) *core.Block {
	t.Helper()
	chain, err := mem.GetAccountChain(receiver.Address())
	if err != nil {
		t.Fatalf("get receiver chain: %v", err)
	}

	var previous string
	var newBal uint64
	var pubKey string

	if chain == nil || len(chain.Blocks) == 0 {
		previous = "0"
		newBal = send.Amount
		pubKey = receiver.PubKeyHex()
	} else {
		previous = chain.Frontier()
		newBal = chain.Blocks[len(chain.Blocks)-1].Balance + send.Amount
	}

	b := &core.Block{
		Type:      core.BlockReceive,
		Account:   receiver.Address(),
		Previous:  previous,
		Balance:   newBal,
		Timestamp: ts,
		Asset:     send.Asset,
		Amount:    send.Amount,
		Source:    send.Hash,
		PubKey:    pubKey,
	}
	if err := core.SignBlock(b, receiver); err != nil {
		t.Fatalf("sign receive block: %v", err)
	}
	if err := ledger.AddBlock(b); err != nil {
		t.Fatalf("add receive block failed: %v", err)
	}
	return b
}

func TestPendingSend_IsExpiredMethod(t *testing.T) {
	now := time.Now().UnixNano()
	ttl := 10 * time.Minute

	// No timestamp -> never expired
	psNoTs := &core.PendingSend{Amount: 100}
	if psNoTs.IsExpired(now, ttl) {
		t.Errorf("expected ps with no timestamp not to be expired")
	}

	// ttl <= 0 -> never expired
	psValid := &core.PendingSend{Timestamp: now - int64(20*time.Minute)}
	if psValid.IsExpired(now, 0) {
		t.Errorf("expected ps with ttl=0 not to be expired")
	}

	// within TTL -> not expired
	psFresh := &core.PendingSend{Timestamp: now - int64(5*time.Minute)}
	if psFresh.IsExpired(now, ttl) {
		t.Errorf("expected ps within ttl not to be expired")
	}

	// beyond TTL -> expired
	psOld := &core.PendingSend{Timestamp: now - int64(15*time.Minute)}
	if !psOld.IsExpired(now, ttl) {
		t.Errorf("expected ps beyond ttl to be expired")
	}
}

func TestPendingSend_TimestampRecorded(t *testing.T) {
	mem := store.NewMemStore()
	alice, _ := core.GenerateKeyPair()
	bob, _ := core.GenerateKeyPair()
	ledger := newTestLedger(mem, alice.Address())

	createFundedAccount(t, ledger, alice, 1_000_000)

	expectedTs := time.Now().UnixNano()
	sb := sendBlock(t, ledger, mem, alice, bob.Address(), 500, expectedTs)

	pends := ledger.GetPendingForAccount(bob.Address())
	if len(pends) != 1 {
		t.Fatalf("expected 1 pending send for bob, got %d", len(pends))
	}
	if pends[0].SendHash != sb.Hash {
		t.Errorf("hash mismatch: got %s, want %s", pends[0].SendHash, sb.Hash)
	}
	if pends[0].Timestamp != expectedTs {
		t.Errorf("timestamp mismatch: got %d, want %d", pends[0].Timestamp, expectedTs)
	}
}

func TestPendingSend_MaxPendingPerDestination(t *testing.T) {
	origCap := core.MaxPendingPerDestination
	core.MaxPendingPerDestination = 3
	defer func() { core.MaxPendingPerDestination = origCap }()

	mem := store.NewMemStore()
	alice, _ := core.GenerateKeyPair()
	bob, _ := core.GenerateKeyPair()
	carol, _ := core.GenerateKeyPair()
	ledger := newTestLedger(mem, alice.Address())

	createFundedAccount(t, ledger, alice, 10_000_000)

	now := time.Now().UnixNano()
	sb1 := sendBlock(t, ledger, mem, alice, bob.Address(), 100, now+1)
	sendBlock(t, ledger, mem, alice, bob.Address(), 100, now+2)
	sendBlock(t, ledger, mem, alice, bob.Address(), 100, now+3)

	// Bob currently has 3 pending sends (reached cap of 3).
	// Attempting a 4th send to Bob must fail.
	chain, _ := mem.GetAccountChain(alice.Address())
	lastBlock := chain.Blocks[len(chain.Blocks)-1]
	overflowBlock := &core.Block{
		Type:        core.BlockSend,
		Account:     alice.Address(),
		Previous:    chain.Frontier(),
		Balance:     lastBlock.Balance - 100,
		Timestamp:   now + 4,
		Asset:       "XCU",
		Amount:      100,
		Destination: bob.Address(),
	}
	if err := core.SignBlock(overflowBlock, alice); err != nil {
		t.Fatalf("sign overflow block: %v", err)
	}
	err := ledger.AddBlock(overflowBlock)
	if err == nil {
		t.Fatalf("expected 4th send to bob to fail due to destination pending cap")
	}
	if !strings.Contains(err.Error(), "reached pending cap") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// Sending to Carol (a different destination) should succeed
	sendBlock(t, ledger, mem, alice, carol.Address(), 100, now+5)

	// Bob claims 1 pending send (sb1)
	receiveBlock(t, ledger, mem, bob, sb1, now+6)

	// Bob's pending count dropped from 3 to 2; sending to Bob should now succeed
	sendBlock(t, ledger, mem, alice, bob.Address(), 100, now+7)
}

func TestPendingSend_MaxPendingPerAccount(t *testing.T) {
	origCap := core.MaxPendingPerAccount
	core.MaxPendingPerAccount = 3
	defer func() { core.MaxPendingPerAccount = origCap }()

	mem := store.NewMemStore()
	alice, _ := core.GenerateKeyPair()
	bob, _ := core.GenerateKeyPair()

	r1, _ := core.GenerateKeyPair()
	r2, _ := core.GenerateKeyPair()
	r3, _ := core.GenerateKeyPair()
	r4, _ := core.GenerateKeyPair()

	ledger := newTestLedger(mem, alice.Address(), bob.Address())

	createFundedAccount(t, ledger, alice, 10_000_000)
	createFundedAccount(t, ledger, bob, 10_000_000)

	now := time.Now().UnixNano()
	sb1 := sendBlock(t, ledger, mem, alice, r1.Address(), 100, now+1)
	sendBlock(t, ledger, mem, alice, r2.Address(), 100, now+2)
	sendBlock(t, ledger, mem, alice, r3.Address(), 100, now+3)

	// Alice has 3 active uncollected outgoing sends (reached cap of 3).
	// Attempting a 4th send to r4 from Alice must fail.
	chain, _ := mem.GetAccountChain(alice.Address())
	lastBlock := chain.Blocks[len(chain.Blocks)-1]
	overflowBlock := &core.Block{
		Type:        core.BlockSend,
		Account:     alice.Address(),
		Previous:    chain.Frontier(),
		Balance:     lastBlock.Balance - 100,
		Timestamp:   now + 4,
		Asset:       "XCU",
		Amount:      100,
		Destination: r4.Address(),
	}
	if err := core.SignBlock(overflowBlock, alice); err != nil {
		t.Fatalf("sign overflow block: %v", err)
	}
	err := ledger.AddBlock(overflowBlock)
	if err == nil {
		t.Fatalf("expected 4th send from alice to fail due to account pending cap")
	}
	if !strings.Contains(err.Error(), "reached pending cap") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// Bob (different sender) sending to r4 succeeds
	sendBlock(t, ledger, mem, bob, r4.Address(), 100, now+5)

	// r1 receives Alice's send (sb1)
	receiveBlock(t, ledger, mem, r1, sb1, now+6)

	// Alice's uncollected send count is now 2 (< 3); Alice can send again
	sendBlock(t, ledger, mem, alice, r4.Address(), 100, now+7)
}

func TestPendingSend_ExpiryTTL(t *testing.T) {
	origTTL := core.PendingSendTTL
	core.PendingSendTTL = 24 * time.Hour
	defer func() { core.PendingSendTTL = origTTL }()

	mem := store.NewMemStore()
	alice, _ := core.GenerateKeyPair()
	bob, _ := core.GenerateKeyPair()
	ledger := newTestLedger(mem, alice.Address())

	createFundedAccount(t, ledger, alice, 10_000_000)

	t0 := time.Now().UnixNano()
	sb := sendBlock(t, ledger, mem, alice, bob.Address(), 1000, t0)

	// Attempt to receive 48 hours later (> 24h TTL)
	tExpired := t0 + int64(48*time.Hour)
	recBlock := &core.Block{
		Type:      core.BlockReceive,
		Account:   bob.Address(),
		Previous:  "0",
		Balance:   1000,
		Timestamp: tExpired,
		Asset:     "XCU",
		Amount:    1000,
		Source:    sb.Hash,
		PubKey:    bob.PubKeyHex(),
	}
	if err := core.SignBlock(recBlock, bob); err != nil {
		t.Fatalf("sign expired receive block: %v", err)
	}
	err := ledger.AddBlock(recBlock)
	if err == nil {
		t.Fatalf("expected receive after TTL expiry to fail")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// Valid receive within TTL (1 hour later)
	tFresh := t0 + int64(1*time.Hour)
	recBlockFresh := &core.Block{
		Type:      core.BlockReceive,
		Account:   bob.Address(),
		Previous:  "0",
		Balance:   1000,
		Timestamp: tFresh,
		Asset:     "XCU",
		Amount:    1000,
		Source:    sb.Hash,
		PubKey:    bob.PubKeyHex(),
	}
	if err := core.SignBlock(recBlockFresh, bob); err != nil {
		t.Fatalf("sign fresh receive block: %v", err)
	}
	if err := ledger.AddBlock(recBlockFresh); err != nil {
		t.Fatalf("expected receive within TTL to succeed: %v", err)
	}
}

func TestPendingSend_ZeroCapsDisabled(t *testing.T) {
	origAccCap := core.MaxPendingPerAccount
	origDstCap := core.MaxPendingPerDestination
	core.MaxPendingPerAccount = 0
	core.MaxPendingPerDestination = 0
	defer func() {
		core.MaxPendingPerAccount = origAccCap
		core.MaxPendingPerDestination = origDstCap
	}()

	mem := store.NewMemStore()
	alice, _ := core.GenerateKeyPair()
	bob, _ := core.GenerateKeyPair()
	ledger := newTestLedger(mem, alice.Address())

	createFundedAccount(t, ledger, alice, 10_000_000)

	now := time.Now().UnixNano()
	for i := 1; i <= 5; i++ {
		sendBlock(t, ledger, mem, alice, bob.Address(), 10, now+int64(i))
	}

	pends := ledger.GetPendingForAccount(bob.Address())
	if len(pends) != 5 {
		t.Fatalf("expected 5 pending sends, got %d", len(pends))
	}
}

func TestXE06PendingCapEnforced(t *testing.T) {
	// Verifies the exact scenario reported in Issue #384:
	// A single account attempting to create unbounded uncollected dust sends to distinct destinations.
	// With DefaultMaxPendingPerAccount = 100, exactly 100 sends succeed and the 101st is rejected.
	mem := store.NewMemStore()
	alice, _ := core.GenerateKeyPair()
	ledger := newTestLedger(mem, alice.Address())

	createFundedAccount(t, ledger, alice, 10_000_000)

	now := time.Now().UnixNano()
	var firstSend *core.Block
	var firstRecipient *core.KeyPair

	for i := 1; i <= core.DefaultMaxPendingPerAccount; i++ {
		recipient, _ := core.GenerateKeyPair()
		sb := sendBlock(t, ledger, mem, alice, recipient.Address(), 1, now+int64(i))
		if i == 1 {
			firstSend = sb
			firstRecipient = recipient
		}
	}

	// Active uncollected sends for alice is now 100
	alicePending := ledger.GetPendingBySource(alice.Address())
	if len(alicePending) != core.DefaultMaxPendingPerAccount {
		t.Fatalf("expected %d pending sends from alice, got %d", core.DefaultMaxPendingPerAccount, len(alicePending))
	}

	// 101st send to a new distinct destination must be rejected by cap
	r101, _ := core.GenerateKeyPair()
	chain, _ := mem.GetAccountChain(alice.Address())
	lastBlock := chain.Blocks[len(chain.Blocks)-1]
	b101 := &core.Block{
		Type:        core.BlockSend,
		Account:     alice.Address(),
		Previous:    chain.Frontier(),
		Balance:     lastBlock.Balance - 1,
		Timestamp:   now + int64(core.DefaultMaxPendingPerAccount+1),
		Asset:       "XCU",
		Amount:      1,
		Destination: r101.Address(),
	}
	if err := core.SignBlock(b101, alice); err != nil {
		t.Fatalf("sign b101: %v", err)
	}
	err := ledger.AddBlock(b101)
	if err == nil {
		t.Fatalf("expected 101st send to be rejected by MaxPendingPerAccount cap")
	}
	if !strings.Contains(err.Error(), "reached pending cap") {
		t.Fatalf("unexpected error: %v", err)
	}

	// Now recipient 1 claims their 1 micro send
	receiveBlock(t, ledger, mem, firstRecipient, firstSend, now+int64(core.DefaultMaxPendingPerAccount+2))

	// Alice's uncollected count drops to 99; 101st send now succeeds
	chainAfter, _ := mem.GetAccountChain(alice.Address())
	lastBlockAfter := chainAfter.Blocks[len(chainAfter.Blocks)-1]
	b101Retry := &core.Block{
		Type:        core.BlockSend,
		Account:     alice.Address(),
		Previous:    chainAfter.Frontier(),
		Balance:     lastBlockAfter.Balance - 1,
		Timestamp:   now + int64(core.DefaultMaxPendingPerAccount+3),
		Asset:       "XCU",
		Amount:      1,
		Destination: r101.Address(),
	}
	if err := core.SignBlock(b101Retry, alice); err != nil {
		t.Fatalf("sign b101Retry: %v", err)
	}
	if err := ledger.AddBlock(b101Retry); err != nil {
		t.Fatalf("expected retry send to succeed after receive unblocking: %v", err)
	}
}
