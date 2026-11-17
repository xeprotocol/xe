package node

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/xeprotocol/xe/core"
	xenet "github.com/xeprotocol/xe/net"
	"github.com/xeprotocol/xe/perf"
	"github.com/xeprotocol/xe/store"
)

func newTestGossipWithFailingPublish(t *testing.T, ledger *core.Ledger) (*xenet.Gossip, *xenet.SyncTracker, context.Context, func()) {
	t.Helper()
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("failed to create libp2p host: %v", err)
	}

	gossip, err := xenet.NewGossip(context.Background(), h)
	if err != nil {
		h.Close()
		t.Fatalf("failed to create gossip: %v", err)
	}

	st, _ := xenet.SetupSync(context.Background(), h, ledger)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled context guarantees publish failure

	cleanup := func() {
		h.Close()
	}
	return gossip, st, ctx, cleanup
}

func TestSend_GossipPublishFailureDoesNotFail(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	destKp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate dest key pair: %v", err)
	}

	ms := store.NewMemStore()
	ledger := core.NewLedger(ms, core.LedgerConfig{})

	gossip, st, ctx, cleanup := newTestGossipWithFailingPublish(t, ledger)
	defer cleanup()

	// Seed XE balance for sender
	mintBlock := &core.Block{
		Type:      core.BlockMint,
		Account:   kp.Address(),
		Previous:  "0",
		Balance:   1_000_000,
		Amount:    1_000_000,
		Asset:     "XE",
		Timestamp: core.Now().UnixNano(),
	}
	if err := core.SignBlock(mintBlock, kp); err != nil {
		t.Fatalf("sign mint block: %v", err)
	}
	if err := ledger.SeedAssetForTesting(mintBlock); err != nil {
		t.Fatalf("seed mint block: %v", err)
	}

	node := &Node{
		KeyPair:     kp,
		Ledger:      ledger,
		Gossip:      gossip,
		syncTracker: st,
		ctx:         ctx,
	}

	sendAmount := uint64(200_000)
	err = node.Send(destKp.Address(), sendAmount, "XE")
	if err != nil {
		t.Fatalf("Send failed unexpectedly on gossip publish error: %v", err)
	}

	// Verify block committed locally
	bal := ledger.GetBalance(kp.Address())
	if bal != 800_000 {
		t.Fatalf("expected remaining balance 800000, got %d", bal)
	}

	// Verify frontier updated
	chain := ledger.GetChain(kp.Address())
	if len(chain) == 0 || chain[len(chain)-1].Type != core.BlockSend {
		t.Fatalf("expected last block to be send block, got %v", chain)
	}
}

func TestReceive_GossipPublishFailureDoesNotFail(t *testing.T) {
	senderKp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate sender key pair: %v", err)
	}
	receiverKp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate receiver key pair: %v", err)
	}

	ms := store.NewMemStore()
	ledger := core.NewLedger(ms, core.LedgerConfig{})

	// Seed XE balance for sender
	mintBlock := &core.Block{
		Type:      core.BlockMint,
		Account:   senderKp.Address(),
		Previous:  "0",
		Balance:   1_000_000,
		Amount:    1_000_000,
		Asset:     "XE",
		Timestamp: core.Now().UnixNano(),
	}
	if err := core.SignBlock(mintBlock, senderKp); err != nil {
		t.Fatalf("sign mint block: %v", err)
	}
	if err := ledger.SeedAssetForTesting(mintBlock); err != nil {
		t.Fatalf("seed mint block: %v", err)
	}

	// Create a send from sender to receiver
	sendBlock := &core.Block{
		Type:        core.BlockSend,
		Account:     senderKp.Address(),
		Previous:    mintBlock.Hash,
		Balance:     800_000,
		Amount:      200_000,
		Destination: receiverKp.Address(),
		Asset:       "XE",
		Timestamp:   core.Now().UnixNano(),
	}
	if err := core.SignBlock(sendBlock, senderKp); err != nil {
		t.Fatalf("sign send block: %v", err)
	}
	if err := ledger.AddBlock(sendBlock); err != nil {
		t.Fatalf("add send block: %v", err)
	}

	// Receiver node with failing gossip
	gossip, st, ctx, cleanup := newTestGossipWithFailingPublish(t, ledger)
	defer cleanup()

	node := &Node{
		KeyPair:     receiverKp,
		Ledger:      ledger,
		Gossip:      gossip,
		syncTracker: st,
		ctx:         ctx,
	}

	count, err := node.Receive()
	if err != nil {
		t.Fatalf("Receive failed unexpectedly on gossip publish error: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected receive count 1, got %d", count)
	}

	// Verify receive block was committed locally
	chain := ledger.GetChain(receiverKp.Address())
	if len(chain) != 1 || chain[0].Type != core.BlockReceive {
		t.Fatalf("expected receive block committed to chain, got %v", chain)
	}
	bal := ledger.GetBalance(receiverKp.Address())
	if bal != 200_000 {
		t.Fatalf("expected receiver balance 200000, got %d", bal)
	}

	// Verify pending send was cleared
	pending := ledger.GetPendingForAccount(receiverKp.Address())
	if len(pending) != 0 {
		t.Fatalf("expected 0 pending sends after receive, got %d", len(pending))
	}
}

func TestCreateLeaseBlock_GossipPublishFailureDoesNotFail(t *testing.T) {
	consumerKp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate consumer key pair: %v", err)
	}
	providerKp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate provider key pair: %v", err)
	}

	certHash := "1111111111111111111111111111111111111111111111111111111111111111"
	cert := &perf.Certificate{
		Hash:                 certHash,
		Provider:             providerKp.Address(),
		PriceMultiplierMilli: 1000,
		ExpiresAt:            core.Now().UnixNano() + int64(24*time.Hour),
	}

	ms := store.NewMemStore()
	ledger := core.NewLedger(ms, core.LedgerConfig{
		CertificateLookupFn: func(h string) *core.CertificateInfo {
			if h == certHash {
				return &core.CertificateInfo{
					Provider:             providerKp.Address(),
					ExpiresAt:            cert.ExpiresAt,
					PriceMultiplierMilli: cert.PriceMultiplierMilli,
				}
			}
			return nil
		},
	})

	// Seed XUSD balance for consumer
	mintBlock := &core.Block{
		Type:      core.BlockMint,
		Account:   consumerKp.Address(),
		Previous:  "0",
		Balance:   1_000_000,
		Amount:    1_000_000,
		Asset:     "XUSD",
		Timestamp: core.Now().UnixNano(),
	}
	if err := core.SignBlock(mintBlock, consumerKp); err != nil {
		t.Fatalf("sign mint block: %v", err)
	}
	if err := ledger.SeedAssetForTesting(mintBlock); err != nil {
		t.Fatalf("seed mint block: %v", err)
	}

	gossip, st, ctx, cleanup := newTestGossipWithFailingPublish(t, ledger)
	defer cleanup()

	node := &Node{
		KeyPair:     consumerKp,
		Ledger:      ledger,
		Gossip:      gossip,
		syncTracker: st,
		ctx:         ctx,
	}

	cost := uint64(40_000)
	accessKey := "0000000000000000000000000000000000000000000000000000000000000001"
	err = node.CreateLeaseBlock(providerKp.Address(), 1, 1024, 10, 3600, cost, accessKey, certHash)
	if err != nil {
		t.Fatalf("CreateLeaseBlock failed unexpectedly on gossip publish error: %v", err)
	}

	// Verify lease block was committed
	chain := ledger.GetChain(consumerKp.Address())
	if len(chain) != 2 || chain[1].Type != core.BlockLease {
		t.Fatalf("expected lease block committed to chain, got %v", chain)
	}

	// Verify XUSD balance debited
	xusdBal := ledger.GetAssetBalances(consumerKp.Address())["XUSD"]
	if xusdBal != 1_000_000-cost {
		t.Fatalf("expected XUSD balance %d, got %d", 1_000_000-cost, xusdBal)
	}
}

func TestRenewLease_GossipPublishFailureDoesNotFail(t *testing.T) {
	consumerKp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate consumer key pair: %v", err)
	}
	providerKp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate provider key pair: %v", err)
	}

	certHash := "2222222222222222222222222222222222222222222222222222222222222222"
	now := core.Now().UnixNano()
	cert := &perf.Certificate{
		Hash:                 certHash,
		Provider:             providerKp.Address(),
		PriceMultiplierMilli: 1000,
		IssuedAt:             now - int64(time.Hour),
		ExpiresAt:            now + int64(24*time.Hour),
	}

	tkKp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate tk key pair: %v", err)
	}
	tkConfig := &core.TimekeeperConfig{
		Threshold: 1,
		Keys:      []string{tkKp.PubKeyHex()},
	}

	ms := store.NewMemStore()
	ledger := core.NewLedger(ms, core.LedgerConfig{
		CertificateLookupFn: func(h string) *core.CertificateInfo {
			if h == certHash {
				return &core.CertificateInfo{
					Provider:             providerKp.Address(),
					ExpiresAt:            cert.ExpiresAt,
					PriceMultiplierMilli: cert.PriceMultiplierMilli,
				}
			}
			return nil
		},
		TimekeeperConfigFn: func() *core.TimekeeperConfig {
			return tkConfig
		},
	})

	// Seed XUSD balance for consumer
	mintBlock := &core.Block{
		Type:      core.BlockMint,
		Account:   consumerKp.Address(),
		Previous:  "0",
		Balance:   1_000_000,
		Amount:    1_000_000,
		Asset:     "XUSD",
		Timestamp: now - int64(10*time.Minute),
	}
	if err := core.SignBlock(mintBlock, consumerKp); err != nil {
		t.Fatalf("sign mint block: %v", err)
	}
	if err := ledger.SeedAssetForTesting(mintBlock); err != nil {
		t.Fatalf("seed mint block: %v", err)
	}

	leaseHash := "3333333333333333333333333333333333333333333333333333333333333333"
	lease := &core.Lease{
		LeaseHash:            leaseHash,
		Consumer:             consumerKp.Address(),
		Provider:             providerKp.Address(),
		VCPUs:                1,
		MemoryMB:             1024,
		DiskGB:               10,
		Duration:             3600,
		StartTime:            now - int64(5*time.Minute),
		Cost:                 40_000,
		State:                core.LeaseAccepted,
		Settled:              false,
	}
	if err := ms.PutLease(lease); err != nil {
		t.Fatalf("put lease: %v", err)
	}
	if err := ms.PutPendingSend(&core.PendingSend{
		SendHash:    leaseHash,
		Source:      consumerKp.Address(),
		Destination: providerKp.Address(),
		Amount:      40_000,
		Asset:       "XUSD",
	}); err != nil {
		t.Fatalf("put pending send: %v", err)
	}

	gossip, st, ctx, cleanup := newTestGossipWithFailingPublish(t, ledger)
	defer cleanup()

	node := &Node{
		KeyPair:     consumerKp,
		Ledger:      ledger,
		store:       ms,
		Gossip:      gossip,
		syncTracker: st,
		ctx:         ctx,
		acceptAttestHook: func(lh string) ([]core.TimekeeperAttestation, error) {
			att, err := core.SignAttestation(lh, core.Now().UnixNano(), tkKp)
			if err != nil {
				return nil, err
			}
			return []core.TimekeeperAttestation{*att}, nil
		},
	}
	node.certs().put(cert)

	renewBlock, err := node.RenewLease(leaseHash, 3600)
	if err != nil {
		t.Fatalf("RenewLease failed unexpectedly on gossip publish error: %v", err)
	}
	if renewBlock == nil {
		t.Fatalf("expected non-nil renewBlock")
	}

	// Verify renew block was committed
	chain := ledger.GetChain(consumerKp.Address())
	if len(chain) != 2 || chain[1].Type != core.BlockLeaseRenew {
		t.Fatalf("expected lease_renew block committed to chain, got %v", chain)
	}
}

func TestSubmitBlock_GossipPublishFailureDoesNotFail(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	destKp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate dest key pair: %v", err)
	}

	ms := store.NewMemStore()
	ledger := core.NewLedger(ms, core.LedgerConfig{})

	// Seed XE balance for sender
	mintBlock := &core.Block{
		Type:      core.BlockMint,
		Account:   kp.Address(),
		Previous:  "0",
		Balance:   1_000_000,
		Amount:    1_000_000,
		Asset:     "XE",
		Timestamp: core.Now().UnixNano(),
	}
	if err := core.SignBlock(mintBlock, kp); err != nil {
		t.Fatalf("sign mint block: %v", err)
	}
	if err := ledger.SeedAssetForTesting(mintBlock); err != nil {
		t.Fatalf("seed mint block: %v", err)
	}

	gossip, st, ctx, cleanup := newTestGossipWithFailingPublish(t, ledger)
	defer cleanup()

	node := &Node{
		KeyPair:     kp,
		Ledger:      ledger,
		Gossip:      gossip,
		syncTracker: st,
		ctx:         ctx,
	}

	sendBlock := &core.Block{
		Type:        core.BlockSend,
		Account:     kp.Address(),
		Previous:    mintBlock.Hash,
		Balance:     700_000,
		Amount:      300_000,
		Destination: destKp.Address(),
		Asset:       "XE",
		Timestamp:   core.Now().UnixNano(),
	}
	if err := core.SignBlock(sendBlock, kp); err != nil {
		t.Fatalf("sign send block: %v", err)
	}

	err = node.SubmitBlock(sendBlock)
	if err != nil {
		t.Fatalf("SubmitBlock failed unexpectedly on gossip publish error: %v", err)
	}

	bal := ledger.GetBalance(kp.Address())
	if bal != 700_000 {
		t.Fatalf("expected balance 700000, got %d", bal)
	}
}
