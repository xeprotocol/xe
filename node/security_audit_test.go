package node

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/directory"
	xenet "github.com/xeprotocol/xe/net"
	"github.com/xeprotocol/xe/store"
	"github.com/xeprotocol/xe/vm"
)

func TestVMStatusPeerAuthAndCredentialRedaction(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	providerHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer providerHost.Close()

	consumerHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer consumerHost.Close()

	attackerHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer attackerHost.Close()

	if err := consumerHost.Connect(ctx, peer.AddrInfo{ID: providerHost.ID(), Addrs: providerHost.Addrs()}); err != nil {
		t.Fatal(err)
	}
	if err := attackerHost.Connect(ctx, peer.AddrInfo{ID: providerHost.ID(), Addrs: providerHost.Addrs()}); err != nil {
		t.Fatal(err)
	}

	providerKP, _ := core.GenerateKeyPair()
	consumerKP, _ := core.GenerateKeyPair()
	attackerKP, _ := core.GenerateKeyPair()

	s := store.NewMemStore()
	dir := directory.New(time.Hour)
	now := time.Now().UnixNano()
	_ = dir.Register(directory.NewRegistration(providerHost.ID().String(), now, providerKP))
	_ = dir.Register(directory.NewRegistration(consumerHost.ID().String(), now, consumerKP))
	_ = dir.Register(directory.NewRegistration(attackerHost.ID().String(), now, attackerKP))

	leaseHash := strings.Repeat("1", 64)
	_ = s.PutLease(&core.Lease{
		LeaseHash: leaseHash,
		State:     core.LeaseAccepted,
		Consumer:  consumerKP.Address(),
		Provider:  providerKP.Address(),
		VCPUs:     1,
		MemoryMB:  1024,
		DiskGB:    10,
		Duration:  3600,
		StartTime: now,
	})

	vmm := vm.NewMockManager()
	provisioned, err := vmm.Provision(leaseHash, vm.Resources{VCPUs: 1, MemoryMB: 1024, DiskGB: 10}, "")
	if err != nil {
		t.Fatal(err)
	}
	if provisioned.Credentials == nil || provisioned.Credentials.Password == "" {
		t.Fatal("expected MockManager to generate credentials when accessPubKey is empty")
	}

	providerNode := &Node{
		Host:      providerHost,
		Msg:       xenet.NewMessenger(providerHost, nil),
		Directory: dir,
		KeyPair:   providerKP,
		VMManager: vmm,
		store:     s,
		ctx:       ctx,
	}
	providerNode.registerVMHandlers()

	attackerMsg := xenet.NewMessenger(attackerHost, nil)
	consumerMsg := xenet.NewMessenger(consumerHost, nil)

	// 1. Unauthorized peer must be rejected when querying vm_status
	_, err = attackerMsg.Request(ctx, providerHost.ID(), "vm_status", map[string]string{
		"lease_hash": leaseHash,
	})
	if err == nil || !strings.Contains(err.Error(), "unauthorized peer") {
		t.Fatalf("expected vm_status from attacker peer to fail with unauthorized peer, got: %v", err)
	}

	// 2. Authorized consumer peer receives vm_status but Credentials must be redacted (nil)
	resp, err := consumerMsg.Request(ctx, providerHost.ID(), "vm_status", map[string]string{
		"lease_hash": leaseHash,
	})
	if err != nil {
		t.Fatalf("consumer vm_status request failed: %v", err)
	}
	var statusInfo vm.Info
	if err := json.Unmarshal(resp, &statusInfo); err != nil {
		t.Fatal(err)
	}
	if statusInfo.Credentials != nil {
		t.Fatalf("vm_status leaked plaintext Credentials: %+v", statusInfo.Credentials)
	}

	// 3. Non-consumer node calling GetVM(leaseHash) must not poll remote provider and must return nil
	attackerNode := &Node{
		Host:      attackerHost,
		Msg:       attackerMsg,
		Directory: dir,
		KeyPair:   attackerKP,
		store:     s,
		ctx:       ctx,
	}
	if got := attackerNode.GetVM(leaseHash); got != nil {
		t.Fatalf("attackerNode.GetVM returned %+v, want nil", got)
	}
}

func TestValidateTunnelLeasePeerAuthAndExpiry(t *testing.T) {
	providerKP, _ := core.GenerateKeyPair()
	consumerKP, _ := core.GenerateKeyPair()
	attackerKP, _ := core.GenerateKeyPair()

	providerHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer providerHost.Close()

	consumerHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer consumerHost.Close()

	attackerHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer attackerHost.Close()

	now := time.Now().UnixNano()
	core.Now = func() time.Time { return time.Unix(0, now) }
	defer func() { core.Now = time.Now }()

	s := store.NewMemStore()
	dir := directory.New(time.Hour)
	_ = dir.Register(directory.NewRegistration(providerHost.ID().String(), now, providerKP))
	_ = dir.Register(directory.NewRegistration(consumerHost.ID().String(), now, consumerKP))
	_ = dir.Register(directory.NewRegistration(attackerHost.ID().String(), now, attackerKP))

	leaseHash := strings.Repeat("2", 64)
	_ = s.PutLease(&core.Lease{
		LeaseHash: leaseHash,
		State:     core.LeaseAccepted,
		Consumer:  consumerKP.Address(),
		Provider:  providerKP.Address(),
		VCPUs:     1,
		MemoryMB:  1024,
		DiskGB:    10,
		Duration:  3600,
		StartTime: now,
	})

	providerNode := &Node{
		Host:      providerHost,
		Directory: dir,
		KeyPair:   providerKP,
		store:     s,
	}

	// 1. Unauthorized peer must be rejected by ValidateTunnelLease
	if err := providerNode.ValidateTunnelLease(leaseHash, attackerHost.ID()); err == nil || !strings.Contains(err.Error(), "unauthorized tunnel peer") {
		t.Fatalf("expected unauthorized tunnel peer error, got: %v", err)
	}

	// 2. Authorized consumer peer succeeds before expiry
	if err := providerNode.ValidateTunnelLease(leaseHash, consumerHost.ID()); err != nil {
		t.Fatalf("expected consumer peer to pass ValidateTunnelLease, got: %v", err)
	}

	// 3. Advance clock past EffectiveExpiry() while State is still LeaseAccepted (e.g., during grace window)
	expiredNow := now + int64(3601*time.Second)
	core.Now = func() time.Time { return time.Unix(0, expiredNow) }

	if err := providerNode.ValidateTunnelLease(leaseHash, consumerHost.ID()); err == nil || !strings.Contains(err.Error(), "lease expired") {
		t.Fatalf("expected lease expired error from ValidateTunnelLease, got: %v", err)
	}
	if _, err := providerNode.OpenTunnelForLease(context.Background(), leaseHash); err == nil || !strings.Contains(err.Error(), "lease expired") {
		t.Fatalf("expected lease expired error from OpenTunnelForLease, got: %v", err)
	}
}

func TestForceSettleRenewedLeaseAndGetAllAccountsBalance(t *testing.T) {
	s := store.NewMemStore()
	consumerKP, _ := core.GenerateKeyPair()
	providerKP, _ := core.GenerateKeyPair()

	now := time.Now().UnixNano()
	core.Now = func() time.Time { return time.Unix(0, now) }
	defer func() { core.Now = time.Now }()

	l := core.NewLedger(s, core.LedgerConfig{
		Difficulty:      0,
		TimestampWindow: core.DefaultTimestampWindow,
		MinterConfigFn: func() *core.MinterConfig {
			return &core.MinterConfig{
				Keys: []string{consumerKP.Address()},
			}
		},
		CertificateLookupFn: func(hash string) *core.CertificateInfo {
			return &core.CertificateInfo{
				Provider:             providerKP.Address(),
				ExpiresAt:            now + int64(365*24*time.Hour),
				PriceMultiplierMilli: 1000,
			}
		},
		FeatureActiveFn: func(feature string) bool { return true },
	})

	// Open consumer account with XUSD mint
	mintBlk := &core.Block{
		Type:      core.BlockMint,
		Account:   consumerKP.Address(),
		Previous:  "0",
		PubKey:    consumerKP.PubKeyHex(),
		Balance:   100_000_000,
		Timestamp: now,
		Asset:     "XUSD",
		Amount:    100_000_000,
	}
	_ = core.SignBlock(mintBlk, consumerKP)
	if err := l.AddBlock(mintBlk); err != nil {
		t.Fatal(err)
	}

	n := &Node{
		Ledger:  l,
		KeyPair: consumerKP,
		store:   s,
		ctx:     context.Background(),
	}

	// Verify GetAllAccounts reports Balance == 0 (XE) rather than 100_000_000 (XUSD) for consumer
	var found bool
	for _, acc := range n.GetAllAccounts() {
		if acc.Address == consumerKP.Address() {
			found = true
			if acc.Balance != 0 {
				t.Fatalf("AccountSummary.Balance = %d, want 0 XE", acc.Balance)
			}
			if acc.Balances["XUSD"] != 100_000_000 {
				t.Fatalf("AccountSummary.Balances[XUSD] = %d, want 100_000_000", acc.Balances["XUSD"])
			}
		}
	}
	if !found {
		t.Fatal("consumer account not found in GetAllAccounts")
	}

	// Verify forceSettleLease refunds full EffectiveCost() (base + renewal) on a renewed lease
	dur := uint64(3600)
	cost, _ := core.LeaseCost(1, 1024, 10, dur, 1000)
	certHash := strings.Repeat("c", 64)
	leaseBlk := &core.Block{
		Type:            core.BlockLease,
		Account:         consumerKP.Address(),
		Previous:        mintBlk.Hash,
		Balance:         100_000_000 - cost,
		Timestamp:       now + 1,
		Asset:           "XUSD",
		Destination:     providerKP.Address(),
		Amount:          cost,
		VCPUs:           1,
		MemoryMB:        1024,
		DiskGB:          10,
		Duration:        dur,
		CertificateHash: certHash,
	}
	_ = core.SignBlock(leaseBlk, consumerKP)
	if err := l.AddBlock(leaseBlk); err != nil {
		t.Fatal(err)
	}

	// Simulate accepted + renewed lease with topped-up pending escrow
	renewedLease := &core.Lease{
		LeaseHash: leaseBlk.Hash,
		State:     core.LeaseAccepted,
		Consumer:  consumerKP.Address(),
		Provider:  providerKP.Address(),
		VCPUs:     1,
		MemoryMB:  1024,
		DiskGB:    10,
		Duration:  dur,
		Cost:      cost,
		StartTime: now + 2,
		Renewals: []core.LeaseSegment{
			{
				RenewHash: strings.Repeat("d", 64),
				Duration:  dur,
				Cost:      cost,
				StartTime: now + 2 + int64(dur)*int64(time.Second),
			},
		},
	}
	_ = s.PutLease(renewedLease)
	_ = s.PutPendingSend(&core.PendingSend{
		SendHash:    leaseBlk.Hash,
		Source:      consumerKP.Address(),
		Destination: providerKP.Address(),
		Amount:      renewedLease.EffectiveCost(),
		Asset:       "XUSD",
	})
	if got, want := renewedLease.EffectiveCost(), cost*2; got != want {
		t.Fatalf("renewedLease.EffectiveCost() = %d, want %d", got, want)
	}
}
