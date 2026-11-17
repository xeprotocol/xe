package net

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pubsub_pb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/xeprotocol/xe/core"
)

func createTestBlock(t *testing.T, kp *core.KeyPair) *core.Block {
	t.Helper()
	destKp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair dest failed: %v", err)
	}
	b := &core.Block{
		Type:        core.BlockSend,
		Account:     kp.Address(),
		Previous:    "0",
		Balance:     1000,
		Destination: destKp.Address(),
		Amount:      10,
		Timestamp:   time.Now().Unix(),
		Asset:       "XE",
		PubKey:      kp.PubKeyHex(),
	}
	if err := core.SignBlock(b, kp); err != nil {
		t.Fatalf("SignBlock failed: %v", err)
	}
	return b
}

func createTestMultisigBlock(t *testing.T) *core.Block {
	t.Helper()
	kp1, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair 1 failed: %v", err)
	}
	kp2, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair 2 failed: %v", err)
	}
	ks := &core.Keyset{
		Keys:      []string{kp1.PubKeyHex(), kp2.PubKeyHex()},
		Threshold: 1,
	}
	msAddr, err := core.DeriveMultisigAddress(ks)
	if err != nil {
		t.Fatalf("DeriveMultisigAddress failed: %v", err)
	}
	srcKp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair src failed: %v", err)
	}
	b := &core.Block{
		Type:      core.BlockReceive,
		Account:   msAddr,
		Previous:  "0",
		Balance:   500,
		Source:    srcKp.Address(),
		Timestamp: time.Now().Unix(),
		Asset:     "XE",
	}
	h, err := core.HashBlock(b)
	if err != nil {
		t.Fatalf("HashBlock failed: %v", err)
	}
	b.Hash = h
	hBytes, err := core.DecodeHash(h)
	if err != nil {
		t.Fatalf("DecodeHash failed: %v", err)
	}
	sig := ed25519.Sign(kp1.Private, hBytes)
	b.Signatures = []core.BlockSignature{
		{
			PublicKey: kp1.PubKeyHex(),
			Sig:       hex.EncodeToString(sig),
		},
	}
	b.Signature = ""
	return b
}

func TestGossipMultisigAndSingleSigDelivery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	h1, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("h1 libp2p.New failed: %v", err)
	}
	defer h1.Close()

	h2, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("h2 libp2p.New failed: %v", err)
	}
	defer h2.Close()

	if err := h1.Connect(ctx, peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()}); err != nil {
		t.Fatalf("h1.Connect failed: %v", err)
	}

	g1, err := NewGossip(ctx, h1)
	if err != nil {
		t.Fatalf("NewGossip g1 failed: %v", err)
	}
	g2, err := NewGossip(ctx, h2)
	if err != nil {
		t.Fatalf("NewGossip g2 failed: %v", err)
	}

	time.Sleep(300 * time.Millisecond)

	subCh := g1.Subscribe(ctx)

	// 1. Single-sig delivery
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	singleBlock := createTestBlock(t, kp)
	if err := g2.Publish(ctx, singleBlock); err != nil {
		t.Fatalf("Publish singleBlock failed: %v", err)
	}

	select {
	case recv := <-subCh:
		if recv == nil || recv.Hash != singleBlock.Hash {
			t.Fatalf("expected single-sig block %s, got %v", singleBlock.Hash, recv)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for single-sig block")
	}

	// 2. Multisig delivery (xeprotocol/xe#552)
	msBlock := createTestMultisigBlock(t)
	if err := g2.Publish(ctx, msBlock); err != nil {
		t.Fatalf("Publish msBlock failed: %v", err)
	}

	select {
	case recv := <-subCh:
		if recv == nil || recv.Hash != msBlock.Hash {
			t.Fatalf("expected multisig block %s, got %v", msBlock.Hash, recv)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for multisig block")
	}

	// 3. Signatureless block rejected on intake by validator
	destKp, _ := core.GenerateKeyPair()
	siglessBlock := &core.Block{
		Type:        core.BlockSend,
		Account:     kp.Address(),
		Previous:    "0",
		Balance:     1000,
		Destination: destKp.Address(),
		Amount:      10,
		Timestamp:   time.Now().Unix(),
		Asset:       "XE",
		PubKey:      kp.PubKeyHex(),
	}
	h, err := core.HashBlock(siglessBlock)
	if err != nil {
		t.Fatalf("HashBlock failed: %v", err)
	}
	siglessBlock.Hash = h
	siglessBlock.Signature = ""
	siglessBlock.Signatures = nil

	// Node 2 validator rejects on intake
	if err := g2.Publish(ctx, siglessBlock); err == nil {
		select {
		case recv := <-subCh:
			t.Fatalf("signatureless block should have been rejected, got: %s", recv.Hash)
		case <-time.After(500 * time.Millisecond):
		}
	}

	// 4. Multisig block with malformed signature length rejected
	badSigMsBlock := createTestMultisigBlock(t)
	badSigMsBlock.Signature = "malformed"
	badH, err := core.HashBlock(badSigMsBlock)
	if err != nil {
		t.Fatalf("HashBlock badSigMsBlock failed: %v", err)
	}
	badSigMsBlock.Hash = badH

	// Node 2 validator rejects on intake
	if err := g2.Publish(ctx, badSigMsBlock); err == nil {
		select {
		case recv := <-subCh:
			t.Fatalf("malformed signature block should have been rejected, got: %s", recv.Hash)
		case <-time.After(500 * time.Millisecond):
		}
	}

	// 5. Unvalidated peer sending across wire is rejected by Node 1 blockValidator
	h3, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("h3 libp2p.New failed: %v", err)
	}
	defer h3.Close()
	ps3, err := pubsub.NewGossipSub(ctx, h3)
	if err != nil {
		t.Fatalf("NewGossipSub ps3 failed: %v", err)
	}
	if err := h1.Connect(ctx, peer.AddrInfo{ID: h3.ID(), Addrs: h3.Addrs()}); err != nil {
		t.Fatalf("h1.Connect h3 failed: %v", err)
	}
	t3, err := ps3.Join(BlockTopic)
	if err != nil {
		t.Fatalf("ps3.Join failed: %v", err)
	}
	_, _ = t3.Subscribe()
	time.Sleep(300 * time.Millisecond)

	siglessWireData, _ := json.Marshal(BlockMsg{Block: siglessBlock})
	_ = t3.Publish(ctx, siglessWireData)

	select {
	case recv := <-subCh:
		t.Fatalf("wire signatureless block delivered to subscriber: %s", recv.Hash)
	case <-time.After(500 * time.Millisecond):
		// Expected: rejected by validator and not delivered
	}
}

func TestValidatorUnitRejections(t *testing.T) {
	ctx := context.Background()
	dummyPeer := peer.ID("test-peer")

	bv := blockValidator(GossipConfig{})

	// Valid single-sig block accepts
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	validBlock := createTestBlock(t, kp)
	data, _ := json.Marshal(BlockMsg{Block: validBlock})
	msg := &pubsub.Message{Message: &pubsub_pb.Message{Data: data}}
	if res := bv(ctx, dummyPeer, msg); res != pubsub.ValidationAccept {
		t.Fatalf("expected ValidationAccept for valid single-sig, got %v", res)
	}

	// Valid multisig block accepts
	validMsBlock := createTestMultisigBlock(t)
	data, _ = json.Marshal(BlockMsg{Block: validMsBlock})
	msg = &pubsub.Message{Message: &pubsub_pb.Message{Data: data}}
	if res := bv(ctx, dummyPeer, msg); res != pubsub.ValidationAccept {
		t.Fatalf("expected ValidationAccept for valid multisig, got %v", res)
	}

	// Signatureless block rejects
	siglessBlock := createTestBlock(t, kp)
	siglessBlock.Signature = ""
	siglessBlock.Signatures = nil
	data, _ = json.Marshal(BlockMsg{Block: siglessBlock})
	msg = &pubsub.Message{Message: &pubsub_pb.Message{Data: data}}
	if res := bv(ctx, dummyPeer, msg); res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for signatureless block, got %v", res)
	}

	// Hash-mismatched block rejects (xeprotocol/xe#551)
	mismatchedBlock := createTestBlock(t, kp)
	mismatchedBlock.Hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	data, _ = json.Marshal(BlockMsg{Block: mismatchedBlock})
	msg = &pubsub.Message{Message: &pubsub_pb.Message{Data: data}}
	if res := bv(ctx, dummyPeer, msg); res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for hash-mismatched block, got %v", res)
	}

	// Malformed signature length rejects
	badSigLenBlock := createTestBlock(t, kp)
	badSigLenBlock.Signature = "bad"
	data, _ = json.Marshal(BlockMsg{Block: badSigLenBlock})
	msg = &pubsub.Message{Message: &pubsub_pb.Message{Data: data}}
	if res := bv(ctx, dummyPeer, msg); res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for malformed signature length, got %v", res)
	}

	// Invalid multisig entry length rejects
	badEntryMsBlock := createTestMultisigBlock(t)
	badEntryMsBlock.Signatures[0].Sig = "bad_length_sig"
	data, _ = json.Marshal(BlockMsg{Block: badEntryMsBlock})
	msg = &pubsub.Message{Message: &pubsub_pb.Message{Data: data}}
	if res := bv(ctx, dummyPeer, msg); res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for bad multisig entry length, got %v", res)
	}

	// Marketplace unknown type rejects (xeprotocol/xe#551)
	mv := marketplaceValidator()
	unknownMm := MarketplaceMsg{Type: "unknown_bogus_type"}
	data, _ = json.Marshal(unknownMm)
	msg = &pubsub.Message{Message: &pubsub_pb.Message{Data: data}}
	if res := mv(ctx, dummyPeer, msg); res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for unknown marketplace type, got %v", res)
	}

	// Marketplace empty type rejects
	emptyMm := MarketplaceMsg{Type: ""}
	data, _ = json.Marshal(emptyMm)
	msg = &pubsub.Message{Message: &pubsub_pb.Message{Data: data}}
	if res := mv(ctx, dummyPeer, msg); res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for empty marketplace type, got %v", res)
	}
}

func TestPeerScoringInvalidMessageRejection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var mu sync.Mutex
	scores := make(map[peer.ID]float64)

	cfg := GossipConfig{
		ScoreInspect: func(s map[peer.ID]float64) {
			mu.Lock()
			defer mu.Unlock()
			for p, sc := range s {
				scores[p] = sc
			}
		},
		ScoreInspectInterval: 20 * time.Millisecond,
	}

	h1, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("h1 libp2p.New failed: %v", err)
	}
	defer h1.Close()

	h2, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("h2 libp2p.New failed: %v", err)
	}
	defer h2.Close()

	ps1, err := NewPubSub(ctx, h1, cfg)
	if err != nil {
		t.Fatalf("NewPubSub ps1 failed: %v", err)
	}

	// Unvalidated GossipSub for peer 2 to simulate attacker sending invalid payload
	ps2, err := pubsub.NewGossipSub(ctx, h2)
	if err != nil {
		t.Fatalf("NewGossipSub ps2 failed: %v", err)
	}

	if err := h1.Connect(ctx, peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()}); err != nil {
		t.Fatalf("h1.Connect failed: %v", err)
	}

	t1, err := ps1.Join(BlockTopic)
	if err != nil {
		t.Fatalf("ps1.Join failed: %v", err)
	}
	_, err = t1.Subscribe()
	if err != nil {
		t.Fatalf("t1.Subscribe failed: %v", err)
	}

	t2, err := ps2.Join(BlockTopic)
	if err != nil {
		t.Fatalf("ps2.Join failed: %v", err)
	}
	_, err = t2.Subscribe()
	if err != nil {
		t.Fatalf("t2.Subscribe failed: %v", err)
	}

	// Wait for mesh connections
	for i := 0; i < 40; i++ {
		if len(t1.ListPeers()) > 0 && len(t2.ListPeers()) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Publish hash-mismatched block from peer 2
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	badBlock := createTestBlock(t, kp)
	badBlock.Hash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	badData, err := json.Marshal(BlockMsg{Block: badBlock})
	if err != nil {
		t.Fatalf("Marshal badBlock failed: %v", err)
	}

	if err := t2.Publish(ctx, badData); err != nil {
		t.Fatalf("t2.Publish failed: %v", err)
	}

	// Verify peer 2's GossipSub score drops into negative territory due to ValidationReject
	start := time.Now()
	penalized := false
	for time.Since(start) < 4*time.Second {
		time.Sleep(50 * time.Millisecond)
		mu.Lock()
		sc, ok := scores[h2.ID()]
		mu.Unlock()
		if ok && sc < 0 {
			penalized = true
			break
		}
	}

	if !penalized {
		mu.Lock()
		sc := scores[h2.ID()]
		mu.Unlock()
		t.Fatalf("expected sending peer %s to have negative score (<0), got %f", h2.ID(), sc)
	}
}
