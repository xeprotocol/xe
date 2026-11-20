package net

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/xeprotocol/xe/core"
)

func makeMsg(b *core.Block) *pubsub.Message {
	data, _ := json.Marshal(BlockMsg{Block: b})
	return &pubsub.Message{
		Message: &pb.Message{
			Data: data,
		},
	}
}

func TestBlockValidator_OpenBlockGarbageSignatureRejected(t *testing.T) {
	// Replicates Issue #53: block with Previous="0" and garbage signature
	core.SetNetworkID("")
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	b := &core.Block{
		Type:        core.BlockSend,
		Account:     kp.Address(),
		Previous:    "0",
		Balance:     100,
		Amount:      10,
		Timestamp:   1000,
		Asset:       "XE",
		Destination: strings.Repeat("b", 64),
		Signature:   strings.Repeat("f", 128), // 128 hex garbage signature
	}
	h, err := core.HashBlock(b)
	if err != nil {
		t.Fatalf("HashBlock: %v", err)
	}
	b.Hash = h

	val := blockValidator(GossipConfig{})
	res := val(context.Background(), peer.ID(""), makeMsg(b))
	if res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for open block without pub_key, got %v", res)
	}

	// Now add pub_key matching kp, but keep garbage signature
	b.PubKey = kp.PubKeyHex()
	h2, err := core.HashBlock(b)
	if err != nil {
		t.Fatalf("HashBlock: %v", err)
	}
	b.Hash = h2

	res = val(context.Background(), peer.ID(""), makeMsg(b))
	if res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for open block with garbage signature, got %v", res)
	}

	// Now sign it correctly
	if err := core.SignBlock(b, kp); err != nil {
		t.Fatalf("SignBlock: %v", err)
	}

	res = val(context.Background(), peer.ID(""), makeMsg(b))
	if res != pubsub.ValidationAccept {
		t.Fatalf("expected ValidationAccept for valid open block, got %v", res)
	}
}

func TestBlockValidator_NonOpenBlockWithKeyResolver(t *testing.T) {
	core.SetNetworkID("")
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	cfg := GossipConfig{
		KeyResolver: func(account string) string {
			if account == kp.Address() {
				return kp.PubKeyHex()
			}
			return ""
		},
	}
	val := blockValidator(cfg)

	// 1. Non-open block declaring PubKey must be rejected
	b := &core.Block{
		Type:        core.BlockSend,
		Account:     kp.Address(),
		Previous:    strings.Repeat("1", 64),
		Balance:     100,
		Amount:      10,
		Timestamp:   1000,
		Asset:       "XE",
		Destination: strings.Repeat("b", 64),
		PubKey:      kp.PubKeyHex(),
		Signature:   strings.Repeat("0", 128),
	}
	h, _ := core.HashBlock(b)
	b.Hash = h

	res := val(context.Background(), peer.ID(""), makeMsg(b))
	if res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for non-open block declaring pub_key, got %v", res)
	}

	// 2. Non-open block with garbage signature for known account must be rejected
	b.PubKey = ""
	h2, _ := core.HashBlock(b)
	b.Hash = h2
	b.Signature = strings.Repeat("a", 128)

	res = val(context.Background(), peer.ID(""), makeMsg(b))
	if res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for known account with garbage signature, got %v", res)
	}

	// 3. Non-open block with valid signature for known account must be accepted
	if err := core.SignBlock(b, kp); err != nil {
		t.Fatalf("SignBlock: %v", err)
	}
	res = val(context.Background(), peer.ID(""), makeMsg(b))
	if res != pubsub.ValidationAccept {
		t.Fatalf("expected ValidationAccept for valid block, got %v", res)
	}
}

func TestBlockValidator_MultisigOpenValidation(t *testing.T) {
	core.SetNetworkID("")
	pub1, priv1, _ := ed25519.GenerateKey(nil)
	pub2, _, _ := ed25519.GenerateKey(nil)

	pk1Hex := hex.EncodeToString(pub1)
	pk2Hex := hex.EncodeToString(pub2)

	ks := &core.Keyset{
		Threshold: 2,
		Keys:      []string{pk1Hex, pk2Hex},
	}
	msAddr, err := core.DeriveMultisigAddress(ks)
	if err != nil {
		t.Fatalf("DeriveMultisigAddress: %v", err)
	}

	b := &core.Block{
		Type:      core.BlockMultisigOpen,
		Account:   msAddr,
		Previous:  "0",
		Balance:   0,
		Timestamp: 1000,
		Asset:     "XE",
		MSKeyset:  ks,
	}
	h, _ := core.HashBlock(b)
	b.Hash = h

	// Only 1 of 2 signatures (below threshold 2)
	hashBytes, _ := hex.DecodeString(b.Hash)
	sig1 := hex.EncodeToString(ed25519.Sign(priv1, hashBytes))
	b.Signatures = []core.BlockSignature{
		{PublicKey: pk1Hex, Sig: sig1},
	}

	val := blockValidator(GossipConfig{})
	res := val(context.Background(), peer.ID(""), makeMsg(b))
	if res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for multisig below threshold, got %v", res)
	}
}
