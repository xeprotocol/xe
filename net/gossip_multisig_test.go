package net

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/xeprotocol/xe/core"
)

func makeSignedMultisigOpenBlock(t *testing.T, difficulty uint64) *core.Block {
	t.Helper()
	kp1, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair 1: %v", err)
	}
	kp2, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair 2: %v", err)
	}
	ks := &core.Keyset{
		Keys:      []string{kp1.PubKeyHex(), kp2.PubKeyHex()},
		Threshold: 2,
	}
	addr, err := core.DeriveMultisigAddress(ks)
	if err != nil {
		t.Fatalf("DeriveMultisigAddress: %v", err)
	}
	b := &core.Block{
		Type:      core.BlockMultisigOpen,
		Account:   addr,
		Previous:  "0",
		Balance:   0,
		Timestamp: time.Now().UnixNano(),
		Asset:     "XE",
		MSKeyset:  ks,
	}
	h, err := core.HashBlock(b)
	if err != nil {
		t.Fatalf("HashBlock: %v", err)
	}
	b.Hash = h
	hashBytes, err := core.DecodeHash(b.Hash)
	if err != nil {
		t.Fatalf("DecodeHash: %v", err)
	}
	if difficulty > 0 {
		b.PoWNonce = core.ComputePoW(hashBytes, difficulty)
	}
	for _, kp := range []*core.KeyPair{kp1, kp2} {
		sig := ed25519.Sign(kp.Private, hashBytes)
		b.Signatures = append(b.Signatures, core.BlockSignature{
			PublicKey: kp.PubKeyHex(),
			Sig:       hex.EncodeToString(sig),
		})
	}
	return b
}

func TestGossipSubscribeDeliversMultisigBlocks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	h1, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("libp2p.New h1: %v", err)
	}
	defer func() { _ = h1.Close() }()

	h2, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("libp2p.New h2: %v", err)
	}
	defer func() { _ = h2.Close() }()

	g1, err := NewGossip(ctx, h1)
	if err != nil {
		t.Fatalf("NewGossip h1: %v", err)
	}
	g2, err := NewGossip(ctx, h2)
	if err != nil {
		t.Fatalf("NewGossip h2: %v", err)
	}

	subCh := g2.Subscribe(ctx)

	if err := h1.Connect(ctx, peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()}); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for len(g1.PubSub().ListPeers(BlockTopic)) == 0 || len(g2.PubSub().ListPeers(BlockTopic)) == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for gossipsub mesh peers on %s", BlockTopic)
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)

	msBlock := makeSignedMultisigOpenBlock(t, 0)
	if msBlock.Signature != "" {
		t.Fatalf("expected empty single Signature on multisig block, got %q", msBlock.Signature)
	}
	if len(msBlock.Signatures) != 2 {
		t.Fatalf("expected 2 multisig signatures, got %d", len(msBlock.Signatures))
	}

	if err := g1.Publish(ctx, msBlock); err != nil {
		t.Fatalf("Publish multisig block: %v", err)
	}

	select {
	case got := <-subCh:
		if got == nil {
			t.Fatalf("received nil block from Gossip.Subscribe")
		}
		if got.Hash != msBlock.Hash {
			t.Fatalf("received block hash %s, want %s", got.Hash, msBlock.Hash)
		}
		if len(got.Signatures) != 2 {
			t.Fatalf("received %d multisig signatures, want 2", len(got.Signatures))
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Gossip.Subscribe silently dropped valid multisig block %s (Signature=%q, len(Signatures)=%d)",
			msBlock.Hash[:12], msBlock.Signature, len(msBlock.Signatures))
	}
}

func TestBlockValidatorMultisigAndMalformedSignatures(t *testing.T) {
	ctx := context.Background()
	v := blockValidator(GossipConfig{Difficulty: 0})

	eval := func(b *core.Block) pubsub.ValidationResult {
		raw, err := json.Marshal(BlockMsg{Block: b})
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		return v(ctx, peer.ID("test-peer"), &pubsub.Message{Message: &pb.Message{Data: raw}})
	}

	// 1. Valid multisig block must be accepted.
	validMS := makeSignedMultisigOpenBlock(t, 0)
	if res := eval(validMS); res != pubsub.ValidationAccept {
		t.Fatalf("valid multisig block: got %v, want ValidationAccept", res)
	}

	// 2. Hybrid block carrying both single Signature and multisig Signatures must be rejected.
	hybrid := *validMS
	hybrid.Signature = strings.Repeat("a", 128)
	if res := eval(&hybrid); res != pubsub.ValidationReject {
		t.Fatalf("hybrid Signature+Signatures block: got %v, want ValidationReject", res)
	}

	// 3. Multisig block with short PublicKey (< 64 hex chars, e.g. trigger for pk[:12] panic) must be rejected.
	shortPK := *validMS
	shortPK.Signatures = []core.BlockSignature{
		{PublicKey: "short", Sig: strings.Repeat("b", 128)},
	}
	if res := eval(&shortPK); res != pubsub.ValidationReject {
		t.Fatalf("short PublicKey multisig block: got %v, want ValidationReject", res)
	}

	// 4. Multisig block with malformed Sig (not 128 hex chars) must be rejected.
	badSig := *validMS
	badSig.Signatures = []core.BlockSignature{
		{PublicKey: validMS.Signatures[0].PublicKey, Sig: "not-128-hex"},
	}
	if res := eval(&badSig); res != pubsub.ValidationReject {
		t.Fatalf("malformed Sig multisig block: got %v, want ValidationReject", res)
	}

	// 5. Multisig block with duplicate signer PublicKey entries must be rejected.
	dupSigner := *validMS
	dupSigner.Signatures = []core.BlockSignature{
		validMS.Signatures[0],
		{PublicKey: strings.ToUpper(validMS.Signatures[0].PublicKey), Sig: validMS.Signatures[0].Sig},
	}
	if res := eval(&dupSigner); res != pubsub.ValidationReject {
		t.Fatalf("duplicate signer multisig block: got %v, want ValidationReject", res)
	}

	// 6. Multisig block exceeding maxMultisigSignatures must be rejected.
	overCap := *validMS
	overCap.Signatures = make([]core.BlockSignature, maxMultisigSignatures+1)
	for i := range overCap.Signatures {
		kp, err := core.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		overCap.Signatures[i] = core.BlockSignature{
			PublicKey: kp.PubKeyHex(),
			Sig:       validMS.Signatures[0].Sig,
		}
	}
	if res := eval(&overCap); res != pubsub.ValidationReject {
		t.Fatalf("over-cap multisig block: got %v, want ValidationReject", res)
	}

	// 7. Single-key block with non-hex 128-character Signature must be rejected.
	nonHexSingle := *validMS
	nonHexSingle.Signatures = nil
	nonHexSingle.Signature = strings.Repeat("z", 128)
	if res := eval(&nonHexSingle); res != pubsub.ValidationReject {
		t.Fatalf("non-hex 128-char Signature block: got %v, want ValidationReject", res)
	}
}
