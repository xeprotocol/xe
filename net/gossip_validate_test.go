package net

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pubsub_pb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/xeprotocol/xe/core"
)

func makeTestPeer() peer.ID {
	return peer.ID("test-peer")
}

func mustGenKP(t *testing.T) *core.KeyPair {
	t.Helper()
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return kp
}

func wrapBlockMsg(t *testing.T, b *core.Block) *pubsub.Message {
	t.Helper()
	data, err := json.Marshal(BlockMsg{Block: b})
	if err != nil {
		t.Fatalf("Marshal BlockMsg: %v", err)
	}
	return &pubsub.Message{
		Message: &pubsub_pb.Message{
			Data: data,
		},
	}
}

func TestBlockValidator_MalformedJSON(t *testing.T) {
	val := blockValidator(GossipConfig{})
	msg := &pubsub.Message{
		Message: &pubsub_pb.Message{
			Data: []byte("not-a-valid-json"),
		},
	}
	res := val(context.Background(), makeTestPeer(), msg)
	if res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for malformed JSON, got %v", res)
	}
}

func TestBlockValidator_NilBlock(t *testing.T) {
	val := blockValidator(GossipConfig{})
	msg := &pubsub.Message{
		Message: &pubsub_pb.Message{
			Data: []byte(`{"block":null}`),
		},
	}
	res := val(context.Background(), makeTestPeer(), msg)
	if res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for nil block, got %v", res)
	}
}

func TestBlockValidator_InvalidHashOrAccount(t *testing.T) {
	val := blockValidator(GossipConfig{})

	tests := []struct {
		name    string
		hash    string
		account string
	}{
		{"empty hash", "", strings.Repeat("a", 64)},
		{"short hash", "abcd", strings.Repeat("a", 64)},
		{"non-hex hash", strings.Repeat("z", 64), strings.Repeat("a", 64)},
		{"empty account", strings.Repeat("a", 64), ""},
		{"short account", strings.Repeat("a", 64), "1234"},
		{"non-hex account", strings.Repeat("a", 64), strings.Repeat("g", 64)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := &core.Block{
				Hash:      tc.hash,
				Account:   tc.account,
				Signature: strings.Repeat("0", 128),
			}
			res := val(context.Background(), makeTestPeer(), wrapBlockMsg(t, b))
			if res != pubsub.ValidationReject {
				t.Fatalf("expected ValidationReject, got %v", res)
			}
		})
	}
}

func TestBlockValidator_SignatureFormat(t *testing.T) {
	val := blockValidator(GossipConfig{})
	acc := strings.Repeat("a", 64)
	h := strings.Repeat("b", 64)

	// Neither signature nor signatures present
	bEmpty := &core.Block{Hash: h, Account: acc}
	if res := val(context.Background(), makeTestPeer(), wrapBlockMsg(t, bEmpty)); res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for empty signature, got %v", res)
	}

	// Signature wrong length
	bShortSig := &core.Block{Hash: h, Account: acc, Signature: strings.Repeat("0", 64)}
	if res := val(context.Background(), makeTestPeer(), wrapBlockMsg(t, bShortSig)); res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for short signature, got %v", res)
	}

	// Signature non-hex
	bNonHexSig := &core.Block{Hash: h, Account: acc, Signature: strings.Repeat("x", 128)}
	if res := val(context.Background(), makeTestPeer(), wrapBlockMsg(t, bNonHexSig)); res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for non-hex signature, got %v", res)
	}

	// Multisig signature wrong length
	bMultiShort := &core.Block{
		Hash:    h,
		Account: acc,
		Signatures: []core.BlockSignature{
			{PublicKey: strings.Repeat("c", 64), Sig: strings.Repeat("0", 64)},
		},
	}
	if res := val(context.Background(), makeTestPeer(), wrapBlockMsg(t, bMultiShort)); res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for short multisig signature, got %v", res)
	}

	// Multisig signature non-hex
	bMultiNonHex := &core.Block{
		Hash:    h,
		Account: acc,
		Signatures: []core.BlockSignature{
			{PublicKey: strings.Repeat("c", 64), Sig: strings.Repeat("z", 128)},
		},
	}
	if res := val(context.Background(), makeTestPeer(), wrapBlockMsg(t, bMultiNonHex)); res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for non-hex multisig signature, got %v", res)
	}
}

func TestBlockValidator_HashMismatch_MustReject(t *testing.T) {
	val := blockValidator(GossipConfig{})
	kp := mustGenKP(t)

	b := &core.Block{
		Type:        core.BlockSend,
		Account:     core.MustDeriveAddress(kp.PubKeyHex()),
		Previous:    strings.Repeat("1", 64),
		Destination: strings.Repeat("2", 64),
		Signature:   strings.Repeat("0", 128),
		Amount:      100,
	}

	// Calculate real hash but put a forged hash
	realHash, err := core.HashBlock(b)
	if err != nil {
		t.Fatalf("HashBlock: %v", err)
	}
	b.Hash = strings.Repeat("f", 64)
	if b.Hash == realHash {
		b.Hash = strings.Repeat("e", 64)
	}

	res := val(context.Background(), makeTestPeer(), wrapBlockMsg(t, b))
	if res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject on hash mismatch (not ValidationIgnore), got %v", res)
	}
}

func TestBlockValidator_OpenBlock_GarbageSignatureRejected(t *testing.T) {
	// Tests the vulnerability where valid-PoW garbage blocks were relayed network-wide
	// because gossip block validator never verified cryptographic signatures.
	val := blockValidator(GossipConfig{})
	kp := mustGenKP(t)
	addr := core.MustDeriveAddress(kp.PubKeyHex())

	b := &core.Block{
		Type:        core.BlockSend,
		Account:     addr,
		Previous:    "0",
		PubKey:      kp.PubKeyHex(),
		Destination: strings.Repeat("2", 64),
		Signature:   strings.Repeat("a", 128), // garbage signature (valid hex, 128 chars)
		Amount:      1000,
	}
	h, err := core.HashBlock(b)
	if err != nil {
		t.Fatalf("HashBlock: %v", err)
	}
	b.Hash = h

	res := val(context.Background(), makeTestPeer(), wrapBlockMsg(t, b))
	if res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for open block with garbage signature, got %v", res)
	}
}

func TestBlockValidator_OpenBlock_ValidSignatureAccepted(t *testing.T) {
	val := blockValidator(GossipConfig{})
	kp := mustGenKP(t)
	addr := core.MustDeriveAddress(kp.PubKeyHex())

	b := &core.Block{
		Type:        core.BlockSend,
		Account:     addr,
		Previous:    "0",
		Destination: strings.Repeat("2", 64),
		Amount:      1000,
	}
	if err := core.SignBlock(b, kp); err != nil {
		t.Fatalf("SignBlock: %v", err)
	}

	res := val(context.Background(), makeTestPeer(), wrapBlockMsg(t, b))
	if res != pubsub.ValidationAccept {
		t.Fatalf("expected ValidationAccept for validly signed open block, got %v", res)
	}
}

func TestBlockValidator_OpenBlock_PubKeyMismatchRejected(t *testing.T) {
	val := blockValidator(GossipConfig{})
	kp1 := mustGenKP(t)
	kp2 := mustGenKP(t)

	// Account derived from kp1, but PubKey declares kp2
	addr := core.MustDeriveAddress(kp1.PubKeyHex())
	b := &core.Block{
		Type:        core.BlockSend,
		Account:     addr,
		Previous:    "0",
		PubKey:      kp2.PubKeyHex(),
		Destination: strings.Repeat("2", 64),
		Signature:   strings.Repeat("0", 128),
		Amount:      1000,
	}
	h, err := core.HashBlock(b)
	if err != nil {
		t.Fatalf("HashBlock: %v", err)
	}
	b.Hash = h

	res := val(context.Background(), makeTestPeer(), wrapBlockMsg(t, b))
	if res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for pubkey mismatch, got %v", res)
	}
}

func TestBlockValidator_PoWEnforcement(t *testing.T) {
	kp := mustGenKP(t)
	addr := core.MustDeriveAddress(kp.PubKeyHex())

	b := &core.Block{
		Type:        core.BlockSend,
		Account:     addr,
		Previous:    "0",
		Destination: strings.Repeat("2", 64),
		Amount:      500,
	}
	if err := core.SignBlock(b, kp); err != nil {
		t.Fatalf("SignBlock: %v", err)
	}

	// 1. With impossible difficulty, validation must reject
	valHigh := blockValidator(GossipConfig{Difficulty: ^uint64(0)})
	b.PoWNonce = 0
	res := valHigh(context.Background(), makeTestPeer(), wrapBlockMsg(t, b))
	if res != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for invalid PoW, got %v", res)
	}

	// 2. With minimal difficulty (1), validation must accept
	valLow := blockValidator(GossipConfig{Difficulty: 1})
	res = valLow(context.Background(), makeTestPeer(), wrapBlockMsg(t, b))
	if res != pubsub.ValidationAccept {
		t.Fatalf("expected ValidationAccept for valid PoW, got %v", res)
	}
}

func TestBlockValidator_NonOpenBlock_VerifyBlockCallback(t *testing.T) {
	kp := mustGenKP(t)
	addr := core.MustDeriveAddress(kp.PubKeyHex())

	makeNonOpenBlock := func(t *testing.T) *core.Block {
		b := &core.Block{
			Type:        core.BlockSend,
			Account:     addr,
			Previous:    strings.Repeat("1", 64),
			Destination: strings.Repeat("2", 64),
			Signature:   strings.Repeat("a", 128),
			Amount:      200,
		}
		h, err := core.HashBlock(b)
		if err != nil {
			t.Fatalf("HashBlock: %v", err)
		}
		b.Hash = h
		return b
	}

	t.Run("garbage signature on known account is rejected", func(t *testing.T) {
		cfg := GossipConfig{
			VerifyBlock: func(b *core.Block) error {
				return fmt.Errorf("signature: signature verification failed")
			},
		}
		val := blockValidator(cfg)
		b := makeNonOpenBlock(t)
		res := val(context.Background(), makeTestPeer(), wrapBlockMsg(t, b))
		if res != pubsub.ValidationReject {
			t.Fatalf("expected ValidationReject for invalid signature, got %v", res)
		}
	})

	t.Run("valid signature on known account is accepted", func(t *testing.T) {
		cfg := GossipConfig{
			VerifyBlock: func(b *core.Block) error {
				return nil
			},
		}
		val := blockValidator(cfg)
		b := makeNonOpenBlock(t)
		res := val(context.Background(), makeTestPeer(), wrapBlockMsg(t, b))
		if res != pubsub.ValidationAccept {
			t.Fatalf("expected ValidationAccept for valid signature, got %v", res)
		}
	})

	t.Run("unopened account returns ValidationIgnore", func(t *testing.T) {
		cfg := GossipConfig{
			VerifyBlock: func(b *core.Block) error {
				return fmt.Errorf("signature: %w for %s", core.ErrUnopenedAccount, b.Account)
			},
		}
		val := blockValidator(cfg)
		b := makeNonOpenBlock(t)
		res := val(context.Background(), makeTestPeer(), wrapBlockMsg(t, b))
		if res != pubsub.ValidationIgnore {
			t.Fatalf("expected ValidationIgnore for unopened account, got %v", res)
		}
	})
}

func TestBlockValidator_MultisigOpenBlock(t *testing.T) {
	kp1 := mustGenKP(t)
	kp2 := mustGenKP(t)
	ks := &core.Keyset{
		Keys:      []string{kp1.PubKeyHex(), kp2.PubKeyHex()},
		Threshold: 2,
	}
	msAddr, err := core.DeriveMultisigAddress(ks)
	if err != nil {
		t.Fatalf("DeriveMultisigAddress: %v", err)
	}

	t.Run("valid signatures accepted", func(t *testing.T) {
		b := &core.Block{
			Type:     core.BlockMultisigOpen,
			Account:  msAddr,
			Previous: "0",
			MSKeyset: ks,
			Amount:   1000,
		}
		h, err := core.HashBlock(b)
		if err != nil {
			t.Fatalf("HashBlock: %v", err)
		}
		b.Hash = h
		hashBytes, _ := hex.DecodeString(h)

		sig1 := ed25519.Sign(kp1.Private, hashBytes)
		sig2 := ed25519.Sign(kp2.Private, hashBytes)
		b.Signatures = []core.BlockSignature{
			{PublicKey: kp1.PubKeyHex(), Sig: hex.EncodeToString(sig1)},
			{PublicKey: kp2.PubKeyHex(), Sig: hex.EncodeToString(sig2)},
		}

		val := blockValidator(GossipConfig{})
		res := val(context.Background(), makeTestPeer(), wrapBlockMsg(t, b))
		if res != pubsub.ValidationAccept {
			t.Fatalf("expected ValidationAccept for valid multisig open block, got %v", res)
		}
	})

	t.Run("garbage signatures rejected", func(t *testing.T) {
		b := &core.Block{
			Type:     core.BlockMultisigOpen,
			Account:  msAddr,
			Previous: "0",
			MSKeyset: ks,
			Amount:   1000,
		}
		h, err := core.HashBlock(b)
		if err != nil {
			t.Fatalf("HashBlock: %v", err)
		}
		b.Hash = h

		b.Signatures = []core.BlockSignature{
			{PublicKey: kp1.PubKeyHex(), Sig: strings.Repeat("1", 128)},
			{PublicKey: kp2.PubKeyHex(), Sig: strings.Repeat("2", 128)},
		}

		val := blockValidator(GossipConfig{})
		res := val(context.Background(), makeTestPeer(), wrapBlockMsg(t, b))
		if res != pubsub.ValidationReject {
			t.Fatalf("expected ValidationReject for garbage multisig signatures, got %v", res)
		}
	})
}
