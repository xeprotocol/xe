package net

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/xeprotocol/xe/core"
)

func TestBlockValidatorRejectsMalformedMultisigSignerPublicKey(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	b := &core.Block{
		Type:      core.BlockMultisigOpen,
		Account:   kp.Address(),
		Previous:  "0",
		Timestamp: 1700000000000000000,
		MSKeyset: &core.Keyset{
			Threshold: 1,
			Keys:      []string{kp.PubKeyHex()},
		},
		Signature: strings.Repeat("a", 128),
		Signatures: []core.BlockSignature{
			{PublicKey: "abcde", Sig: strings.Repeat("b", 128)},
		},
	}
	h, err := core.HashBlock(b)
	if err != nil {
		t.Fatalf("HashBlock: %v", err)
	}
	b.Hash = h

	raw, err := json.Marshal(BlockMsg{Block: b})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	msg := &pubsub.Message{Message: &pb.Message{Data: raw}}

	validator := blockValidator(GossipConfig{Difficulty: 0})
	if got := validator(context.Background(), "", msg); got != pubsub.ValidationReject {
		t.Fatalf("expected ValidationReject for 5-char multisig public_key, got %v", got)
	}
	if validGossipBlockEnvelope(b) {
		t.Fatalf("expected validGossipBlockEnvelope to reject 5-char multisig public_key")
	}

	b.Signatures[0].PublicKey = kp.PubKeyHex()
	rawValid, err := json.Marshal(BlockMsg{Block: b})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	msgValid := &pubsub.Message{Message: &pb.Message{Data: rawValid}}
	if got := validator(context.Background(), "", msgValid); got != pubsub.ValidationAccept {
		t.Fatalf("expected ValidationAccept for well-formed multisig envelope, got %v", got)
	}
	if !validGossipBlockEnvelope(b) {
		t.Fatalf("expected validGossipBlockEnvelope to accept well-formed multisig envelope")
	}
}

func TestSpawnGateRecoversFromWorkerPanic(t *testing.T) {
	gate := &spawnGate{}
	done := make(chan struct{})
	ok := gate.spawn(func() {
		defer close(done)
		panic("simulated sync worker panic")
	})
	if !ok {
		t.Fatalf("expected gate.spawn to succeed")
	}
	<-done
	gate.wait()
}
