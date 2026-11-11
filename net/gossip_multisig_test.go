package net

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pubsub_pb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/xeprotocol/xe/core"
)

func TestBlockValidator_MultisigAcceptance(t *testing.T) {
	v := blockValidator(GossipConfig{})

	// 1. Single-key block with valid 128-char signature
	singleBlock := &core.Block{
		Type:        core.BlockSend,
		Account:     strings.Repeat("1", 64),
		Previous:    strings.Repeat("2", 64),
		Destination: strings.Repeat("7", 64),
		Signature:   strings.Repeat("3", 128),
		Amount:      10,
	}
	h, err := core.HashBlock(singleBlock)
	if err != nil {
		t.Fatalf("HashBlock single: %v", err)
	}
	singleBlock.Hash = h

	rawSingle, _ := json.Marshal(BlockMsg{Block: singleBlock})
	res := v(context.Background(), "", &pubsub.Message{Message: &pubsub_pb.Message{Data: rawSingle}})
	if res != pubsub.ValidationAccept {
		t.Fatalf("expected single-key block to be accepted, got %v", res)
	}

	// 2. Multisig block with empty Signature and non-empty Signatures
	msBlock := &core.Block{
		Type:     core.BlockMultisigOpen,
		Account:  strings.Repeat("4", 64),
		Previous: "0",
		MSKeyset: &core.Keyset{
			Keys:      []string{strings.Repeat("5", 64)},
			Threshold: 1,
		},
		Signatures: []core.BlockSignature{
			{PublicKey: strings.Repeat("5", 64), Sig: strings.Repeat("6", 128)},
		},
	}
	msH, err := core.HashBlock(msBlock)
	if err != nil {
		t.Fatalf("HashBlock multisig: %v", err)
	}
	msBlock.Hash = msH

	rawMS, _ := json.Marshal(BlockMsg{Block: msBlock})
	resMS := v(context.Background(), "", &pubsub.Message{Message: &pubsub_pb.Message{Data: rawMS}})
	if resMS != pubsub.ValidationAccept {
		t.Fatalf("expected multisig block to be accepted by validator, got %v", resMS)
	}

	// 3. Invalid block with empty Signature and empty Signatures
	badBlock := &core.Block{
		Type:        core.BlockSend,
		Account:     strings.Repeat("7", 64),
		Previous:    strings.Repeat("8", 64),
		Destination: strings.Repeat("9", 64),
		Amount:      10,
	}
	badH, err := core.HashBlock(badBlock)
	if err != nil {
		t.Fatalf("HashBlock bad: %v", err)
	}
	badBlock.Hash = badH

	rawBad, _ := json.Marshal(BlockMsg{Block: badBlock})
	resBad := v(context.Background(), "", &pubsub.Message{Message: &pubsub_pb.Message{Data: rawBad}})
	if resBad != pubsub.ValidationReject {
		t.Fatalf("expected block with neither signature to be rejected, got %v", resBad)
	}
}

func TestGossipSubscribe_ReceivesMultisigBlock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	h1, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("host 1: %v", err)
	}
	defer h1.Close()

	h2, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("host 2: %v", err)
	}
	defer h2.Close()

	ps1, err := NewPubSub(ctx, h1, GossipConfig{})
	if err != nil {
		t.Fatalf("pubsub 1: %v", err)
	}
	g1, err := NewGossip(ctx, h1, ps1)
	if err != nil {
		t.Fatalf("gossip 1: %v", err)
	}
	ch := g1.Subscribe(ctx)

	ps2, err := NewPubSub(ctx, h2, GossipConfig{})
	if err != nil {
		t.Fatalf("pubsub 2: %v", err)
	}
	g2, err := NewGossip(ctx, h2, ps2)
	if err != nil {
		t.Fatalf("gossip 2: %v", err)
	}

	if err := h1.Connect(ctx, h2.Peerstore().PeerInfo(h2.ID())); err != nil {
		t.Fatalf("connect: %v", err)
	}
	time.Sleep(1 * time.Second)

	msBlock := &core.Block{
		Type:     core.BlockMultisigOpen,
		Account:  strings.Repeat("4", 64),
		Previous: "0",
		MSKeyset: &core.Keyset{
			Keys:      []string{strings.Repeat("5", 64)},
			Threshold: 1,
		},
		Signatures: []core.BlockSignature{
			{PublicKey: strings.Repeat("5", 64), Sig: strings.Repeat("6", 128)},
		},
	}
	msH, err := core.HashBlock(msBlock)
	if err != nil {
		t.Fatalf("HashBlock: %v", err)
	}
	msBlock.Hash = msH

	if err := g2.Publish(ctx, msBlock); err != nil {
		t.Fatalf("publish: %v", err)
	}

	select {
	case b := <-ch:
		if b == nil {
			t.Fatalf("channel closed without block")
		}
		if b.Hash != msBlock.Hash {
			t.Fatalf("expected block %s, got %s", msBlock.Hash, b.Hash)
		}
		if len(b.Signatures) != 1 {
			t.Fatalf("expected 1 signature in multisig block, got %d", len(b.Signatures))
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for multisig block on Subscribe channel")
	}
}
