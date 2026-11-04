package net

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/xeprotocol/xe/statechain"
)

func TestStateChainValidatorHashAndSignatures(t *testing.T) {
	val := stateChainValidator(GossipConfig{})

	// 1. PoC case from Issue #45: Dummy body with fabricated hash and dummy Signatures=[{}]
	// Must be REJECTED
	dummy := &statechain.Block{
		Hash:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Signatures: []statechain.BlockSignature{{}},
	}
	dummyData, err := json.Marshal(StateChainMsg{Block: dummy})
	if err != nil {
		t.Fatalf("marshal dummy: %v", err)
	}
	res := val(context.Background(), peer.ID(""), &pubsub.Message{Message: &pb.Message{Data: dummyData}})
	if res != pubsub.ValidationReject {
		t.Fatalf("expected dummy block to be REJECTED, got %v", res)
	}

	// 2. Block with empty signatures must be REJECTED
	emptySig := &statechain.Block{
		Hash:       dummy.Hash,
		Signatures: []statechain.BlockSignature{},
	}
	emptyData, _ := json.Marshal(StateChainMsg{Block: emptySig})
	res = val(context.Background(), peer.ID(""), &pubsub.Message{Message: &pb.Message{Data: emptyData}})
	if res != pubsub.ValidationReject {
		t.Fatalf("expected block with empty signatures to be REJECTED, got %v", res)
	}

	// 3. Create a valid block with valid hash and valid signature
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	validBlock := &statechain.Block{
		Index:     1,
		PrevHash:  "1111111111111111111111111111111111111111111111111111111111111111",
		Timestamp: time.Now().UnixNano(),
		Ops: []statechain.Op{
			{Action: statechain.ActionSet, Key: "sys.network_id", Value: json.RawMessage(`"testnet-0005"`)},
		},
	}
	hash, err := statechain.HashBlock(validBlock)
	if err != nil {
		t.Fatalf("HashBlock: %v", err)
	}
	validBlock.Hash = hash

	sig, err := statechain.SignBlock(validBlock, priv)
	if err != nil {
		t.Fatalf("SignBlock: %v", err)
	}
	validBlock.Signatures = []statechain.BlockSignature{sig}

	validData, _ := json.Marshal(StateChainMsg{Block: validBlock})
	res = val(context.Background(), peer.ID(""), &pubsub.Message{Message: &pb.Message{Data: validData}})
	if res != pubsub.ValidationAccept {
		t.Fatalf("expected valid block to be ACCEPTED, got %v", res)
	}

	// 4. Block with tampered hash (mismatch with body) must be REJECTED
	tamperedHashBlock := *validBlock
	tamperedHashBlock.Hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	tamperedData, _ := json.Marshal(StateChainMsg{Block: &tamperedHashBlock})
	res = val(context.Background(), peer.ID(""), &pubsub.Message{Message: &pb.Message{Data: tamperedData}})
	if res != pubsub.ValidationReject {
		t.Fatalf("expected block with tampered hash to be REJECTED, got %v", res)
	}

	// 5. Block with corrupted signature bytes must be REJECTED
	badSigBlock := *validBlock
	badSigBlock.Signatures = []statechain.BlockSignature{
		{
			PublicKey: sig.PublicKey,
			Sig:       "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		},
	}
	badSigData, _ := json.Marshal(StateChainMsg{Block: &badSigBlock})
	res = val(context.Background(), peer.ID(""), &pubsub.Message{Message: &pb.Message{Data: badSigData}})
	if res != pubsub.ValidationReject {
		t.Fatalf("expected block with bad signature to be REJECTED, got %v", res)
	}

	// 6. Block tested with StateChainVerify rejecting
	rejectingCfg := GossipConfig{
		StateChainVerify: func(b *statechain.Block) error {
			return context.Canceled
		},
	}
	rejectingVal := stateChainValidator(rejectingCfg)
	res = rejectingVal(context.Background(), peer.ID(""), &pubsub.Message{Message: &pb.Message{Data: validData}})
	if res != pubsub.ValidationReject {
		t.Fatalf("expected block failing StateChainVerify to be REJECTED, got %v", res)
	}
}
