package net

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/xeprotocol/xe/core"
)

func signTestVote(v *core.Vote, priv ed25519.PrivateKey) error {
	rep, err := hex.DecodeString(v.RepPubKey)
	if err != nil || len(rep) != 32 {
		return fmt.Errorf("invalid rep pub key")
	}
	bh, err := hex.DecodeString(v.BlockHash)
	if err != nil || len(bh) != 32 {
		return fmt.Errorf("invalid block hash")
	}
	acc, err := hex.DecodeString(v.ConflictAccount)
	if err != nil || len(acc) != 32 {
		return fmt.Errorf("invalid conflict account")
	}
	var prev []byte
	if v.ConflictPrev == "0" {
		prev = make([]byte, 32)
	} else {
		prev, err = hex.DecodeString(v.ConflictPrev)
		if err != nil || len(prev) != 32 {
			return fmt.Errorf("invalid conflict prev")
		}
	}

	var buf bytes.Buffer
	buf.WriteByte(0x02)
	buf.Write(rep)
	buf.Write(bh)
	buf.Write(acc)
	buf.Write(prev)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(v.Timestamp))
	buf.Write(ts[:])
	if v.Final {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	v.Signature = ed25519.Sign(priv, buf.Bytes())
	return nil
}

func TestVoteValidatorWeightAndWindow(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubHex := hex.EncodeToString(pub)

	weights := make(map[string]*big.Int)
	cfg := GossipConfig{
		VoteWeight: func(repAccount string) *big.Int {
			if w, ok := weights[repAccount]; ok {
				return w
			}
			return big.NewInt(0)
		},
	}
	val := voteValidator(cfg, core.VerifyVoteSignature)

	repAccount, err := core.DeriveAddress(pubHex)
	if err != nil {
		t.Fatalf("derive address: %v", err)
	}

	// 1. Throwaway key / Zero vote weight should be REJECTED
	now := time.Now().UnixNano()
	zeroVote := &core.Vote{
		RepPubKey:       pubHex,
		BlockHash:       "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ConflictAccount: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		ConflictPrev:    "0",
		Timestamp:       now,
		Final:           false,
	}
	if err := signTestVote(zeroVote, priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	data, _ := json.Marshal(VoteMsg{Vote: zeroVote})
	res := val(context.Background(), peer.ID(""), &pubsub.Message{Message: &pb.Message{Data: data}})
	if res != pubsub.ValidationReject {
		t.Fatalf("expected throwaway key with 0 vote weight to be REJECTED, got %v", res)
	}

	// 2. Representative with positive vote weight should be ACCEPTED
	weights[repAccount] = big.NewInt(1000)
	res = val(context.Background(), peer.ID(""), &pubsub.Message{Message: &pb.Message{Data: data}})
	if res != pubsub.ValidationAccept {
		t.Fatalf("expected vote from representative with positive weight to be ACCEPTED, got %v", res)
	}

	// 3. Vote with timestamp > 5 minutes in the past should be REJECTED
	stalePastVote := &core.Vote{
		RepPubKey:       pubHex,
		BlockHash:       "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ConflictAccount: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		ConflictPrev:    "0",
		Timestamp:       now - (core.VoteWindowNanos + int64(10*time.Second)),
		Final:           false,
	}
	if err := signTestVote(stalePastVote, priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	dataPast, _ := json.Marshal(VoteMsg{Vote: stalePastVote})
	res = val(context.Background(), peer.ID(""), &pubsub.Message{Message: &pb.Message{Data: dataPast}})
	if res != pubsub.ValidationReject {
		t.Fatalf("expected stale past vote to be REJECTED, got %v", res)
	}

	// 4. Vote with timestamp > 5 minutes in the future should be REJECTED
	futureVote := &core.Vote{
		RepPubKey:       pubHex,
		BlockHash:       "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ConflictAccount: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		ConflictPrev:    "0",
		Timestamp:       now + (core.VoteWindowNanos + int64(10*time.Second)),
		Final:           false,
	}
	if err := signTestVote(futureVote, priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	dataFuture, _ := json.Marshal(VoteMsg{Vote: futureVote})
	res = val(context.Background(), peer.ID(""), &pubsub.Message{Message: &pb.Message{Data: dataFuture}})
	if res != pubsub.ValidationReject {
		t.Fatalf("expected future vote to be REJECTED, got %v", res)
	}

	// 5. Vote with negative timestamp should be REJECTED
	negVote := &core.Vote{
		RepPubKey:       pubHex,
		BlockHash:       "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ConflictAccount: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		ConflictPrev:    "0",
		Timestamp:       -100,
		Final:           false,
	}
	if err := signTestVote(negVote, priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	dataNeg, _ := json.Marshal(VoteMsg{Vote: negVote})
	res = val(context.Background(), peer.ID(""), &pubsub.Message{Message: &pb.Message{Data: dataNeg}})
	if res != pubsub.ValidationReject {
		t.Fatalf("expected negative timestamp vote to be REJECTED, got %v", res)
	}
}

func TestIngestVoteWeightAndWindow(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubHex := hex.EncodeToString(pub)
	repAccount, _ := core.DeriveAddress(pubHex)

	now := time.Now().UnixNano()
	ch := make(chan *core.Vote, 10)
	seen := make(map[string]int64)

	voteWeightLookup := func(acc string) *big.Int {
		if acc == repAccount {
			return big.NewInt(500)
		}
		return big.NewInt(0)
	}

	validVote := &core.Vote{
		RepPubKey:       pubHex,
		BlockHash:       "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ConflictAccount: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		ConflictPrev:    "0",
		Timestamp:       now,
		Final:           false,
	}
	if err := signTestVote(validVote, priv); err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Ingest valid vote with positive weight
	if !ingestVote(context.Background(), ch, seen, validVote, core.VerifyVoteSignature, voteWeightLookup, now) {
		t.Fatal("expected valid vote to be ingested successfully")
	}

	// Attempt ingest with 0 weight (unknown rep)
	pub2, priv2, _ := ed25519.GenerateKey(nil)
	zeroVote := &core.Vote{
		RepPubKey:       hex.EncodeToString(pub2),
		BlockHash:       "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ConflictAccount: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		ConflictPrev:    "0",
		Timestamp:       now,
		Final:           false,
	}
	if err := signTestVote(zeroVote, priv2); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if ingestVote(context.Background(), ch, seen, zeroVote, core.VerifyVoteSignature, voteWeightLookup, now) {
		t.Fatal("expected zero weight vote to be rejected by ingestVote")
	}

	// Attempt ingest with out-of-window timestamp
	staleVote := &core.Vote{
		RepPubKey:       pubHex,
		BlockHash:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ConflictAccount: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		ConflictPrev:    "0",
		Timestamp:       now - (core.VoteWindowNanos + int64(time.Minute)),
		Final:           false,
	}
	if err := signTestVote(staleVote, priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if ingestVote(context.Background(), ch, seen, staleVote, core.VerifyVoteSignature, voteWeightLookup, now) {
		t.Fatal("expected out of window vote to be rejected by ingestVote")
	}
}
