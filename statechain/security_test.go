package statechain_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/statechain"
	"github.com/xeprotocol/xe/store"
)

func TestStateChainCaseVariantDuplicateSignerAndSysKeyValidation(t *testing.T) {
	kp1, _ := core.GenerateKeyPair()
	kp2, _ := core.GenerateKeyPair()

	// 1. ValidateOp must reject case-variant duplicate keys in sys.dao_keyset and sys.timekeepers,
	// as well as non-hex keys in sys.timekeepers.
	dupDAO, _ := json.Marshal(statechain.DAOKeyset{
		Keys:      []string{strings.ToLower(kp1.PubKeyHex()), strings.ToUpper(kp1.PubKeyHex())},
		Threshold: 2,
	})
	if err := statechain.ValidateOp(statechain.Op{Action: statechain.ActionSet, Key: "sys.dao_keyset", Value: dupDAO}); err == nil {
		t.Fatalf("expected ValidateOp to reject case-variant duplicate keys in sys.dao_keyset")
	}

	badTK, _ := json.Marshal(map[string]any{
		"keys":      []string{strings.Repeat("z", 64)},
		"threshold": 1,
	})
	if err := statechain.ValidateOp(statechain.Op{Action: statechain.ActionSet, Key: "sys.timekeepers", Value: badTK}); err == nil {
		t.Fatalf("expected ValidateOp to reject non-hex key in sys.timekeepers")
	}

	dupTK, _ := json.Marshal(map[string]any{
		"keys":      []string{strings.ToLower(kp1.PubKeyHex()), strings.ToUpper(kp1.PubKeyHex())},
		ThresholdField(): 2,
	})
	if err := statechain.ValidateOp(statechain.Op{Action: statechain.ActionSet, Key: "sys.timekeepers", Value: dupTK}); err == nil {
		t.Fatalf("expected ValidateOp to reject duplicate keys in sys.timekeepers")
	}

	// 2. Chain.AddBlock must reject a single DAO signer submitting lowercase + uppercase signatures.
	genesis, err := statechain.GenerateTestGenesis([]string{kp1.PubKeyHex(), kp2.PubKeyHex()}, 2)
	if err != nil {
		t.Fatalf("GenerateTestGenesis: %v", err)
	}
	ms := store.NewMemStore()
	chain, err := statechain.NewChain(ms, genesis)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}

	blk := &statechain.Block{
		Index:     1,
		PrevHash:  genesis.Hash,
		Ops:       []statechain.Op{{Action: statechain.ActionSet, Key: "app.config", Value: json.RawMessage(`"v1"`)}},
		Timestamp: 100,
	}
	h, err := statechain.HashBlock(blk)
	if err != nil {
		t.Fatalf("HashBlock: %v", err)
	}
	blk.Hash = h
	sig1, err := statechain.SignBlock(blk, kp1.Private)
	if err != nil {
		t.Fatalf("SignBlock: %v", err)
	}
	sig1Upper := sig1
	sig1Upper.PublicKey = strings.ToUpper(sig1.PublicKey)
	blk.Signatures = []statechain.BlockSignature{sig1, sig1Upper}

	if err := chain.AddBlock(blk); err == nil {
		t.Fatalf("expected Chain.AddBlock to reject case-variant duplicate DAO signer")
	}
}

func ThresholdField() string { return "threshold" }

func TestStateChainIntraBlockEpochWriteOnceAndOraclePrefixGuard(t *testing.T) {
	dao1, _ := core.GenerateKeyPair()
	dao2, _ := core.GenerateKeyPair()
	ora1, _ := core.GenerateKeyPair()

	genesis, err := statechain.GenerateTestGenesis([]string{dao1.PubKeyHex(), dao2.PubKeyHex()}, 2)
	if err != nil {
		t.Fatalf("GenerateTestGenesis: %v", err)
	}
	ms := store.NewMemStore()
	chain, err := statechain.NewChain(ms, genesis)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}

	// Configure sys.oracle with allowed_prefix "epoch.".
	ocJSON, _ := json.Marshal(statechain.OracleConfig{
		Keys:          []string{ora1.PubKeyHex()},
		Threshold:     1,
		AllowedPrefix: "epoch.",
	})
	b1 := &statechain.Block{
		Index:     1,
		PrevHash:  genesis.Hash,
		Ops:       []statechain.Op{{Action: statechain.ActionSet, Key: "sys.oracle", Value: ocJSON}},
		Timestamp: 100,
	}
	b1.Hash, _ = statechain.HashBlock(b1)
	s1, _ := statechain.SignBlock(b1, dao1.Private)
	s2, _ := statechain.SignBlock(b1, dao2.Private)
	b1.Signatures = []statechain.BlockSignature{s1, s2}
	if err := chain.AddBlock(b1); err != nil {
		t.Fatalf("AddBlock sys.oracle: %v", err)
	}

	// Oracle block attempting to write the same epoch key twice in one block must be rejected.
	ev := statechain.EpochValue{
		Epoch:        1,
		StartNS:      100,
		EndNS:        200,
		TWAPMilliUSD: 1000,
		RVolume:      1500,
		RPriceFloor:  1250,
		REffective:   1500,
		RSource:      "volume",
		Phase:        1,
	}
	evJSON, _ := json.Marshal(ev)
	bDupEpoch := &statechain.Block{
		Index:    2,
		PrevHash: b1.Hash,
		Ops: []statechain.Op{
			{Action: statechain.ActionSet, Key: "epoch.1", Value: evJSON},
			{Action: statechain.ActionSet, Key: "epoch.1", Value: evJSON},
		},
		Timestamp: 200,
	}
	bDupEpoch.Hash, _ = statechain.HashBlock(bDupEpoch)
	osig, _ := statechain.SignBlock(bDupEpoch, ora1.Private)
	bDupEpoch.Signatures = []statechain.BlockSignature{osig}
	if err := chain.AddBlock(bDupEpoch); err == nil {
		t.Fatalf("expected Oracle block with duplicate intra-block epoch.1 set ops to be rejected")
	}

	// Oracle block attempting ActionDelete on an epoch.* key must be rejected.
	bDelEpoch := &statechain.Block{
		Index:    2,
		PrevHash: b1.Hash,
		Ops: []statechain.Op{
			{Action: statechain.ActionDelete, Key: "epoch.1"},
		},
		Timestamp: 200,
	}
	bDelEpoch.Hash, _ = statechain.HashBlock(bDelEpoch)
	osigDel, _ := statechain.SignBlock(bDelEpoch, ora1.Private)
	bDelEpoch.Signatures = []statechain.BlockSignature{osigDel}
	if err := chain.AddBlock(bDelEpoch); err == nil {
		t.Fatalf("expected Oracle block with delete op on epoch.* key to be rejected")
	}
}
