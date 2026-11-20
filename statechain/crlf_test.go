package statechain

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestStatechainGenesis_AllTestnetsCRLF(t *testing.T) {
	testnetDirs := []string{
		"../genesis/testnet-0001",
		"../genesis/testnet-0003",
		"../genesis/testnet-0005",
		"../genesis/testnet-0006",
	}

	for _, dir := range testnetDirs {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			path := filepath.Join(dir, "statechain-genesis.json")
			rawLF, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read genesis %s: %v", path, err)
			}

			// 1. Verify LF parsing
			blockLF, err := ParseGenesis(rawLF)
			if err != nil {
				t.Fatalf("ParseGenesis LF failed: %v", err)
			}
			hashLF, err := HashBlock(blockLF)
			if err != nil {
				t.Fatalf("HashBlock LF failed: %v", err)
			}
			if hashLF != blockLF.Hash {
				t.Fatalf("hashLF %s != declared %s", hashLF, blockLF.Hash)
			}

			// 2. Convert to CRLF (simulating git autocrlf=true on Windows)
			rawCRLF := bytes.ReplaceAll(rawLF, []byte("\n"), []byte("\r\n"))

			// 3. Verify CRLF parsing succeeds without hash mismatch
			blockCRLF, err := ParseGenesis(rawCRLF)
			if err != nil {
				t.Fatalf("ParseGenesis CRLF failed: %v", err)
			}
			hashCRLF, err := HashBlock(blockCRLF)
			if err != nil {
				t.Fatalf("HashBlock CRLF failed: %v", err)
			}

			if hashCRLF != hashLF {
				t.Fatalf("hash mismatch between CRLF and LF: got %s, want %s", hashCRLF, hashLF)
			}
			if hashCRLF != blockLF.Hash {
				t.Fatalf("hashCRLF %s != declared %s", hashCRLF, blockLF.Hash)
			}
		})
	}
}

func TestStatechainGenesis_EmbeddedCRLF(t *testing.T) {
	defer ClearGenesisOverride()

	embLF := EmbeddedGenesisJSON()
	blockLF, err := ParseGenesis(embLF)
	if err != nil {
		t.Fatalf("embedded genesis LF parse failed: %v", err)
	}

	embCRLF := bytes.ReplaceAll(embLF, []byte("\n"), []byte("\r\n"))

	// Test SetGenesisJSON with CRLF
	if err := SetGenesisJSON(embCRLF); err != nil {
		t.Fatalf("SetGenesisJSON CRLF failed: %v", err)
	}

	loaded, err := LoadGenesis()
	if err != nil {
		t.Fatalf("LoadGenesis after CRLF override failed: %v", err)
	}

	hashLoaded, err := HashBlock(loaded)
	if err != nil {
		t.Fatalf("HashBlock failed: %v", err)
	}

	if hashLoaded != blockLF.Hash {
		t.Fatalf("hash mismatch: got %s, want %s", hashLoaded, blockLF.Hash)
	}
}

func TestStatechainOp_CRLFInValue(t *testing.T) {
	valLF := `{"keys":["key1","key2"],"threshold":2}`
	valCRLF := "{\r\n  \"keys\": [\r\n    \"key1\",\r\n    \"key2\"\r\n  ],\r\n  \"threshold\": 2\r\n}"
	valNormalizedLF := "{\n  \"keys\": [\n    \"key1\",\n    \"key2\"\n  ],\n  \"threshold\": 2\n}"

	b1 := &Block{
		Index:    1,
		PrevHash: "0000000000000000000000000000000000000000000000000000000000000000",
		Ops: []Op{
			{Action: ActionSet, Key: "sys.dao_keyset", Value: json.RawMessage(valCRLF)},
		},
		Timestamp: 1000,
	}

	b2 := &Block{
		Index:    1,
		PrevHash: "0000000000000000000000000000000000000000000000000000000000000000",
		Ops: []Op{
			{Action: ActionSet, Key: "sys.dao_keyset", Value: json.RawMessage(valNormalizedLF)},
		},
		Timestamp: 1000,
	}

	h1, err := HashBlock(b1)
	if err != nil {
		t.Fatalf("HashBlock b1: %v", err)
	}
	h2, err := HashBlock(b2)
	if err != nil {
		t.Fatalf("HashBlock b2: %v", err)
	}

	if h1 != h2 {
		t.Fatalf("expected identical hashes for CRLF and LF blocks: got %s and %s", h1, h2)
	}
	_ = valLF
}

func TestStatechainOp_UnmarshalJSONNormalizesCRLF(t *testing.T) {
	jsonCRLF := []byte("{\r\n\"action\": \"set\",\r\n\"key\": \"sys.test\",\r\n\"value\": {\r\n\"a\": 1\r\n}\r\n}")

	var op Op
	if err := json.Unmarshal(jsonCRLF, &op); err != nil {
		t.Fatalf("unmarshal Op: %v", err)
	}

	if bytes.Contains(op.Value, []byte("\r")) {
		t.Fatalf("expected op.Value to have carriage returns stripped, got: %q", string(op.Value))
	}
}
