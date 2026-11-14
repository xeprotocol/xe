package statechain

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestMarshalCanonical_LineEndingInvariance(t *testing.T) {
	// Sample block with multi-line JSON values and various field types.
	lfJSON := []byte(`{
  "index": 1,
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "ops": [
    {
      "action": "set",
      "key": "sys.dao_keyset",
      "value": {
        "keys": [
          "9aa08bf7220d6d5fc2ef0e72bad0167e3c5f5086f474c271e9e7adf79f0295cd",
          "c1ffec6908b22b220e58d3ca22233abb4ffa79bdcd1d1264895380930f1fe936"
        ],
        "threshold": 2
      }
    },
    {
      "action": "set",
      "key": "sys.network_id",
      "value": "testnet-sample"
    },
    {
      "action": "delete",
      "key": "deprecated.key"
    }
  ],
  "timestamp": 1700000000
}`)

	crlfJSON := bytes.ReplaceAll(lfJSON, []byte("\n"), []byte("\r\n"))
	crJSON := bytes.ReplaceAll(lfJSON, []byte("\n"), []byte("\r"))

	var bLF, bCRLF, bCR Block
	if err := json.Unmarshal(lfJSON, &bLF); err != nil {
		t.Fatalf("unmarshal LF JSON: %v", err)
	}
	if err := json.Unmarshal(crlfJSON, &bCRLF); err != nil {
		t.Fatalf("unmarshal CRLF JSON: %v", err)
	}
	if err := json.Unmarshal(crJSON, &bCR); err != nil {
		t.Fatalf("unmarshal CR JSON: %v", err)
	}

	canonLF, err := MarshalCanonical(&bLF)
	if err != nil {
		t.Fatalf("MarshalCanonical LF: %v", err)
	}
	canonCRLF, err := MarshalCanonical(&bCRLF)
	if err != nil {
		t.Fatalf("MarshalCanonical CRLF: %v", err)
	}
	canonCR, err := MarshalCanonical(&bCR)
	if err != nil {
		t.Fatalf("MarshalCanonical CR: %v", err)
	}

	if !bytes.Equal(canonLF, canonCRLF) {
		t.Fatalf("canonical bytes mismatch between LF and CRLF")
	}
	if !bytes.Equal(canonLF, canonCR) {
		t.Fatalf("canonical bytes mismatch between LF and CR")
	}

	hashLF, err := HashBlock(&bLF)
	if err != nil {
		t.Fatalf("HashBlock LF: %v", err)
	}
	hashCRLF, err := HashBlock(&bCRLF)
	if err != nil {
		t.Fatalf("HashBlock CRLF: %v", err)
	}
	hashCR, err := HashBlock(&bCR)
	if err != nil {
		t.Fatalf("HashBlock CR: %v", err)
	}

	if hashLF != hashCRLF {
		t.Fatalf("hash mismatch LF (%s) vs CRLF (%s)", hashLF, hashCRLF)
	}
	if hashLF != hashCR {
		t.Fatalf("hash mismatch LF (%s) vs CR (%s)", hashLF, hashCR)
	}
}

func TestMarshalCanonical_EscapedNewlinesUntouched(t *testing.T) {
	// Escaped \r\n inside JSON string values must not be modified.
	rawWithEscaped := []byte(`{
  "index": 2,
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "ops": [
    {
      "action": "set",
      "key": "sys.text_with_escapes",
      "value": "line1\r\nline2\rline3\nline4"
    }
  ],
  "timestamp": 1700000001
}`)

	var b Block
	if err := json.Unmarshal(rawWithEscaped, &b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	canon, err := MarshalCanonical(&b)
	if err != nil {
		t.Fatalf("MarshalCanonical: %v", err)
	}

	// The value in b.Ops[0].Value must retain escaped sequence verbatim.
	wantSubstr := []byte(`"line1\r\nline2\rline3\nline4"`)
	if !bytes.Contains(canon, wantSubstr) {
		t.Fatalf("expected canonical bytes to contain verbatim escaped string")
	}
}

func TestGenesis_Testnet0005CanonicalHash(t *testing.T) {
	// Verify testnet-0005 genesis matches published hash regardless of CRLF.
	genesisPath := filepath.Join("..", "genesis", "testnet-0005", "statechain-genesis.json")
	data, err := os.ReadFile(genesisPath)
	if err != nil {
		t.Fatalf("read testnet-0005 genesis: %v", err)
	}

	const publishedHash = "d01aabc1a29dc64bc6bbc30031a716cd2e0ceb867e5479953cd5ad22c8f296d6"

	// Test original bytes from disk.
	block, err := ParseGenesis(data)
	if err != nil {
		t.Fatalf("ParseGenesis original: %v", err)
	}
	if block.Hash != publishedHash {
		t.Fatalf("genesis hash mismatch: got %s, want %s", block.Hash, publishedHash)
	}

	// Test forced CRLF.
	crlfData := bytes.ReplaceAll(bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n")),
		[]byte("\n"), []byte("\r\n"))
	blockCRLF, err := ParseGenesis(crlfData)
	if err != nil {
		t.Fatalf("ParseGenesis CRLF: %v", err)
	}
	hashCRLF, err := HashBlock(blockCRLF)
	if err != nil {
		t.Fatalf("HashBlock CRLF: %v", err)
	}
	if hashCRLF != publishedHash {
		t.Fatalf("hashCRLF mismatch: got %s, want %s", hashCRLF, publishedHash)
	}

	// Test forced LF.
	lfData := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	blockLF, err := ParseGenesis(lfData)
	if err != nil {
		t.Fatalf("ParseGenesis LF: %v", err)
	}
	hashLF, err := HashBlock(blockLF)
	if err != nil {
		t.Fatalf("HashBlock LF: %v", err)
	}
	if hashLF != publishedHash {
		t.Fatalf("hashLF mismatch: got %s, want %s", hashLF, publishedHash)
	}
}

func TestGenesis_EmbeddedCanonicalHash(t *testing.T) {
	// Verify embedded statechain genesis parses and hashes cleanly.
	data := EmbeddedGenesisJSON()
	block, err := ParseGenesis(data)
	if err != nil {
		t.Fatalf("ParseGenesis embedded: %v", err)
	}

	hash, err := HashBlock(block)
	if err != nil {
		t.Fatalf("HashBlock embedded: %v", err)
	}
	if block.Hash != hash {
		t.Fatalf("embedded genesis hash mismatch: got %s, want %s", block.Hash, hash)
	}

	// Forced CRLF embedded JSON.
	crlfData := bytes.ReplaceAll(bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n")),
		[]byte("\n"), []byte("\r\n"))
	blockCRLF, err := ParseGenesis(crlfData)
	if err != nil {
		t.Fatalf("ParseGenesis CRLF: %v", err)
	}
	hashCRLF, err := HashBlock(blockCRLF)
	if err != nil {
		t.Fatalf("HashBlock CRLF: %v", err)
	}
	if hashCRLF != hash {
		t.Fatalf("embedded hashCRLF mismatch: got %s, want %s", hashCRLF, hash)
	}
}
