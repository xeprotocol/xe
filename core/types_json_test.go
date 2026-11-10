package core

import (
	"encoding/json"
	"testing"
)

func TestBlock_UnmarshalJSON_NumericAndString64BitFields(t *testing.T) {
	const (
		expectedTimestamp = int64(1781801279942067170)
		expectedNonce     = uint64(10051993738983095315)
		expectedBalance   = uint64(9007199254740999)
		expectedAmount    = uint64(9007199254740995)
		expectedAttTs     = int64(1781801279942067999)
	)

	// 1. Quoted string representation (used by JS/OpenAPI clients to avoid IEEE-754 2^53 rounding)
	strJSON := `{
		"type": "send",
		"account": "f6c78bbb04",
		"previous": "0",
		"balance": "9007199254740999",
		"timestamp": "1781801279942067170",
		"asset": "XE",
		"destination": "47815b6f77",
		"amount": "9007199254740995",
		"pow_nonce": "10051993738983095315",
		"hash": "a1d201",
		"attestations": [
			{"public_key": "aa", "timestamp": "1781801279942067999", "signature": "bb"}
		]
	}`

	var bFromStr Block
	if err := json.Unmarshal([]byte(strJSON), &bFromStr); err != nil {
		t.Fatalf("failed to unmarshal block with string 64-bit fields: %v", err)
	}
	if bFromStr.Timestamp != expectedTimestamp {
		t.Fatalf("timestamp mismatch: got %d, want %d", bFromStr.Timestamp, expectedTimestamp)
	}
	if bFromStr.PoWNonce != expectedNonce {
		t.Fatalf("pow_nonce mismatch: got %d, want %d", bFromStr.PoWNonce, expectedNonce)
	}
	if bFromStr.Balance != expectedBalance {
		t.Fatalf("balance mismatch: got %d, want %d", bFromStr.Balance, expectedBalance)
	}
	if bFromStr.Amount != expectedAmount {
		t.Fatalf("amount mismatch: got %d, want %d", bFromStr.Amount, expectedAmount)
	}
	if len(bFromStr.Attestations) != 1 || bFromStr.Attestations[0].Timestamp != expectedAttTs {
		t.Fatalf("attestation timestamp mismatch: got %+v, want %d", bFromStr.Attestations, expectedAttTs)
	}

	// 2. Standard JSON number representation
	numJSON := `{
		"type": "send",
		"account": "f6c78bbb04",
		"previous": "0",
		"balance": 9007199254740999,
		"timestamp": 1781801279942067170,
		"asset": "XE",
		"destination": "47815b6f77",
		"amount": 9007199254740995,
		"pow_nonce": 10051993738983095315,
		"hash": "a1d201",
		"attestations": [
			{"public_key": "aa", "timestamp": 1781801279942067999, "signature": "bb"}
		]
	}`

	var bFromNum Block
	if err := json.Unmarshal([]byte(numJSON), &bFromNum); err != nil {
		t.Fatalf("failed to unmarshal block with numeric 64-bit fields: %v", err)
	}
	if bFromNum.Timestamp != expectedTimestamp || bFromNum.PoWNonce != expectedNonce || bFromNum.Balance != expectedBalance || bFromNum.Amount != expectedAmount {
		t.Fatalf("numeric unmarshal mismatch: %+v", bFromNum)
	}

	// 3. Round-trip hash verification on a real signed block with >2^53 timestamp and pow_nonce
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	orig := &Block{
		Type:        BlockSend,
		Account:     kp.Address(),
		Previous:    "0",
		PubKey:      kp.PubKeyHex(),
		Balance:     expectedBalance,
		Timestamp:   expectedTimestamp,
		Asset:       "XE",
		Destination: kp.Address(),
		Amount:      100,
		PoWNonce:    expectedNonce,
	}
	if err := SignBlock(orig, kp); err != nil {
		t.Fatalf("SignBlock: %v", err)
	}

	// Re-unmarshal from quoted strings and verify HashBlock + VerifyBlock succeed
	quotedPayload, err := json.Marshal(map[string]any{
		"type":        orig.Type,
		"account":     orig.Account,
		"previous":    orig.Previous,
		"pub_key":     orig.PubKey,
		"balance":     "9007199254740999",
		"timestamp":   "1781801279942067170",
		"asset":       orig.Asset,
		"destination": orig.Destination,
		"amount":      "100",
		"pow_nonce":   "10051993738983095315",
		"signature":   orig.Signature,
		"hash":        orig.Hash,
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded Block
	if err := json.Unmarshal(quotedPayload, &decoded); err != nil {
		t.Fatalf("json.Unmarshal quoted payload: %v", err)
	}
	gotHash, err := HashBlock(&decoded)
	if err != nil {
		t.Fatalf("HashBlock: %v", err)
	}
	if gotHash != orig.Hash {
		t.Fatalf("hash mismatch after string unmarshal: got %s, want %s", gotHash, orig.Hash)
	}
	if err := VerifyBlock(&decoded); err != nil {
		t.Fatalf("VerifyBlock failed after string unmarshal: %v", err)
	}
}
