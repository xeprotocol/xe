package net

import (
	"testing"

	"github.com/xeprotocol/xe/core"
)

func TestBlockQuarantineSignatureKeying(t *testing.T) {
	q := newBlockQuarantine()

	blockHash := "8e2f6ea9efc393baa95ee9fd811a958507e915c61f7c6ff559233a175055a79b"
	badSig := "bad_signature_from_malicious_peer_1"
	goodSig := "good_signature_from_honest_peer_2"

	badBlock := &core.Block{
		Hash:      blockHash,
		Signature: badSig,
	}

	goodBlock := &core.Block{
		Hash:      blockHash,
		Signature: goodSig,
	}

	badKey := blockQuarantineKey(badBlock)
	goodKey := blockQuarantineKey(goodBlock)

	if badKey == goodKey {
		t.Fatalf("Expected different quarantine keys for different signatures on same hash, got %q", badKey)
	}

	// 1. Bad block rejected and quarantined
	q.add(badKey)

	if !q.contains(badKey) {
		t.Fatalf("Expected bad block key to be quarantined")
	}

	// 2. Genuine block with same hash but valid signature must NOT be quarantined
	if q.contains(goodKey) {
		t.Fatalf("Poisoning detected: genuine block was suppressed by quarantine")
	}

	// 3. Multisig block signature handling
	msBlock := &core.Block{
		Hash: blockHash,
		Signatures: []core.BlockSignature{
			{Sig: "sig1"},
			{Sig: "sig2"},
		},
	}
	msKey := blockQuarantineKey(msBlock)
	if msKey == badKey || msKey == goodKey {
		t.Fatalf("Multisig key collision: %q", msKey)
	}
}
