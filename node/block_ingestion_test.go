package node

import (
	"strings"
	"testing"

	"github.com/xeprotocol/xe/core"
)

func TestHandleIncomingRecoversFromMalformedBlockAndContinues(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	otherKP, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Intentionally leave Ledger nil on the first block to trigger a nil-pointer panic inside AddBlock,
	// proving handleIncoming recovers per-block and continues draining the channel.
	n := &Node{
		KeyPair: kp,
	}

	ch := make(chan *core.Block, 3)
	ch <- nil
	ch <- &core.Block{
		Type:      core.BlockMultisigOpen,
		Account:   otherKP.Address(),
		Previous:  "0",
		Hash:      strings.Repeat("a", 64),
		Signature: strings.Repeat("b", 128),
		Signatures: []core.BlockSignature{
			{PublicKey: "abcde", Sig: strings.Repeat("c", 128)},
		},
	}
	close(ch)

	n.handleIncoming(ch)
}
