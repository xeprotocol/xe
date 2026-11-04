package node

import (
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/directory"
)

func TestHandleDirectoryGossipDoesNotPanicOnShortNodePeerOrNil(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	now := time.Now().UnixNano()

	n := &Node{
		Directory: directory.New(directory.DefaultTTL),
	}

	ch := make(chan *directory.Registration, 5)
	ch <- nil
	ch <- directory.NewRegistration("A", now, kp)
	ch <- directory.NewRegistration("abc", now+1, kp)
	const validPeer = "12D3KooWGgkhY5EXnz9xCVEee4UNAMFPMVe8SzqpQNgwwdn4ChMs"
	ch <- directory.NewRegistration(validPeer, now+2, kp)
	close(ch)

	n.handleDirectoryGossip(ch)

	got := n.LookupDirectory(kp.Address())
	if got == nil || got.NodePeer != validPeer {
		t.Fatalf("expected valid registration to be stored after malformed entries, got %+v", got)
	}
}
