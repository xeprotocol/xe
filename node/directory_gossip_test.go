package node

import (
	"strings"
	"testing"
	"time"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/directory"
)

func TestVerifyRegistration_RejectsShortNodePeer(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	reg := directory.NewRegistration("short-peer", time.Now().UnixNano(), kp)
	err = directory.VerifyRegistration(reg)
	if err == nil {
		t.Fatal("expected error for NodePeer with length < 12, got nil")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Fatalf("unexpected error message: %v", err)
	}

	validPeer := "12D3KooWDpJ7As7BWAwRMfu1VU2WCqnjvq387JEYKDBj4kx6nXTN"
	validReg := directory.NewRegistration(validPeer, time.Now().UnixNano(), kp)
	if err := directory.VerifyRegistration(validReg); err != nil {
		t.Fatalf("expected valid registration to succeed, got %v", err)
	}
}

func TestHandleDirectoryGossip_SafeWithShortNodePeer(t *testing.T) {
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Short NodePeer (< 12 characters, e.g. "a")
	shortPeer := "a"
	reg := directory.NewRegistration(shortPeer, time.Now().UnixNano(), kp)

	n := &Node{
		Directory: directory.New(time.Hour),
	}

	regs := make(chan *directory.Registration, 1)
	regs <- reg
	close(regs)

	// Must not panic on short NodePeer
	n.handleDirectoryGossip(regs)
}
