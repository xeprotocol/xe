package net

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

func TestCheckPeer_GenesisHashRequirement(t *testing.T) {
	oursWithGenesis := netcheckMsg{
		NetworkID:   "testnet",
		Version:     "1.0.0",
		GenesisHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	oursWithoutGenesis := netcheckMsg{
		NetworkID: "testnet",
		Version:   "1.0.0",
	}

	tests := []struct {
		name       string
		ours       netcheckMsg
		remote     netcheckMsg
		wantReject bool
		wantBan    time.Duration
	}{
		{
			name: "Remote peer omits genesis_hash when local has genesis -> rejected and banned",
			ours: oursWithGenesis,
			remote: netcheckMsg{
				NetworkID:   "testnet",
				Version:     "1.0.0",
				GenesisHash: "", // omitted
			},
			wantReject: true,
			wantBan:    defaultBanDur,
		},
		{
			name: "Remote peer provides mismatched genesis_hash -> rejected and banned",
			ours: oursWithGenesis,
			remote: netcheckMsg{
				NetworkID:   "testnet",
				Version:     "1.0.0",
				GenesisHash: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
			},
			wantReject: true,
			wantBan:    defaultBanDur,
		},
		{
			name: "Remote peer provides matching genesis_hash -> accepted",
			ours: oursWithGenesis,
			remote: netcheckMsg{
				NetworkID:   "testnet",
				Version:     "1.0.0",
				GenesisHash: oursWithGenesis.GenesisHash,
			},
			wantReject: false,
			wantBan:    0,
		},
		{
			name: "Local node has no genesis_hash yet -> genesis check skipped",
			ours: oursWithoutGenesis,
			remote: netcheckMsg{
				NetworkID:   "testnet",
				Version:     "1.0.0",
				GenesisHash: "",
			},
			wantReject: false,
			wantBan:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, banDur := checkPeer(tt.remote, tt.ours)
			if tt.wantReject {
				if reason == "" {
					t.Fatalf("expected rejection, got reason=\"\"")
				}
				if banDur != tt.wantBan {
					t.Errorf("got banDuration %v, want %v", banDur, tt.wantBan)
				}
			} else {
				if reason != "" {
					t.Fatalf("expected acceptance, got reason=%q", reason)
				}
				if banDur != 0 {
					t.Errorf("got banDuration %v, want 0", banDur)
				}
			}
		})
	}
}

func TestNetworkGater_IsAuthenticated(t *testing.T) {
	g := NewNetworkGater()
	pid1 := peer.ID("peer-test-1")
	pid2 := peer.ID("peer-test-2")
	pid3 := peer.ID("peer-test-3")

	// Untrusted peer with no capabilities recorded
	if g.IsAuthenticated(pid1) {
		t.Errorf("expected pid1 not to be authenticated initially")
	}

	// Trusted peer
	g.Trust(pid2)
	if !g.IsAuthenticated(pid2) {
		t.Errorf("expected trusted peer pid2 to be authenticated")
	}

	// Peer with recorded capabilities (passed netcheck)
	g.RecordPeerCapabilities(pid3, PeerCapabilities{Version: "1.0.0"})
	if !g.IsAuthenticated(pid3) {
		t.Errorf("expected peer pid3 with capabilities to be authenticated")
	}

	// Banned peer should not be authenticated
	g.Ban(pid3, 10*time.Minute)
	if g.IsAuthenticated(pid3) {
		t.Errorf("expected banned peer pid3 not to be authenticated")
	}
}
