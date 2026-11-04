package net

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

type mockDiscoveryHost struct {
	host.Host
	net network.Network
}

func (m *mockDiscoveryHost) Network() network.Network {
	return m.net
}

type mockDiscoveryNetwork struct {
	network.Network
	conns []network.Conn
}

func (m *mockDiscoveryNetwork) Conns() []network.Conn {
	return m.conns
}

func (m *mockDiscoveryNetwork) Peers() []peer.ID {
	pids := make(map[peer.ID]struct{})
	for _, c := range m.conns {
		pids[c.RemotePeer()] = struct{}{}
	}
	res := make([]peer.ID, 0, len(pids))
	for p := range pids {
		res = append(res, p)
	}
	return res
}

type mockDiscoveryConn struct {
	network.Conn
	remote peer.ID
	dir    network.Direction
}

func (c *mockDiscoveryConn) RemotePeer() peer.ID {
	return c.remote
}

func (c *mockDiscoveryConn) Stat() network.ConnStats {
	return network.ConnStats{
		Stats: network.Stats{
			Direction: c.dir,
		},
	}
}

func TestOutboundPeerCount_PreventsInboundSybilSuppression(t *testing.T) {
	// Create 24 inbound connections (sybil attack) and 2 outbound connections.
	var conns []network.Conn
	for i := 0; i < 24; i++ {
		p := peer.ID([]byte(string(rune(1000 + i))))
		conns = append(conns, &mockDiscoveryConn{
			remote: p,
			dir:    network.DirInbound,
		})
	}

	for i := 0; i < 2; i++ {
		p := peer.ID([]byte(string(rune(2000 + i))))
		conns = append(conns, &mockDiscoveryConn{
			remote: p,
			dir:    network.DirOutbound,
		})
	}

	mockNet := &mockDiscoveryNetwork{conns: conns}
	mockH := &mockDiscoveryHost{net: mockNet}

	ad := &AmbientDiscovery{
		host:   mockH,
		target: 24,
	}

	// Total peers is 26
	if ad.peerCount() != 26 {
		t.Fatalf("expected 26 total peers, got %d", ad.peerCount())
	}

	// Prior to fix, peerCount (26) >= target (24), so discovery would be completely suppressed!
	// With outboundPeerCount, only 2 outbound connections exist.
	if count := ad.outboundPeerCount(); count != 2 {
		t.Fatalf("expected 2 outbound peers, got %d", count)
	}

	// Outbound count must allow discovery to continue
	if ad.outboundPeerCount() >= ad.target {
		t.Fatalf("expected outboundPeerCount (%d) < target (%d)", ad.outboundPeerCount(), ad.target)
	}
}
