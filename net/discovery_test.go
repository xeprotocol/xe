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
	// Replicates Issue #201 scenario:
	// Attacker opens 24 inbound connections (target=24).
	// With peerCount(), total connections (24) halted discovery rounds permanently.
	// With outboundPeerCount(), only outbound connections count towards target.
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

	// Total peers is 26 (24 inbound sybil + 2 outbound honest)
	if ad.peerCount() != 26 {
		t.Fatalf("expected 26 total peers, got %d", ad.peerCount())
	}

	// Prior to fix, peerCount() >= target (26 >= 24) would permanently halt discovery.
	// With outboundPeerCount(), only 2 outbound peers are counted.
	outbound := ad.outboundPeerCount()
	if outbound != 2 {
		t.Fatalf("expected 2 outbound peers, got %d", outbound)
	}

	if outbound >= ad.target {
		t.Fatalf("expected outbound (%d) < target (%d), discovery should continue", outbound, ad.target)
	}
}

func TestOutboundPeerCount_DeduplicatesMultipleConns(t *testing.T) {
	// Test that multiple connections to the same peer (e.g. 1 inbound + 1 outbound,
	// or 2 outbound) are deduplicated correctly.
	peerA := peer.ID("peer-A")
	peerB := peer.ID("peer-B")

	conns := []network.Conn{
		&mockDiscoveryConn{remote: peerA, dir: network.DirInbound},
		&mockDiscoveryConn{remote: peerA, dir: network.DirOutbound},
		&mockDiscoveryConn{remote: peerB, dir: network.DirOutbound},
		&mockDiscoveryConn{remote: peerB, dir: network.DirOutbound},
	}

	mockNet := &mockDiscoveryNetwork{conns: conns}
	mockH := &mockDiscoveryHost{net: mockNet}

	ad := &AmbientDiscovery{
		host:   mockH,
		target: 24,
	}

	if count := ad.outboundPeerCount(); count != 2 {
		t.Fatalf("expected 2 unique outbound peers, got %d", count)
	}
}

func TestOutboundPeerCount_TargetReachedStopsDiscovery(t *testing.T) {
	// When target outbound peers is reached, discovery pauses as expected.
	var conns []network.Conn
	for i := 0; i < 24; i++ {
		p := peer.ID([]byte(string(rune(3000 + i))))
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

	if count := ad.outboundPeerCount(); count != 24 {
		t.Fatalf("expected 24 outbound peers, got %d", count)
	}

	if ad.outboundPeerCount() < ad.target {
		t.Fatalf("expected outbound (%d) >= target (%d)", ad.outboundPeerCount(), ad.target)
	}
}
