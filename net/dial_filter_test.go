package net

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

func TestDialFilterNonRoutableAddresses(t *testing.T) {
	g := &NetworkGater{}
	dummyPeer := peer.ID("testpeer123")

	blockedCases := []string{
		"/ip4/127.0.0.1/tcp/80",
		"/ip4/127.0.0.2/tcp/37427",
		"/ip4/169.254.169.254/tcp/80",
		"/ip4/10.0.0.5/tcp/22",
		"/ip4/192.168.1.1/tcp/443",
		"/ip4/172.16.0.1/tcp/8080",
		"/ip4/0.0.0.0/tcp/9000",
		"/ip6/::1/tcp/80",
		"/ip6/fe80::1/tcp/22",
		"/ip6/fc00::1/tcp/80",
	}

	for _, addrStr := range blockedCases {
		maddr, err := ma.NewMultiaddr(addrStr)
		if err != nil {
			t.Fatalf("failed to parse multiaddr %s: %v", addrStr, err)
		}
		if g.InterceptAddrDial(dummyPeer, maddr) {
			t.Errorf("expected InterceptAddrDial to block %s, but it was allowed", addrStr)
		}
	}

	allowedCases := []string{
		"/ip4/8.8.8.8/tcp/53",
		"/ip4/1.1.1.1/tcp/443",
		"/ip4/104.26.10.228/tcp/80",
		"/ip6/2001:4860:4860::8888/tcp/53",
	}

	for _, addrStr := range allowedCases {
		maddr, err := ma.NewMultiaddr(addrStr)
		if err != nil {
			t.Fatalf("failed to parse multiaddr %s: %v", addrStr, err)
		}
		if !g.InterceptAddrDial(dummyPeer, maddr) {
			t.Errorf("expected InterceptAddrDial to allow %s, but it was blocked", addrStr)
		}
	}
}

func TestDialFilterAllowPrivateAddrsOverride(t *testing.T) {
	g := &NetworkGater{AllowPrivateAddrs: true}
	dummyPeer := peer.ID("testpeer123")

	loopback, err := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/80")
	if err != nil {
		t.Fatal(err)
	}

	if !g.InterceptAddrDial(dummyPeer, loopback) {
		t.Errorf("expected AllowPrivateAddrs=true to allow loopback in dev mode")
	}
}
