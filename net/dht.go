package net

import (
	"context"
	"fmt"
	"log"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/protocol"
)

// SetupDHT creates and bootstraps a Kademlia DHT instance for the host.
// It uses server mode so this node participates in routing.
// The protocol prefix isolates our DHT from the public IPFS DHT.
func SetupDHT(ctx context.Context, h host.Host) (*dht.IpfsDHT, error) {
	d, err := dht.New(ctx, h,
		dht.Mode(dht.ModeServer),
		dht.ProtocolPrefix(protocol.ID("/xe")),
	)
	if err != nil {
		return nil, fmt.Errorf("new dht: %w", err)
	}

	if err := d.Bootstrap(ctx); err != nil {
		return nil, fmt.Errorf("dht bootstrap: %w", err)
	}

	log.Printf("DHT bootstrapped (server mode, prefix /xe)")
	return d, nil
}
