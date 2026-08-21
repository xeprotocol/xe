package net

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

const TunnelProtocol = protocol.ID("/xe/tunnel/2.0.0")

const tunnelHandshakeDeadline = 30 * time.Second

type TunnelValidator interface {
	// ValidateTunnelLease checks that the lease is valid and that the
	// connecting peer is authorized to use it.
	ValidateTunnelLease(leaseHash string, peerID peer.ID) error
	DialSSH(leaseHash string) (net.Conn, error)
}

// TunnelRegistry tracks active tunnel connections per lease hash so they can
// be torn down when a lease is settled.
type TunnelRegistry struct {
	mu      sync.Mutex
	tunnels map[string][]io.Closer // leaseHash → active connections
}

// NewTunnelRegistry creates an empty registry.
func NewTunnelRegistry() *TunnelRegistry {
	return &TunnelRegistry{tunnels: make(map[string][]io.Closer)}
}

func (r *TunnelRegistry) add(leaseHash string, c io.Closer) {
	r.mu.Lock()
	r.tunnels[leaseHash] = append(r.tunnels[leaseHash], c)
	r.mu.Unlock()
}

func (r *TunnelRegistry) remove(leaseHash string, c io.Closer) {
	r.mu.Lock()
	conns := r.tunnels[leaseHash]
	for i, conn := range conns {
		if conn == c {
			r.tunnels[leaseHash] = append(conns[:i], conns[i+1:]...)
			break
		}
	}
	if len(r.tunnels[leaseHash]) == 0 {
		delete(r.tunnels, leaseHash)
	}
	r.mu.Unlock()
}

// CloseTunnelsForLease closes all active tunnel connections for the given lease.
func (r *TunnelRegistry) CloseTunnelsForLease(leaseHash string) {
	r.mu.Lock()
	conns := r.tunnels[leaseHash]
	delete(r.tunnels, leaseHash)
	r.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func SetupTunnelHandler(h host.Host, validator TunnelValidator, registry *TunnelRegistry) {
	h.SetStreamHandler(TunnelProtocol, func(s network.Stream) {
		defer func() { _ = s.Close() }()

		_ = s.SetDeadline(time.Now().Add(tunnelHandshakeDeadline))

		var leaseBytes [32]byte
		if _, err := io.ReadFull(s, leaseBytes[:]); err != nil {
			log.Printf("tunnel: read lease hash: %v", err)
			writeTunnelError(s, "read lease hash: "+err.Error())
			return
		}
		leaseHash := hex.EncodeToString(leaseBytes[:])

		if err := validator.ValidateTunnelLease(leaseHash, s.Conn().RemotePeer()); err != nil {
			log.Printf("tunnel: invalid lease %s: %v", leaseHash[:16], err)
			writeTunnelError(s, err.Error())
			return
		}

		backend, err := validator.DialSSH(leaseHash)
		if err != nil {
			log.Printf("tunnel: dial ssh for %s: %v", leaseHash[:16], err)
			writeTunnelError(s, err.Error())
			return
		}
		defer func() { _ = backend.Close() }()

		if _, err := s.Write([]byte{0x00}); err != nil {
			log.Printf("tunnel: write ok: %v", err)
			return
		}

		_ = s.SetDeadline(time.Time{})

		registry.add(leaseHash, s)
		defer registry.remove(leaseHash, s)

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			_, _ = io.Copy(s, backend)
			if rs, ok := s.(interface{ CloseWrite() error }); ok {
				_ = rs.CloseWrite()
			}
		}()

		go func() {
			defer wg.Done()
			_, _ = io.Copy(backend, s)
			_ = backend.Close()
		}()

		wg.Wait()
	})
}

func writeTunnelError(s network.Stream, msg string) {
	buf := make([]byte, 1+len(msg))
	buf[0] = 0x01
	copy(buf[1:], msg)
	_, _ = s.Write(buf)
}

func OpenTunnel(ctx context.Context, h host.Host, d *dht.IpfsDHT, providerPeerID peer.ID, leaseHash string) (io.ReadWriteCloser, error) {
	if d != nil && len(h.Peerstore().Addrs(providerPeerID)) == 0 {
		pi, err := d.FindPeer(ctx, providerPeerID)
		if err != nil {
			return nil, fmt.Errorf("tunnel: find peer %s: %w", providerPeerID.ShortString(), err)
		}
		if err := h.Connect(ctx, pi); err != nil {
			return nil, fmt.Errorf("tunnel: connect to %s: %w", providerPeerID.ShortString(), err)
		}
	}

	s, err := h.NewStream(ctx, providerPeerID, TunnelProtocol)
	if err != nil {
		return nil, fmt.Errorf("tunnel: open stream: %w", err)
	}

	_ = s.SetDeadline(time.Now().Add(tunnelHandshakeDeadline))

	leaseBytes, err := hex.DecodeString(leaseHash)
	if err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("tunnel: decode lease hash: %w", err)
	}
	if len(leaseBytes) != 32 {
		_ = s.Close()
		return nil, fmt.Errorf("tunnel: lease hash must be 32 bytes, got %d", len(leaseBytes))
	}

	if _, err := s.Write(leaseBytes); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("tunnel: write lease hash: %w", err)
	}

	var status [1]byte
	if _, err := io.ReadFull(s, status[:]); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("tunnel: read status: %w", err)
	}

	if status[0] == 0x01 {
		errMsg, _ := io.ReadAll(io.LimitReader(s, 4096))
		_ = s.Close()
		return nil, fmt.Errorf("tunnel: provider error: %s", string(errMsg))
	}

	if status[0] != 0x00 {
		_ = s.Close()
		return nil, fmt.Errorf("tunnel: unexpected status byte: 0x%02x", status[0])
	}

	_ = s.SetDeadline(time.Time{})

	return s, nil
}
