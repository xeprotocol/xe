package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/logging"
)

type sshGatewayBackend interface {
	GetLease(hash string) *core.Lease
	PeerForAccount(account string) peer.ID
	OpenTunnel(ctx context.Context, providerPeer peer.ID, leaseHash string) (io.ReadWriteCloser, error)
}

const (
	maxSSHConnections    = 100
	maxPreAuthPerIP      = 10
	sshHandshakeDeadline = 15 * time.Second
)

type SSHGateway struct {
	listener   net.Listener
	hostKey    ssh.Signer
	backend    sshGatewayBackend
	wg         sync.WaitGroup
	done       chan struct{}
	connSem    chan struct{}
	ipMu       sync.Mutex
	preAuthIPs map[string]int
}

func NewSSHGateway(listenAddr string, dataDir string, backend sshGatewayBackend) (*SSHGateway, error) {
	hostKey, err := loadOrCreateHostKey(filepath.Join(dataDir, "ssh_host_key"))
	if err != nil {
		return nil, fmt.Errorf("ssh host key: %w", err)
	}

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("ssh listen: %w", err)
	}

	gw := &SSHGateway{
		listener:   listener,
		hostKey:    hostKey,
		backend:    backend,
		done:       make(chan struct{}),
		connSem:    make(chan struct{}, maxSSHConnections),
		preAuthIPs: make(map[string]int),
	}
	return gw, nil
}

func (gw *SSHGateway) Addr() net.Addr {
	return gw.listener.Addr()
}

func (gw *SSHGateway) Start() {
	gw.wg.Add(1)
	go func() {
		defer gw.wg.Done()
		for {
			conn, err := gw.listener.Accept()
			if err != nil {
				select {
				case <-gw.done:
					return
				default:
					log.Printf("ssh: accept error: %v", err)
					continue
				}
			}

			clientIP := clientIPFromConn(conn)
			if !gw.acquirePreAuth(clientIP) {
				logging.Warnf("ssh: pre-auth connection limit reached (%d) for %s, rejecting", maxPreAuthPerIP, clientIP)
				_ = conn.Close()
				continue
			}

			select {
			case gw.connSem <- struct{}{}:
			default:
				gw.releasePreAuth(clientIP)
				logging.Warnf("ssh: connection limit reached (%d), rejecting", maxSSHConnections)
				_ = conn.Close()
				continue
			}
			gw.wg.Add(1)
			go func(c net.Conn, ip string) {
				defer gw.wg.Done()
				defer func() { <-gw.connSem }()
				gw.handleConnection(c, ip)
			}(conn, clientIP)
		}
	}()
}

func (gw *SSHGateway) Stop() {
	close(gw.done)
	_ = gw.listener.Close()
	gw.wg.Wait()
}

func (gw *SSHGateway) handleConnection(conn net.Conn, clientIP string) {
	defer func() { _ = conn.Close() }()

	var releaseOnce sync.Once
	releasePreAuthSlot := func() {
		releaseOnce.Do(func() {
			gw.releasePreAuth(clientIP)
		})
	}
	defer releasePreAuthSlot()

	// Enforce handshake timeout to prevent connection slot exhaustion by silent clients
	_ = conn.SetDeadline(time.Now().Add(sshHandshakeDeadline))

	var authenticatedLease *core.Lease

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(connMeta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			leaseHash := connMeta.User()
			if len(leaseHash) != 64 {
				return nil, fmt.Errorf("invalid lease hash")
			}

			lease := gw.backend.GetLease(leaseHash)
			if lease == nil {
				return nil, fmt.Errorf("lease not found")
			}

			if lease.State != core.LeaseAccepted {
				return nil, fmt.Errorf("lease not active")
			}
			if lease.AccessPubKey == "" {
				return nil, fmt.Errorf("lease has no ssh key")
			}

			presentedKey := key.Marshal()
			ed25519Key, ok := extractED25519Key(presentedKey)
			if !ok {
				return nil, fmt.Errorf("not an ed25519 key")
			}

			leaseKeyBytes, err := core.DecodePublicKey(lease.AccessPubKey)
			if err != nil {
				return nil, fmt.Errorf("invalid lease ssh key")
			}

			if !bytes.Equal(ed25519Key, leaseKeyBytes) {
				return nil, fmt.Errorf("key mismatch")
			}

			authenticatedLease = lease
			return &ssh.Permissions{}, nil
		},
	}
	config.AddHostKey(gw.hostKey)

	serverConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	releasePreAuthSlot()
	if err != nil {
		return
	}
	defer func() { _ = serverConn.Close() }()

	// Clear handshake deadline for active authenticated session
	_ = conn.SetDeadline(time.Time{})

	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		switch newChan.ChannelType() {
		case "session":
			channel, requests, err := newChan.Accept()
			if err != nil {
				continue
			}
			go gw.handleSession(channel, requests, authenticatedLease)

		case "direct-tcpip":
			channel, _, err := newChan.Accept()
			if err != nil {
				continue
			}
			go gw.handleDirectTCPIP(channel, authenticatedLease)

		default:
			_ = newChan.Reject(ssh.UnknownChannelType, "unsupported channel type")
		}
	}
}

func (gw *SSHGateway) handleDirectTCPIP(channel ssh.Channel, lease *core.Lease) {
	defer func() { _ = channel.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		select {
		case <-gw.done:
			cancel()
		case <-ctx.Done():
		}
	}()

	providerPeer := gw.backend.PeerForAccount(lease.Provider)
	if providerPeer == "" {
		return
	}

	tunnel, err := gw.backend.OpenTunnel(ctx, providerPeer, lease.LeaseHash)
	if err != nil {
		return
	}
	defer func() { _ = tunnel.Close() }()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(channel, tunnel) }()
	go func() { defer wg.Done(); _, _ = io.Copy(tunnel, channel) }()
	wg.Wait()
}

func (gw *SSHGateway) handleSession(channel ssh.Channel, requests <-chan *ssh.Request, lease *core.Lease) {
	defer func() { _ = channel.Close() }()

	for req := range requests {
		switch req.Type {
		case "pty-req", "env", "window-change":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}

		case "shell", "exec":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			_, _ = io.WriteString(channel.Stderr(), gw.jumpHint(lease.LeaseHash))
			sendExitStatus(channel, 1)
			return

		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func (gw *SSHGateway) jumpHint(leaseHash string) string {
	port := 2222
	if tcp, ok := gw.listener.Addr().(*net.TCPAddr); ok {
		port = tcp.Port
	}
	return fmt.Sprintf("This XE gateway forwards SSH to your VM; it does not open a shell itself.\r\n"+
		"Connect to the VM through it:\r\n\r\n"+
		"  ssh -i <lease key> -J %s@<gateway host>:%d root@vm\r\n\r\n"+
		"or: xe ssh %s\r\n", leaseHash, port, leaseHash)
}

func sendExitStatus(channel ssh.Channel, code uint32) {
	payload := []byte{byte(code >> 24), byte(code >> 16), byte(code >> 8), byte(code)}
	_, _ = channel.SendRequest("exit-status", false, payload)
}

func extractED25519Key(marshaledKey []byte) ([]byte, bool) {

	if len(marshaledKey) < 4 {
		return nil, false
	}
	keyTypeLen := int(marshaledKey[0])<<24 | int(marshaledKey[1])<<16 | int(marshaledKey[2])<<8 | int(marshaledKey[3])
	if len(marshaledKey) < 4+keyTypeLen+4 {
		return nil, false
	}
	keyType := string(marshaledKey[4 : 4+keyTypeLen])
	if keyType != "ssh-ed25519" {
		return nil, false
	}
	off := 4 + keyTypeLen
	keyLen := int(marshaledKey[off])<<24 | int(marshaledKey[off+1])<<16 | int(marshaledKey[off+2])<<8 | int(marshaledKey[off+3])
	off += 4
	if len(marshaledKey) < off+keyLen || keyLen != 32 {
		return nil, false
	}
	return marshaledKey[off : off+keyLen], true
}

func loadOrCreateHostKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse host key: %w", err)
		}
		return signer, nil
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate host key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}

	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, fmt.Errorf("marshal host key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create host key dir: %w", err)
	}

	pemBytes := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		return nil, fmt.Errorf("write host key: %w", err)
	}

	return signer, nil
}

func clientIPFromConn(conn net.Conn) string {
	if conn == nil {
		return ""
	}
	addr := conn.RemoteAddr()
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func (gw *SSHGateway) acquirePreAuth(ip string) bool {
	if ip == "" {
		return true
	}
	gw.ipMu.Lock()
	defer gw.ipMu.Unlock()
	if gw.preAuthIPs[ip] >= maxPreAuthPerIP {
		return false
	}
	gw.preAuthIPs[ip]++
	return true
}

func (gw *SSHGateway) releasePreAuth(ip string) {
	if ip == "" {
		return
	}
	gw.ipMu.Lock()
	defer gw.ipMu.Unlock()
	if count, ok := gw.preAuthIPs[ip]; ok {
		if count <= 1 {
			delete(gw.preAuthIPs, ip)
		} else {
			gw.preAuthIPs[ip]--
		}
	}
}
