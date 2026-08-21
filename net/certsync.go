package net

import (
	"context"
	"encoding/json"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/xeprotocol/xe/perf"

	"github.com/xeprotocol/xe/logging"
)

const (
	// CertRequestMsgType is the Messenger message type a node uses to ask a
	// peer for the performance certificates it currently holds.
	CertRequestMsgType = "cert_request"

	// certPullTimeout bounds a single on-connect certificate pull.
	certPullTimeout = 10 * time.Second

	// certSweepInterval paces the background pull from rotating connected
	// peers, the backstop for missed on-connect pulls (#630).
	certSweepInterval = 2 * time.Minute

	// certPullMaxResponse caps how many certificates a peer serves in one
	// response, keeping the reply comfortably under MsgMaxResponseSize. The
	// network holds at most one cert per provider, so this is a generous
	// ceiling that simply guards against an unbounded reply.
	certPullMaxResponse = 256
)

// SetupCertSync wires provider-performance-certificate exchange over the
// Messenger so that a node which restarts (or joins late) can obtain the
// certificates it needs to validate cert-referencing lease blocks immediately
// on connecting to a peer, instead of waiting for the periodic gossip
// rebroadcast (see #502).
//
//   - provide() returns the certificates this node currently holds, to serve
//     to a requesting peer (its own cert plus everything cached from peers).
//   - ingest(cert) is called for each certificate received from a peer; it is
//     responsible for verification and caching — the same path used by the
//     gossip handler — and returns true if the certificate was newly cached.
//
// On every new peer connection this node pulls that peer's certificates. The
// pull is best-effort: if the peer doesn't answer (e.g. it is still starting
// up, or predates this protocol), the gossip rebroadcast remains the backstop.
func SetupCertSync(ctx context.Context, h host.Host, msg *Messenger, provide func() []*perf.Certificate, ingest func(*perf.Certificate) bool) {
	msg.Handle(CertRequestMsgType, func(_ peer.ID, _ json.RawMessage) (json.RawMessage, error) {
		certs := provide()
		if len(certs) > certPullMaxResponse {
			certs = certs[:certPullMaxResponse]
		}
		return json.Marshal(certs)
	})

	h.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(_ network.Network, conn network.Conn) {
			pid := conn.RemotePeer()
			go pullCertsFrom(ctx, msg, pid, ingest)
		},
	})

	// Periodic sweep: pull from one connected peer every certSweepInterval.
	// The on-connect pull is a single shot per connection — if it races the
	// peer's startup (or the response is lost) nothing retries it, and a
	// cold-syncing node is then permanently starved of the certificates its
	// lease history references (#630). The sweep makes cert delivery
	// eventually-consistent at negligible cost.
	go func() {
		ticker := time.NewTicker(certSweepInterval)
		defer ticker.Stop()
		i := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			peers := h.Network().Peers()
			if len(peers) == 0 {
				continue
			}
			pullCertsFrom(ctx, msg, peers[i%len(peers)], ingest)
			i++
		}
	}()
}

// pullCertsFrom requests the certificates a peer holds and ingests each one.
func pullCertsFrom(ctx context.Context, msg *Messenger, pid peer.ID, ingest func(*perf.Certificate) bool) {
	// Retry with backoff: a single pull fired from the connect notification
	// often races the peer's protocol setup and fails silently, and without
	// an active gossip republisher there is no backstop — the cold node then
	// never obtains the certs its lease history needs (#630).
	var lastErr error
	for attempt, delay := 0, time.Duration(0); attempt < 3; attempt, delay = attempt+1, delay*2+5*time.Second {
		if delay > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}
		reqCtx, cancel := context.WithTimeout(ctx, certPullTimeout)
		raw, err := msg.Request(reqCtx, pid, CertRequestMsgType, nil)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}

		var certs []*perf.Certificate
		if err := json.Unmarshal(raw, &certs); err != nil {
			logging.Warnf("certsync: decode certs from %s: %v", pid.ShortString(), err)
			return
		}

		cached := 0
		for _, cert := range certs {
			if cert != nil && ingest(cert) {
				cached++
			}
		}
		if cached > 0 {
			logging.Debugf("certsync: pulled %d new cert(s) from %s on connect", cached, pid.ShortString())
		}
		return
	}
	logging.Warnf("certsync: cert pull from %s failed after retries: %v", pid.ShortString(), lastErr)
}
