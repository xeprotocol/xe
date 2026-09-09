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
	CertRequestMsgType = "cert_request"

	certPullTimeout = 10 * time.Second

	certSweepInterval = 2 * time.Minute

	certPullMaxResponse = 256
)

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

func pullCertsFrom(ctx context.Context, msg *Messenger, pid peer.ID, ingest func(*perf.Certificate) bool) {

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
