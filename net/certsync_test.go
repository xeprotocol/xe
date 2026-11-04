package net

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/xeprotocol/xe/core"
	"github.com/xeprotocol/xe/perf"
)

func TestCertSync_CertRequestFiltersExpired(t *testing.T) {
	oldNow := core.Now
	defer func() { core.Now = oldNow }()

	fixedNow := int64(2_000_000_000_000)
	core.Now = func() time.Time { return time.Unix(0, fixedNow) }

	cValid, _ := createTestCert(t, fixedNow-1000, fixedNow+int64(time.Hour))
	cExpired, _ := createTestCert(t, fixedNow-2000, fixedNow-1000)

	msg := &Messenger{
		handlers: make(map[string]MsgHandler),
	}

	SetupCertSync(context.Background(), nil, msg, func() []*perf.Certificate {
		return []*perf.Certificate{cValid, cExpired}
	}, func(c *perf.Certificate) bool { return true })

	handler, ok := msg.handlers[CertRequestMsgType]
	if !ok {
		t.Fatalf("handler for %s not registered", CertRequestMsgType)
	}

	raw, err := handler(peer.ID(""), nil)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	var resp []*perf.Certificate
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if len(resp) != 1 {
		t.Fatalf("expected 1 unexpired cert, got %d", len(resp))
	}
	if resp[0].Hash != cValid.Hash {
		t.Fatalf("expected cert hash %s, got %s", cValid.Hash, resp[0].Hash)
	}
}

func TestCertSync_CertRequestCapsResponse(t *testing.T) {
	oldNow := core.Now
	defer func() { core.Now = oldNow }()

	fixedNow := int64(2_000_000_000_000)
	core.Now = func() time.Time { return time.Unix(0, fixedNow) }

	certs := make([]*perf.Certificate, 300)
	for i := 0; i < 300; i++ {
		c, _ := createTestCert(t, fixedNow-1000, fixedNow+int64(time.Hour))
		certs[i] = c
	}

	msg := &Messenger{
		handlers: make(map[string]MsgHandler),
	}

	SetupCertSync(context.Background(), nil, msg, func() []*perf.Certificate {
		return certs
	}, func(c *perf.Certificate) bool { return true })

	handler := msg.handlers[CertRequestMsgType]
	raw, err := handler(peer.ID(""), nil)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	var resp []*perf.Certificate
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(resp) != certPullMaxResponse {
		t.Fatalf("expected %d capped certs, got %d", certPullMaxResponse, len(resp))
	}
}
