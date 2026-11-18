package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestOutboundHTTPClientTimeoutConfigured(t *testing.T) {
	if outboundHTTPClient == nil {
		t.Fatal("expected outboundHTTPClient to be initialized, got nil")
	}
	expectedTimeout := 30 * time.Second
	if outboundHTTPClient.Timeout != expectedTimeout {
		t.Fatalf("expected outboundHTTPClient.Timeout to be %v, got %v", expectedTimeout, outboundHTTPClient.Timeout)
	}
}

func TestOutboundHTTPClientTimesOutOnNeverRespondingNode(t *testing.T) {
	done := make(chan struct{})

	// Simulate black-hole node that accepts TCP connection and headers but never writes back
	neverRespondingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-done:
			return
		case <-r.Context().Done():
			return
		}
	}))
	defer neverRespondingServer.Close()
	defer close(done) // runs before server.Close() due to LIFO defer execution

	// Exercise production outboundHTTPClient directly
	origTimeout := outboundHTTPClient.Timeout
	defer func() { outboundHTTPClient.Timeout = origTimeout }()
	outboundHTTPClient.Timeout = 100 * time.Millisecond

	// 1. Test POST request (exercised by cmdLeaseRenew)
	req, err := http.NewRequestWithContext(context.Background(), "POST", neverRespondingServer.URL+"/lease/test/renew", nil)
	if err != nil {
		t.Fatalf("unexpected error creating request: %v", err)
	}

	start := time.Now()
	_, err = outboundHTTPClient.Do(req)
	duration := time.Since(start)

	if err == nil {
		t.Fatal("expected outboundHTTPClient.Do to fail on never-responding server, got nil error")
	}

	if !os.IsTimeout(err) && !strings.Contains(err.Error(), "Client.Timeout exceeded") && !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("expected timeout error from outboundHTTPClient, got: %v", err)
	}

	if duration < 80*time.Millisecond || duration > 2000*time.Millisecond {
		t.Fatalf("expected timeout around 100ms, took %v", duration)
	}

	// 2. Test Post call (exercised by cmdFaucet)
	start = time.Now()
	_, err = outboundHTTPClient.Post(neverRespondingServer.URL+"/request", "application/json", strings.NewReader(`{"address":"test"}`))
	duration = time.Since(start)

	if err == nil {
		t.Fatal("expected outboundHTTPClient.Post to fail on never-responding server, got nil error")
	}

	if !os.IsTimeout(err) && !strings.Contains(err.Error(), "Client.Timeout exceeded") && !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("expected timeout error from outboundHTTPClient.Post, got: %v", err)
	}
}
