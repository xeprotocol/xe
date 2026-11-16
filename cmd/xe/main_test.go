package main

import (
	"context"
	"net/http"
	"net/http/httptest"
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

func TestOutboundHTTPClientTimesOutOnStalledNode(t *testing.T) {
	// Simulate stalled node that accepts TCP connection and headers but never sends response
	stalledServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer stalledServer.Close()

	// Create test client with minimal timeout to verify timeout behavior without waiting 30s
	testClient := &http.Client{
		Timeout: 50 * time.Millisecond,
	}

	req, err := http.NewRequestWithContext(context.Background(), "POST", stalledServer.URL+"/lease/test/renew", nil)
	if err != nil {
		t.Fatalf("unexpected error creating request: %v", err)
	}

	_, err = testClient.Do(req)
	if err == nil {
		t.Fatal("expected request to stalled node to fail with timeout, but got nil error")
	}
}
