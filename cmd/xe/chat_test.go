package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xeprotocol/xe/client"
	"github.com/xeprotocol/xe/core"
)

func TestChatSend_DifficultyCapEnforced(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/node":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"chat_pow_difficulty": "fffffffffffffff0",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	c := client.New(server.URL)
	_, err = chatSend(c, kp, kp.Address(), "test message")
	if err == nil {
		t.Fatalf("expected chatSend to fail on malicious PoW difficulty, got nil")
	}

	if !strings.Contains(err.Error(), "exceeds maximum allowed difficulty") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestChatSend_Success(t *testing.T) {
	var chatReceived bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/node":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"chat_pow_difficulty": fmt.Sprintf("%016x", core.TestDifficulty),
			})
		case "/chat/send":
			chatReceived = true
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	c := client.New(server.URL)
	id, err := chatSend(c, kp, kp.Address(), "test message")
	if err != nil {
		t.Fatalf("chatSend failed: %v", err)
	}

	if id == "" {
		t.Errorf("expected non-empty message ID")
	}
	if !chatReceived {
		t.Errorf("expected server to receive /chat/send request")
	}
}
