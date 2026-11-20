package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xeprotocol/xe/chat"
)

func TestChatPoWDifficulty_Valid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/node" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"chat_pow_difficulty": "ffffc00000000000",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	c := New(server.URL)
	diff, err := c.ChatPoWDifficulty()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff != chat.DefaultPoWDifficulty {
		t.Errorf("expected 0x%x, got 0x%x", chat.DefaultPoWDifficulty, diff)
	}
}

func TestChatPoWDifficulty_ExceedsMaxDifficulty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/node" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"chat_pow_difficulty": "fffffffffffffff0",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	c := New(server.URL)
	_, err := c.ChatPoWDifficulty()
	if err == nil {
		t.Fatalf("expected error for difficulty exceeding MaxPoWDifficulty, got nil")
	}

	if !strings.Contains(err.Error(), "exceeds maximum allowed difficulty") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestChatPoWDifficulty_MissingOrInvalid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/node" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"chat_pow_difficulty": "",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	c := New(server.URL)
	_, err := c.ChatPoWDifficulty()
	if err == nil {
		t.Fatalf("expected error for empty difficulty, got nil")
	}

	invalidServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/node" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"chat_pow_difficulty": "not-a-hex",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer invalidServer.Close()

	cInvalid := New(invalidServer.URL)
	_, err = cInvalid.ChatPoWDifficulty()
	if err == nil {
		t.Fatalf("expected error for non-hex difficulty, got nil")
	}
}
