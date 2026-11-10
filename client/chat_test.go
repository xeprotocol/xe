package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xeprotocol/xe/chat"
)

func TestChatPoWDifficulty_RejectsZero(t *testing.T) {
	for _, adv := range []string{"0", "0000000000000000"} {
		adv := adv
		t.Run(adv, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"chat_pow_difficulty": adv,
				})
			}))
			defer srv.Close()

			c := New(srv.URL)
			_, err := c.ChatPoWDifficulty()
			if err == nil {
				t.Fatalf("expected error when node advertises %q, got nil", adv)
			}
			if !strings.Contains(err.Error(), "cannot be zero") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestChatPoWDifficultyWithFloor_EnforcesMinimum(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"chat_pow_difficulty": "0000000000000010",
		})
	}))
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.ChatPoWDifficultyWithFloor(chat.MinPoWDifficulty)
	if err == nil {
		t.Fatalf("expected error when advertised difficulty is below floor")
	}
	if !strings.Contains(err.Error(), "below minimum floor") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestChatPoWDifficulty_AcceptsDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"chat_pow_difficulty": "ffffc00000000000",
		})
	}))
	defer srv.Close()

	c := New(srv.URL)
	diff, err := c.ChatPoWDifficultyWithFloor(chat.MinPoWDifficulty)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff != chat.DefaultPoWDifficulty {
		t.Fatalf("expected 0x%x, got 0x%x", chat.DefaultPoWDifficulty, diff)
	}
}
