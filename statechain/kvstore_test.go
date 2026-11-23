package statechain

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateSysTimekeepers(t *testing.T) {
	key1 := hex.EncodeToString(make([]byte, 32))
	key2Bytes := make([]byte, 32)
	key2Bytes[0] = 0x01
	key2 := hex.EncodeToString(key2Bytes)

	makePayload := func(keys []string, threshold int) json.RawMessage {
		data, _ := json.Marshal(map[string]any{
			"keys":      keys,
			"threshold": threshold,
		})
		return data
	}

	tests := []struct {
		name        string
		keys        []string
		threshold   int
		wantErrSub  string
	}{
		{
			name:       "valid 2-of-2 timekeepers",
			keys:       []string{key1, key2},
			threshold:  2,
			wantErrSub: "",
		},
		{
			name:       "reject empty keys",
			keys:       []string{},
			threshold:  1,
			wantErrSub: "at least one key",
		},
		{
			name:       "reject threshold 0",
			keys:       []string{key1},
			threshold:  0,
			wantErrSub: "threshold",
		},
		{
			name:       "reject threshold exceeding key count",
			keys:       []string{key1},
			threshold:  2,
			wantErrSub: "threshold",
		},
		{
			name:       "reject invalid key length",
			keys:       []string{"0123456789abcdef"},
			threshold:  1,
			wantErrSub: "invalid length",
		},
		{
			name:       "reject non-hex characters in key",
			keys:       []string{strings.Repeat("z", 64)},
			threshold:  1,
			wantErrSub: "invalid hex",
		},
		{
			name:       "reject duplicate timekeeper keys",
			keys:       []string{key1, key1},
			threshold:  2,
			wantErrSub: "is a duplicate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := makePayload(tt.keys, tt.threshold)
			err := validateSysKeyValue("sys.timekeepers", payload)
			if tt.wantErrSub == "" {
				if err != nil {
					t.Fatalf("expected nil error, got %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErrSub)
				}
				if !strings.Contains(err.Error(), tt.wantErrSub) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErrSub, err)
				}
			}
		})
	}
}
