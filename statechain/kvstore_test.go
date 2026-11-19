package statechain

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func generateTestHexKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pubHex := hex.EncodeToString(pub)
	return priv, pubHex
}

func generateMixedCaseHexKey(t *testing.T) (ed25519.PrivateKey, string, string) {
	t.Helper()
	for {
		priv, pubHex := generateTestHexKey(t)
		upper := strings.ToUpper(pubHex)
		if pubHex != upper {
			return priv, pubHex, upper
		}
	}
}

func TestDAOKeysetValidation_CaseSensitivity(t *testing.T) {
	_, k1Lower, k1Upper := generateMixedCaseHexKey(t)
	_, k2Lower, _ := generateMixedCaseHexKey(t)

	tests := []struct {
		name        string
		keys        []string
		threshold   int
		wantErr     bool
		errContains string
	}{
		{
			name:        "reject identical case duplicates [K, K]",
			keys:        []string{k1Lower, k1Lower},
			threshold:   2,
			wantErr:     true,
			errContains: "dao_keyset key[1] is a duplicate",
		},
		{
			name:        "reject case-insensitive duplicates [K, UPPER(K)] - Issue #363 bypass attempt",
			keys:        []string{k1Lower, k1Upper},
			threshold:   2,
			wantErr:     true,
			errContains: "dao_keyset key[1] is a duplicate",
		},
		{
			name:        "reject case-insensitive duplicates [UPPER(K), K]",
			keys:        []string{k1Upper, k1Lower},
			threshold:   2,
			wantErr:     true,
			errContains: "dao_keyset key[1] is a duplicate",
		},
		{
			name:        "reject duplicate in larger keyset [K1, K2, UPPER(K1)]",
			keys:        []string{k1Lower, k2Lower, k1Upper},
			threshold:   2,
			wantErr:     true,
			errContains: "dao_keyset key[2] is a duplicate",
		},
		{
			name:      "accept valid distinct keys [K1, K2]",
			keys:      []string{k1Lower, k2Lower},
			threshold: 2,
			wantErr:   false,
		},
		{
			name:        "reject below minimum threshold",
			keys:        []string{k1Lower, k2Lower},
			threshold:   1,
			wantErr:     true,
			errContains: fmt.Sprintf("below minimum %d", MinDAOThreshold),
		},
		{
			name:        "reject threshold exceeding key count",
			keys:        []string{k1Lower, k2Lower},
			threshold:   3,
			wantErr:     true,
			errContains: "threshold 3 exceeds key count 2",
		},
		{
			name:        "reject empty keyset",
			keys:        []string{},
			threshold:   2,
			wantErr:     true,
			errContains: "must have at least one key",
		},
		{
			name:        "reject invalid length key",
			keys:        []string{k1Lower[:60], k2Lower},
			threshold:   2,
			wantErr:     true,
			errContains: "invalid length: got 60, want 64",
		},
		{
			name:        "reject invalid hex key",
			keys:        []string{"zz" + k1Lower[2:], k2Lower},
			threshold:   2,
			wantErr:     true,
			errContains: "invalid hex",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(DAOKeyset{
				Keys:      tc.keys,
				Threshold: tc.threshold,
			})
			if err != nil {
				t.Fatalf("json.Marshal failed: %v", err)
			}

			op := Op{
				Action: ActionSet,
				Key:    "sys.dao_keyset",
				Value:  raw,
			}
			err = ValidateOp(op)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errContains)
				}
				if !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("expected error containing %q, got %q", tc.errContains, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestTimekeepersValidation_CaseSensitivity(t *testing.T) {
	_, k1Lower, k1Upper := generateMixedCaseHexKey(t)
	_, k2Lower, _ := generateMixedCaseHexKey(t)

	tests := []struct {
		name        string
		keys        []string
		threshold   int
		wantErr     bool
		errContains string
	}{
		{
			name:        "reject identical duplicates [K, K]",
			keys:        []string{k1Lower, k1Lower},
			threshold:   1,
			wantErr:     true,
			errContains: "timekeepers key[1] is a duplicate",
		},
		{
			name:        "reject case-insensitive duplicates [K, UPPER(K)]",
			keys:        []string{k1Lower, k1Upper},
			threshold:   1,
			wantErr:     true,
			errContains: "timekeepers key[1] is a duplicate",
		},
		{
			name:      "accept valid distinct keys",
			keys:      []string{k1Lower, k2Lower},
			threshold: 2,
			wantErr:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(struct {
				Keys      []string `json:"keys"`
				Threshold int      `json:"threshold"`
			}{
				Keys:      tc.keys,
				Threshold: tc.threshold,
			})
			if err != nil {
				t.Fatalf("json.Marshal failed: %v", err)
			}

			op := Op{
				Action: ActionSet,
				Key:    "sys.timekeepers",
				Value:  raw,
			}
			err = ValidateOp(op)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errContains)
				}
				if !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("expected error containing %q, got %q", tc.errContains, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestMinterValidation_CaseSensitivity(t *testing.T) {
	_, k1Lower, k1Upper := generateMixedCaseHexKey(t)
	_, k2Lower, _ := generateMixedCaseHexKey(t)

	tests := []struct {
		name        string
		keys        []string
		wantErr     bool
		errContains string
	}{
		{
			name:        "reject identical duplicates [K, K]",
			keys:        []string{k1Lower, k1Lower},
			wantErr:     true,
			errContains: "minter key[1] is a duplicate",
		},
		{
			name:        "reject case-insensitive duplicates [K, UPPER(K)]",
			keys:        []string{k1Lower, k1Upper},
			wantErr:     true,
			errContains: "minter key[1] is a duplicate",
		},
		{
			name:    "accept valid distinct keys",
			keys:    []string{k1Lower, k2Lower},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(struct {
				Keys []string `json:"keys"`
			}{
				Keys: tc.keys,
			})
			if err != nil {
				t.Fatalf("json.Marshal failed: %v", err)
			}

			op := Op{
				Action: ActionSet,
				Key:    "sys.minter",
				Value:  raw,
			}
			err = ValidateOp(op)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errContains)
				}
				if !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("expected error containing %q, got %q", tc.errContains, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestOracleValidation_CaseSensitivity(t *testing.T) {
	_, k1Lower, k1Upper := generateMixedCaseHexKey(t)
	_, k2Lower, _ := generateMixedCaseHexKey(t)

	tests := []struct {
		name        string
		keys        []string
		threshold   int
		prefix      string
		wantErr     bool
		errContains string
	}{
		{
			name:        "reject identical duplicates [K, K]",
			keys:        []string{k1Lower, k1Lower},
			threshold:   1,
			prefix:      "epoch.",
			wantErr:     true,
			errContains: "oracle key[1] is a duplicate",
		},
		{
			name:        "reject case-insensitive duplicates [K, UPPER(K)]",
			keys:        []string{k1Lower, k1Upper},
			threshold:   1,
			prefix:      "epoch.",
			wantErr:     true,
			errContains: "oracle key[1] is a duplicate",
		},
		{
			name:      "accept valid distinct keys",
			keys:      []string{k1Lower, k2Lower},
			threshold: 1,
			prefix:    "epoch.",
			wantErr:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(OracleConfig{
				Keys:          tc.keys,
				Threshold:     tc.threshold,
				AllowedPrefix: tc.prefix,
			})
			if err != nil {
				t.Fatalf("json.Marshal failed: %v", err)
			}

			op := Op{
				Action: ActionSet,
				Key:    "sys.oracle",
				Value:  raw,
			}
			err = ValidateOp(op)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errContains)
				}
				if !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("expected error containing %q, got %q", tc.errContains, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestRepresentativesValidation_CaseSensitivity(t *testing.T) {
	_, k1Lower, k1Upper := generateMixedCaseHexKey(t)
	_, k2Lower, _ := generateMixedCaseHexKey(t)

	tests := []struct {
		name        string
		mode        string
		addresses   []string
		wantErr     bool
		errContains string
	}{
		{
			name:        "reject identical duplicate addresses [A, A]",
			mode:        RepModeAllowlist,
			addresses:   []string{k1Lower, k1Lower},
			wantErr:     true,
			errContains: "representatives address[1] is a duplicate",
		},
		{
			name:        "reject case-insensitive duplicate addresses [A, UPPER(A)]",
			mode:        RepModeAllowlist,
			addresses:   []string{k1Lower, k1Upper},
			wantErr:     true,
			errContains: "representatives address[1] is a duplicate",
		},
		{
			name:      "accept valid distinct addresses",
			mode:      RepModeAllowlist,
			addresses: []string{k1Lower, k2Lower},
			wantErr:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(RepresentativeConfig{
				Mode:      tc.mode,
				Addresses: tc.addresses,
			})
			if err != nil {
				t.Fatalf("json.Marshal failed: %v", err)
			}

			op := Op{
				Action: ActionSet,
				Key:    "sys.representatives",
				Value:  raw,
			}
			err = ValidateOp(op)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errContains)
				}
				if !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("expected error containing %q, got %q", tc.errContains, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestLowercaseKeys_Normalization(t *testing.T) {
	_, k1Lower, k1Upper := generateMixedCaseHexKey(t)
	_, k2Lower, k2Upper := generateMixedCaseHexKey(t)

	kv := NewKVStore()
	daoRaw, _ := json.Marshal(DAOKeyset{
		Keys:      []string{k1Upper, k2Upper},
		Threshold: 2,
	})
	kv.ApplyOps([]Op{{Action: ActionSet, Key: "sys.dao_keyset", Value: daoRaw}})

	storedDao, err := kv.DAOKeyset()
	if err != nil {
		t.Fatalf("DAOKeyset() failed: %v", err)
	}
	if storedDao.Keys[0] != k1Lower || storedDao.Keys[1] != k2Lower {
		t.Errorf("expected keys normalized to lowercase: got %v, want [%s %s]", storedDao.Keys, k1Lower, k2Lower)
	}

	oracleRaw, _ := json.Marshal(OracleConfig{
		Keys:          []string{k1Upper},
		Threshold:     1,
		AllowedPrefix: "epoch.",
	})
	kv.ApplyOps([]Op{{Action: ActionSet, Key: "sys.oracle", Value: oracleRaw}})

	storedOracle, err := kv.OracleConfig()
	if err != nil {
		t.Fatalf("OracleConfig() failed: %v", err)
	}
	if storedOracle.Keys[0] != k1Lower {
		t.Errorf("expected oracle key normalized to lowercase: got %s, want %s", storedOracle.Keys[0], k1Lower)
	}

	repRaw, _ := json.Marshal(RepresentativeConfig{
		Mode:      RepModeAllowlist,
		Addresses: []string{k1Upper},
	})
	kv.ApplyOps([]Op{{Action: ActionSet, Key: "sys.representatives", Value: repRaw}})

	storedRep, err := kv.Representatives()
	if err != nil {
		t.Fatalf("Representatives() failed: %v", err)
	}
	if storedRep.Addresses[0] != k1Lower {
		t.Errorf("expected rep address normalized to lowercase: got %s, want %s", storedRep.Addresses[0], k1Lower)
	}
}

func TestDAOKeyset_DefenseInDepthGetter(t *testing.T) {
	_, k1Lower, k1Upper := generateMixedCaseHexKey(t)

	kv := NewKVStore()
	// Manually inject unnormalized duplicates into kv.data
	raw := json.RawMessage(fmt.Sprintf(`{"keys":["%s","%s"],"threshold":2}`, k1Lower, k1Upper))
	kv.data["sys.dao_keyset"] = raw

	_, err := kv.DAOKeyset()
	if err == nil {
		t.Fatal("expected DAOKeyset() to reject duplicate keys, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected error containing 'duplicate', got %q", err.Error())
	}
}

func TestOracleConfig_DefenseInDepthGetter(t *testing.T) {
	_, k1Lower, k1Upper := generateMixedCaseHexKey(t)

	kv := NewKVStore()
	raw := json.RawMessage(fmt.Sprintf(`{"keys":["%s","%s"],"threshold":1,"allowed_prefix":"epoch."}`, k1Lower, k1Upper))
	kv.data["sys.oracle"] = raw

	_, err := kv.OracleConfig()
	if err == nil {
		t.Fatal("expected OracleConfig() to reject duplicate keys, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected error containing 'duplicate', got %q", err.Error())
	}
}
