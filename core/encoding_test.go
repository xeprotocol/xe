package core

import (
	"strings"
	"testing"
)

// TestMultisigPoWNonceRoundTrip verifies that UnmarshalBlock correctly decodes
// the 8-byte PoWNonce for multisig_open and multisig_update blocks (#100).
func TestMultisigPoWNonceRoundTrip(t *testing.T) {
	key1 := strings.Repeat("11", 32)
	key2 := strings.Repeat("22", 32)

	multisigTypes := []BlockType{BlockMultisigOpen, BlockMultisigUpdate}

	for _, bType := range multisigTypes {
		t.Run(string(bType), func(t *testing.T) {
			b := &Block{
				Type:           bType,
				Asset:          "XE",
				Account:        strings.Repeat("aa", 32),
				Previous:       strings.Repeat("bb", 32),
				Balance:        1000000,
				Timestamp:      1730000000,
				Representative: strings.Repeat("cc", 32),
				MSKeyset: &Keyset{
					Threshold: 2,
					Keys:      []string{key1, key2},
				},
				PoWNonce: 0xDEADBEEF, // 3735928559
			}

			data, err := MarshalBlock(b)
			if err != nil {
				t.Fatalf("MarshalBlock failed: %v", err)
			}

			// Expected size: 1 (version) + 1 (type) + 8 (asset) + 32 (account) + 32 (prev) +
			// 8 (balance) + 8 (timestamp) + 4 (threshold) + 4 (count) + 64 (2 keys) +
			// 32 (rep) + 8 (PoWNonce) = 202 bytes
			expectedLen := 1 + 1 + 8 + 32 + 32 + 8 + 8 + 8 + 64 + 32 + 8
			if len(data) != expectedLen {
				t.Fatalf("expected encoded length %d, got %d", expectedLen, len(data))
			}

			decoded, err := UnmarshalBlock(data)
			if err != nil {
				t.Fatalf("UnmarshalBlock failed: %v", err)
			}

			if decoded.PoWNonce != b.PoWNonce {
				t.Fatalf("PoWNonce mismatch: got %d (0x%x), want %d (0x%x)",
					decoded.PoWNonce, decoded.PoWNonce, b.PoWNonce, b.PoWNonce)
			}

			if decoded.Type != bType {
				t.Errorf("Type mismatch: got %v, want %v", decoded.Type, bType)
			}

			if decoded.MSKeyset == nil {
				t.Fatalf("decoded MSKeyset is nil")
			}

			if decoded.MSKeyset.Threshold != 2 || len(decoded.MSKeyset.Keys) != 2 {
				t.Fatalf("keyset mismatch: threshold=%d, keys=%d",
					decoded.MSKeyset.Threshold, len(decoded.MSKeyset.Keys))
			}
		})
	}
}

// TestGeneralBlocksPoWNonceRoundTrip checks that PoWNonce is preserved across
// standard block types after tailOffset computation changes.
func TestGeneralBlocksPoWNonceRoundTrip(t *testing.T) {
	testCases := []struct {
		name  string
		block *Block
	}{
		{
			name: "SendBlockWithMemo",
			block: &Block{
				Type:           BlockSend,
				Asset:          "XE",
				Account:        strings.Repeat("11", 32),
				Previous:       strings.Repeat("22", 32),
				Balance:        500000,
				Timestamp:      1730000001,
				Destination:    strings.Repeat("33", 32),
				Amount:         100000,
				Representative: strings.Repeat("44", 32),
				Memo:           "payment ref 123",
				PoWNonce:       9988776655,
			},
		},
		{
			name: "ReceiveBlock",
			block: &Block{
				Type:           BlockReceive,
				Asset:          "XE",
				Account:        strings.Repeat("11", 32),
				Previous:       strings.Repeat("22", 32),
				Balance:        600000,
				Timestamp:      1730000002,
				Source:         strings.Repeat("55", 32),
				Representative: strings.Repeat("44", 32),
				PoWNonce:       1122334455,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := MarshalBlock(tc.block)
			if err != nil {
				t.Fatalf("MarshalBlock failed: %v", err)
			}

			decoded, err := UnmarshalBlock(data)
			if err != nil {
				t.Fatalf("UnmarshalBlock failed: %v", err)
			}

			if decoded.PoWNonce != tc.block.PoWNonce {
				t.Fatalf("PoWNonce mismatch: got %d, want %d", decoded.PoWNonce, tc.block.PoWNonce)
			}
		})
	}
}
