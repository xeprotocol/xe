package core_test

import (
	"reflect"
	"testing"

	"github.com/xeprotocol/xe/core"
)

func encKey(t *testing.T) *core.KeyPair {
	t.Helper()
	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return kp
}

func TestEncoding_MultisigPoWNonceRoundTrip(t *testing.T) {
	key1 := encKey(t).PubKeyHex()
	key2 := encKey(t).PubKeyHex()
	keys := []string{key1, key2}
	if keys[0] > keys[1] {
		keys[0], keys[1] = keys[1], keys[0]
	}
	ks := &core.Keyset{
		Threshold: 2,
		Keys:      keys,
	}

	for _, bType := range []core.BlockType{core.BlockMultisigOpen, core.BlockMultisigUpdate} {
		t.Run(string(bType), func(t *testing.T) {
			orig := &core.Block{
				Type:           bType,
				Asset:          "XE",
				Account:        encKey(t).Address(),
				Previous:       "0",
				Balance:        1000000,
				Timestamp:      core.Now().UnixNano(),
				Representative: encKey(t).Address(),
				MSKeyset:       ks,
				PoWNonce:       0xdeadbeef,
			}

			encoded, err := core.MarshalBlock(orig)
			if err != nil {
				t.Fatalf("MarshalBlock failed: %v", err)
			}

			decoded, err := core.UnmarshalBlock(encoded)
			if err != nil {
				t.Fatalf("UnmarshalBlock failed: %v", err)
			}

			if decoded.PoWNonce != orig.PoWNonce {
				t.Fatalf("PoWNonce mismatch: got %d (0x%x), want %d (0x%x)",
					decoded.PoWNonce, decoded.PoWNonce, orig.PoWNonce, orig.PoWNonce)
			}
		})
	}
}

func TestEncoding_LeaseRenewRoundTrip(t *testing.T) {
	orig := &core.Block{
		Type:            core.BlockLeaseRenew,
		Asset:           "XE",
		Account:         encKey(t).Address(),
		Previous:        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Balance:         5000000,
		Timestamp:       core.Now().UnixNano(),
		Representative:  encKey(t).Address(),
		Source:          "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		Amount:          2000000,
		Duration:        3600,
		LockedR:         100,
		LockedPayoutCap: 200,
		LockedTWAP:      300,
		PoWNonce:        0x123456789abcdef0,
	}

	encoded, err := core.MarshalBlock(orig)
	if err != nil {
		t.Fatalf("MarshalBlock(BlockLeaseRenew) failed: %v", err)
	}

	decoded, err := core.UnmarshalBlock(encoded)
	if err != nil {
		t.Fatalf("UnmarshalBlock(BlockLeaseRenew) failed: %v", err)
	}

	if decoded.Type != orig.Type {
		t.Errorf("Type mismatch: got %s, want %s", decoded.Type, orig.Type)
	}
	if decoded.Source != orig.Source {
		t.Errorf("Source mismatch: got %s, want %s", decoded.Source, orig.Source)
	}
	if decoded.Amount != orig.Amount {
		t.Errorf("Amount mismatch: got %d, want %d", decoded.Amount, orig.Amount)
	}
	if decoded.Duration != orig.Duration {
		t.Errorf("Duration mismatch: got %d, want %d", decoded.Duration, orig.Duration)
	}
	if decoded.LockedR != orig.LockedR {
		t.Errorf("LockedR mismatch: got %d, want %d", decoded.LockedR, orig.LockedR)
	}
	if decoded.LockedPayoutCap != orig.LockedPayoutCap {
		t.Errorf("LockedPayoutCap mismatch: got %d, want %d", decoded.LockedPayoutCap, orig.LockedPayoutCap)
	}
	if decoded.LockedTWAP != orig.LockedTWAP {
		t.Errorf("LockedTWAP mismatch: got %d, want %d", decoded.LockedTWAP, orig.LockedTWAP)
	}
	if decoded.PoWNonce != orig.PoWNonce {
		t.Errorf("PoWNonce mismatch: got %d, want %d", decoded.PoWNonce, orig.PoWNonce)
	}
}

func TestEncoding_AllBlockTypesRoundTrip(t *testing.T) {
	rep := encKey(t).Address()
	source := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	prev := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	acc := encKey(t).Address()
	now := core.Now().UnixNano()

	key1 := encKey(t).PubKeyHex()
	key2 := encKey(t).PubKeyHex()
	keys := []string{key1, key2}
	if keys[0] > keys[1] {
		keys[0], keys[1] = keys[1], keys[0]
	}
	ks := &core.Keyset{
		Threshold: 2,
		Keys:      keys,
	}

	blocks := []*core.Block{
		{
			Type:           core.BlockGenesis,
			Asset:          "XE",
			Account:        acc,
			Previous:       "0",
			Balance:        42000000,
			Timestamp:      now,
			Representative: rep,
			PoWNonce:       42,
		},
		{
			Type:           core.BlockSend,
			Asset:          "XE",
			Account:        acc,
			Previous:       prev,
			Balance:        10000,
			Amount:         5000,
			Destination:    encKey(t).Address(),
			Timestamp:      now,
			Representative: rep,
			Memo:           "test memo",
			PoWNonce:       101,
		},
		{
			Type:           core.BlockReceive,
			Asset:          "XE",
			Account:        acc,
			Previous:       prev,
			Balance:        15000,
			Source:         source,
			Timestamp:      now,
			Representative: rep,
			PoWNonce:       102,
		},
		{
			Type:           core.BlockMultisigOpen,
			Asset:          "XE",
			Account:        acc,
			Previous:       "0",
			Balance:        20000,
			Timestamp:      now,
			Representative: rep,
			MSKeyset:       ks,
			PoWNonce:       104,
		},
		{
			Type:           core.BlockMultisigUpdate,
			Asset:          "XE",
			Account:        acc,
			Previous:       prev,
			Balance:        20000,
			Timestamp:      now,
			Representative: rep,
			MSKeyset:       ks,
			PoWNonce:       105,
		},
		{
			Type:           core.BlockLease,
			Asset:          "XE",
			Account:        acc,
			Previous:       prev,
			Balance:        30000,
			Timestamp:      now,
			Representative: rep,
			Source:         source,
			Destination:    encKey(t).Address(),
			Amount:         1000,
			Duration:       3600,
			PoWNonce:       106,
		},
		{
			Type:            core.BlockLeaseAccept,
			Asset:           "XE",
			Account:         acc,
			Previous:        prev,
			Balance:         30000,
			Timestamp:       now,
			Representative:  rep,
			Source:          source,
			Amount:          1000,
			LockedR:         10,
			LockedPayoutCap: 20,
			LockedTWAP:      30,
			PoWNonce:        107,
		},
		{
			Type:            core.BlockLeaseSettle,
			Asset:           "XE",
			Account:         acc,
			Previous:        prev,
			Balance:         30000,
			Timestamp:       now,
			Representative:  rep,
			Source:          source,
			Amount:          1000,
			PoWNonce:        108,
		},
		{
			Type:           core.BlockLeaseCancel,
			Asset:          "XE",
			Account:        acc,
			Previous:       prev,
			Balance:        30000,
			Timestamp:      now,
			Representative: rep,
			Source:         source,
			PoWNonce:       109,
		},
		{
			Type:           core.BlockLeaseForceSettle,
			Asset:          "XE",
			Account:        acc,
			Previous:       prev,
			Balance:        30000,
			Timestamp:      now,
			Representative: rep,
			Source:         source,
			PoWNonce:       110,
		},
		{
			Type:           core.BlockBurn,
			Asset:          "XE",
			Account:        acc,
			Previous:       prev,
			Balance:        5000,
			Amount:         5000,
			Timestamp:      now,
			Representative: rep,
			Memo:           "burn memo",
			PoWNonce:       111,
		},
		{
			Type:           core.BlockMint,
			Asset:          "XE",
			Account:        acc,
			Previous:       "0",
			Balance:        100000,
			Amount:         100000,
			Timestamp:      now,
			Representative: rep,
			PoWNonce:       112,
		},
		{
			Type:            core.BlockLeaseRenew,
			Asset:           "XE",
			Account:         acc,
			Previous:        prev,
			Balance:         50000,
			Timestamp:       now,
			Representative:  rep,
			Source:          source,
			Amount:          2000,
			Duration:        7200,
			LockedR:         11,
			LockedPayoutCap: 22,
			LockedTWAP:      33,
			PoWNonce:        113,
		},
	}

	for _, b := range blocks {
		t.Run(string(b.Type), func(t *testing.T) {
			enc, err := core.MarshalBlock(b)
			if err != nil {
				t.Fatalf("MarshalBlock failed: %v", err)
			}
			dec, err := core.UnmarshalBlock(enc)
			if err != nil {
				t.Fatalf("UnmarshalBlock failed: %v", err)
			}
			if dec.Type != b.Type {
				t.Errorf("Type mismatch: got %s, want %s", dec.Type, b.Type)
			}
			if dec.PoWNonce != b.PoWNonce {
				t.Errorf("PoWNonce mismatch: got %d, want %d", dec.PoWNonce, b.PoWNonce)
			}
			if dec.Balance != b.Balance {
				t.Errorf("Balance mismatch: got %d, want %d", dec.Balance, b.Balance)
			}
			if dec.Amount != b.Amount {
				t.Errorf("Amount mismatch: got %d, want %d", dec.Amount, b.Amount)
			}
			if dec.Account != b.Account {
				t.Errorf("Account mismatch: got %s, want %s", dec.Account, b.Account)
			}
			if dec.Previous != b.Previous {
				t.Errorf("Previous mismatch: got %s, want %s", dec.Previous, b.Previous)
			}
			if dec.Representative != b.Representative {
				t.Errorf("Representative mismatch: got %s, want %s", dec.Representative, b.Representative)
			}
			if b.MSKeyset != nil {
				if dec.MSKeyset == nil || !reflect.DeepEqual(dec.MSKeyset, b.MSKeyset) {
					t.Errorf("MSKeyset mismatch: got %+v, want %+v", dec.MSKeyset, b.MSKeyset)
				}
			}
		})
	}
}
