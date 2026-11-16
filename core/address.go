package core

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ValidateAddress checks that an address is a valid 32-byte (64 hex character)
// hex string and returns the canonical lowercased address.
func ValidateAddress(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", errors.New("missing address")
	}
	if len(addr) != 64 {
		return "", errors.New("invalid address: must be 64 hex characters")
	}
	if _, err := hex.DecodeString(addr); err != nil {
		return "", errors.New("invalid address: must be valid hex")
	}
	return strings.ToLower(addr), nil
}

func VerifyPayloadKey(pubKeyHex, account string) error {
	if pubKeyHex == "" {
		return fmt.Errorf("missing public key")
	}
	if account == "" {
		return fmt.Errorf("missing account")
	}
	derived, err := DeriveAddress(pubKeyHex)
	if err != nil {
		return err
	}
	if derived != account {
		return fmt.Errorf("public key does not derive account %s", account)
	}
	return nil
}
