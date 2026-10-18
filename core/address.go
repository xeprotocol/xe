package core

import "fmt"

func ValidateAddress(addr string) error {
	if len(addr) != 64 {
		return fmt.Errorf("invalid address length: got %d, want 64 hex chars", len(addr))
	}
	for i := 0; i < len(addr); i++ {
		c := addr[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("invalid address: must be 64 lowercase hex chars")
		}
	}
	return nil
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
