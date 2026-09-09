package core

import "fmt"

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
