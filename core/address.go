package core

import "fmt"

// VerifyPayloadKey checks that pubKeyHex is the verifying key for the account
// ADDRESS `account` — that is, DeriveAddress(pubKeyHex) == account (#829).
//
// Since an address is sha256("xe/account/v1" || pubkey) and no longer the key
// itself, every OFF-CHAIN signed payload that names an account — chat
// envelopes, directory registrations, performance certificates, marketplace
// advertisements/requests/offers, the chat ownership proof — must carry the
// signer's public key alongside the address. Those payloads travel gossip and
// ingress paths that have to stay stateless (they cannot ask the ledger who
// owns an address, and the account may have no chain at all), so they are made
// SELF-CERTIFYING instead: the key is bound into the payload's signed bytes,
// this check ties the key to the claimed address, and the signature check then
// ties the payload to the key.
//
// Order matters: call this BEFORE verifying the signature. A signature that
// verifies under an attacker-supplied key proves nothing about the account the
// payload claims.
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
