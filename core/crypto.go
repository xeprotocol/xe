package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync/atomic"
)

type KeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

func (kp *KeyPair) PubKeyHex() string {
	return hex.EncodeToString(kp.Public)
}

const AccountAddressDomain = "xe/account/v1"

func DeriveAddress(pubKeyHex string) (string, error) {
	pub, err := DecodePublicKey(pubKeyHex)
	if err != nil {
		return "", fmt.Errorf("derive address: %w", err)
	}
	return deriveAddressFromKey(pub), nil
}

func deriveAddressFromKey(pub ed25519.PublicKey) string {
	h := sha256.New()
	h.Write([]byte(AccountAddressDomain))
	h.Write(pub)
	return hex.EncodeToString(h.Sum(nil))
}

func (kp *KeyPair) Address() string {
	return deriveAddressFromKey(kp.Public)
}

func MustDeriveAddress(pubKeyHex string) string {
	a, err := DeriveAddress(pubKeyHex)
	if err != nil {
		panic("MustDeriveAddress: " + err.Error())
	}
	return a
}

func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keygen: %w", err)
	}
	return &KeyPair{Public: pub, Private: priv}, nil
}

func KeyPairFromSeed(seed []byte) *KeyPair {
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &KeyPair{Public: pub, Private: priv}
}

func TryKeyPairFromSeed(seed []byte) (*KeyPair, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid seed length: got %d, want %d", len(seed), ed25519.SeedSize)
	}
	return KeyPairFromSeed(seed), nil
}

var networkID atomic.Pointer[[]byte]

func SetNetworkID(id string) {
	b := []byte(id)
	networkID.Store(&b)
}

func GetNetworkID() string {
	if p := networkID.Load(); p != nil {
		return string(*p)
	}
	return ""
}

func HashBlock(b *Block) (string, error) {
	data, err := MarshalBlockCanonical(b)
	if err != nil {
		return "", fmt.Errorf("HashBlock: %w", err)
	}
	h := sha256.New()
	if p := networkID.Load(); p != nil {
		h.Write(*p)
	}
	h.Write(data)

	h.Write(MarshalBlockAux(b))
	return hex.EncodeToString(h.Sum(nil)), nil
}

func SignBlock(b *Block, kp *KeyPair) error {
	if b.Previous == "0" && b.PubKey == "" && len(b.Signatures) == 0 &&
		b.Type != BlockMultisigOpen && b.Type != BlockMultisigUpdate {
		b.PubKey = kp.PubKeyHex()
	}
	hash, err := HashBlock(b)
	if err != nil {
		return err
	}
	b.Hash = hash
	hashBytes, err := DecodeHash(b.Hash)
	if err != nil {
		return fmt.Errorf("SignBlock: %w", err)
	}
	sig := ed25519.Sign(kp.Private, hashBytes)
	b.Signature = hex.EncodeToString(sig)
	return nil
}

func ValidatePubKeyDeclaration(b *Block) error {
	if len(b.Signatures) > 0 {
		if b.PubKey != "" {
			return fmt.Errorf("multisig block must not declare pub_key")
		}
		return nil
	}
	if b.Previous == "0" {
		if b.PubKey == "" {
			return fmt.Errorf("open block must declare pub_key")
		}
		derived, err := DeriveAddress(b.PubKey)
		if err != nil {
			return fmt.Errorf("invalid pub_key: %w", err)
		}
		if derived != b.Account {
			return fmt.Errorf("pub_key does not derive account address: derived %s, account %s", derived, b.Account)
		}
		return nil
	}
	if b.PubKey != "" {
		return fmt.Errorf("non-open block must not declare pub_key")
	}
	return nil
}

func VerifyBlock(b *Block) error {
	expected, err := HashBlock(b)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if b.Hash != expected {
		return fmt.Errorf("hash mismatch: got %s, want %s", b.Hash, expected)
	}

	if err := ValidatePubKeyDeclaration(b); err != nil {
		return err
	}

	if len(b.Signatures) > 0 {
		return nil
	}

	if b.Previous != "0" {
		return nil
	}

	return VerifyBlockSignatureWith(b, b.PubKey)
}

func VerifyBlockSignatureWith(b *Block, pubKeyHex string) error {
	hashBytes, err := DecodeHash(b.Hash)
	if err != nil {
		return err
	}
	return VerifyHexSignature(pubKeyHex, b.Signature, hashBytes)
}

func DecodePublicKey(hexStr string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid public key hex: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: got %d, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

func DecodeSignature(hexStr string) ([]byte, error) {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid signature hex: %w", err)
	}
	if len(b) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid signature length: got %d, want %d", len(b), ed25519.SignatureSize)
	}
	return b, nil
}

func DecodeHash(hexStr string) ([]byte, error) {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid hash hex: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("invalid hash length: got %d, want 32", len(b))
	}
	return b, nil
}

func VerifyHexSignature(pubKeyHex, sigHex string, message []byte) error {
	pub, err := DecodePublicKey(pubKeyHex)
	if err != nil {
		return err
	}
	sig, err := DecodeSignature(sigHex)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, message, sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func MustSignBlock(b *Block, kp *KeyPair) {
	if err := SignBlock(b, kp); err != nil {
		panic("MustSignBlock: " + err.Error())
	}
}

func MustSign(priv ed25519.PrivateKey, message []byte) string {
	sig := ed25519.Sign(priv, message)
	return hex.EncodeToString(sig)
}

func MustHashBlock(b *Block) string {
	h, err := HashBlock(b)
	if err != nil {
		panic("MustHashBlock: " + err.Error())
	}
	return h
}
