package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync/atomic"
)

// KeyPair holds an ed25519 key pair.
type KeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// PubKeyHex returns the hex-encoded ed25519 public key. Since #829 this is the
// account's CREDENTIAL, not its identity — use Address() for the account address.
func (kp *KeyPair) PubKeyHex() string {
	return hex.EncodeToString(kp.Public)
}

// AccountAddressDomain is the domain-separation tag for single-key account
// address derivation (#605 tagging convention, #829). It can never collide with
// DeriveMultisigAddress, and the argument is about LENGTH, not leading bytes:
// this derivation always hashes exactly 45 bytes (13-byte tag + 32-byte key),
// while DeriveMultisigAddress always hashes 8+32n (threshold + key count + n
// keys, n ≥ 1). 8+32n is ≡ 8 (mod 32) and 45 is not, so the two pre-images can
// never be equal for any n — no assumption about key or threshold values is
// needed. Pinned by TestDeriveAddress_NoCollisionWithMultisig.
const AccountAddressDomain = "xe/account/v1"

// DeriveAddress computes a single-key account's address from its ed25519 public
// key:
//
//	address = sha256("xe/account/v1" || pubkey_32)
//
// Both inputs are fixed-length (the tag is a compile-time constant, the key is
// exactly 32 bytes), so the concatenation is unambiguous. The output is 32
// bytes, which is why the 32-byte account slot in the canonical block header
// survives this change unchanged (#829).
//
// Decoupling identity (the address) from the credential (the key) is what makes
// key rotation expressible at all: the address commits to the key rather than
// being it, exactly as DeriveMultisigAddress commits to a keyset. See #424.
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

// Address returns the key pair's account address (see DeriveAddress).
func (kp *KeyPair) Address() string {
	return deriveAddressFromKey(kp.Public)
}

// MustDeriveAddress is DeriveAddress, panicking on a malformed key. For tests
// and tooling that already hold a valid key.
func MustDeriveAddress(pubKeyHex string) string {
	a, err := DeriveAddress(pubKeyHex)
	if err != nil {
		panic("MustDeriveAddress: " + err.Error())
	}
	return a
}

// GenerateKeyPair creates a new random ed25519 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keygen: %w", err)
	}
	return &KeyPair{Public: pub, Private: priv}, nil
}

// KeyPairFromSeed recreates a key pair from a 32-byte seed (deterministic).
// Panics if seed is not exactly 32 bytes — use TryKeyPairFromSeed for
// untrusted input.
func KeyPairFromSeed(seed []byte) *KeyPair {
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &KeyPair{Public: pub, Private: priv}
}

// TryKeyPairFromSeed is like KeyPairFromSeed but returns an error instead
// of panicking when the seed length is invalid.
func TryKeyPairFromSeed(seed []byte) (*KeyPair, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid seed length: got %d, want %d", len(seed), ed25519.SeedSize)
	}
	return KeyPairFromSeed(seed), nil
}

// networkID is prepended to the block hash input to scope blocks to a
// specific network instance. Set once at startup via SetNetworkID().
// When unset (nil), hashing works without a network prefix
// (backward compatible for tests and tools that don't set it).
//
// Guarded by an atomic pointer so the write (SetNetworkID) and reads
// (GetNetworkID, HashBlock) are safe under concurrent access. In production
// a process hosts one node and SetNetworkID runs once at boot before any
// gossip goroutine starts, but in-process integration tests construct
// multiple nodes, racing a later write against live handler reads (#717).
var networkID atomic.Pointer[[]byte]

// SetNetworkID sets the network identifier used in all block hash
// computations. Must be called once at startup before any blocks are
// created or validated. The value is typically "testnet", "mainnet",
// or a deployment-specific identifier, stored as sys.network_id in
// the state chain.
func SetNetworkID(id string) {
	b := []byte(id)
	networkID.Store(&b)
}

// GetNetworkID returns the currently configured network identifier.
func GetNetworkID() string {
	if p := networkID.Load(); p != nil {
		return string(*p)
	}
	return ""
}

// HashBlock computes the SHA-256 hash of a block's canonical content,
// prefixed with the network ID. PoWNonce is excluded from the hash so
// it can be set after signing.
// Returns an error if the block cannot be encoded (e.g. malformed hex fields).
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
	// #570/H3+H4: bind the certificate hash and timekeeper attestations (which
	// are attached to lease-family blocks after the body and gate validation /
	// set the lease StartTime) into the hash, so they can't be tampered in
	// transit while keeping Hash and signature valid. Empty for non-lease blocks.
	h.Write(MarshalBlockAux(b))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SignBlock signs the block's hash with the private key and sets both Hash and Signature.
// Returns an error if hashing fails.
//
// #829: if this is the FIRST block on a single-key chain (Previous == "0") and
// no key has been declared yet, the signer's public key is declared here. The
// declaration is a property of signing an opening block — the signer is the only
// party that knows the key — so every producer (wallet, CLI, node, driver) gets
// it right by construction. An explicitly-set PubKey is never overwritten, so a
// deliberately-wrong declaration still reaches validation and is still rejected.
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

// ValidatePubKeyDeclaration enforces the structural rules for a block's PubKey
// field (#829). It is a pure function of the block — no ledger state — so every
// failure here is DETERMINISTIC and identical on every node, and none of the
// messages match core.IsRetryableError's allowlist. That matters both ways: a
// retryable classification would park these blocks forever, and a wrongly
// deterministic one would let a node quarantine a peer over a transient cause
// (#673).
//
// The rules:
//   - a multisig block (one carrying Signatures) never declares a PubKey — its
//     credential is the keyset and its address already commits to it;
//   - the FIRST block on a single-key chain (Previous == "0") MUST declare the
//     account's public key, and that key must derive the account address;
//   - any later block MUST NOT declare one — the ledger already holds the key,
//     and accepting a redeclaration would be a silent credential swap.
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

// VerifyBlock checks the block's hash and its self-contained credential claims.
//
// Since #829 an account address is sha256("xe/account/v1" || pubkey), so the
// account field is no longer a verifying key and a non-open block cannot be
// signature-checked without ledger state. VerifyBlock therefore verifies:
//
//   - the hash (which, via MarshalBlockAux, binds PubKey), and
//   - the PubKey declaration rules, and
//   - for an OPEN single-key block, the signature against the key the block
//     itself declares. That is self-certifying — the address commits to that
//     key, so no lookup is needed — and it is what keeps the genesis block
//     verifiable standalone, before any ledger exists.
//
// Signature verification for every OTHER block is done by the ledger, which
// resolves the stored credential (the multisig keyset or the account's declared
// key) in Ledger.verifyBlockCredential. Both sit on the one validated AddBlock
// path (invariant C1); there is no second path.
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

	// Multisig blocks defer signature verification to the ledger.
	if len(b.Signatures) > 0 {
		return nil
	}

	// Non-open blocks defer to the ledger, which holds the account's key.
	if b.Previous != "0" {
		return nil
	}

	return VerifyBlockSignatureWith(b, b.PubKey)
}

// VerifyBlockSignatureWith verifies a single-key block's signature over its hash
// against an explicitly supplied public key. The ledger calls this with the key
// resolved from the account key store; VerifyBlock calls it with the key an open
// block declares.
func VerifyBlockSignatureWith(b *Block, pubKeyHex string) error {
	hashBytes, err := DecodeHash(b.Hash)
	if err != nil {
		return err
	}
	return VerifyHexSignature(pubKeyHex, b.Signature, hashBytes)
}

// DecodePublicKey decodes a hex-encoded ed25519 public key and validates its length.
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

// DecodeSignature decodes a hex-encoded ed25519 signature and validates its length.
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

// DecodeHash decodes a hex-encoded SHA-256 hash and validates its length (32 bytes).
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

// VerifyHexSignature decodes hex-encoded public key and signature, then verifies
// the signature over the given message bytes.
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

// MustSignBlock calls SignBlock and panics on error. For use in tests only.
func MustSignBlock(b *Block, kp *KeyPair) {
	if err := SignBlock(b, kp); err != nil {
		panic("MustSignBlock: " + err.Error())
	}
}

// MustSign signs a message with a private key and returns the hex signature.
// Panics on error. For use in tests only.
func MustSign(priv ed25519.PrivateKey, message []byte) string {
	sig := ed25519.Sign(priv, message)
	return hex.EncodeToString(sig)
}

// MustHashBlock calls HashBlock and panics on error. For use in tests only.
func MustHashBlock(b *Block) string {
	h, err := HashBlock(b)
	if err != nil {
		panic("MustHashBlock: " + err.Error())
	}
	return h
}
