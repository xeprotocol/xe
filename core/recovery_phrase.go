package core

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/text/unicode/norm"
)

const RecoveryPhraseWords = 24

const RecoveryPhraseCoinType uint32 = 1

//go:embed wordlist_english.txt
var wordlistEnglish string

func parseWordlist(raw string) []string {
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	normalized = strings.TrimRight(normalized, "\r\n")
	words := strings.Split(normalized, "\n")
	for i, w := range words {
		words[i] = strings.TrimSpace(w)
	}
	return words
}

var (
	phraseWords = parseWordlist(wordlistEnglish)
	phraseIndex = func() map[string]int {
		m := make(map[string]int, len(phraseWords))
		for i, w := range phraseWords {
			m[w] = i
		}
		return m
	}()
)

func init() {
	if len(phraseWords) != 2048 || len(phraseIndex) != 2048 {
		panic(fmt.Sprintf("recovery_phrase: invalid BIP39 wordlist length (words=%d, index=%d, want 2048)", len(phraseWords), len(phraseIndex)))
	}
	for i, w := range phraseWords {
		if w == "" || strings.ContainsAny(w, "\r\n \t") {
			panic(fmt.Sprintf("recovery_phrase: malformed BIP39 word at index %d: %q", i, w))
		}
	}
}

var (
	ErrPhraseWordCount = errors.New("recovery phrase must have 12, 15, 18, 21 or 24 words")

	ErrPhraseUnknownWord = errors.New("unknown recovery phrase word")
	ErrPhraseChecksum    = errors.New("recovery phrase checksum does not match")
	ErrPhraseAccount     = errors.New("recovery phrase account must be between 0 and 2147483647")
)

func NormalizePhrase(phrase string) string {
	return norm.NFKD.String(strings.Join(strings.Fields(strings.ToLower(phrase)), " "))
}

func NewRecoveryPhrase() (string, error) {
	entropy := make([]byte, 32)
	if _, err := rand.Read(entropy); err != nil {
		return "", fmt.Errorf("generate recovery phrase: %w", err)
	}
	return phraseFromEntropy(entropy), nil
}

func phraseFromEntropy(entropy []byte) string {
	sum := sha256.Sum256(entropy)
	data := append(append([]byte(nil), entropy...), sum[0])
	words := make([]string, (len(entropy)*8+len(entropy)/4)/11)
	for i := range words {
		index := 0
		for bit := i * 11; bit < (i+1)*11; bit++ {
			index = index<<1 | int(data[bit/8]>>uint(7-bit%8)&1)
		}
		words[i] = phraseWords[index]
	}
	return strings.Join(words, " ")
}

func ValidatePhrase(phrase string) error {
	words := strings.Fields(NormalizePhrase(phrase))
	if len(words) < 12 || len(words) > 24 || len(words)%3 != 0 {
		return fmt.Errorf("%w, got %d", ErrPhraseWordCount, len(words))
	}
	data := make([]byte, (len(words)*11+7)/8)
	for i, word := range words {
		index, ok := phraseIndex[word]
		if !ok {
			return fmt.Errorf("%w at position %d", ErrPhraseUnknownWord, i+1)
		}
		for j := 0; j < 11; j++ {
			bit := i*11 + j
			data[bit/8] |= byte(index>>uint(10-j)&1) << uint(7-bit%8)
		}
	}
	entropyBytes := len(words) * 11 / 33 * 4
	checksumBits := entropyBytes / 4
	sum := sha256.Sum256(data[:entropyBytes])
	if data[entropyBytes]>>uint(8-checksumBits) != sum[0]>>uint(8-checksumBits) {
		return ErrPhraseChecksum
	}
	return nil
}

func bip39Seed(phrase, passphrase string) ([]byte, error) {
	if err := ValidatePhrase(phrase); err != nil {
		return nil, err
	}
	return pbkdf2.Key(sha512.New, NormalizePhrase(phrase), []byte("mnemonic"+norm.NFKD.String(passphrase)), 2048, 64)
}

func slip10Ed25519(seed []byte, path []uint32) (key, chainCode []byte, err error) {
	h := hmac.New(sha512.New, []byte("ed25519 seed"))
	h.Write(seed)
	node := h.Sum(nil)
	for _, index := range path {
		if index >= 1<<31 {
			return nil, nil, ErrPhraseAccount
		}
		data := make([]byte, 37)
		copy(data[1:], node[:32])
		binary.BigEndian.PutUint32(data[33:], index|1<<31)
		h = hmac.New(sha512.New, node[32:])
		h.Write(data)
		node = h.Sum(nil)
	}
	return node[:32], node[32:], nil
}

func KeyPairFromPhrase(phrase, passphrase string, account uint32) (*KeyPair, error) {
	if account >= 1<<31 {
		return nil, ErrPhraseAccount
	}
	seed, err := bip39Seed(phrase, passphrase)
	if err != nil {
		return nil, err
	}
	key, _, err := slip10Ed25519(seed, []uint32{44, RecoveryPhraseCoinType, account})
	if err != nil {
		return nil, err
	}
	return KeyPairFromSeed(key), nil
}
