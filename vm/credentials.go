package vm

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
)

func GenerateCredentials() *Credentials {
	return &Credentials{
		Username: "xe-" + randomHex(8),
		Password: randomAlphanumeric(24),
	}
}

func randomHex(n int) string {

	b := make([]byte, (n+1)/2)
	rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

const alphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomAlphanumeric(n int) string {
	b := make([]byte, n)
	max := big.NewInt(int64(len(alphanumeric)))
	for i := range b {
		idx, _ := rand.Int(rand.Reader, max)
		b[i] = alphanumeric[idx.Int64()]
	}
	return string(b)
}
