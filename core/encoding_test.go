package core

import (
	"encoding/binary"
	"testing"
)

func TestDecodeVoteSigLenOverflow(t *testing.T) {
	sigLen := uint16(65535)
	data := make([]byte, 140+int(sigLen))
	data[0] = voteVersionByte
	binary.BigEndian.PutUint16(data[138:140], sigLen)

	// In unpatched code, this panics with slice bounds out of range [140:139]
	v, err := DecodeVote(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(v.Signature) != int(sigLen) {
		t.Fatalf("expected signature len %d, got %d", sigLen, len(v.Signature))
	}
}
