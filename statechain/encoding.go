package statechain

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// MarshalCanonical encodes a state chain block into its canonical binary
// representation for hashing and signing.
//
// Binary layout:
//
//	[index:     8 bytes big-endian uint64]
//	[prev_hash: 32 bytes raw (hex-decoded)]
//	[num_ops:   4 bytes big-endian uint32]
//	for each op:
//	  [action:    1 byte (0x01=set, 0x02=delete)]
//	  [key_len:   2 bytes big-endian uint16]
//	  [key:       key_len bytes UTF-8]
//	  [value_len: 4 bytes big-endian uint32] (0 for delete)
//	  [value:     value_len bytes raw JSON]  (omitted for delete)
//	[timestamp: 8 bytes big-endian int64]
func MarshalCanonical(b *Block) ([]byte, error) {
	var buf bytes.Buffer

	// Index: 8 bytes BE
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], b.Index)
	buf.Write(idx[:])

	// PrevHash: 32 bytes raw
	prevHash, err := hex.DecodeString(b.PrevHash)
	if err != nil {
		return nil, fmt.Errorf("MarshalCanonical: invalid prev_hash hex: %w", err)
	}
	if len(prevHash) != 32 {
		return nil, fmt.Errorf("MarshalCanonical: prev_hash must be 32 bytes, got %d", len(prevHash))
	}
	buf.Write(prevHash)

	// NumOps: 4 bytes BE
	var numOps [4]byte
	binary.BigEndian.PutUint32(numOps[:], uint32(len(b.Ops)))
	buf.Write(numOps[:])

	for i, op := range b.Ops {
		switch op.Action {
		case ActionSet:
			buf.WriteByte(actionByteSet)
		case ActionDelete:
			buf.WriteByte(actionByteDelete)
		default:
			return nil, fmt.Errorf("MarshalCanonical: op %d: unknown action %q", i, op.Action)
		}

		// Key
		keyBytes := []byte(op.Key)
		var keyLen [2]byte
		binary.BigEndian.PutUint16(keyLen[:], uint16(len(keyBytes)))
		buf.Write(keyLen[:])
		buf.Write(keyBytes)

		// Value
		if op.Action == ActionSet {
			valBytes := []byte(op.Value)
			var valLen [4]byte
			binary.BigEndian.PutUint32(valLen[:], uint32(len(valBytes)))
			buf.Write(valLen[:])
			buf.Write(valBytes)
		} else {
			var zero [4]byte
			buf.Write(zero[:])
		}
	}

	// Timestamp: 8 bytes BE (signed int64)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(b.Timestamp))
	buf.Write(ts[:])

	return buf.Bytes(), nil
}
