package statechain

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

func MarshalCanonical(b *Block) ([]byte, error) {
	var buf bytes.Buffer

	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], b.Index)
	buf.Write(idx[:])

	prevHash, err := hex.DecodeString(b.PrevHash)
	if err != nil {
		return nil, fmt.Errorf("MarshalCanonical: invalid prev_hash hex: %w", err)
	}
	if len(prevHash) != 32 {
		return nil, fmt.Errorf("MarshalCanonical: prev_hash must be 32 bytes, got %d", len(prevHash))
	}
	buf.Write(prevHash)

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

		keyBytes := []byte(op.Key)
		var keyLen [2]byte
		binary.BigEndian.PutUint16(keyLen[:], uint16(len(keyBytes)))
		buf.Write(keyLen[:])
		buf.Write(keyBytes)

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

	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(b.Timestamp))
	buf.Write(ts[:])

	return buf.Bytes(), nil
}
