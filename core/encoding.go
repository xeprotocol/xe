package core

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
)

const (
	versionByte = byte(0x02)

	typeByteSend             = byte(0x01)
	typeByteReceive          = byte(0x02)
	typeByteLease            = byte(0x04)
	typeByteLeaseAccept      = byte(0x05)
	typeByteLeaseSettle      = byte(0x06)
	typeByteGenesis          = byte(0x07)
	typeByteMultisigOpen     = byte(0x08)
	typeByteMultisigUpdate   = byte(0x09)
	typeByteLeaseCancel      = byte(0x0A)
	typeByteBurn             = byte(0x0B)
	typeByteLeaseForceSettle = byte(0x0C)
	typeByteMint             = byte(0x0D)

	assetFieldSize      = 8
	fixedHeaderSize     = 90
	sendTailSize        = 40
	receiveTailSize     = 32
	leaseTailSize       = 104
	leaseAcceptTailSize = 64
	leaseSettleTailSize = 40
	burnTailSize        = 8
	mintTailSize        = 8
	representativeSize  = 32
	genesisTimingSize   = 48

	auxTagAccountPubKey = "xe/block/pubkey/v1"
)

func MarshalBlockCanonical(b *Block) ([]byte, error) {
	var typeByte byte
	switch b.Type {
	case BlockSend:
		typeByte = typeByteSend
	case BlockReceive:
		typeByte = typeByteReceive
	case BlockLease:
		typeByte = typeByteLease
	case BlockLeaseAccept:
		typeByte = typeByteLeaseAccept
	case BlockLeaseSettle:
		typeByte = typeByteLeaseSettle
	case BlockGenesis:
		typeByte = typeByteGenesis
	case BlockMultisigOpen:
		typeByte = typeByteMultisigOpen
	case BlockMultisigUpdate:
		typeByte = typeByteMultisigUpdate
	case BlockLeaseCancel:
		typeByte = typeByteLeaseCancel
	case BlockLeaseForceSettle:
		typeByte = typeByteLeaseForceSettle
	case BlockBurn:
		typeByte = typeByteBurn
	case BlockMint:
		typeByte = typeByteMint
	default:
		return nil, fmt.Errorf("MarshalBlock: unknown block type %q", b.Type)
	}

	if b.Memo != "" && b.Type != BlockSend && b.Type != BlockBurn {
		return nil, fmt.Errorf("MarshalBlock: memo not allowed on %s blocks", b.Type)
	}
	if err := ValidateMemo(b.Memo); err != nil {
		return nil, fmt.Errorf("MarshalBlock: %w", err)
	}

	var assetBytes [assetFieldSize]byte
	if len(b.Asset) > assetFieldSize {
		return nil, fmt.Errorf("MarshalBlock: asset too long: %d bytes (max %d)", len(b.Asset), assetFieldSize)
	}
	copy(assetBytes[:], b.Asset)

	account, err := hex.DecodeString(b.Account)
	if err != nil {
		return nil, fmt.Errorf("MarshalBlock: invalid account hex: %w", err)
	}
	if len(account) != 32 {
		return nil, fmt.Errorf("MarshalBlock: account must be 32 bytes, got %d", len(account))
	}

	var previous []byte
	if b.Previous == "0" {
		previous = make([]byte, 32)
	} else {
		previous, err = hex.DecodeString(b.Previous)
		if err != nil {
			return nil, fmt.Errorf("MarshalBlock: invalid previous hex: %w", err)
		}
		if len(previous) != 32 {
			return nil, fmt.Errorf("MarshalBlock: previous must be 32 bytes, got %d", len(previous))
		}
	}

	var buf bytes.Buffer
	buf.WriteByte(versionByte)
	buf.WriteByte(typeByte)
	buf.Write(assetBytes[:])
	buf.Write(account)
	buf.Write(previous)

	var balance [8]byte
	binary.BigEndian.PutUint64(balance[:], b.Balance)
	buf.Write(balance[:])

	var timestamp [8]byte
	binary.BigEndian.PutUint64(timestamp[:], uint64(b.Timestamp))
	buf.Write(timestamp[:])

	switch b.Type {
	case BlockSend:
		dest, err := hex.DecodeString(b.Destination)
		if err != nil {
			return nil, fmt.Errorf("MarshalBlock: invalid destination hex: %w", err)
		}
		if len(dest) != 32 {
			return nil, fmt.Errorf("MarshalBlock: destination must be 32 bytes, got %d", len(dest))
		}
		buf.Write(dest)
		var amount [8]byte
		binary.BigEndian.PutUint64(amount[:], b.Amount)
		buf.Write(amount[:])

	case BlockReceive:
		source, err := hex.DecodeString(b.Source)
		if err != nil {
			return nil, fmt.Errorf("MarshalBlock: invalid source hex: %w", err)
		}
		if len(source) != 32 {
			return nil, fmt.Errorf("MarshalBlock: source must be 32 bytes, got %d", len(source))
		}
		buf.Write(source)

	case BlockLease:
		dest, err := hex.DecodeString(b.Destination)
		if err != nil {
			return nil, fmt.Errorf("MarshalBlock: invalid destination hex: %w", err)
		}
		if len(dest) != 32 {
			return nil, fmt.Errorf("MarshalBlock: destination must be 32 bytes, got %d", len(dest))
		}
		buf.Write(dest)
		var amount [8]byte
		binary.BigEndian.PutUint64(amount[:], b.Amount)
		buf.Write(amount[:])
		var vcpus [8]byte
		binary.BigEndian.PutUint64(vcpus[:], b.VCPUs)
		buf.Write(vcpus[:])
		var memoryMB [8]byte
		binary.BigEndian.PutUint64(memoryMB[:], b.MemoryMB)
		buf.Write(memoryMB[:])
		var diskGB [8]byte
		binary.BigEndian.PutUint64(diskGB[:], b.DiskGB)
		buf.Write(diskGB[:])
		var duration [8]byte
		binary.BigEndian.PutUint64(duration[:], b.Duration)
		buf.Write(duration[:])

		var sshKey []byte
		if b.AccessPubKey == "" {
			sshKey = make([]byte, 32)
		} else {
			sshKey, err = hex.DecodeString(b.AccessPubKey)
			if err != nil {
				return nil, fmt.Errorf("MarshalBlock: invalid access_pub_key hex: %w", err)
			}
			if len(sshKey) != 32 {
				return nil, fmt.Errorf("MarshalBlock: access_pub_key must be 32 bytes, got %d", len(sshKey))
			}
		}
		buf.Write(sshKey)

	case BlockGenesis:

	case BlockMultisigOpen, BlockMultisigUpdate:
		ksBytes, err := marshalKeysetCanonical(b.MSKeyset)
		if err != nil {
			return nil, fmt.Errorf("MarshalBlock: %w", err)
		}
		buf.Write(ksBytes)

	case BlockLeaseCancel, BlockLeaseForceSettle:
		source, err := hex.DecodeString(b.Source)
		if err != nil {
			return nil, fmt.Errorf("MarshalBlock: invalid source hex: %w", err)
		}
		if len(source) != 32 {
			return nil, fmt.Errorf("MarshalBlock: source must be 32 bytes, got %d", len(source))
		}
		buf.Write(source)

	case BlockLeaseAccept, BlockLeaseSettle:
		source, err := hex.DecodeString(b.Source)
		if err != nil {
			return nil, fmt.Errorf("MarshalBlock: invalid source hex: %w", err)
		}
		if len(source) != 32 {
			return nil, fmt.Errorf("MarshalBlock: source must be 32 bytes, got %d", len(source))
		}
		buf.Write(source)
		var amount [8]byte
		binary.BigEndian.PutUint64(amount[:], b.Amount)
		buf.Write(amount[:])

		if b.Type == BlockLeaseAccept {
			var locked [24]byte
			binary.BigEndian.PutUint64(locked[0:8], b.LockedR)
			binary.BigEndian.PutUint64(locked[8:16], b.LockedPayoutCap)
			binary.BigEndian.PutUint64(locked[16:24], b.LockedTWAP)
			buf.Write(locked[:])
		}

	case BlockBurn:
		var amount [8]byte
		binary.BigEndian.PutUint64(amount[:], b.Amount)
		buf.Write(amount[:])

	case BlockMint:
		var amount [8]byte
		binary.BigEndian.PutUint64(amount[:], b.Amount)
		buf.Write(amount[:])
	}

	var rep []byte
	if b.Representative == "" {
		rep = make([]byte, 32)
	} else {
		rep, err = hex.DecodeString(b.Representative)
		if err != nil {
			return nil, fmt.Errorf("MarshalBlock: invalid representative hex: %w", err)
		}
		if len(rep) != 32 {
			return nil, fmt.Errorf("MarshalBlock: representative must be 32 bytes, got %d", len(rep))
		}
	}
	buf.Write(rep)

	if hasGenesisLeaseTiming(b) {
		if b.Type != BlockGenesis {
			return nil, fmt.Errorf("MarshalBlock: lease-timing fields not allowed on %s blocks", b.Type)
		}
		var timing [genesisTimingSize]byte
		binary.BigEndian.PutUint64(timing[0:8], b.LeaseMinDurationSecs)
		binary.BigEndian.PutUint64(timing[8:16], uint64(b.LeaseSettleGraceNs))
		binary.BigEndian.PutUint64(timing[16:24], uint64(b.LeaseForceSettleGapNs))
		binary.BigEndian.PutUint64(timing[24:32], uint64(b.LeaseEscrowExpiryNs))
		binary.BigEndian.PutUint64(timing[32:40], uint64(b.LeaseArchiveGapNs))
		binary.BigEndian.PutUint64(timing[40:48], uint64(b.MaxAttestationSkewNs))
		buf.Write(timing[:])
	}

	if b.Type == BlockSend || b.Type == BlockBurn {
		buf.WriteByte(byte(len(b.Memo)))
		buf.WriteString(b.Memo)
	}

	return buf.Bytes(), nil
}

func hasGenesisLeaseTiming(b *Block) bool {
	return b.LeaseMinDurationSecs != 0 || b.LeaseSettleGraceNs != 0 ||
		b.LeaseForceSettleGapNs != 0 || b.LeaseEscrowExpiryNs != 0 || b.LeaseArchiveGapNs != 0 ||
		b.MaxAttestationSkewNs != 0
}

func MarshalBlockAux(b *Block) []byte {
	var buf bytes.Buffer

	if b.PubKey != "" {
		writeLenPrefixedBytes(&buf, []byte(auxTagAccountPubKey))
		writeLenPrefixedBytes(&buf, []byte(b.PubKey))
	}

	switch b.Type {
	case BlockLease, BlockLeaseAccept, BlockLeaseSettle, BlockLeaseForceSettle:
	default:
		if buf.Len() == 0 {
			return nil
		}
		return buf.Bytes()
	}
	writeLenPrefixedBytes(&buf, []byte(b.CertificateHash))
	atts := append([]TimekeeperAttestation(nil), b.Attestations...)
	sort.Slice(atts, func(i, j int) bool { return atts[i].PublicKey < atts[j].PublicKey })
	var cnt [8]byte
	binary.BigEndian.PutUint64(cnt[:], uint64(len(atts)))
	buf.Write(cnt[:])
	for _, a := range atts {
		writeLenPrefixedBytes(&buf, []byte(a.PublicKey))
		var ts [8]byte
		binary.BigEndian.PutUint64(ts[:], uint64(a.Timestamp))
		buf.Write(ts[:])
		writeLenPrefixedBytes(&buf, []byte(a.Signature))
	}
	return buf.Bytes()
}

func writeLenPrefixedBytes(buf *bytes.Buffer, b []byte) {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(b)))
	buf.Write(l[:])
	buf.Write(b)
}

func MarshalBlock(b *Block) ([]byte, error) {
	if b.PubKey != "" {
		return nil, fmt.Errorf("MarshalBlock: the binary canonical encoding cannot represent a declared pub_key (it is bound into the hash via the aux input, not the canonical bytes) — use JSON, which is the wire and store format for blocks")
	}
	canonical, err := MarshalBlockCanonical(b)
	if err != nil {
		return nil, err
	}
	var nonce [8]byte
	binary.LittleEndian.PutUint64(nonce[:], b.PoWNonce)
	return append(canonical, nonce[:]...), nil
}

func UnmarshalBlock(data []byte) (*Block, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("UnmarshalBlock: data too short (%d bytes)", len(data))
	}
	if data[0] != versionByte {
		return nil, fmt.Errorf("UnmarshalBlock: unsupported version byte 0x%02x", data[0])
	}
	return unmarshalBlock(data)
}

func unmarshalBlock(data []byte) (*Block, error) {
	var blockType BlockType
	var minLen int
	switch data[1] {
	case typeByteSend:
		blockType = BlockSend

		minLen = fixedHeaderSize + sendTailSize + representativeSize + 1
	case typeByteReceive:
		blockType = BlockReceive
		minLen = fixedHeaderSize + receiveTailSize + representativeSize
	case typeByteGenesis:
		blockType = BlockGenesis
		minLen = fixedHeaderSize + representativeSize
	case typeByteMultisigOpen:
		blockType = BlockMultisigOpen
		minLen = fixedHeaderSize + 8 + representativeSize
	case typeByteMultisigUpdate:
		blockType = BlockMultisigUpdate
		minLen = fixedHeaderSize + 8 + representativeSize
	case typeByteLease:
		blockType = BlockLease
		minLen = fixedHeaderSize + leaseTailSize + representativeSize
	case typeByteLeaseAccept:
		blockType = BlockLeaseAccept
		minLen = fixedHeaderSize + leaseAcceptTailSize + representativeSize
	case typeByteLeaseSettle:
		blockType = BlockLeaseSettle
		minLen = fixedHeaderSize + leaseSettleTailSize + representativeSize
	case typeByteLeaseCancel:
		blockType = BlockLeaseCancel
		minLen = fixedHeaderSize + receiveTailSize + representativeSize
	case typeByteLeaseForceSettle:
		blockType = BlockLeaseForceSettle
		minLen = fixedHeaderSize + receiveTailSize + representativeSize
	case typeByteBurn:
		blockType = BlockBurn

		minLen = fixedHeaderSize + burnTailSize + representativeSize + 1
	case typeByteMint:
		blockType = BlockMint
		minLen = fixedHeaderSize + mintTailSize + representativeSize
	default:
		return nil, fmt.Errorf("UnmarshalBlock: unknown type byte 0x%02x", data[1])
	}

	if len(data) < minLen {
		return nil, fmt.Errorf("UnmarshalBlock: data too short for %s block: need %d bytes, got %d", blockType, minLen, len(data))
	}

	assetBytes := data[2:10]
	asset := string(bytes.TrimRight(assetBytes, "\x00"))

	account := hex.EncodeToString(data[10:42])

	var previous string
	prevBytes := data[42:74]
	if allZero(prevBytes) {
		previous = "0"
	} else {
		previous = hex.EncodeToString(prevBytes)
	}

	balance := binary.BigEndian.Uint64(data[74:82])
	timestamp := int64(binary.BigEndian.Uint64(data[82:90]))

	b := &Block{
		Type:      blockType,
		Account:   account,
		Previous:  previous,
		Balance:   balance,
		Timestamp: timestamp,
		Asset:     asset,
	}

	var repOffset int
	switch blockType {
	case BlockSend:
		b.Destination = hex.EncodeToString(data[90:122])
		b.Amount = binary.BigEndian.Uint64(data[122:130])
		repOffset = 130
	case BlockReceive:
		b.Source = hex.EncodeToString(data[90:122])
		repOffset = 122
	case BlockLease:
		b.Destination = hex.EncodeToString(data[90:122])
		b.Amount = binary.BigEndian.Uint64(data[122:130])
		b.VCPUs = binary.BigEndian.Uint64(data[130:138])
		b.MemoryMB = binary.BigEndian.Uint64(data[138:146])
		b.DiskGB = binary.BigEndian.Uint64(data[146:154])
		b.Duration = binary.BigEndian.Uint64(data[154:162])
		sshKeyBytes := data[162:194]
		if !allZero(sshKeyBytes) {
			b.AccessPubKey = hex.EncodeToString(sshKeyBytes)
		}
		repOffset = 194
	case BlockLeaseCancel, BlockLeaseForceSettle:
		b.Source = hex.EncodeToString(data[90:122])
		repOffset = 122
	case BlockLeaseSettle:
		b.Source = hex.EncodeToString(data[90:122])
		b.Amount = binary.BigEndian.Uint64(data[122:130])
		repOffset = 130
	case BlockLeaseAccept:
		b.Source = hex.EncodeToString(data[90:122])
		b.Amount = binary.BigEndian.Uint64(data[122:130])

		b.LockedR = binary.BigEndian.Uint64(data[130:138])
		b.LockedPayoutCap = binary.BigEndian.Uint64(data[138:146])
		b.LockedTWAP = binary.BigEndian.Uint64(data[146:154])
		repOffset = 154
	case BlockMultisigOpen, BlockMultisigUpdate:
		ks, ksLen, err := unmarshalKeysetCanonical(data[90:])
		if err != nil {
			return nil, fmt.Errorf("UnmarshalBlock: keyset: %w", err)
		}
		b.MSKeyset = ks
		repOffset = 90 + ksLen
		if len(data) < repOffset+representativeSize {
			return nil, fmt.Errorf("UnmarshalBlock: data too short for %s after keyset", blockType)
		}
	case BlockBurn:
		b.Amount = binary.BigEndian.Uint64(data[90:98])
		repOffset = 98
	case BlockMint:
		b.Amount = binary.BigEndian.Uint64(data[90:98])
		repOffset = 98
	default:
		repOffset = 90
	}

	repBytes := data[repOffset : repOffset+32]
	if !allZero(repBytes) {
		b.Representative = hex.EncodeToString(repBytes)
	}

	tailOffset := minLen

	if blockType == BlockGenesis && len(data) >= repOffset+32+genesisTimingSize {
		t := data[repOffset+32 : repOffset+32+genesisTimingSize]
		b.LeaseMinDurationSecs = binary.BigEndian.Uint64(t[0:8])
		b.LeaseSettleGraceNs = int64(binary.BigEndian.Uint64(t[8:16]))
		b.LeaseForceSettleGapNs = int64(binary.BigEndian.Uint64(t[16:24]))
		b.LeaseEscrowExpiryNs = int64(binary.BigEndian.Uint64(t[24:32]))
		b.LeaseArchiveGapNs = int64(binary.BigEndian.Uint64(t[32:40]))
		b.MaxAttestationSkewNs = int64(binary.BigEndian.Uint64(t[40:48]))
		tailOffset = repOffset + 32 + genesisTimingSize
	}
	if blockType == BlockSend || blockType == BlockBurn {
		memoLen := int(data[repOffset+32])
		if memoLen > MaxMemoBytes {
			return nil, fmt.Errorf("UnmarshalBlock: memo length %d exceeds max %d", memoLen, MaxMemoBytes)
		}
		if len(data) < minLen+memoLen {
			return nil, fmt.Errorf("UnmarshalBlock: data too short for %d-byte memo", memoLen)
		}
		if memoLen > 0 {
			memo := string(data[minLen : minLen+memoLen])
			if err := ValidateMemo(memo); err != nil {
				return nil, fmt.Errorf("UnmarshalBlock: %w", err)
			}
			b.Memo = memo
		}
		tailOffset = minLen + memoLen
	}

	if len(data) == tailOffset+8 {
		b.PoWNonce = binary.LittleEndian.Uint64(data[tailOffset:])
	}

	return b, nil
}

func marshalKeysetCanonical(ks *Keyset) ([]byte, error) {
	if ks == nil {
		return nil, fmt.Errorf("keyset is nil")
	}
	sorted := make([]string, len(ks.Keys))
	copy(sorted, ks.Keys)
	sort.Strings(sorted)

	size := 8 + 32*len(sorted)
	buf := make([]byte, size)
	binary.BigEndian.PutUint32(buf[0:4], uint32(ks.Threshold))
	binary.BigEndian.PutUint32(buf[4:8], uint32(len(sorted)))
	for i, k := range sorted {
		kb, err := hex.DecodeString(k)
		if err != nil {
			return nil, fmt.Errorf("invalid key hex: %w", err)
		}
		if len(kb) != 32 {
			return nil, fmt.Errorf("key must be 32 bytes, got %d", len(kb))
		}
		copy(buf[8+i*32:8+(i+1)*32], kb)
	}
	return buf, nil
}

func unmarshalKeysetCanonical(data []byte) (*Keyset, int, error) {
	if len(data) < 8 {
		return nil, 0, fmt.Errorf("keyset data too short")
	}
	threshold := int(binary.BigEndian.Uint32(data[0:4]))
	numKeys := int(binary.BigEndian.Uint32(data[4:8]))
	if numKeys < 1 || numKeys > 256 {
		return nil, 0, fmt.Errorf("invalid key count: %d", numKeys)
	}
	totalLen := 8 + 32*numKeys
	if len(data) < totalLen {
		return nil, 0, fmt.Errorf("keyset data too short for %d keys", numKeys)
	}
	keys := make([]string, numKeys)
	for i := 0; i < numKeys; i++ {
		keys[i] = hex.EncodeToString(data[8+i*32 : 8+(i+1)*32])
	}
	return &Keyset{Keys: keys, Threshold: threshold}, totalLen, nil
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

const voteVersionByte = byte(0x02)

func voteSigningBytes(v *Vote) ([]byte, error) {
	repBytes, err := hex.DecodeString(v.RepPubKey)
	if err != nil {
		return nil, fmt.Errorf("voteSigningBytes: invalid RepPubKey hex: %w", err)
	}
	if len(repBytes) != 32 {
		return nil, fmt.Errorf("voteSigningBytes: RepPubKey must be 32 bytes, got %d", len(repBytes))
	}

	blockHashBytes, err := hex.DecodeString(v.BlockHash)
	if err != nil {
		return nil, fmt.Errorf("voteSigningBytes: invalid BlockHash hex: %w", err)
	}
	if len(blockHashBytes) != 32 {
		return nil, fmt.Errorf("voteSigningBytes: BlockHash must be 32 bytes, got %d", len(blockHashBytes))
	}

	conflictAccountBytes, err := hex.DecodeString(v.ConflictAccount)
	if err != nil {
		return nil, fmt.Errorf("voteSigningBytes: invalid ConflictAccount hex: %w", err)
	}
	if len(conflictAccountBytes) != 32 {
		return nil, fmt.Errorf("voteSigningBytes: ConflictAccount must be 32 bytes, got %d", len(conflictAccountBytes))
	}

	var conflictPrevBytes []byte
	if v.ConflictPrev == "0" {
		conflictPrevBytes = make([]byte, 32)
	} else {
		conflictPrevBytes, err = hex.DecodeString(v.ConflictPrev)
		if err != nil {
			return nil, fmt.Errorf("voteSigningBytes: invalid ConflictPrev hex: %w", err)
		}
		if len(conflictPrevBytes) != 32 {
			return nil, fmt.Errorf("voteSigningBytes: ConflictPrev must be 32 bytes, got %d", len(conflictPrevBytes))
		}
	}

	var buf bytes.Buffer
	buf.WriteByte(voteVersionByte)
	buf.Write(repBytes)
	buf.Write(blockHashBytes)
	buf.Write(conflictAccountBytes)
	buf.Write(conflictPrevBytes)

	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(v.Timestamp))
	buf.Write(ts[:])

	if v.Final {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}

	return buf.Bytes(), nil
}

func EncodeVote(v *Vote) ([]byte, error) {
	signing, err := voteSigningBytes(v)
	if err != nil {
		return nil, fmt.Errorf("EncodeVote: %w", err)
	}

	var buf bytes.Buffer
	buf.Write(signing)

	sigLen := uint16(len(v.Signature))
	var sigLenBytes [2]byte
	binary.BigEndian.PutUint16(sigLenBytes[:], sigLen)
	buf.Write(sigLenBytes[:])
	buf.Write(v.Signature)

	return buf.Bytes(), nil
}

func DecodeVote(data []byte) (*Vote, error) {
	const signingSize = 138
	if len(data) < signingSize+2 {
		return nil, fmt.Errorf("DecodeVote: data too short (%d bytes)", len(data))
	}

	if data[0] != voteVersionByte {
		return nil, fmt.Errorf("DecodeVote: unsupported version byte 0x%02x", data[0])
	}

	repPubKey := hex.EncodeToString(data[1:33])
	blockHash := hex.EncodeToString(data[33:65])
	conflictAccount := hex.EncodeToString(data[65:97])

	var conflictPrev string
	prevBytes := data[97:129]
	if allZero(prevBytes) {
		conflictPrev = "0"
	} else {
		conflictPrev = hex.EncodeToString(prevBytes)
	}

	timestamp := int64(binary.BigEndian.Uint64(data[129:137]))
	final := data[137] != 0

	sigLen := binary.BigEndian.Uint16(data[138:140])
	if len(data) < 140+int(sigLen) {
		return nil, fmt.Errorf("DecodeVote: data truncated: need %d bytes for signature, have %d", sigLen, len(data)-140)
	}

	sig := make([]byte, sigLen)
	copy(sig, data[140:140+sigLen])

	return &Vote{
		RepPubKey:       repPubKey,
		BlockHash:       blockHash,
		ConflictAccount: conflictAccount,
		ConflictPrev:    conflictPrev,
		Timestamp:       timestamp,
		Final:           final,
		Signature:       sig,
	}, nil
}
