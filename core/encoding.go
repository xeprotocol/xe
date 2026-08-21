package core

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
)

const (
	// versionByte is the single accepted magic byte at offset 0 of a canonical
	// block. It exists as a cheap corruption check and an escape hatch for a
	// future format bump; there is no dual-decode logic.
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

	assetFieldSize      = 8   // 8-byte asset field (left-aligned UTF-8, zero-padded)
	fixedHeaderSize     = 90  // version(1) + type(1) + asset(8) + account(32) + previous(32) + balance(8) + timestamp(8)
	sendTailSize        = 40  // destination(32) + amount(8)
	receiveTailSize     = 32  // source(32)
	leaseTailSize       = 104 // destination(32) + amount(8) + vcpus(8) + memory_mb(8) + disk_gb(8) + duration(8) + access_pub_key(32)
	leaseAcceptTailSize = 64  // source(32) + amount(8) + locked_r(8) + locked_payout_cap(8) + locked_twap(8) (#501)
	leaseSettleTailSize = 40  // source(32) + amount(8)
	burnTailSize        = 8   // amount(8)
	mintTailSize        = 8   // amount(8)
	representativeSize  = 32  // representative(32); appended after type-specific tail in canonical encoding
	genesisTimingSize   = 48  // genesis lease-timing tail (#524, #662): min_duration(8) + settle_grace(8) + force_settle_gap(8) + escrow_expiry(8) + archive_gap(8) + max_attestation_skew(8)

	// auxTagAccountPubKey domain-separates the account public-key section of the
	// aux hash input from the lease certificate/attestation sections (#605, #829).
	auxTagAccountPubKey = "xe/block/pubkey/v1"
)

// MarshalBlockCanonical encodes a Block into its canonical binary representation,
// excluding PoWNonce. This is the data used for hashing and signing.
//
// Binary layout:
//
//	offset  size  field
//	0       1     version byte (0x02)
//	1       1     type byte (0x01=send, 0x02=receive, 0x04=lease, …)
//	2       8     asset (left-aligned UTF-8, zero-padded)
//	10      32    account (hex-decoded)
//	42      32    previous (hex-decoded; "0" → 32 zero bytes)
//	74      8     balance (big-endian uint64)
//	82      8     timestamp (big-endian int64)
//	90+     var   type-specific tail
//	90+tail 32    representative (hex-decoded; "" → 32 zero bytes)
//	+var          (genesis only) lease-timing tail (48 bytes) — present IFF any field non-zero (#524, #662)
//	+var          (send/burn only) memo_len(1) + memo_bytes — memo_len is 0..64
//
// Send tail:    destination(32) + amount(8) + representative(32) + memo_len(1) + memo → 163+ bytes
// Receive tail: source(32) + representative(32)                                       → 154 bytes
// Genesis tail: representative(32) [+ lease-timing(48) when pinned]                   → 122 or 170 bytes
// Burn tail:    amount(8) + representative(32) + memo_len(1) + memo                   → 131+ bytes
//
// Genesis lease-timing tail (#524, #662) is appended after the representative ONLY
// when at least one of the six timing fields is non-zero. An all-default genesis
// (every field zero) adds nothing, so it hashes identically to a pre-#524 genesis and
// existing networks are unaffected. The six fields are big-endian: min_duration_secs(8),
// settle_grace_ns(8), force_settle_gap_ns(8), escrow_expiry_ns(8), archive_gap_ns(8),
// max_attestation_skew_ns(8).
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

	// Memo is only valid on send and burn. Reject memos on other types at
	// canonical-encoding time so they cannot be smuggled in via the JSON
	// field on a non-supporting block.
	if b.Memo != "" && b.Type != BlockSend && b.Type != BlockBurn {
		return nil, fmt.Errorf("MarshalBlock: memo not allowed on %s blocks", b.Type)
	}
	if err := ValidateMemo(b.Memo); err != nil {
		return nil, fmt.Errorf("MarshalBlock: %w", err)
	}

	// Encode asset as 8-byte field (left-aligned UTF-8, zero-padded).
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

		// AccessPubKey: 32 bytes; empty string encodes as 32 zero bytes.
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
		// No type-specific tail.

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
		// #501: lease_accept carries the locked emission params (R, payout cap,
		// TWAP) in the signed canonical bytes, so every node records identical
		// settle-rate inputs no matter which epoch it applies the accept in.
		// lease_settle does not carry them — it reads the lease record (#434).
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

	// Representative: 32 bytes; empty string encodes as 32 zero bytes.
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

	// Genesis lease-timing tail (#524): appended after the representative ONLY
	// when at least one of the five fields is non-zero, so an all-default genesis
	// encodes byte-identically to a pre-#524 genesis (same hash, existing networks
	// unaffected). The fields are only meaningful on a genesis block; reject them
	// on any other type so they cannot be smuggled in via the JSON wire form.
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

	// Send and burn blocks carry a 1-byte memo length (0..MaxMemoBytes), then
	// that many bytes of UTF-8 memo content. The length byte is always
	// present so a missing memo and an empty memo encode identically.
	if b.Type == BlockSend || b.Type == BlockBurn {
		buf.WriteByte(byte(len(b.Memo)))
		buf.WriteString(b.Memo)
	}

	return buf.Bytes(), nil
}

// hasGenesisLeaseTiming reports whether any of the genesis lease-timing fields
// (#524) is set. Used to decide whether the canonical encoding carries the timing
// tail, keeping an all-default genesis byte-identical to a pre-#524 genesis.
func hasGenesisLeaseTiming(b *Block) bool {
	return b.LeaseMinDurationSecs != 0 || b.LeaseSettleGraceNs != 0 ||
		b.LeaseForceSettleGapNs != 0 || b.LeaseEscrowExpiryNs != 0 || b.LeaseArchiveGapNs != 0 ||
		b.MaxAttestationSkewNs != 0
}

// MarshalBlockAux returns the canonical encoding of the fields that ride in the
// JSON wire form rather than the fixed-width canonical header, but which MUST
// still be bound to the block hash: the account's public-key declaration (#829,
// any block type) and, on a lease-family block, the certificate hash and the
// timekeeper attestations. These are NOT part of
// MarshalBlockCanonical (they are variable-length and ride in the JSON wire
// form), but they MUST be bound to the block hash and signature: otherwise a
// relay can rewrite the certificate_hash (#570/H3) or strip/swap the
// attestation set (#570/H4) while Hash/signature still verify, so a node that
// got the original accepts and a node that got the tampered copy rejects — the
// same per-node validity divergence that #501/#514 fixed for LockedR.
//
// HashBlock folds this into the hash. Returns nil for non-lease blocks so their
// hash is unchanged. Attestations are sorted by public key so the SET (not the
// order) is bound — a relay reordering them does not change the hash, but
// adding/removing/swapping any attestation does.
func MarshalBlockAux(b *Block) []byte {
	var buf bytes.Buffer

	// #829: the account's declared public key rides in the JSON wire form (it is
	// only present on an opening block, so it is not part of the fixed-width
	// canonical header), but it MUST be bound to the hash and signature. Without
	// the binding a relay could swap the declared key on an open block whose
	// address happens to be reachable another way, or strip it to turn a valid
	// open block into one that fails the declaration rule on some nodes and not
	// others — the same per-node validity divergence the lease aux binding closes
	// (#570/H3+H4). Tagged and length-prefixed per #605; emitted only when set,
	// so a non-declaring block's aux is unchanged.
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

// writeLenPrefixedBytes writes an 8-byte big-endian length followed by b, so
// concatenated variable-length fields are unambiguously framed (#570/H3+H4).
func writeLenPrefixedBytes(buf *bytes.Buffer, b []byte) {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(b)))
	buf.Write(l[:])
	buf.Write(b)
}

// MarshalBlock encodes a Block into its full binary representation,
// including PoWNonce as a trailing 8-byte little-endian field.
// Hash and Signature are not encoded.
//
// It REFUSES a block that declares a pub_key (#829). The binary form has no
// field for one — an account's declared key is bound into the hash through
// MarshalBlockAux, not through the canonical bytes — so encoding a declaring
// block would silently drop a hash-bound field and hand the caller bytes that
// decode into a block whose re-derived hash no longer matches. Failing loudly
// here beats returning a block that will not verify and cannot be traced back
// to this function. Blocks are gossiped and persisted as JSON; this binary form
// is the hashing/signing pre-image, not a transport.
//
// MarshalBlockCanonical deliberately does NOT carry this guard: it is the
// hashing pre-image and must keep omitting PubKey, because HashBlock folds the
// key in via the aux input instead.
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

// UnmarshalBlock decodes a Block from its binary representation.
// Hash, Signature and PubKey are left empty: like the certificate hash and the
// attestations, an opening block's PubKey (#829) rides in the JSON wire form and
// is bound to the hash through MarshalBlockAux rather than living in the
// fixed-width canonical header. Blocks are gossiped and persisted as JSON; this
// binary form is the hashing/signing pre-image, not a transport.
// If data contains a trailing 8-byte little-endian PoWNonce beyond the
// canonical block bytes, it is decoded into PoWNonce; otherwise PoWNonce=0.
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
		// +1 for the always-present memo length byte (memo content adds more
		// when non-empty, validated below).
		minLen = fixedHeaderSize + sendTailSize + representativeSize + 1
	case typeByteReceive:
		blockType = BlockReceive
		minLen = fixedHeaderSize + receiveTailSize + representativeSize
	case typeByteGenesis:
		blockType = BlockGenesis
		minLen = fixedHeaderSize + representativeSize
	case typeByteMultisigOpen:
		blockType = BlockMultisigOpen
		minLen = fixedHeaderSize + 8 + representativeSize // 8 = threshold(4) + num_keys(4) min
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
		// +1 for the always-present memo length byte (memo content adds more
		// when non-empty, validated below).
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

	// Decode 8-byte asset field: trim trailing zero bytes.
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

	// repOffset is where the representative field starts (after type-specific tail).
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
		// #501: locked emission params follow the amount on lease_accept.
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
	default: // BlockGenesis
		repOffset = 90
	}

	// Representative: 32 bytes; all-zero encodes as "" (no delegation).
	repBytes := data[repOffset : repOffset+32]
	if !allZero(repBytes) {
		b.Representative = hex.EncodeToString(repBytes)
	}

	// Memo trailer (send/burn only): 1-byte length (0..MaxMemoBytes) followed
	// by the memo bytes. tailOffset advances past the trailer so the PoW
	// read below stays a clean trailing-8-byte check.
	tailOffset := minLen

	// Genesis lease-timing tail (#524): present only when the genesis pinned timing,
	// detected by length (122 bytes = none, 170 = pinned). An all-default genesis has
	// no tail and decodes exactly as before. tailOffset advances past it so the PoW
	// read stays a clean trailing-8-byte check.
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

	// Backward-compatible: read trailing 8-byte LE PoWNonce if present.
	if len(data) == tailOffset+8 {
		b.PoWNonce = binary.LittleEndian.Uint64(data[tailOffset:])
	}

	return b, nil
}

// marshalKeysetCanonical encodes a keyset into its canonical binary representation.
// Layout: threshold(4 bytes BE) + num_keys(4 bytes BE) + keys(32 bytes each, sorted).
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

// unmarshalKeysetCanonical decodes a keyset from its canonical binary representation.
// Returns the keyset and the number of bytes consumed.
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

// allZero returns true if all bytes in b are zero.
func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// voteVersionByte is the version marker for vote binary encoding.
const voteVersionByte = byte(0x02)

// voteSigningBytes encodes all Vote fields except Signature into a byte slice
// for use in signing and verification. Layout:
//
//	offset  size  field
//	0       1     version byte (0x02)
//	1       32    RepPubKey (hex-decoded)
//	33      32    BlockHash (hex-decoded)
//	65      32    ConflictAccount (hex-decoded)
//	97      32    ConflictPrev (hex-decoded; "0" → 32 zero bytes)
//	129     8     Timestamp (big-endian int64)
//	137     1     Final flag (0 = converge, 1 = final) (#526)
//	total = 138 bytes
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

	// Final flag (#526): signed so a converge vote can't be forged into a final
	// vote (or vice versa) by flipping the bit — that would corrupt the tally.
	if v.Final {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}

	return buf.Bytes(), nil
}

// EncodeVote encodes a Vote into its binary representation.
// Layout: voteSigningBytes(138) + sig_len(2, big-endian) + sig(N bytes)
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

// DecodeVote decodes a Vote from its binary representation produced by EncodeVote.
func DecodeVote(data []byte) (*Vote, error) {
	const signingSize = 138 // 1 + 32 + 32 + 32 + 32 + 8 + 1
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
