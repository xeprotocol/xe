// Canonical encoding + hash for state-chain blocks.
// Mirrors core/statechain/encoding.go MarshalCanonical and crypto.go HashBlock.
// Layout:
//   [index:     8 bytes BE uint64]
//   [prev_hash: 32 bytes raw (hex-decoded)]
//   [num_ops:   4 bytes BE uint32]
//   for each op:
//     [action:    1 byte (0x01=set, 0x02=delete)]
//     [key_len:   2 bytes BE uint16]
//     [key:       key_len bytes UTF-8]
//     [value_len: 4 bytes BE uint32]  (0 for delete)
//     [value:     value_len bytes raw JSON]  (omitted for delete)
//   [timestamp: 8 bytes BE int64]
// Hash: SHA-256 of canonical bytes, returned as hex.

const ACTION_BYTE = { set: 0x01, delete: 0x02 };

export function hexToBytes(hex, expectedLen) {
  if (typeof hex !== 'string') throw new TypeError('hexToBytes: expected string');
  if (hex.length % 2 !== 0) throw new Error('hexToBytes: odd length');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const b = parseInt(hex.substr(i * 2, 2), 16);
    if (Number.isNaN(b)) throw new Error('hexToBytes: invalid hex');
    out[i] = b;
  }
  if (expectedLen != null && out.length !== expectedLen) {
    throw new Error(`hexToBytes: expected ${expectedLen} bytes, got ${out.length}`);
  }
  return out;
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function writeU64BE(view, offset, value) {
  // value is a BigInt
  const v = BigInt(value);
  for (let i = 7; i >= 0; i--) {
    view.setUint8(offset + i, Number(v >> BigInt((7 - i) * 8) & 0xffn));
  }
}

function writeU32BE(view, offset, value) {
  view.setUint32(offset, value >>> 0, false);
}

function writeU16BE(view, offset, value) {
  view.setUint16(offset, value & 0xffff, false);
}

// Encode a single op into a byte array.
// op = { action: 'set'|'delete', key: string, value: string (raw JSON for set) }
function encodeOp(op) {
  if (!ACTION_BYTE[op.action]) throw new Error(`unknown action: ${op.action}`);
  const keyBytes = new TextEncoder().encode(op.key);
  const valBytes = op.action === 'set' ? new TextEncoder().encode(op.value || '') : new Uint8Array(0);
  const len = 1 + 2 + keyBytes.length + 4 + valBytes.length;
  const out = new Uint8Array(len);
  const view = new DataView(out.buffer);
  let p = 0;
  out[p++] = ACTION_BYTE[op.action];
  writeU16BE(view, p, keyBytes.length); p += 2;
  out.set(keyBytes, p); p += keyBytes.length;
  writeU32BE(view, p, valBytes.length); p += 4;
  if (valBytes.length) out.set(valBytes, p);
  return out;
}

// MarshalCanonical encodes a block. Block = { index, prev_hash, ops, timestamp }.
export function marshalCanonical(block) {
  const opBufs = (block.ops || []).map(encodeOp);
  const opsTotal = opBufs.reduce((s, b) => s + b.length, 0);
  const total = 8 + 32 + 4 + opsTotal + 8;
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  let p = 0;
  writeU64BE(view, p, block.index || 0); p += 8;
  const prev = hexToBytes(block.prev_hash, 32);
  out.set(prev, p); p += 32;
  writeU32BE(view, p, opBufs.length); p += 4;
  for (const b of opBufs) { out.set(b, p); p += b.length; }
  // Timestamp: int64 written as the bit pattern of uint64 (matches Go's
  // binary.BigEndian.PutUint64(uint64(b.Timestamp))). For positive
  // timestamps under 2^63 this is identical.
  writeU64BE(view, p, BigInt(block.timestamp || 0)); p += 8;
  return out;
}

export async function hashBlock(block) {
  const data = marshalCanonical(block);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return bytesToHex(new Uint8Array(digest));
}
