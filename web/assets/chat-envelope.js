// Canonical encoding + signing for chat envelopes.
// Mirrors core/chat/envelope.go envelopeCanonical / ComputeEnvelopeID / NewEnvelope.
//
// envelope canonical layout:
//   [4-byte len BE][from utf-8 bytes]
//   [4-byte len BE][pub_key utf-8 bytes]   ← #829
//   [4-byte len BE][to utf-8 bytes]
//   [4-byte len BE][message utf-8 bytes]
//   [8-byte timestamp BE int64]
// id = sha256(canonical) hex
// signature = Ed25519 sign over the 32-byte id (raw, hex-decoded)
// pow_nonce = anti-spam PoW solved over the 32-byte id (#729)
//
// #829: `from` is the sender's ADDRESS — sha256("xe/account/v1" || pubkey) —
// so it can no longer verify the envelope's own signature. The envelope
// therefore declares `pub_key` and the node checks that it derives `from`
// before checking the signature. The key is framed into the canonical bytes
// next to the address it certifies, so it is covered by both the signature and
// the PoW and cannot be swapped in transit.

import { hexToBytes, bytesToHex } from './statechain-block.js';
import { solvePow, getDifficulties } from './pow.js';

function appendField(parts, bytes) {
  const lenBuf = new Uint8Array(4);
  new DataView(lenBuf.buffer).setUint32(0, bytes.length, false);
  parts.push(lenBuf, bytes);
}

export function envelopeCanonical(from, pubKey, to, message, timestampNs) {
  const enc = new TextEncoder();
  const parts = [];
  appendField(parts, enc.encode(from));
  appendField(parts, enc.encode(pubKey));
  appendField(parts, enc.encode(to));
  appendField(parts, enc.encode(message));
  const ts = new Uint8Array(8);
  // Treat int64 timestamp as the same bit pattern uint64 — matches Go's
  // binary.BigEndian.PutUint64(uint64(ts)).
  new DataView(ts.buffer).setBigUint64(0, BigInt(timestampNs), false);
  parts.push(ts);
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let p = 0;
  for (const part of parts) { out.set(part, p); p += part.length; }
  return out;
}

export async function computeEnvelopeID(from, pubKey, to, message, timestampNs) {
  const data = envelopeCanonical(from, pubKey, to, message, timestampNs);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return bytesToHex(new Uint8Array(digest));
}

// Build + sign an envelope, then solve its anti-spam PoW over the id at the
// node's advertised chat difficulty (#729).
// keyPair = { addressHex, pubKeyHex, sign(bytes) }.
// Returns the envelope object with `timestamp`/`pow_nonce` as BigInts — pass
// through serializeEnvelopeJson before POSTing so the uint64s round-trip
// cleanly. onProgress (optional) is forwarded to the PoW solver.
export async function buildEnvelope(keyPair, to, message, onProgress) {
  const ts = BigInt(Date.now()) * 1_000_000n; // ns
  // The key comes from the signing key pair, never from a caller, so the
  // declared key is always the one that signs (#829).
  const pubKey = keyPair.pubKeyHex;
  const id = await computeEnvelopeID(keyPair.addressHex, pubKey, to, message, ts);
  const idBytes = hexToBytes(id, 32);
  const sigBytes = await keyPair.sign(idBytes);
  const { chat: difficulty } = await getDifficulties();
  const nonce = difficulty > 0n ? await solvePow(idBytes, difficulty, onProgress) : 0n;
  return {
    id,
    from: keyPair.addressHex,
    pub_key: pubKey,
    to,
    message,
    timestamp: ts, // BigInt — exceeds Number.MAX_SAFE_INTEGER
    signature: bytesToHex(sigBytes),
    pow_nonce: nonce,
  };
}

// Serialize envelope to JSON without losing int64 precision on the timestamp.
// Go's json.Unmarshal accepts bare decimal numbers for int64 fields.
export function serializeEnvelopeJson(env) {
  const parts = [];
  for (const [k, v] of Object.entries(env)) {
    if (v == null) continue;
    if (typeof v === 'bigint') {
      parts.push(JSON.stringify(k) + ':' + v.toString());
    } else {
      parts.push(JSON.stringify(k) + ':' + JSON.stringify(v));
    }
  }
  return '{' + parts.join(',') + '}';
}
