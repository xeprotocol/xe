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

export async function buildEnvelope(keyPair, to, message, onProgress) {
  const ts = BigInt(Date.now()) * 1_000_000n;
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
    timestamp: ts,
    signature: bytesToHex(sigBytes),
    pow_nonce: nonce,
  };
}

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
