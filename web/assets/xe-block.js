import { solvePow, getDifficulties } from './pow.js';

const TYPE_SEND = 0x01;
const TYPE_RECEIVE = 0x02;
const VERSION = 0x02;
const MAX_MEMO_BYTES = 64;

const ACCOUNT_ADDRESS_DOMAIN = 'xe/account/v1';

const AUX_TAG_ACCOUNT_PUBKEY = 'xe/block/pubkey/v1';

const PKCS8_ED25519_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

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
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

export function randomSeed() {
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  return seed;
}

function seedToPkcs8(seed) {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) {
    throw new Error('seedToPkcs8: seed must be 32 bytes');
  }
  const out = new Uint8Array(PKCS8_ED25519_PREFIX.length + 32);
  out.set(PKCS8_ED25519_PREFIX, 0);
  out.set(seed, PKCS8_ED25519_PREFIX.length);
  return out;
}

function base64UrlDecode(s) {
  let std = s.replace(/-/g, '+').replace(/_/g, '/');
  while (std.length % 4) std += '=';
  const bin = atob(std);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export async function deriveAddress(pubBytes) {
  if (!(pubBytes instanceof Uint8Array) || pubBytes.length !== 32) {
    throw new Error('deriveAddress: public key must be 32 bytes');
  }
  const tag = new TextEncoder().encode(ACCOUNT_ADDRESS_DOMAIN);
  const buf = new Uint8Array(tag.length + 32);
  buf.set(tag, 0);
  buf.set(pubBytes, tag.length);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
  return bytesToHex(digest);
}

export async function loadKeyPair(seed) {
  const pkcs8 = seedToPkcs8(seed);
  const priv = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', priv);
  const pub = base64UrlDecode(jwk.x);
  if (pub.length !== 32) throw new Error('exported public key not 32 bytes');
  return {
    publicKey: pub,
    pubKeyHex: bytesToHex(pub),
    addressHex: await deriveAddress(pub),
    sign: async (data) => {
      const sig = await crypto.subtle.sign('Ed25519', priv, data);
      return new Uint8Array(sig);
    },
  };
}

function writeAssetField(out, off, asset) {
  const bytes = new TextEncoder().encode(asset);
  if (bytes.length > 8) throw new Error('asset too long: ' + asset);
  out.set(bytes, off);
  return off + 8;
}

function writeBigUint64BE(view, off, value) {
  view.setBigUint64(off, BigInt(value), false);
  return off + 8;
}

function writeBytesAt(out, off, bytes) {
  out.set(bytes, off);
  return off + bytes.length;
}

function writeHexAt(out, off, hex, expectedLen) {
  return writeBytesAt(out, off, hexToBytes(hex, expectedLen));
}

function writePreviousAt(out, off, prev) {
  if (prev === '0' || prev === '') return off + 32;
  return writeHexAt(out, off, prev, 32);
}

function writeRepresentativeAt(out, off, rep) {
  if (!rep) return off + 32;
  return writeHexAt(out, off, rep, 32);
}

export function marshalSendCanonical({
  asset, account, previous, balance, timestamp,
  destination, amount, representative, memo,
}) {
  const memoBytes = memo ? new TextEncoder().encode(memo) : new Uint8Array(0);
  if (memoBytes.length > MAX_MEMO_BYTES) {
    throw new Error(`memo too long: ${memoBytes.length} bytes (max ${MAX_MEMO_BYTES})`);
  }
  const totalLen = 163 + memoBytes.length;
  const out = new Uint8Array(totalLen);
  const view = new DataView(out.buffer);
  let off = 0;
  view.setUint8(off++, VERSION);
  view.setUint8(off++, TYPE_SEND);
  off = writeAssetField(out, off, asset);
  off = writeHexAt(out, off, account, 32);
  off = writePreviousAt(out, off, previous);
  off = writeBigUint64BE(view, off, balance);
  off = writeBigUint64BE(view, off, timestamp);
  off = writeHexAt(out, off, destination, 32);
  off = writeBigUint64BE(view, off, amount);
  off = writeRepresentativeAt(out, off, representative || '');
  view.setUint8(off++, memoBytes.length);
  out.set(memoBytes, off);
  off += memoBytes.length;
  if (off !== totalLen) throw new Error('marshalSendCanonical: wrote ' + off + ' bytes');
  return out;
}

export function marshalReceiveCanonical({
  asset, account, previous, balance, timestamp,
  source, representative,
}) {
  const out = new Uint8Array(154);
  const view = new DataView(out.buffer);
  let off = 0;
  view.setUint8(off++, VERSION);
  view.setUint8(off++, TYPE_RECEIVE);
  off = writeAssetField(out, off, asset);
  off = writeHexAt(out, off, account, 32);
  off = writePreviousAt(out, off, previous);
  off = writeBigUint64BE(view, off, balance);
  off = writeBigUint64BE(view, off, timestamp);
  off = writeHexAt(out, off, source, 32);
  off = writeRepresentativeAt(out, off, representative || '');
  if (off !== 154) throw new Error('marshalReceiveCanonical: wrote ' + off + ' bytes');
  return out;
}

function writeLenPrefixed(parts, str) {
  const bytes = new TextEncoder().encode(str);
  const len = new Uint8Array(8);
  new DataView(len.buffer).setBigUint64(0, BigInt(bytes.length), false);
  parts.push(len, bytes);
}

export function marshalBlockAux(pubKeyHex) {
  if (!pubKeyHex) return new Uint8Array(0);
  const parts = [];
  writeLenPrefixed(parts, AUX_TAG_ACCOUNT_PUBKEY);
  writeLenPrefixed(parts, pubKeyHex);
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

export async function hashCanonical(networkId, canonical, aux) {
  const netBytes = new TextEncoder().encode(networkId);
  const auxBytes = aux || new Uint8Array(0);
  const buf = new Uint8Array(netBytes.length + canonical.length + auxBytes.length);
  buf.set(netBytes, 0);
  buf.set(canonical, netBytes.length);
  buf.set(auxBytes, netBytes.length + canonical.length);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
  return { bytes: digest, hex: bytesToHex(digest) };
}

export async function fetchBlockJsonLossless(path) {
  const res = await fetch(path);
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try { const body = await res.json(); if (body && body.error) detail = body.error; } catch {}
    throw new Error(detail);
  }
  const text = await res.text();
  const fixed = text.replace(/"(timestamp|balance|amount|pow_nonce)"\s*:\s*(\d+)/g, '"$1":"$2"');
  return JSON.parse(fixed);
}

export function isOpenBlock(previous) {
  return !previous || previous === '0';
}

export async function verifyKnownBlock(networkId, block) {
  let canonical;
  if (block.type === 'send') {
    canonical = marshalSendCanonical({ ...block, memo: block.memo || '' });
  } else if (block.type === 'receive') {
    canonical = marshalReceiveCanonical(block);
  } else {
    throw new Error('verifyKnownBlock: unsupported type ' + block.type);
  }
  const { hex } = await hashCanonical(networkId, canonical, marshalBlockAux(block.pub_key || ''));
  if (hex !== block.hash) {
    throw new Error(`hash mismatch: got ${hex}, expected ${block.hash}`);
  }
  return true;
}

export async function requestFaucet(address) {
  const res = await fetch('/faucet/request', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ address }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    let msg = data.error || 'HTTP ' + res.status;
    if (res.status === 429 && data.retry_after_seconds) {
      msg += ` — try again in ${formatRetry(data.retry_after_seconds)}`;
    }
    throw new Error(msg);
  }
  return data;
}

function formatRetry(seconds) {
  const s = Math.max(0, Math.floor(Number(seconds) || 0));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (h > 0) return m > 0 ? `${h}h ${m}m` : `${h}h`;
  if (m > 0) return `${m}m`;
  return `${s}s`;
}

export async function buildAndSubmitSend({ keyPair, networkId, previous, currentBalance, asset, destination, amount, memo }) {
  const ts = nowNs();
  const newBalance = BigInt(currentBalance) - BigInt(amount);
  if (newBalance < 0n) throw new Error('insufficient balance');
  const fields = {
    asset,
    account: keyPair.addressHex,
    previous: previous || '0',
    balance: newBalance,
    timestamp: ts,
    destination,
    amount: BigInt(amount),
    representative: '',
    memo: memo || '',
  };
  const canonical = marshalSendCanonical(fields);
  const pubKey = isOpenBlock(fields.previous) ? keyPair.pubKeyHex : '';
  const { bytes: hashBytes, hex: hashHex } = await hashCanonical(networkId, canonical, marshalBlockAux(pubKey));
  const sigBytes = await keyPair.sign(hashBytes);
  const sigHex = bytesToHex(sigBytes);
  const nonce = await computePow(hashBytes);
  const blockJson = {
    type: 'send',
    account: fields.account,
    previous: fields.previous,
    balance: fields.balance,
    timestamp: fields.timestamp,
    asset: fields.asset,
    destination: fields.destination,
    amount: fields.amount,
    signature: sigHex,
    hash: hashHex,
  };
  if (pubKey) blockJson.pub_key = pubKey;
  if (fields.memo) blockJson.memo = fields.memo;
  const body = serializeBlockJson(blockJson, nonce);
  return await postBlock('/api/blocks/send', body);
}

export async function buildAndSubmitReceive({ keyPair, networkId, previous, currentBalance, asset, source, amount }) {
  const ts = nowNs();
  const newBalance = BigInt(currentBalance) + BigInt(amount);
  const fields = {
    asset,
    account: keyPair.addressHex,
    previous: previous || '0',
    balance: newBalance,
    timestamp: ts,
    source,
    representative: '',
  };
  const canonical = marshalReceiveCanonical(fields);
  const pubKey = isOpenBlock(fields.previous) ? keyPair.pubKeyHex : '';
  const { bytes: hashBytes, hex: hashHex } = await hashCanonical(networkId, canonical, marshalBlockAux(pubKey));
  const sigBytes = await keyPair.sign(hashBytes);
  const sigHex = bytesToHex(sigBytes);
  const nonce = await computePow(hashBytes);
  const blockJson = {
    type: 'receive',
    account: fields.account,
    previous: fields.previous,
    balance: fields.balance,
    timestamp: fields.timestamp,
    asset: fields.asset,
    source: fields.source,
    signature: sigHex,
    hash: hashHex,
  };
  if (pubKey) blockJson.pub_key = pubKey;
  const body = serializeBlockJson(blockJson, nonce);
  return await postBlock('/api/blocks/receive', body);
}

async function computePow(hashBytes) {
  const { pow: difficulty } = await getDifficulties();
  if (difficulty <= 0n) return 0n;
  return solvePow(hashBytes, difficulty);
}

async function postBlock(path, body) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'HTTP ' + res.status }));
    throw new Error(err.error || 'submit failed');
  }
  return res.json();
}

function serializeBlockJson(block, nonceBigInt) {
  const fullBlock = { ...block, pow_nonce: nonceBigInt };
  const parts = [];
  for (const [k, v] of Object.entries(fullBlock)) {
    if (v == null) continue;
    if (typeof v === 'bigint') {
      parts.push(JSON.stringify(k) + ':' + v.toString());
    } else {
      parts.push(JSON.stringify(k) + ':' + JSON.stringify(v));
    }
  }
  return '{' + parts.join(',') + '}';
}

function nowNs() {
  return BigInt(Date.now()) * 1000000n;
}
