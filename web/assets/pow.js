// Client-side blake2b proof-of-work, mirroring core/pow.go: an 8-byte
// blake2b digest over nonce_LE(8) || hash(32), read as a big-endian uint64;
// a nonce is valid when that value >= difficulty.

import { blake2b } from './blake2b.js';

// Mirrors core.DefaultDifficulty (~2M expected attempts).
export const DEFAULT_POW_DIFFICULTY = 0xfffff80000000000n;
// Mirrors chat.DefaultPoWDifficulty (~2^18 expected attempts).
export const DEFAULT_CHAT_POW_DIFFICULTY = 0xffffc00000000000n;

const U64_MASK = 0xffffffffffffffffn;

// powHash mirrors core.powHash: blake2b-8 over nonce_LE || hash, big-endian.
export function powHash(nonce, hashBytes) {
  const msg = new Uint8Array(8 + hashBytes.length);
  writeNonceLE(msg, nonce & U64_MASK);
  msg.set(hashBytes, 8);
  const d = blake2b(msg, 8);
  let out = 0n;
  for (let i = 0; i < 8; i++) out = (out << 8n) | BigInt(d[i]);
  return out;
}

// validatePow mirrors core.ValidatePoW: higher difficulty is harder.
export function validatePow(hashBytes, nonce, difficulty) {
  return powHash(nonce, hashBytes) >= difficulty;
}

// solvePow brute-forces a valid nonce from a random start, incrementing with
// wrap. The hot loop is BigInt-free: the nonce lives as two 32-bit halves
// written straight into a preallocated message buffer, and the digest is
// compared against precomputed big-endian difficulty bytes. Yields to the
// event loop (and calls onProgress(attempts), if given) every 16384 attempts.
export async function solvePow(hashBytes, difficulty, onProgress) {
  const diff = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    diff[i] = Number((difficulty >> BigInt(8 * (7 - i))) & 0xffn);
  }

  const msg = new Uint8Array(8 + hashBytes.length);
  msg.set(hashBytes, 8);
  const digest = new Uint8Array(8);

  const start = new Uint8Array(8);
  crypto.getRandomValues(start);
  let lo = (start[0] | (start[1] << 8) | (start[2] << 16) | (start[3] << 24)) >>> 0;
  let hi = (start[4] | (start[5] << 8) | (start[6] << 16) | (start[7] << 24)) >>> 0;

  let attempts = 0;
  for (;;) {
    msg[0] = lo;
    msg[1] = lo >>> 8;
    msg[2] = lo >>> 16;
    msg[3] = lo >>> 24;
    msg[4] = hi;
    msg[5] = hi >>> 8;
    msg[6] = hi >>> 16;
    msg[7] = hi >>> 24;
    blake2b(msg, 8, digest);
    if (digestAtLeast(digest, diff)) {
      return (BigInt(hi) << 32n) | BigInt(lo);
    }
    lo = (lo + 1) >>> 0;
    if (lo === 0) hi = (hi + 1) >>> 0;
    attempts++;
    if ((attempts & 0x3fff) === 0) {
      if (onProgress) onProgress(attempts);
      await new Promise(r => setTimeout(r, 0));
    }
  }
}

// Lexicographic compare of two 8-byte big-endian values: digest >= diff.
function digestAtLeast(digest, diff) {
  for (let i = 0; i < 8; i++) {
    if (digest[i] > diff[i]) return true;
    if (digest[i] < diff[i]) return false;
  }
  return true;
}

let difficultiesPromise = null;

// getDifficulties returns { pow, chat } as BigInts, from the node's
// /api/node hex-string fields, falling back to the mirrored constants on
// fetch failure or missing fields. The result is cached for the page's life.
export async function getDifficulties() {
  if (!difficultiesPromise) difficultiesPromise = fetchDifficulties();
  return difficultiesPromise;
}

async function fetchDifficulties() {
  let pow = DEFAULT_POW_DIFFICULTY;
  let chat = DEFAULT_CHAT_POW_DIFFICULTY;
  try {
    const res = await fetch('/api/node');
    if (res.ok) {
      const data = await res.json();
      pow = parseHexDifficulty(data.pow_difficulty, pow);
      chat = parseHexDifficulty(data.chat_pow_difficulty, chat);
    }
  } catch {
    // fall through to defaults
  }
  return { pow, chat };
}

function parseHexDifficulty(s, fallback) {
  if (typeof s !== 'string' || !/^[0-9a-fA-F]{1,16}$/.test(s)) return fallback;
  return BigInt('0x' + s);
}

function writeNonceLE(buf, nonce) {
  for (let i = 0; i < 8; i++) {
    buf[i] = Number((nonce >> BigInt(8 * i)) & 0xffn);
  }
}
