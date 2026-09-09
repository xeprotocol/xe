import { blake2b } from './blake2b.js';

export const DEFAULT_POW_DIFFICULTY = 0xfffff80000000000n;
export const DEFAULT_CHAT_POW_DIFFICULTY = 0xffffc00000000000n;

const U64_MASK = 0xffffffffffffffffn;

export function powHash(nonce, hashBytes) {
  const msg = new Uint8Array(8 + hashBytes.length);
  writeNonceLE(msg, nonce & U64_MASK);
  msg.set(hashBytes, 8);
  const d = blake2b(msg, 8);
  let out = 0n;
  for (let i = 0; i < 8; i++) out = (out << 8n) | BigInt(d[i]);
  return out;
}

export function validatePow(hashBytes, nonce, difficulty) {
  return powHash(nonce, hashBytes) >= difficulty;
}

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

function digestAtLeast(digest, diff) {
  for (let i = 0; i < 8; i++) {
    if (digest[i] > diff[i]) return true;
    if (digest[i] < diff[i]) return false;
  }
  return true;
}

let difficultiesPromise = null;

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
