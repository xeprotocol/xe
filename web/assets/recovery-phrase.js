import { wordlist } from './wordlist-english.js';

export const RECOVERY_PHRASE_COIN_TYPE = 22597;
const wordIndex = new Map(wordlist.map((word, index) => [word, index]));
const utf8 = new TextEncoder();

export class PhraseError extends Error {
  constructor(code, message, position) {
    super(message);
    this.name = 'PhraseError';
    this.code = code;
    this.position = position;
  }
}

export function normalizePhrase(phrase) {
  return phrase.toLowerCase().split(/\p{White_Space}+/u).filter(Boolean).join(' ').normalize('NFKD');
}

export async function phraseFromEntropy(entropy) {
  if (![16, 20, 24, 28, 32].includes(entropy.length)) throw new Error('invalid BIP39 entropy length');
  const checksum = new Uint8Array(await crypto.subtle.digest('SHA-256', entropy));
  const data = new Uint8Array([...entropy, checksum[0]]);
  const words = [];
  const length = (entropy.length * 8 + entropy.length / 4) / 11;
  for (let i = 0; i < length; i++) {
    let index = 0;
    for (let bit = i * 11; bit < (i + 1) * 11; bit++) {
      index = (index << 1) | ((data[bit >> 3] >> (7 - bit % 8)) & 1);
    }
    words.push(wordlist[index]);
  }
  return words.join(' ');
}

export function generatePhrase() {
  return phraseFromEntropy(crypto.getRandomValues(new Uint8Array(32)));
}

export async function validatePhrase(phrase) {
  const normalized = normalizePhrase(phrase);
  const words = normalized ? normalized.split(' ') : [];
  if (![12, 15, 18, 21, 24].includes(words.length)) {
    throw new PhraseError('word_count', 'recovery phrase must have 12, 15, 18, 21 or 24 words');
  }
  const data = new Uint8Array(Math.ceil(words.length * 11 / 8));
  for (let i = 0; i < words.length; i++) {
    const index = wordIndex.get(words[i]);
    if (index === undefined) {
      throw new PhraseError('unknown_word', `unknown recovery phrase word at position ${i + 1}`, i + 1);
    }
    for (let j = 0; j < 11; j++) {
      const bit = i * 11 + j;
      data[bit >> 3] |= ((index >> (10 - j)) & 1) << (7 - bit % 8);
    }
  }
  const entropyBytes = words.length * 4 / 3;
  const shift = 8 - entropyBytes / 4;
  const checksum = new Uint8Array(await crypto.subtle.digest('SHA-256', data.slice(0, entropyBytes)));
  if ((data[entropyBytes] >> shift) !== (checksum[0] >> shift)) {
    throw new PhraseError('checksum', 'recovery phrase checksum does not match');
  }
  return normalized;
}

export async function bip39Seed(phrase, passphrase = '') {
  const normalized = await validatePhrase(phrase);
  const key = await crypto.subtle.importKey('raw', utf8.encode(normalized), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({
    name: 'PBKDF2', hash: 'SHA-512', iterations: 2048,
    salt: utf8.encode('mnemonic' + passphrase.normalize('NFKD')),
  }, key, 512));
}

async function hmac(keyBytes, data) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-512' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
}

export async function slip10Ed25519(seed, path) {
  let node = await hmac(utf8.encode('ed25519 seed'), seed);
  for (const index of path) {
    validateAccount(index);
    const data = new Uint8Array(37);
    data.set(node.subarray(0, 32), 1);
    new DataView(data.buffer).setUint32(33, index + 0x80000000, false);
    node = await hmac(node.subarray(32), data);
  }
  return { key: node.slice(0, 32), chainCode: node.slice(32) };
}

function validateAccount(account) {
  if (!Number.isInteger(account) || account < 0 || account >= 0x80000000) {
    throw new PhraseError('account', 'recovery phrase account must be between 0 and 2147483647');
  }
}

export async function seedFromPhrase(phrase, { passphrase = '', account = 0 } = {}) {
  validateAccount(account);
  const seed = await bip39Seed(phrase, passphrase);
  return (await slip10Ed25519(seed, [44, RECOVERY_PHRASE_COIN_TYPE, account])).key;
}

export function pickCheckPositions(total = 24) {
  const positions = new Set();
  while (positions.size < 3) {
    const value = crypto.getRandomValues(new Uint8Array(1))[0];
    if (value < 256 - 256 % total) positions.add(value % total);
  }
  return [...positions].sort((a, b) => a - b);
}
