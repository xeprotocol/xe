const VAULT_KEY = 'xe.wallets';
const LEGACY_SEED_KEY = 'xe.wallet.seed';
const LEGACY_ACTIVITY_KEY = 'xe.wallet.activity';
const PBKDF2_ITERATIONS = 600000;
const SALT_BYTES = 16;
const IV_BYTES = 12;

export function loadVault() {
  const raw = localStorage.getItem(VAULT_KEY);
  if (!raw) return null;
  try {
    const v = JSON.parse(raw);
    if (!v || !Array.isArray(v.wallets)) return null;
    return v;
  } catch {
    return null;
  }
}

export function saveVault(vault) {
  localStorage.setItem(VAULT_KEY, JSON.stringify(vault));
}

export function clearVault() {
  localStorage.removeItem(VAULT_KEY);
}

export function hasLegacySeed() {
  return localStorage.getItem(LEGACY_SEED_KEY) != null;
}

export function loadLegacySeed() {
  return localStorage.getItem(LEGACY_SEED_KEY);
}

export function deleteLegacySeed() {
  localStorage.removeItem(LEGACY_SEED_KEY);
}

export function loadLegacyActivity() {
  const raw = localStorage.getItem(LEGACY_ACTIVITY_KEY);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

export function deleteLegacyActivity() {
  localStorage.removeItem(LEGACY_ACTIVITY_KEY);
}

function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

function bytesToB64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function b64ToBytes(b64) {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

async function deriveKey(passphrase, saltBytes, iterations) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function encryptSeed(passphrase, seedBytes) {
  if (!(seedBytes instanceof Uint8Array) || seedBytes.length !== 32) {
    throw new Error('encryptSeed: seed must be 32 bytes');
  }
  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);
  const key = await deriveKey(passphrase, salt, PBKDF2_ITERATIONS);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    seedBytes,
  ));
  return {
    salt: bytesToB64(salt),
    iv: bytesToB64(iv),
    encrypted_seed: bytesToB64(ciphertext),
    iterations: PBKDF2_ITERATIONS,
  };
}

export async function decryptSeed(passphrase, walletEntry) {
  const salt = b64ToBytes(walletEntry.salt);
  const iv = b64ToBytes(walletEntry.iv);
  const ciphertext = b64ToBytes(walletEntry.encrypted_seed);
  const key = await deriveKey(passphrase, salt, walletEntry.iterations || PBKDF2_ITERATIONS);
  let plaintext;
  try {
    plaintext = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      ciphertext,
    ));
  } catch {
    throw new Error('incorrect passphrase');
  }
  if (plaintext.length !== 32) throw new Error('decrypted seed has wrong length');
  return plaintext;
}

export async function buildWalletEntry(passphrase, name, keyPair, seedBytes) {
  const enc = await encryptSeed(passphrase, seedBytes);
  return {
    name,
    address: keyPair.addressHex,
    pub_key: keyPair.pubKeyHex,
    created_at: Date.now(),
    ...enc,
  };
}

export function syncWalletIdentity(entry, keyPair) {
  let changed = false;
  if (entry.address !== keyPair.addressHex) {
    entry.address = keyPair.addressHex;
    changed = true;
  }
  if (entry.pub_key !== keyPair.pubKeyHex) {
    entry.pub_key = keyPair.pubKeyHex;
    changed = true;
  }
  return changed;
}

export function emptyVault() {
  return { wallets: [], active: 0 };
}

export function removeWallet(vault, index) {
  const [removed] = vault.wallets.splice(index, 1);
  if (vault.active > index) vault.active -= 1;
  if (vault.active >= vault.wallets.length) {
    vault.active = Math.max(0, vault.wallets.length - 1);
  }
  return removed;
}

const UNLOCK_KEY = 'xe.session.unlock';
const UNLOCK_TTL_MS = 30 * 60 * 1000;

export function cacheUnlock(passphrase) {
  if (!passphrase) return;
  try {
    sessionStorage.setItem(UNLOCK_KEY, JSON.stringify({
      passphrase,
      expires_at: Date.now() + UNLOCK_TTL_MS,
    }));
  } catch {   }
}

export function loadCachedUnlock() {
  try {
    const raw = sessionStorage.getItem(UNLOCK_KEY);
    if (!raw) return null;
    const obj = JSON.parse(raw);
    if (!obj || !obj.passphrase) return null;
    if (typeof obj.expires_at === 'number' && obj.expires_at < Date.now()) {
      sessionStorage.removeItem(UNLOCK_KEY);
      return null;
    }
    return obj.passphrase;
  } catch { return null; }
}

export function clearCachedUnlock() {
  try { sessionStorage.removeItem(UNLOCK_KEY); } catch {}
}

export async function tryCachedDecrypt(walletEntry) {
  const pass = loadCachedUnlock();
  if (!pass) return null;
  try {
    return await decryptSeed(pass, walletEntry);
  } catch {
    clearCachedUnlock();
    return null;
  }
}
