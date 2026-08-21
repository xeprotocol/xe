// Canonical signing for directory registrations. Mirrors the Go side
// (directory/verify.go canonicalBytes, #605): a domain tag, then each of
// [networkID, account, pubKey, nodePeer, decimal timestamp] framed with an
// 8-byte big-endian length prefix, signed as ed25519(sha256(bytes)).
//
// #829: `account` is an ADDRESS — sha256("xe/account/v1" || pubkey) — so a
// registration no longer carries a key that can verify its own signature. It
// declares `pub_key` alongside, framed into these bytes next to the address it
// certifies; the node checks the key derives the account BEFORE checking the
// signature, so a registration cannot be re-pointed at another account.

const DOMAIN_TAG = 'xe/directory-registration/v1\x00';

// buildRegistrationCanonical returns the exact byte preimage the node hashes
// and verifies. timestamp must already be a decimal string (nanoseconds) —
// it can exceed Number.MAX_SAFE_INTEGER, so callers keep it as BigInt/string.
export function buildRegistrationCanonical(networkID, account, pubKey, nodePeer, timestamp) {
  const enc = new TextEncoder();
  const parts = [enc.encode(DOMAIN_TAG)];
  for (const field of [networkID, account, pubKey, nodePeer, timestamp]) {
    const bytes = enc.encode(field);
    const len = new Uint8Array(8);
    new DataView(len.buffer).setBigUint64(0, BigInt(bytes.length));
    parts.push(len, bytes);
  }
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// signRegistration returns the hex signature for a registration, matching
// Go directory.SignRegistration. keyPair is the object from loadKeyPair();
// the declared key is taken from it rather than from a parameter, so the key
// bound into the signed bytes is always the one that signs them (#829).
export async function signRegistration(keyPair, networkID, account, nodePeer, timestamp) {
  const canonical = buildRegistrationCanonical(networkID, account, keyPair.pubKeyHex, nodePeer, timestamp);
  const digest = await crypto.subtle.digest('SHA-256', canonical);
  const sig = await keyPair.sign(new Uint8Array(digest));
  return Array.from(sig, (b) => b.toString(16).padStart(2, '0')).join('');
}

// buildRegistration returns the complete registration body the node accepts,
// as a JSON string. It is the one construction path that cannot forget to
// declare pub_key — mirrors Go directory.NewRegistration (#829). timestamp is
// a decimal nanosecond string, emitted bare so Go's int64 unmarshal keeps full
// precision.
export async function buildRegistrationJson(keyPair, networkID, nodePeer, timestamp) {
  const account = keyPair.addressHex;
  const sig = await signRegistration(keyPair, networkID, account, nodePeer, timestamp);
  return '{' + [
    `"account":${JSON.stringify(account)}`,
    `"pub_key":${JSON.stringify(keyPair.pubKeyHex)}`,
    `"node_peer":${JSON.stringify(nodePeer)}`,
    `"timestamp":${timestamp}`,
    `"signature":${JSON.stringify(sig)}`,
  ].join(',') + '}';
}
