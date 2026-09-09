const DOMAIN_TAG = 'xe/directory-registration/v1\x00';

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

export async function signRegistration(keyPair, networkID, account, nodePeer, timestamp) {
  const canonical = buildRegistrationCanonical(networkID, account, keyPair.pubKeyHex, nodePeer, timestamp);
  const digest = await crypto.subtle.digest('SHA-256', canonical);
  const sig = await keyPair.sign(new Uint8Array(digest));
  return Array.from(sig, (b) => b.toString(16).padStart(2, '0')).join('');
}

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
