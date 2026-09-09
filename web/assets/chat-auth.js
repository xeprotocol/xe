import { api } from './api.js';
import { hexToBytes } from './statechain-block.js';

const CHAT_AUTH_DOMAIN = 'xe/chat-read-auth/v1\x00';

async function signChallenge(keyPair, challengeHex) {
  const tokenBytes = hexToBytes(challengeHex);
  const enc = new TextEncoder();
  const domain = enc.encode(CHAT_AUTH_DOMAIN);
  const preimage = new Uint8Array(domain.length + tokenBytes.length);
  preimage.set(domain, 0);
  preimage.set(tokenBytes, domain.length);
  const digest = await crypto.subtle.digest('SHA-256', preimage);
  const sig = await keyPair.sign(new Uint8Array(digest));
  return Array.from(sig, (b) => b.toString(16).padStart(2, '0')).join('');
}

export async function chatProofParams(keyPair) {
  const { challenge } = await api('/chat/auth/challenge');
  const sig = await signChallenge(keyPair, challenge);
  const q = new URLSearchParams();
  q.set('account', keyPair.addressHex);
  q.set('pub_key', keyPair.pubKeyHex);
  q.set('challenge', challenge);
  q.set('sig', sig);
  return q.toString();
}
