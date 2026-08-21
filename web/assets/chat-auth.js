// Chat read ownership proof (#745). Reading an account's history or event
// stream requires proving ownership of that account: fetch a short-lived
// server challenge, sign sha256(domain || challengeBytes) with the account
// key, and pass account+challenge+sig as query params (params, not headers,
// so it works with EventSource).
//
// Mirrors api/chat_auth.go: chatAuthDomain and chatSignTarget.

import { api } from './api.js';
import { hexToBytes } from './statechain-block.js';

const CHAT_AUTH_DOMAIN = 'xe/chat-read-auth/v1\x00';

// signChallenge signs a hex challenge token as the given key pair and returns
// the hex signature.
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

// chatProofParams fetches a fresh challenge and returns the URLSearchParams
// fragment (account, challenge, sig) proving ownership of keyPair's account.
// Each call consumes one single-use challenge, so call it per request.
// #829: `account` is an ADDRESS and can no longer verify the proof signature,
// so the verifying key is sent alongside it as `pub_key` (required — see
// api/chat_auth.go requireChatOwnership, which checks the key derives the
// account before checking the signature).
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
