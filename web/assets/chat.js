import { api } from './api.js';
import { shortAddr } from './format.js';
import { loadKeyPair } from './xe-block.js';
import { loadVault, decryptSeed, cacheUnlock, tryCachedDecrypt } from './vault.js';
import { buildEnvelope, serializeEnvelopeJson } from './chat-envelope.js';
import { buildRegistrationJson } from './directory-registration.js';
import { refreshNode as navRefreshNode } from './nav.js';
import { chatProofParams } from './chat-auth.js';

const CONTACTS_PREFIX = 'xe.chat.contacts.';

const state = {
  vault: null,
  walletIdx: -1,
  keyPair: null,
  nodePeer: '',
  networkID: '',
  contacts: new Set(),
  active: null,
  messages: [],
  unread: new Map(),
  registered: new Map(),
  sse: null,
  sseReconnect: null,
  syncTimer: null,
  dirTimer: null,
};

const DIRECTORY_REFRESH_MS = 10 * 60 * 1000;

const CHAT_SYNC_MS = 45 * 1000;

async function init() {
  await refreshNode();
  bindStaticHandlers();
  state.vault = loadVault();
  if (!state.vault || state.vault.wallets.length === 0) {
    document.getElementById('setup-section').hidden = false;
    return;
  }
  state.walletIdx = state.vault.active >= 0 && state.vault.active < state.vault.wallets.length
    ? state.vault.active
    : 0;
  const w = state.vault.wallets[state.walletIdx];
  const seed = await tryCachedDecrypt(w);
  if (seed) {
    try {
      state.keyPair = await loadKeyPair(seed);
      await showChat();
      return;
    } catch (e) {
      showError('could not open chat: ' + e.message);
    }
  }
  showUnlock();
}

async function refreshNode() {
  const node = await navRefreshNode();
  if (node) {
    state.nodePeer = node.id || '';
    state.networkID = node.network_id || '';
  }
}

function bindStaticHandlers() {
  document.getElementById('unlock-form').addEventListener('submit', onUnlockSubmit);
  document.getElementById('add-contact-form').addEventListener('submit', onAddContact);
  document.getElementById('send-form').addEventListener('submit', onSend);
}

function showUnlock() {
  const w = state.vault.wallets[state.walletIdx];
  setText('unlock-target', `${w.name || ''} · ${shortAddr(w.address)}`);
  document.getElementById('setup-section').hidden = true;
  document.getElementById('unlock-section').hidden = false;
  document.getElementById('chat-section').hidden = true;
  setTimeout(() => document.getElementById('unlock-passphrase')?.focus(), 0);
}

async function onUnlockSubmit(ev) {
  ev.preventDefault();
  const pass = document.getElementById('unlock-passphrase').value;
  document.getElementById('unlock-passphrase').value = '';
  const w = state.vault.wallets[state.walletIdx];
  let seed;
  try {
    seed = await decryptSeed(pass, w);
  } catch {
    showError('incorrect passphrase');
    return;
  }
  try {
    state.keyPair = await loadKeyPair(seed);
    cacheUnlock(pass);
    await showChat();
  } catch (e) {
    showError('could not unlock: ' + e.message);
  }
}

async function showChat() {
  document.getElementById('unlock-section').hidden = true;
  document.getElementById('chat-section').hidden = false;
  setText('self-addr', state.keyPair.addressHex);
  setText('node-peer', state.nodePeer || '–');

  loadContacts();
  await registerInDirectory();
  scheduleDirectoryRefresh();
  await loadMessages();
  startSSE();
  scheduleChatSync();
  renderContacts();
}

function scheduleDirectoryRefresh() {
  if (state.dirTimer) {
    clearInterval(state.dirTimer);
    state.dirTimer = null;
  }
  state.dirTimer = setInterval(() => {
    registerInDirectory();
  }, DIRECTORY_REFRESH_MS);
}

function scheduleChatSync() {
  if (state.syncTimer) {
    clearInterval(state.syncTimer);
    state.syncTimer = null;
  }
  state.syncTimer = setInterval(() => {
    loadMessages();
  }, CHAT_SYNC_MS);
}

async function registerInDirectory() {
  if (!state.nodePeer) {
    setText('dir-status', 'not registered (no node peer)');
    return;
  }
  try {
    const ts = BigInt(Date.now()) * 1_000_000n;
    const body = await buildRegistrationJson(
      state.keyPair, state.networkID, state.nodePeer, ts.toString()
    );
    const res = await fetch('/api/directory/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      setText('dir-status', `registration failed: ${detail || res.status}`);
      return;
    }
    setText('dir-status', `registered on ${state.nodePeer.slice(0, 12)}…`);
  } catch (e) {
    setText('dir-status', `registration failed: ${e.message}`);
  }
}

function contactsKey() {
  return CONTACTS_PREFIX + state.keyPair.addressHex;
}

function loadContacts() {
  state.contacts = new Set();
  try {
    const raw = localStorage.getItem(contactsKey());
    if (raw) {
      const arr = JSON.parse(raw);
      if (Array.isArray(arr)) for (const c of arr) state.contacts.add(c);
    }
  } catch {}
}

function persistContacts() {
  try {
    localStorage.setItem(contactsKey(), JSON.stringify(Array.from(state.contacts)));
  } catch {}
}

function onAddContact(ev) {
  ev.preventDefault();
  const addr = document.getElementById('add-contact-input').value.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(addr)) {
    showError('contact must be 64 hex chars');
    return;
  }
  if (addr === state.keyPair.addressHex) {
    showError("can't add yourself as a contact");
    return;
  }
  state.contacts.add(addr);
  persistContacts();
  document.getElementById('add-contact-input').value = '';
  showError('');
  resolveRecipient(addr);
  if (!state.active) selectContact(addr);
  else renderContacts();
}

function deriveContactsFromMessages() {
  const me = state.keyPair.addressHex;
  let changed = false;
  for (const env of state.messages) {
    const other = env.from === me ? env.to : env.from;
    if (other && other !== me && !state.contacts.has(other)) {
      state.contacts.add(other);
      changed = true;
    }
  }
  if (changed) persistContacts();
}

async function resolveRecipient(addr) {
  try {
    const res = await fetch(`/api/directory/${encodeURIComponent(addr)}`);
    state.registered.set(addr, res.ok);
  } catch {
    return;
  }
  renderContacts();
  if (addr === state.active) showRecipientAdvisory(addr);
}

function showRecipientAdvisory(addr) {
  if (state.registered.get(addr) === false) {
    showInfo('recipient not registered in the directory — they may not receive this');
  } else {
    showInfo('');
  }
}

function selectContact(addr) {
  state.active = addr;
  state.unread.set(addr, 0);
  document.getElementById('conversation-section').hidden = false;
  setText('active-contact', shortAddr(addr));
  showRecipientAdvisory(addr);
  resolveRecipient(addr);
  renderContacts();
  renderMessages();
}

function renderContacts() {
  const pills = document.getElementById('contacts-pills');
  pills.innerHTML = '';
  const list = Array.from(state.contacts).sort();
  setText('contacts-count', `${list.length}`);
  if (list.length === 0) {
    const empty = document.createElement('span');
    empty.className = 'muted';
    empty.textContent = 'no contacts yet · paste an address above to start';
    pills.appendChild(empty);
    return;
  }
  for (const addr of list) {
    const btn = document.createElement('button');
    btn.type = 'button';
    const unregistered = state.registered.get(addr) === false;
    btn.className = 'pill' + (addr === state.active ? ' pill-active' : '') + (unregistered ? ' pill-unregistered' : '');
    btn.title = unregistered ? `${addr} — not registered in the directory` : addr;
    const name = document.createElement('span');
    name.textContent = shortAddr(addr) + (unregistered ? ' ⚠' : '');
    btn.appendChild(name);
    const unread = state.unread.get(addr) || 0;
    if (unread > 0) {
      const badge = document.createElement('span');
      badge.className = 'pill-badge';
      badge.textContent = String(unread);
      btn.appendChild(badge);
    }
    btn.addEventListener('click', () => selectContact(addr));
    pills.appendChild(btn);
  }
}

async function loadMessages() {
  try {
    const proof = await chatProofParams(state.keyPair);
    const list = await api(`/chat/messages?${proof}`);
    state.messages = Array.isArray(list) ? list : [];
    state.messages.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
    deriveContactsFromMessages();
    renderMessages();
  } catch (e) {
    showError('messages: ' + e.message);
  }
}

function renderMessages() {
  const box = document.getElementById('messages');
  box.innerHTML = '';
  if (!state.active) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = 'select a contact to start';
    box.appendChild(empty);
    return;
  }
  const me = state.keyPair.addressHex;
  const filtered = state.messages.filter((m) =>
    (m.from === me && m.to === state.active) || (m.from === state.active && m.to === me)
  );
  if (filtered.length === 0) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = 'no messages yet · type below to send the first one';
    box.appendChild(empty);
    return;
  }
  for (const m of filtered) {
    const div = document.createElement('div');
    div.className = 'msg ' + (m.from === me ? 'msg-self' : 'msg-other');
    const ts = document.createElement('span');
    ts.className = 'msg-ts';
    ts.textContent = formatHMS(m.timestamp);
    const body = document.createElement('span');
    body.className = 'msg-body';
    body.textContent = m.message;
    div.appendChild(body);
    div.appendChild(ts);
    box.appendChild(div);
  }
  box.scrollTop = box.scrollHeight;
}

function formatHMS(tsNs) {
  if (!tsNs) return '';
  const d = new Date(Math.floor(Number(tsNs) / 1_000_000));
  const p = (n) => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

async function onSend(ev) {
  ev.preventDefault();
  if (!state.active) {
    showError('select a contact first');
    return;
  }
  const text = document.getElementById('send-input').value.trim();
  if (!text) return;
  document.getElementById('send-input').value = '';
  showError('');
  const btn = ev.target.querySelector('button[type="submit"]');
  btn.disabled = true;
  btn.textContent = 'solving pow…';
  try {
    const env = await buildEnvelope(state.keyPair, state.active, text);
    btn.textContent = 'sending…';
    const res = await fetch('/api/chat/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: serializeEnvelopeJson(env),
    });
    if (!res.ok) {
      const detail = await errorDetail(res);
      if (res.status === 404) {
        state.registered.set(state.active, false);
        renderContacts();
        showError('recipient not registered — message not delivered');
      } else {
        showError('send failed: ' + detail);
      }
      return;
    }
    appendEnvelope({
      id: env.id,
      from: env.from,
      to: env.to,
      message: env.message,
      timestamp: Number(env.timestamp),
      signature: env.signature,
    });
  } catch (e) {
    showError('send failed: ' + e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'send';
  }
}

function appendEnvelope(env) {
  if (state.messages.find((m) => m.id === env.id)) return;
  state.messages.push(env);
  state.messages.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
  const me = state.keyPair.addressHex;
  const other = env.from === me ? env.to : env.from;
  if (other && other !== me && !state.contacts.has(other)) {
    state.contacts.add(other);
    persistContacts();
  }
  if (env.from !== me && other !== state.active) {
    state.unread.set(other, (state.unread.get(other) || 0) + 1);
  }
  renderContacts();
  renderMessages();
}

async function startSSE() {
  if (state.sse) {
    state.sse.close();
    state.sse = null;
  }
  if (state.sseReconnect) {
    clearTimeout(state.sseReconnect);
    state.sseReconnect = null;
  }
  let proof;
  try {
    proof = await chatProofParams(state.keyPair);
  } catch (e) {
    setStatus('chat stream auth failed, retrying…', 'err');
    scheduleSSEReconnect();
    return;
  }
  const es = new EventSource(`/api/chat/events?${proof}`);
  es.onmessage = (e) => {
    try {
      const env = JSON.parse(e.data);
      appendEnvelope(env);
    } catch {}
  };
  es.onerror = () => {
    const closed = es.readyState === 2;
    setStatus(closed ? 'chat stream disconnected — retrying…' : 'chat stream reconnecting…', closed ? 'err' : '');
    es.close();
    if (state.sse === es) state.sse = null;
    scheduleSSEReconnect();
  };
  es.onopen = () => {
    setStatus('ok', 'ok');
    loadMessages();
  };
  state.sse = es;
}

function scheduleSSEReconnect() {
  if (state.sseReconnect) return;
  state.sseReconnect = setTimeout(() => {
    state.sseReconnect = null;
    startSSE();
  }, 3000);
}

function setText(id, t) {
  const el = document.getElementById(id);
  if (el) el.textContent = t;
}

function setStatus(text, cls) {
  const el = document.getElementById('status');
  if (!el) return;
  el.textContent = text;
  el.className = 'status ' + (cls || '');
}

function showError(msg) {
  const el = document.getElementById('error');
  if (!msg) { el.hidden = true; el.textContent = ''; return; }
  el.textContent = msg;
  el.hidden = false;
}

async function errorDetail(res) {
  const raw = await res.text().catch(() => '');
  try {
    const body = JSON.parse(raw);
    if (body && typeof body.error === 'string') return body.error;
  } catch {}
  return raw || String(res.status);
}

function showInfo(msg) {
  const el = document.getElementById('info');
  if (!el) return;
  if (!msg) { el.hidden = true; el.textContent = ''; return; }
  el.textContent = msg;
  el.hidden = false;
}

init().catch((e) => showError('startup failed: ' + e.message));
