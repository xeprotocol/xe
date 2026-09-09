import { api } from './api.js';
import { shortHash, shortAddr } from './format.js';
import { loadKeyPair, hexToBytes, bytesToHex } from './xe-block.js';
import { hashBlock as hashStateChainBlock } from './statechain-block.js';
import { loadVault, decryptSeed, cacheUnlock, tryCachedDecrypt } from './vault.js';

const state = {
  tip: null,
  keyset: null,
  vault: null,
  walletIdx: -1,
  keyPair: null,
  draft: null,
  signatures: [],
  ops: [{ action: 'set', key: '', value: '' }],
  hashLocked: false,
};

async function init() {
  await refreshNode();
  bindStaticHandlers();
  try {
    state.tip = await api('/statechain/tip');
    state.keyset = await api('/statechain/keyset');
  } catch (e) {
    showError('state chain: ' + e.message);
    return;
  }
  state.vault = loadVault();
  await routeStartup();
}

async function refreshNode() {
  try {
    const node = await api('/node');
    setText('network', node.network_id || '(no network)');
    setText('version', node.version || '');
    setStatus('ok', 'ok');
  } catch (e) {
    setStatus('node: ' + e.message, 'err');
  }
}

async function routeStartup() {
  const ws = (state.vault && state.vault.wallets) || [];
  const keys = (state.keyset && state.keyset.keys) || [];
  if (ws.length === 0) {
    showNotMember('no wallet in this browser. set up a wallet at /wallet/ first.');
    return;
  }
  const isMember = (w) => !!w.pub_key && keys.includes(w.pub_key);
  const active = state.vault.active >= 0 && state.vault.active < ws.length ? state.vault.active : 0;
  if (isMember(ws[active])) {
    state.walletIdx = active;
  } else {
    state.walletIdx = ws.findIndex(isMember);
  }
  if (state.walletIdx < 0) {
    showNotMember('no wallet in this browser is in the dao keyset. if this wallet predates the address change, unlock it once at /wallet/ and come back.');
    return;
  }
  const seed = await tryCachedDecrypt(ws[state.walletIdx]);
  if (seed) {
    state.keyPair = await loadKeyPair(seed);
    await showDAO();
    return;
  }
  showUnlock();
}

function showNotMember(msg) {
  setText('not-member-msg', msg);
  document.getElementById('not-member-section').hidden = false;
  document.getElementById('unlock-section').hidden = true;
  document.getElementById('dao-section').hidden = true;
}

function showUnlock() {
  const w = state.vault.wallets[state.walletIdx];
  setText('unlock-target', `${w.name || ''} · ${shortAddr(w.address)}`);
  document.getElementById('not-member-section').hidden = true;
  document.getElementById('unlock-section').hidden = false;
  document.getElementById('dao-section').hidden = true;
  setTimeout(() => document.getElementById('unlock-passphrase')?.focus(), 0);
}

async function showDAO() {
  document.getElementById('not-member-section').hidden = true;
  document.getElementById('unlock-section').hidden = true;
  document.getElementById('dao-section').hidden = false;

  setText('tip-index', state.tip.index);
  setText('tip-hash', state.tip.hash);
  setText('threshold', `${state.keyset.threshold} of ${state.keyset.keys.length}`);
  setText('self-pub', state.keyPair.pubKeyHex);
  setText('self-status', state.keyset.keys.includes(state.keyPair.pubKeyHex) ? '· member' : '· not member');

  renderOps();
}

function bindStaticHandlers() {
  document.getElementById('unlock-form').addEventListener('submit', onUnlockSubmit);
  document.getElementById('btn-add-op').addEventListener('click', onAddOp);
  document.getElementById('btn-generate-hash').addEventListener('click', onGenerateHash);
  document.getElementById('btn-reset-draft').addEventListener('click', onResetDraft);
  document.getElementById('btn-sign-self').addEventListener('click', onSignSelf);
  document.getElementById('import-form').addEventListener('submit', onImportSig);
  document.getElementById('btn-submit-block').addEventListener('click', onSubmitBlock);
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
  state.keyPair = await loadKeyPair(seed);
  cacheUnlock(pass);
  await showDAO();
}

function renderOps() {
  const list = document.getElementById('ops-list');
  list.innerHTML = '';
  if (state.ops.length === 0) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = 'no ops — add at least one to draft a block.';
    list.appendChild(empty);
    return;
  }
  state.ops.forEach((op, idx) => {
    const row = document.createElement('div');
    row.className = 'op-row';

    const sel = document.createElement('select');
    for (const a of ['set', 'delete']) {
      const o = document.createElement('option');
      o.value = a; o.textContent = a;
      if (op.action === a) o.selected = true;
      sel.appendChild(o);
    }
    sel.disabled = state.hashLocked;
    sel.addEventListener('change', () => { op.action = sel.value; renderOps(); });

    const key = document.createElement('input');
    key.type = 'text';
    key.placeholder = 'key (e.g. epoch.42)';
    key.value = op.key;
    key.disabled = state.hashLocked;
    key.addEventListener('input', () => { op.key = key.value; });

    const val = document.createElement('input');
    val.type = 'text';
    val.placeholder = 'value (raw JSON, e.g. {"epoch":42} or "hello" or 123)';
    val.value = op.value;
    val.disabled = state.hashLocked || op.action !== 'set';
    val.addEventListener('input', () => { op.value = val.value; });

    const rm = document.createElement('button');
    rm.type = 'button';
    rm.className = 'hint-btn warn';
    rm.textContent = 'remove';
    rm.disabled = state.hashLocked;
    rm.addEventListener('click', () => {
      state.ops.splice(idx, 1);
      renderOps();
    });

    row.appendChild(sel);
    row.appendChild(key);
    row.appendChild(val);
    row.appendChild(rm);
    list.appendChild(row);
  });
}

function onAddOp() {
  if (state.hashLocked) return;
  state.ops.push({ action: 'set', key: '', value: '' });
  renderOps();
}

function onResetDraft() {
  if (!confirm('reset draft? this discards unsaved ops + signatures.')) return;
  state.ops = [{ action: 'set', key: '', value: '' }];
  state.draft = null;
  state.signatures = [];
  state.hashLocked = false;
  document.getElementById('hash-section').hidden = true;
  document.getElementById('sigs-section').hidden = true;
  setText('draft-state', '');
  renderOps();
}

async function onGenerateHash() {
  if (state.ops.length === 0) {
    showError('add at least one op before generating hash');
    return;
  }
  for (const [i, op] of state.ops.entries()) {
    if (!op.key) {
      showError(`op ${i}: key cannot be empty`);
      return;
    }
    if (op.action === 'set') {
      try { JSON.parse(op.value); } catch {
        showError(`op ${i}: value must be valid JSON (e.g. "string", 123, {"x":1}, true, null)`);
        return;
      }
    }
  }
  showError('');

  state.draft = {
    index: BigInt(state.tip.index || 0) + 1n,
    prev_hash: state.tip.hash,
    ops: state.ops.map((o) => ({
      action: o.action,
      key: o.key,
      value: o.action === 'set' ? o.value : '',
    })),
    timestamp: Date.now() * 1_000_000,
  };
  const hash = await hashStateChainBlock(state.draft);
  state.draft.hash = hash;
  state.hashLocked = true;
  state.signatures = [];

  setText('draft-state', '· hash generated, ops locked');
  document.getElementById('draft-hash').textContent = hash;
  document.getElementById('hash-section').hidden = false;
  document.getElementById('sigs-section').hidden = false;
  renderOps();
  renderSigs();
}

async function onSignSelf() {
  if (!state.draft || !state.keyPair) return;
  const pub = state.keyPair.pubKeyHex;
  if (state.signatures.find((s) => s.public_key === pub)) {
    showError('this key has already signed');
    return;
  }
  showError('');
  const hashBytes = hexToBytes(state.draft.hash, 32);
  const sigBytes = await state.keyPair.sign(hashBytes);
  state.signatures.push({ public_key: pub, signature: bytesToHex(sigBytes) });
  renderSigs();
}

async function onImportSig(ev) {
  ev.preventDefault();
  const raw = document.getElementById('import-json').value.trim();
  let obj;
  try { obj = JSON.parse(raw); } catch (e) {
    showError('not valid JSON: ' + e.message);
    return;
  }
  if (!obj.public_key || !obj.signature) {
    showError('expected {"public_key":"…","signature":"…"}');
    return;
  }
  if (!state.draft) {
    showError('generate hash first');
    return;
  }
  if (state.signatures.find((s) => s.public_key === obj.public_key)) {
    showError('this key has already signed');
    return;
  }
  try {
    const pub = await crypto.subtle.importKey(
      'raw', hexToBytes(obj.public_key, 32), { name: 'Ed25519' }, false, ['verify'],
    );
    const ok = await crypto.subtle.verify(
      'Ed25519', pub, hexToBytes(obj.signature, 64), hexToBytes(state.draft.hash, 32),
    );
    if (!ok) {
      showError('signature does not match the current draft hash');
      return;
    }
  } catch (e) {
    showError('signature verification failed: ' + e.message);
    return;
  }
  state.signatures.push({ public_key: obj.public_key, signature: obj.signature });
  document.getElementById('import-json').value = '';
  showError('');
  renderSigs();
}

function renderSigs() {
  const tbody = document.getElementById('sigs-tbody');
  tbody.innerHTML = '';
  setText('sigs-count', `${state.signatures.length} of ${state.keyset.threshold}`);
  if (state.signatures.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" class="muted">no signatures yet</td></tr>';
  } else {
    for (const s of state.signatures) {
      const tr = document.createElement('tr');
      const pubTd = document.createElement('td');
      const pubCode = document.createElement('code');
      pubCode.textContent = shortHash(s.public_key, 16);
      pubCode.title = s.public_key;
      pubTd.appendChild(pubCode);
      tr.appendChild(pubTd);

      const labelTd = document.createElement('td');
      labelTd.textContent = state.keyset.keys.includes(s.public_key) ? 'member' : 'unknown';
      if (!state.keyset.keys.includes(s.public_key)) labelTd.style.color = 'var(--bad)';
      tr.appendChild(labelTd);

      const sigTd = document.createElement('td');
      const sigCode = document.createElement('code');
      sigCode.textContent = shortHash(s.signature, 16);
      sigCode.title = s.signature;
      sigTd.appendChild(sigCode);
      tr.appendChild(sigTd);

      const actionsTd = document.createElement('td');
      const copy = document.createElement('button');
      copy.type = 'button';
      copy.className = 'hint-btn';
      copy.textContent = 'copy json';
      copy.addEventListener('click', async () => {
        await navigator.clipboard.writeText(JSON.stringify({ public_key: s.public_key, signature: s.signature }));
        showInfo('signature json copied');
      });
      actionsTd.appendChild(copy);
      const remove = document.createElement('button');
      remove.type = 'button';
      remove.className = 'hint-btn warn';
      remove.textContent = 'remove';
      remove.style.marginLeft = '0.4rem';
      remove.addEventListener('click', () => {
        state.signatures = state.signatures.filter((x) => x.public_key !== s.public_key);
        renderSigs();
      });
      actionsTd.appendChild(remove);
      tr.appendChild(actionsTd);

      tbody.appendChild(tr);
    }
  }

  const memberCount = state.signatures.filter((s) => state.keyset.keys.includes(s.public_key)).length;
  const need = state.keyset.threshold - memberCount;
  const submit = document.getElementById('btn-submit-block');
  submit.disabled = need > 0;
  setText('submit-hint', need > 0 ? `need ${need} more member signature${need === 1 ? '' : 's'}` : 'threshold reached');
}

async function onSubmitBlock() {
  if (!state.draft) return;
  const opCount = state.draft.ops.length;
  const sigCount = state.signatures.filter((s) => state.keyset.keys.includes(s.public_key)).length;
  const opLabel = opCount === 1 ? 'op' : 'ops';
  const sigLabel = sigCount === 1 ? 'signature' : 'signatures';
  if (!confirm(`submit state-chain block at index ${state.draft.index}?\n\n${opCount} ${opLabel} · ${sigCount} member ${sigLabel}\nhash ${state.draft.hash.slice(0, 12)}…\n\nthis cannot be undone.`)) {
    return;
  }
  const block = {
    index: Number(state.draft.index),
    prev_hash: state.draft.prev_hash,
    ops: state.draft.ops.map((o) => ({
      action: o.action,
      key: o.key,
      value: o.action === 'set' ? JSON.parse(o.value) : undefined,
    })),
    signatures: state.signatures.map((s) => ({ public_key: s.public_key, signature: s.signature })),
    hash: state.draft.hash,
    timestamp: Number(state.draft.timestamp),
  };
  try {
    const res = await fetch('/api/statechain/blocks', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(block),
    });
    if (!res.ok) {
      let msg = `HTTP ${res.status}`;
      try { const body = await res.json(); if (body && body.error) msg = body.error; } catch {}
      showError('submit failed: ' + msg);
      return;
    }
    showInfo(`block submitted · index ${block.index} · hash ${shortHash(block.hash)}`);
    onResetDraft();
    state.tip = await api('/statechain/tip');
    setText('tip-index', state.tip.index);
    setText('tip-hash', state.tip.hash);
  } catch (e) {
    showError('submit failed: ' + e.message);
  }
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

function showInfo(msg) {
  const el = document.getElementById('info');
  if (!msg) { el.hidden = true; el.textContent = ''; return; }
  el.textContent = msg;
  el.hidden = false;
}

init();
