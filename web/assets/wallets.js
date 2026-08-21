import { api } from './api.js';
import { shortAddr } from './format.js';
import { bytesToHex, hexToBytes, randomSeed, loadKeyPair } from './xe-block.js';
import {
  loadVault, saveVault, emptyVault, removeWallet,
  decryptSeed, buildWalletEntry,
  loadCachedUnlock, cacheUnlock,
} from './vault.js';

const ACTIVITY_PREFIX = 'xe.wallet.activity.';
// Cached-balance snapshot key: persist.js SNAP_PREFIX ('xe.snap.') +
// wallet.js snapshotKey() ('wallet.<address>'). Purged on delete (#748).
const SNAP_WALLET_PREFIX = 'xe.snap.wallet.';

function purgeWalletKeys(address) {
  localStorage.removeItem(ACTIVITY_PREFIX + address);
  localStorage.removeItem(SNAP_WALLET_PREFIX + address);
}

const state = {
  vault: null,
  revealIdx: null,
  renameIdx: null,
  removeIdx: null,
};

// Wallets may have an empty name, so fall back to a literal token to type.
function removeToken(w) {
  return (w.name || '').trim() || 'remove';
}

async function init() {
  await refreshNode();
  bindHandlers();
  state.vault = loadVault();
  if (!state.vault || state.vault.wallets.length === 0) {
    document.getElementById('list-section').hidden = true;
    document.getElementById('empty-section').hidden = false;
    return;
  }
  render();
  openRemoveFromQuery();
}

// The main wallet page deep-links here as ?remove=<address> so the destructive
// flow has one implementation. Drop the param so a reload doesn't reopen it.
function openRemoveFromQuery() {
  const addr = new URLSearchParams(location.search).get('remove');
  if (!addr) return;
  history.replaceState(null, '', location.pathname);
  const i = state.vault.wallets.findIndex(w => w.address === addr);
  if (i >= 0) startRemove(i);
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

function bindHandlers() {
  document.getElementById('reveal-form').addEventListener('submit', onRevealSubmit);
  document.getElementById('btn-cancel-reveal').addEventListener('click', cancelReveal);
  document.getElementById('btn-copy-reveal').addEventListener('click', async () => {
    const t = document.getElementById('reveal-display').textContent;
    if (t) await navigator.clipboard.writeText(t);
    showInfo('seed copied.');
  });
  document.getElementById('btn-hide-reveal').addEventListener('click', () => {
    document.getElementById('reveal-display').textContent = '';
    document.getElementById('reveal-output').hidden = true;
  });
  document.getElementById('rename-form').addEventListener('submit', onRenameSubmit);
  document.getElementById('btn-cancel-rename').addEventListener('click', cancelRename);
  document.getElementById('remove-form').addEventListener('submit', onRemoveSubmit);
  document.getElementById('btn-cancel-remove').addEventListener('click', cancelRemove);
  const addBtn = document.getElementById('btn-add-wallet');
  if (addBtn) addBtn.addEventListener('click', onAddWallet);
  document.getElementById('add-form').addEventListener('submit', onAddSubmit);
  document.getElementById('btn-cancel-add').addEventListener('click', cancelAdd);
  document.getElementById('add-mode').addEventListener('change', onAddModeChange);
}

function render() {
  const tbody = document.getElementById('list-tbody');
  tbody.innerHTML = '';
  const ws = state.vault.wallets;
  setText('list-count', `${ws.length}`);
  for (let i = 0; i < ws.length; i++) {
    const w = ws[i];
    const tr = document.createElement('tr');
    const activeTd = document.createElement('td');
    if (i === state.vault.active) {
      const pill = document.createElement('span');
      pill.className = 'active-pill';
      pill.textContent = 'active';
      activeTd.appendChild(pill);
    } else {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'hint-btn';
      btn.textContent = 'select';
      btn.addEventListener('click', () => onSelect(i));
      activeTd.appendChild(btn);
    }
    tr.appendChild(activeTd);
    tr.appendChild(td(w.name || '–'));
    tr.appendChild(addrLinkTd(w.address));
    tr.appendChild(td(w.created_at ? new Date(w.created_at).toISOString().slice(0, 10) : '–'));
    const actions = document.createElement('td');
    actions.appendChild(actionBtn('rename', () => startRename(i)));
    actions.appendChild(actionBtn('reveal seed', () => startReveal(i)));
    actions.appendChild(actionBtn('remove', () => startRemove(i), 'warn'));
    tr.appendChild(actions);
    tbody.appendChild(tr);
  }
}

function actionBtn(label, fn, cls) {
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'hint-btn' + (cls ? ' ' + cls : '');
  b.textContent = label;
  b.style.marginRight = '0.4rem';
  b.addEventListener('click', fn);
  return b;
}

function onSelect(i) {
  state.vault.active = i;
  saveVault(state.vault);
  render();
  showInfo(`active wallet set to "${state.vault.wallets[i].name || shortAddr(state.vault.wallets[i].address)}".`);
}

function startReveal(i) {
  state.revealIdx = i;
  const w = state.vault.wallets[i];
  setText('reveal-target', `${w.name || ''} · ${shortAddr(w.address)}`);
  document.getElementById('reveal-passphrase').value = '';
  document.getElementById('reveal-output').hidden = true;
  document.getElementById('reveal-display').textContent = '';
  document.getElementById('reveal-section').hidden = false;
  document.getElementById('rename-section').hidden = true;
  document.getElementById('remove-section').hidden = true;
  document.getElementById('reveal-passphrase').focus();
}

function cancelReveal() {
  state.revealIdx = null;
  document.getElementById('reveal-passphrase').value = '';
  document.getElementById('reveal-display').textContent = '';
  document.getElementById('reveal-section').hidden = true;
}

async function onRevealSubmit(ev) {
  ev.preventDefault();
  if (state.revealIdx == null) return;
  const pass = document.getElementById('reveal-passphrase').value;
  document.getElementById('reveal-passphrase').value = '';
  const w = state.vault.wallets[state.revealIdx];
  let seed;
  try {
    seed = await decryptSeed(pass, w);
  } catch {
    showError('incorrect passphrase');
    return;
  }
  document.getElementById('reveal-display').textContent = bytesToHex(seed);
  document.getElementById('reveal-output').hidden = false;
}

function startRename(i) {
  state.renameIdx = i;
  const w = state.vault.wallets[i];
  setText('rename-target', shortAddr(w.address));
  document.getElementById('rename-name').value = w.name || '';
  document.getElementById('rename-section').hidden = false;
  document.getElementById('reveal-section').hidden = true;
  document.getElementById('remove-section').hidden = true;
  document.getElementById('rename-name').focus();
}

function cancelRename() {
  state.renameIdx = null;
  document.getElementById('rename-section').hidden = true;
}

function onRenameSubmit(ev) {
  ev.preventDefault();
  if (state.renameIdx == null) return;
  const name = document.getElementById('rename-name').value.trim().slice(0, 32);
  if (!name) { showError('name cannot be empty'); return; }
  state.vault.wallets[state.renameIdx].name = name;
  saveVault(state.vault);
  state.renameIdx = null;
  document.getElementById('rename-section').hidden = true;
  render();
  showInfo('renamed.');
}

function onAddWallet() {
  // Reset form state.
  document.getElementById('add-name').value = '';
  document.getElementById('add-mode').value = 'create';
  document.getElementById('add-seed').value = '';
  document.getElementById('add-passphrase').value = '';
  onAddModeChange();
  // Hide passphrase input if cached unlock is available.
  const cached = loadCachedUnlock();
  document.getElementById('add-passphrase-label').hidden = !!cached;
  document.getElementById('add-passphrase').required = !cached;
  document.getElementById('add-section').hidden = false;
  document.getElementById('reveal-section').hidden = true;
  document.getElementById('rename-section').hidden = true;
  document.getElementById('remove-section').hidden = true;
  setTimeout(() => document.getElementById('add-name').focus(), 0);
}

function onAddModeChange() {
  const mode = document.getElementById('add-mode').value;
  document.getElementById('add-seed-label').hidden = (mode !== 'import');
  document.getElementById('add-seed').required = (mode === 'import');
}

function cancelAdd() {
  document.getElementById('add-section').hidden = true;
  document.getElementById('add-passphrase').value = '';
  document.getElementById('add-seed').value = '';
}

async function onAddSubmit(ev) {
  ev.preventDefault();
  const name = (document.getElementById('add-name').value.trim() || defaultWalletName()).slice(0, 32);
  const mode = document.getElementById('add-mode').value;
  const passInput = document.getElementById('add-passphrase').value;
  const passphrase = passInput || loadCachedUnlock();
  if (!passphrase) { showError('enter your passphrase to add a wallet'); return; }

  let seed;
  if (mode === 'import') {
    const hex = document.getElementById('add-seed').value.trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(hex)) { showError('seed must be 64 hex characters'); return; }
    try { seed = hexToBytes(hex, 32); } catch (e) { showError('seed: ' + e.message); return; }
  } else {
    seed = randomSeed();
  }

  // Verify the passphrase against an existing wallet before persisting.
  if (state.vault && state.vault.wallets.length > 0) {
    try {
      await decryptSeed(passphrase, state.vault.wallets[clampActive()]);
    } catch {
      showError('incorrect passphrase');
      return;
    }
  }

  const kp = await loadKeyPair(seed);
  if (state.vault.wallets.find(w => w.address === kp.addressHex)) {
    showError('a wallet with this address already exists');
    return;
  }
  const entry = await buildWalletEntry(passphrase, name, kp, seed);
  state.vault.wallets.push(entry);
  state.vault.active = state.vault.wallets.length - 1;
  saveVault(state.vault);
  cacheUnlock(passphrase);

  document.getElementById('add-section').hidden = true;
  document.getElementById('add-passphrase').value = '';
  document.getElementById('add-seed').value = '';

  if (mode === 'create') {
    showInfo(`wallet "${name}" created. seed: ${bytesToHex(seed)} — back this up now (use "reveal seed" later).`);
  } else {
    showInfo(`wallet "${name}" imported.`);
  }
  render();
}

function clampActive() {
  if (!state.vault) return 0;
  let i = state.vault.active;
  if (!Number.isInteger(i) || i < 0 || i >= state.vault.wallets.length) i = 0;
  return i;
}

function defaultWalletName() {
  const n = (state.vault && state.vault.wallets.length) || 0;
  return n === 0 ? 'main' : `wallet ${n + 1}`;
}

function startRemove(i) {
  state.removeIdx = i;
  const w = state.vault.wallets[i];
  setText('remove-target', `${w.name || ''} · ${shortAddr(w.address)}`);
  setText('remove-token', removeToken(w));
  document.getElementById('remove-confirm').value = '';
  document.getElementById('remove-section').hidden = false;
  document.getElementById('reveal-section').hidden = true;
  document.getElementById('rename-section').hidden = true;
  document.getElementById('add-section').hidden = true;
  document.getElementById('remove-confirm').focus();
}

function cancelRemove() {
  state.removeIdx = null;
  document.getElementById('remove-confirm').value = '';
  document.getElementById('remove-section').hidden = true;
}

function onRemoveSubmit(ev) {
  ev.preventDefault();
  if (state.removeIdx == null) return;
  const w = state.vault.wallets[state.removeIdx];
  const token = removeToken(w);
  if (document.getElementById('remove-confirm').value.trim() !== token) {
    showError(`type "${token}" exactly to confirm removal`);
    return;
  }
  showError('');
  const label = w.name || shortAddr(w.address);
  // removeWallet keeps the active pointer on the same wallet when an earlier
  // entry is deleted, and clamps it in range (#748).
  removeWallet(state.vault, state.removeIdx);
  saveVault(state.vault);
  purgeWalletKeys(w.address);
  state.removeIdx = null;
  document.getElementById('remove-confirm').value = '';
  document.getElementById('remove-section').hidden = true;
  if (state.vault.wallets.length === 0) {
    document.getElementById('list-section').hidden = true;
    document.getElementById('empty-section').hidden = false;
  } else {
    render();
  }
  showInfo(`wallet "${label}" removed.`);
}

function addrLinkTd(addr) {
  const el = document.createElement('td');
  if (!addr) { el.textContent = '–'; return el; }
  const a = document.createElement('a');
  a.href = `/accounts/?addr=${encodeURIComponent(addr)}`;
  const code = document.createElement('code');
  code.textContent = shortAddr(addr);
  a.appendChild(code);
  a.title = addr;
  el.appendChild(a);
  return el;
}

function td(s) {
  const el = document.createElement('td');
  el.textContent = s == null ? '–' : String(s);
  return el;
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
  if (!msg) { el.hidden = true; return; }
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
