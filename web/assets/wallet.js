import { api, fetchChainTail } from './api.js';
import { shortAddr, shortHash, timeOfDay, formatAmount, parseAmount } from './format.js';
import {
  hexToBytes, bytesToHex,
  loadKeyPair, verifyKnownBlock, fetchBlockJsonLossless,
  buildAndSubmitSend, buildAndSubmitReceive, requestFaucet,
} from './xe-block.js';
import {
  loadVault, saveVault, emptyVault,
  hasLegacySeed, loadLegacySeed, deleteLegacySeed,
  loadLegacyActivity, deleteLegacyActivity,
  buildWalletEntry, decryptSeed, decryptPhrase, syncWalletIdentity,
  cacheUnlock, loadCachedUnlock, clearCachedUnlock, tryCachedDecrypt,
} from './vault.js';
import { loadSnapshot, saveSnapshot } from './persist.js';
import { generatePhrase, validatePhrase, seedFromPhrase, pickCheckPositions } from './recovery-phrase.js';

const ACTIVITY_PREFIX = 'xe.wallet.activity.';
const ACTIVITY_MAX = 20;
const HISTORY_LIMIT = 25;

const state = {
  vault: null,
  passphrase: null,
  seed: null,
  keyPair: null,
  networkId: '',
  chain: [],
  chainTotal: 0,
  balances: {},
  spendable: {},
  pending: [],
  activity: [],
  pendingSeedBytes: null,
};

async function init() {
  await refreshNode();
  bindHandlers();
  await applyFeatures();
  await selfCheck();
  await routeStartup();
}

async function applyFeatures() {
  let faucet = false;
  try {
    const res = await fetch('/features.json');
    if (res.ok) faucet = (await res.json()).faucet === true;
  } catch {   }
  const btn = document.getElementById('btn-faucet');
  if (btn) btn.hidden = !faucet;
}

async function refreshNode() {
  try {
    const node = await api('/node');
    state.networkId = node.network_id || '';
    setText('network', state.networkId || '(no network)');
    setText('version', node.version || '');
    setStatus('ok', 'ok');
  } catch (e) {
    setStatus('node: ' + e.message, 'err');
  }
}

async function selfCheck() {
  if (!state.networkId) return;
  try {
    const recent = await fetchBlockJsonLossless('/api/blocks/recent');
    const sample = (recent || []).find(b => b && b.type === 'send');
    if (!sample) return;
    await verifyKnownBlock(state.networkId, sample);
  } catch (e) {
    showError('canonical encoding self-check failed: ' + e.message + ' — wallet sends will not be accepted by the network');
  }
}

async function routeStartup() {
  state.vault = loadVault();
  if (!state.vault || state.vault.wallets.length === 0) {
    if (hasLegacySeed()) {
      showOnly('migration-section');
      return;
    }
    showOnly('setup-section');
    return;
  }
  const w = activeWallet();
  if (w) {
    const seed = await tryCachedDecrypt(w);
    if (seed) {
      state.passphrase = loadCachedUnlock();
      state.seed = seed;
      state.keyPair = await loadKeyPair(seed);
      await activateActive();
      return;
    }
  }
  showUnlock();
}

function showOnly(id) {
  const ids = ['setup-section', 'migration-section', 'unlock-section', 'wallet-section'];
  for (const sid of ids) {
    const el = document.getElementById(sid);
    if (el) el.hidden = sid !== id;
  }
}

function showUnlock() {
  const w = activeWallet();
  setText('unlock-summary', w ? `${w.name} · ${shortAddr(w.address)}` : '');
  showOnly('unlock-section');
  setTimeout(() => document.getElementById('unlock-passphrase')?.focus(), 0);
}

function activeWallet() {
  if (!state.vault || state.vault.wallets.length === 0) return null;
  const i = clampActive();
  return state.vault.wallets[i];
}

function clampActive() {
  if (!state.vault) return 0;
  let i = state.vault.active;
  if (!Number.isInteger(i) || i < 0 || i >= state.vault.wallets.length) i = 0;
  state.vault.active = i;
  return i;
}

function bindHandlers() {
  document.getElementById('btn-create').addEventListener('click', () => switchSetupMode('create'));
  document.getElementById('btn-import-toggle').addEventListener('click', () => switchSetupMode('import'));
  document.getElementById('btn-next-account').addEventListener('click', () => switchSetupMode('account'));
  document.getElementById('setup-bip39-enabled').addEventListener('change', (e) => {
    const input = document.getElementById('setup-bip39-passphrase');
    input.disabled = !e.target.checked;
    if (input.disabled) {
      input.value = '';
      document.getElementById('setup-bip39-passphrase-confirm').value = '';
    }
    updateBIP39Confirmation();
  });
  document.getElementById('setup-bip39-passphrase').addEventListener('input', updateBIP39Confirmation);
  document.getElementById('setup-bip39-passphrase-confirm').addEventListener('input', updateBIP39Confirmation);
  document.getElementById('setup-form').addEventListener('submit', onSetupSubmit);
  document.getElementById('btn-confirm-seed-saved').addEventListener('click', onConfirmSeedSaved);
  document.getElementById('seed-saved-check').addEventListener('change', (e) => {
    document.getElementById('seed-confirm-display').hidden = e.target.checked;
    document.getElementById('seed-confirm-advanced').hidden = e.target.checked;
    document.getElementById('btn-copy-confirm-seed').hidden = e.target.checked;
    document.getElementById('phrase-checks').hidden = !e.target.checked;
    updatePhraseCheck();
  });
  document.getElementById('btn-copy-confirm-seed').addEventListener('click', async () => {
    if (!state.pendingSeedBytes) return;
    await navigator.clipboard.writeText(state.pendingPhrase);
    showInfo('phrase copied.');
  });

  document.getElementById('migrate-form').addEventListener('submit', onMigrateSubmit);

  document.getElementById('unlock-form').addEventListener('submit', onUnlockSubmit);

  document.getElementById('btn-lock').addEventListener('click', lockWallet);
  document.getElementById('btn-add-wallet').addEventListener('click', onAddWallet);
  document.getElementById('btn-remove-wallet').addEventListener('click', onRemoveWallet);
  document.getElementById('send-form').addEventListener('submit', onSend);
  document.getElementById('btn-faucet').addEventListener('click', onFaucet);
  document.getElementById('btn-clear-activity').addEventListener('click', clearActivity);

  document.getElementById('reveal-form').addEventListener('submit', onReveal);
  document.getElementById('btn-copy-reveal').addEventListener('click', async () => {
    const text = document.getElementById('reveal-display').textContent;
    if (text) await navigator.clipboard.writeText(text);
    showInfo('backup copied.');
  });
  document.getElementById('btn-hide-reveal').addEventListener('click', () => {
    document.getElementById('reveal-output').hidden = true;
    document.getElementById('reveal-display').textContent = '';
    document.getElementById('reveal-hex').textContent = '';
  });
}

let setupMode = 'create';
let setupBusy = false;

function bip39ConfirmationMatches() {
  return setupMode !== 'create' || !document.getElementById('setup-bip39-enabled').checked ||
    document.getElementById('setup-bip39-passphrase').value === document.getElementById('setup-bip39-passphrase-confirm').value;
}

function updateBIP39Confirmation() {
  const required = setupMode === 'create' && document.getElementById('setup-bip39-enabled').checked;
  document.getElementById('setup-bip39-confirm-label').hidden = !required;
  document.getElementById('setup-bip39-passphrase-confirm').disabled = !required;
  document.getElementById('setup-submit').disabled = setupBusy || !bip39ConfirmationMatches();
}

function switchSetupMode(mode) {
  clearPendingPhrase();
  setupMode = mode;
  document.getElementById('setup-bip39-passphrase-confirm').value = '';
  updateBIP39Confirmation();
  const seedLabel = document.getElementById('setup-seed-label');
  const submit = document.getElementById('setup-submit');
  const seedInput = document.getElementById('setup-seed-input');
  document.getElementById('setup-account').disabled = mode !== 'import';
  document.getElementById('setup-account').value = mode === 'account' ? (activeWallet().account || 0) + 1 : 0;
  if (mode === 'import') {
    seedLabel.hidden = false;
    seedInput.required = true;
    submit.textContent = 'import wallet';
  } else {
    seedLabel.hidden = true;
    seedInput.required = false;
    submit.textContent = mode === 'account' ? 'derive next account' : 'create wallet';
  }
}

async function onSetupSubmit(ev) {
  ev.preventDefault();
  const name = (document.getElementById('setup-name').value.trim() || defaultWalletName()).slice(0, 32);
  const pass1 = document.getElementById('setup-passphrase').value;
  const pass2 = document.getElementById('setup-passphrase-confirm').value;
  if (pass1.length < 8) { showError('passphrase must be at least 8 characters'); return; }
  if (pass1 !== pass2) { showError('passphrases do not match'); return; }
  if (!bip39ConfirmationMatches()) { showError('BIP39 passphrases do not match'); return; }
  if (setupBusy) return;

  setupBusy = true;
  updateBIP39Confirmation();
  try {
    const mode = setupMode;
    const input = document.getElementById('setup-seed-input').value.trim();
    const passInput = document.getElementById('setup-bip39-passphrase');
    const bip39Pass = document.getElementById('setup-bip39-enabled').checked ? passInput.value : '';
    const account = Number(document.getElementById('setup-account').value);
    if (state.vault?.wallets.length) await decryptSeed(pass1, activeWallet());
    let phrase = null;
    let seed;
    if (mode === 'import' && /^[0-9a-f]{64}$/i.test(input)) {
      if (bip39Pass || account !== 0) throw new Error('hex seed import does not use a BIP39 passphrase or account index');
      seed = hexToBytes(input, 32);
    } else {
      if (mode === 'create') phrase = await generatePhrase();
      else if (mode === 'account') phrase = await decryptPhrase(state.passphrase, activeWallet());
      else phrase = await validatePhrase(input);
      if (!phrase) throw new Error('this hex-only wallet has no recovery phrase');
      if (mode === 'account') {
        const currentSeed = await seedFromPhrase(phrase, { passphrase: bip39Pass, account: activeWallet().account || 0 });
        if (!currentSeed.every((byte, i) => byte === state.seed[i])) {
          passInput.value = '';
          throw new Error('BIP39 passphrase does not match this wallet; the next account was not created');
        }
      }
      seed = await seedFromPhrase(phrase, { passphrase: bip39Pass, account });
    }
    passInput.value = '';
    document.getElementById('setup-bip39-passphrase-confirm').value = '';
    document.getElementById('setup-seed-input').value = '';
    if (mode === 'create') {
      state.pendingSeedBytes = seed;
      state.pendingPhrase = phrase;
      state.pendingSeedName = name;
      state.pendingSeedPassphrase = pass1;
      stagePhraseCheck(phrase);
    } else {
      await persistNewWallet(name, seed, pass1, phrase ? { phrase, account } : null);
      state.passphrase = pass1;
      cacheUnlock(pass1);
      await activateActive();
      showInfo(`wallet "${name}" imported. account ${account}.`);
    }
  } catch (e) {
    showError(e.message);
  } finally {
    setupBusy = false;
    updateBIP39Confirmation();
  }
}

function stagePhraseCheck(phrase) {
  const words = phrase.split(' ');
  document.getElementById('seed-confirm-display').textContent = words.map((word, i) => `${i + 1}. ${word}`).join('\n');
  document.getElementById('seed-confirm-hex').textContent = bytesToHex(state.pendingSeedBytes);
  state.checkPositions = pickCheckPositions();
  const checks = document.getElementById('phrase-checks');
  checks.replaceChildren();
  for (const index of state.checkPositions) {
    const label = document.createElement('label');
    label.textContent = `word ${index + 1}`;
    const input = document.createElement('input');
    input.type = 'password';
    input.autocomplete = 'off';
    input.spellcheck = false;
    input.dataset.position = index;
    input.addEventListener('input', updatePhraseCheck);
    label.append(input);
    checks.append(label);
  }
  document.getElementById('seed-saved-check').checked = false;
  document.getElementById('seed-confirm-display').hidden = false;
  document.getElementById('seed-confirm-advanced').hidden = false;
  document.getElementById('btn-copy-confirm-seed').hidden = false;
  checks.hidden = true;
  document.getElementById('btn-confirm-seed-saved').disabled = true;
  document.getElementById('seed-confirm-section').hidden = false;
}

function phraseCheckPassed() {
  if (!state.pendingPhrase || !document.getElementById('seed-saved-check').checked) return false;
  const words = state.pendingPhrase.split(' ');
  const inputs = [...document.querySelectorAll('#phrase-checks input')];
  return inputs.length === 3 && inputs.every(input => input.value.trim().toLowerCase() === words[Number(input.dataset.position)]);
}

function updatePhraseCheck() {
  document.getElementById('btn-confirm-seed-saved').disabled = !phraseCheckPassed();
}

function clearPendingPhrase() {
  state.pendingSeedBytes = null;
  state.pendingPhrase = null;
  state.pendingSeedPassphrase = null;
  document.getElementById('seed-confirm-display').textContent = '';
  document.getElementById('seed-confirm-hex').textContent = '';
  document.getElementById('phrase-checks').replaceChildren();
  document.getElementById('seed-confirm-section').hidden = true;
}

async function onConfirmSeedSaved() {
  if (!state.pendingSeedBytes || !state.pendingSeedPassphrase || !phraseCheckPassed()) return;
  document.getElementById('btn-confirm-seed-saved').disabled = true;
  try {
    await persistNewWallet(state.pendingSeedName, state.pendingSeedBytes, state.pendingSeedPassphrase, { phrase: state.pendingPhrase, account: 0 });
    state.passphrase = state.pendingSeedPassphrase;
    cacheUnlock(state.pendingSeedPassphrase);
    clearPendingPhrase();
    await activateActive();
    showInfo('wallet created.');
  } catch (e) {
    showError(e.message);
    updatePhraseCheck();
  }
}

async function persistNewWallet(name, seedBytes, passphrase, recovery = null) {
  const kp = await loadKeyPair(seedBytes);
  const entry = await buildWalletEntry(passphrase, name, kp, seedBytes, recovery);
  if (!state.vault) state.vault = emptyVault();
  if (state.vault.wallets.find(w => w.address === kp.addressHex)) {
    throw new Error('wallet with this address already exists');
  }
  state.vault.wallets.push(entry);
  state.vault.active = state.vault.wallets.length - 1;
  saveVault(state.vault);
}

async function onMigrateSubmit(ev) {
  ev.preventDefault();
  const name = (document.getElementById('migrate-name').value.trim() || 'main').slice(0, 32);
  const pass1 = document.getElementById('migrate-passphrase').value;
  const pass2 = document.getElementById('migrate-passphrase-confirm').value;
  if (pass1.length < 8) { showError('passphrase must be at least 8 characters'); return; }
  if (pass1 !== pass2) { showError('passphrases do not match'); return; }

  const hex = loadLegacySeed();
  let seed;
  try { seed = hexToBytes(hex, 32); } catch (e) { showError('legacy seed invalid: ' + e.message); return; }

  try {
    await persistNewWallet(name, seed, pass1);
  } catch (e) {
    showError('migrate failed: ' + e.message);
    return;
  }
  const legacyActivity = loadLegacyActivity();
  if (Array.isArray(legacyActivity)) {
    const w = activeWallet();
    if (w) localStorage.setItem(ACTIVITY_PREFIX + w.address, JSON.stringify(legacyActivity));
  }
  deleteLegacyActivity();
  deleteLegacySeed();
  state.passphrase = pass1;
  cacheUnlock(pass1);
  await activateActive();
  showInfo('wallet migrated. plaintext seed has been removed from storage.');
}

async function onUnlockSubmit(ev) {
  ev.preventDefault();
  const pass = document.getElementById('unlock-passphrase').value;
  document.getElementById('unlock-passphrase').value = '';
  const w = activeWallet();
  if (!w) return;
  let seed;
  try {
    seed = await decryptSeed(pass, w);
  } catch (e) {
    showError('incorrect passphrase');
    return;
  }
  state.passphrase = pass;
  state.seed = seed;
  state.keyPair = await loadKeyPair(seed);
  cacheUnlock(pass);
  await activateActive();
}

function lockWallet() {
  clearPendingPhrase();
  document.getElementById('reveal-display').textContent = '';
  document.getElementById('reveal-hex').textContent = '';
  document.getElementById('reveal-output').hidden = true;
  state.passphrase = null;
  state.seed = null;
  state.keyPair = null;
  state.chain = [];
  state.balances = {};
  state.spendable = {};
  state.pending = [];
  state.activity = [];
  clearCachedUnlock();
  showUnlock();
  showInfo('locked.');
}

async function onAddWallet() {
  if (!state.passphrase) { showError('unlock first'); return; }
  document.getElementById('setup-name').value = defaultWalletName();
  document.getElementById('setup-passphrase').value = state.passphrase;
  document.getElementById('setup-passphrase-confirm').value = state.passphrase;
  document.getElementById('btn-next-account').hidden = !activeWallet().encrypted_phrase;
  switchSetupMode('create');
  showOnly('setup-section');
}

function defaultWalletName() {
  const n = (state.vault && state.vault.wallets.length) || 0;
  return n === 0 ? 'main' : `wallet ${n + 1}`;
}

async function activateActive() {
  const w = activeWallet();
  if (!w) { showOnly('setup-section'); return; }
  if (!state.passphrase) { showUnlock(); return; }

  try {
    state.seed = await decryptSeed(state.passphrase, w);
  } catch {
    lockWallet();
    showError('this wallet was encrypted with a different passphrase. lock and unlock again.');
    return;
  }
  state.keyPair = await loadKeyPair(state.seed);
  document.getElementById('reveal-display').textContent = '';
  document.getElementById('reveal-hex').textContent = '';
  document.getElementById('reveal-output').hidden = true;
  if (syncWalletIdentity(w, state.keyPair)) saveVault(state.vault);

  showOnly('wallet-section');
  renderSwitcher();
  setText('wallet-name-hint', w.name || '');
  loadActivityForActive();
  renderActivity();
  hydrateFromSnapshot();
  await refreshAll();
  if (new URLSearchParams(location.search).get('add') === '1') {
    history.replaceState(null, '', location.pathname);
    await onAddWallet();
  }
}

function snapshotKey() {
  const w = activeWallet();
  return w ? `wallet.${w.address}` : null;
}

function hydrateFromSnapshot() {
  const key = snapshotKey();
  if (!key) return;
  const snap = loadSnapshot(key);
  if (!snap || !snap.value) return;
  const v = snap.value;
  if (v.balances) state.balances = v.balances;
  if (v.spendable) state.spendable = v.spendable;
  if (Array.isArray(v.pending)) state.pending = v.pending;
  state.chainLoaded = false;
  if (typeof v.previous === 'string' && state.chain.length === 0) {
    state.chain = v.previous === '0' ? [] : [{ hash: v.previous }];
  }
  if (state.keyPair) {
    setText('wallet-address', state.keyPair.addressHex);
    setText('wallet-pubkey', state.keyPair.pubKeyHex);
    document.getElementById('open-account-link').href =
      `/accounts/?addr=${encodeURIComponent(state.keyPair.addressHex)}`;
  }
  renderPrevious();
  renderBalances();
  renderPending();
  renderSendAssets();
}

function persistSnapshot() {
  const key = snapshotKey();
  if (!key) return;
  const last = state.chain.length ? state.chain[state.chain.length - 1] : null;
  saveSnapshot(key, {
    balances: state.balances,
    spendable: state.spendable,
    pending: state.pending,
    previous: last ? last.hash : '0',
  });
}

function renderSwitcher() {
  const switcher = document.getElementById('wallet-switcher');
  const pills = document.getElementById('wallet-pills');
  pills.innerHTML = '';
  const ws = (state.vault && state.vault.wallets) || [];
  const active = clampActive();
  document.getElementById('btn-remove-wallet').hidden = ws.length === 0;
  if (ws.length <= 1) {
    switcher.hidden = false;
  } else {
    switcher.hidden = false;
  }
  for (let i = 0; i < ws.length; i++) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'pill' + (i === active ? ' pill-active' : '');
    btn.textContent = ws[i].name || shortAddr(ws[i].address);
    btn.title = ws[i].address;
    btn.addEventListener('click', () => switchWallet(i));
    pills.appendChild(btn);
  }
}

function onRemoveWallet() {
  const w = activeWallet();
  if (!w) return;
  location.href = `/wallet/wallets/?remove=${encodeURIComponent(w.address)}`;
}

async function switchWallet(idx) {
  if (!state.vault || idx < 0 || idx >= state.vault.wallets.length) return;
  if (idx === state.vault.active) return;
  state.vault.active = idx;
  saveVault(state.vault);
  await activateActive();
}

function activityKey() {
  const w = activeWallet();
  return w ? ACTIVITY_PREFIX + w.address : null;
}

function loadActivityForActive() {
  state.activity = [];
  const key = activityKey();
  if (!key) return;
  const raw = localStorage.getItem(key);
  if (!raw) return;
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) state.activity = parsed.slice(0, ACTIVITY_MAX);
  } catch {}
}

function persistActivity() {
  const key = activityKey();
  if (!key) return;
  try { localStorage.setItem(key, JSON.stringify(state.activity)); } catch {}
}

function logActivity(level, message) {
  state.activity.unshift({ level, message, ts: Date.now() });
  if (state.activity.length > ACTIVITY_MAX) state.activity.length = ACTIVITY_MAX;
  persistActivity();
  renderActivity();
}

function clearActivity() {
  if (!confirm('clear activity log?')) return;
  state.activity = [];
  persistActivity();
  renderActivity();
}

function renderActivity() {
  const list = document.getElementById('activity-list');
  if (!list) return;
  list.innerHTML = '';
  setText('activity-count', state.activity.length ? `${state.activity.length}` : '');
  if (state.activity.length === 0) {
    const li = document.createElement('li');
    li.className = 'muted';
    li.textContent = 'no activity yet';
    list.appendChild(li);
    return;
  }
  for (const entry of state.activity) {
    const li = document.createElement('li');
    li.className = `activity-${entry.level || 'info'}`;
    const ts = document.createElement('span');
    ts.className = 'activity-ts';
    ts.textContent = formatHMS(entry.ts);
    const msg = document.createElement('span');
    msg.className = 'activity-msg';
    msg.textContent = entry.message;
    li.appendChild(ts);
    li.appendChild(msg);
    list.appendChild(li);
  }
}

function formatHMS(ms) {
  const d = new Date(ms);
  const p = (n) => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

async function onReveal(ev) {
  ev.preventDefault();
  const pass = document.getElementById('reveal-passphrase').value;
  document.getElementById('reveal-passphrase').value = '';
  const w = activeWallet();
  if (!w) return;
  let seed;
  try {
    seed = await decryptSeed(pass, w);
  } catch {
    showError('incorrect passphrase');
    return;
  }
  const phrase = await decryptPhrase(pass, w);
  document.getElementById('reveal-display').textContent = phrase || bytesToHex(seed);
  document.getElementById('reveal-note').textContent = phrase
    ? `Account ${w.account || 0}. Keep any BIP39 passphrase separately; it is never stored. A wrong passphrase opens a different, empty account.`
    : 'This wallet was created from a hex seed and has no recovery phrase. Its backup is this hex seed. Wallets made before v2 restore from their hex seed.';
  document.getElementById('reveal-hex').textContent = bytesToHex(seed);
  document.getElementById('reveal-advanced').hidden = !phrase;
  document.getElementById('reveal-advanced').open = false;
  document.getElementById('reveal-output').hidden = false;
}

async function onFaucet(ev) {
  const btn = ev.currentTarget;
  btn.disabled = true;
  const orig = btn.textContent;
  btn.textContent = 'requesting…';
  try {
    logActivity('info', 'faucet: requesting grant…');
    const result = await requestFaucet(state.keyPair.addressHex);
    const asset = result.asset || 'XE';
    const amt = result.amount != null ? `${formatAmount(result.amount, asset)} ${asset}` : asset;
    showInfo(`faucet sent ${amt} · tx ${shortHash(result.tx_hash || '?')} · arriving as a pending receive`);
    logActivity('success', `faucet sent ${amt} · tx ${shortHash(result.tx_hash || '?')}`);
    await refreshAll();
  } catch (e) {
    const msg = stripDomainPrefix(e.message, 'faucet');
    showError('faucet failed: ' + msg);
    logActivity('error', `faucet failed: ${msg}`);
  } finally {
    btn.disabled = false;
    btn.textContent = orig;
  }
}

function stripDomainPrefix(msg, domain) {
  if (!msg) return '';
  const re = new RegExp('^' + domain + ':\\s*', 'i');
  return String(msg).replace(re, '');
}

async function refreshAll() {
  if (!state.keyPair) return;
  const addr = state.keyPair.addressHex;
  setText('wallet-address', addr);
  setText('wallet-pubkey', state.keyPair.pubKeyHex);
  document.getElementById('open-account-link').href = `/accounts/?addr=${encodeURIComponent(addr)}`;

  const errors = [];
  const [chainRes, balanceRes, pendingRes] = await Promise.allSettled([
    fetchChainTail(addr, HISTORY_LIMIT),
    api(`/accounts/${encodeURIComponent(addr)}/balance`),
    api(`/pending/${encodeURIComponent(addr)}`),
  ]);

  if (chainRes.status === 'fulfilled') {
    state.chain = chainRes.value.blocks;
    state.chainTotal = chainRes.value.total;
    state.chainLoaded = true;
  } else {
    state.chainLoaded = false;
    errors.push('chain: ' + chainRes.reason.message);
  }
  if (balanceRes.status === 'fulfilled') {
    state.balances = (balanceRes.value && balanceRes.value.balances) || {};
    state.spendable = (balanceRes.value && balanceRes.value.spendable) || {};
  } else {
    errors.push('balance: ' + balanceRes.reason.message);
  }
  if (pendingRes.status === 'fulfilled') {
    state.pending = (pendingRes.value && pendingRes.value.pending) || [];
  } else {
    errors.push('pending: ' + pendingRes.reason.message);
  }

  renderPrevious();
  renderBalances();
  renderHistory();
  renderPending();
  renderSendAssets();
  persistSnapshot();

  if (errors.length) showError(errors.join(' · '));
}

function renderPrevious() {
  const last = state.chain.length ? state.chain[state.chain.length - 1] : null;
  const prev = last ? last.hash : '0';
  setText('wallet-previous', prev === '0' ? '(none — open chain)' : prev);
}

function renderBalances() {
  const tbody = document.getElementById('balances-tbody');
  tbody.innerHTML = '';
  const keys = Object.keys(state.balances).sort();
  if (keys.length === 0) {
    tbody.innerHTML = '<tr><td colspan="3" class="muted">no balances yet</td></tr>';
    return;
  }
  for (const asset of keys) {
    const tr = document.createElement('tr');
    tr.appendChild(td(asset));
    tr.appendChild(td(formatAmount(state.balances[asset], asset)));
    tr.appendChild(td(formatAmount(state.spendable[asset] || 0, asset)));
    tbody.appendChild(tr);
  }
}

function renderHistory() {
  const tbody = document.getElementById('history-tbody');
  if (!tbody) return;
  tbody.innerHTML = '';
  const n = state.chainTotal;
  setText('history-count', n ? `${n} block${n === 1 ? '' : 's'}` : '');
  if (n === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="muted">no blocks yet</td></tr>';
    return;
  }
  const recent = state.chain.slice(-HISTORY_LIMIT).reverse();
  for (const b of recent) {
    const tr = document.createElement('tr');
    tr.appendChild(td(timeOfDay(b.timestamp)));
    tr.appendChild(td(b.type || '–'));
    tr.appendChild(td(b.asset || '–'));
    tr.appendChild(td(b.amount == null ? '–' : formatAmount(b.amount, b.asset)));
    tr.appendChild(td(b.balance == null ? '–' : formatAmount(b.balance, b.asset)));
    tr.appendChild(blockLinkTd(b.hash));
    tbody.appendChild(tr);
  }
}

function renderPending() {
  const tbody = document.getElementById('pending-tbody');
  tbody.innerHTML = '';
  setText('pending-count', state.pending.length ? `${state.pending.length}` : '');
  if (state.pending.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="muted">no pending receives</td></tr>';
    return;
  }
  for (const p of state.pending) {
    const tr = document.createElement('tr');
    tr.appendChild(td('—'));
    tr.appendChild(td(p.Asset || '–'));
    tr.appendChild(td(formatAmount(p.Amount, p.Asset)));
    tr.appendChild(addrLinkTd(p.Source));
    tr.appendChild(blockLinkTd(p.SendHash));
    const actionTd = document.createElement('td');
    const btn = document.createElement('button');
    btn.textContent = 'receive';
    btn.addEventListener('click', () => onReceive(p, btn));
    actionTd.appendChild(btn);
    tr.appendChild(actionTd);
    tbody.appendChild(tr);
  }
}

function renderSendAssets() {
  const sel = document.getElementById('send-asset');
  const current = sel.value;
  sel.innerHTML = '';
  const assets = Object.keys(state.balances).sort();
  if (assets.length === 0) assets.push('XUSD');
  for (const a of assets) {
    const opt = document.createElement('option');
    opt.value = a;
    opt.textContent = `${a} (${formatAmount(state.spendable[a] || 0, a)} spendable)`;
    sel.appendChild(opt);
  }
  if (current && assets.includes(current)) sel.value = current;
}

async function onSend(ev) {
  ev.preventDefault();
  const btn = document.getElementById('send-submit');
  const asset = document.getElementById('send-asset').value;
  const dest = document.getElementById('send-destination').value.trim().toLowerCase();
  const memo = document.getElementById('send-memo').value;

  if (!/^[0-9a-f]{64}$/.test(dest)) {
    showError('destination must be 64 hex chars');
    return;
  }
  let amount;
  try {
    amount = parseAmount(document.getElementById('send-amount').value.trim(), asset);
  } catch (e) {
    showError('amount: ' + e.message);
    return;
  }
  if (amount <= 0) {
    showError('amount must be greater than zero');
    return;
  }
  const spendable = Number(state.spendable[asset] || 0);
  if (amount > spendable) {
    showError(`insufficient spendable ${asset}: have ${formatAmount(spendable, asset)} spendable, need ${formatAmount(amount, asset)}`);
    return;
  }
  const have = Number(state.balances[asset] || 0);
  if (new TextEncoder().encode(memo).length > 64) {
    showError('memo too long (max 64 bytes)');
    return;
  }

  if (!state.chainLoaded) {
    showError('cannot send: account chain could not be verified with node; please refresh');
    return;
  }
  if (state.chain.length === 0 && (state.chainTotal == null || state.chainTotal > 0)) {
    showError('cannot send: incomplete chain state; please refresh');
    return;
  }

  btn.disabled = true;
  btn.textContent = 'signing + computing pow…';
  showInfo('');
  logActivity('info', `send: signing ${formatAmount(amount, asset)} ${asset} to ${shortAddr(dest)}…`);
  try {
    const last = state.chain.length ? state.chain[state.chain.length - 1] : null;
    if (!last && state.chainTotal !== 0) {
      throw new Error('cannot determine previous block hash; refresh chain');
    }
    const previous = last ? last.hash : '0';
    const result = await buildAndSubmitSend({
      keyPair: state.keyPair,
      networkId: state.networkId,
      previous,
      currentBalance: have,
      asset,
      destination: dest,
      amount,
      memo,
    });
    showInfo(`send accepted · hash ${shortHash(result.hash || '?')}`);
    logActivity('success', `sent ${formatAmount(amount, asset)} ${asset} to ${shortAddr(dest)} · hash ${shortHash(result.hash || '?')}`);
    document.getElementById('send-form').reset();
    await refreshAll();
  } catch (e) {
    showError('send failed: ' + e.message);
    logActivity('error', `send failed: ${e.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = 'send';
  }
}

async function onReceive(pending, btn) {
  const orig = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'receiving…';
  logActivity('info', `receive: signing ${formatAmount(pending.Amount, pending.Asset)} ${pending.Asset} from ${shortAddr(pending.Source)}…`);
  try {
    const last = state.chain.length ? state.chain[state.chain.length - 1] : null;
    const previous = last ? last.hash : '0';
    const have = Number(state.balances[pending.Asset] || 0);
    const result = await buildAndSubmitReceive({
      keyPair: state.keyPair,
      networkId: state.networkId,
      previous,
      currentBalance: have,
      asset: pending.Asset,
      source: pending.SendHash,
      amount: pending.Amount,
    });
    showInfo(`receive accepted · hash ${shortHash(result.hash || '?')}`);
    logActivity('success', `received ${formatAmount(pending.Amount, pending.Asset)} ${pending.Asset} from ${shortAddr(pending.Source)} · hash ${shortHash(result.hash || '?')}`);
    await refreshAll();
  } catch (e) {
    showError('receive failed: ' + e.message);
    logActivity('error', `receive failed: ${e.message}`);
    btn.disabled = false;
    btn.textContent = orig;
  }
}

function blockLinkTd(hash) {
  const el = document.createElement('td');
  if (!hash) { el.textContent = '–'; return el; }
  const a = document.createElement('a');
  a.href = `/blocks/?hash=${encodeURIComponent(hash)}`;
  const code = document.createElement('code');
  code.textContent = shortHash(hash);
  a.appendChild(code);
  a.title = hash;
  el.appendChild(a);
  return el;
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
  if (!msg) {
    document.getElementById('error').hidden = true;
    return;
  }
  const el = document.getElementById('error');
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
