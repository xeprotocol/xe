import { api, fetchAllPages } from './api.js';
import { shortAddr, shortHash, timeOfDay, relativeTime, commas, durationString, formatAmount, formatMilli } from './format.js';
import { loadVault } from './vault.js';
import { makeSortableTable } from './sortable.js';
import { loadSnapshot, saveSnapshot } from './persist.js';

const POLL_MS = 5000;

const TERMINAL_STATES = new Set(['settled', 'cancelled', 'unfulfilled', 'expired']);

function isTerminal(l) {
  return TERMINAL_STATES.has(l.state);
}

const state = {
  selfAddr: null,
  providerRow: null,
  cert: null,
  active: [],
  past: [],
  pollTimer: null,
};

async function init() {
  await refreshNode();
  state.selfAddr = activeWalletAddress();
  if (!state.selfAddr) {
    showNotProvider('no wallet in this browser. set up a wallet at /wallet/ first.');
    return;
  }
  hydrateFromSnapshot();
  await refreshAll();
  if (state.providerRow) {
    renderAll();
    showProvider();
    persistSnapshot();
    state.pollTimer = setInterval(pollSafely, POLL_MS);
  }
}

function snapshotKey() {
  return state.selfAddr ? `provider.${state.selfAddr}` : null;
}

function hydrateFromSnapshot() {
  const key = snapshotKey();
  if (!key) return;
  const snap = loadSnapshot(key);
  if (!snap || !snap.value) return;
  const v = snap.value;
  if (v.providerRow) state.providerRow = v.providerRow;
  if (v.cert !== undefined) state.cert = v.cert;
  const leases = [...(Array.isArray(v.active) ? v.active : []),
                  ...(Array.isArray(v.past) ? v.past : [])];
  state.active = leases.filter(l => !isTerminal(l));
  state.past   = leases.filter(l =>  isTerminal(l));
  if (state.providerRow) {
    renderAll();
    showProvider();
  }
}

function persistSnapshot() {
  const key = snapshotKey();
  if (!key || !state.providerRow) return;
  saveSnapshot(key, {
    providerRow: state.providerRow,
    cert: state.cert,
    active: state.active,
    past: state.past,
  });
}

function activeWalletAddress() {
  const vault = loadVault();
  if (!vault || !vault.wallets || vault.wallets.length === 0) return null;
  let i = vault.active;
  if (!Number.isInteger(i) || i < 0 || i >= vault.wallets.length) i = 0;
  const w = vault.wallets[i];
  return (w && w.address) ? String(w.address).toLowerCase() : null;
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

async function refreshAll() {
  let providers, leases, cert;
  try {
    providers = await api('/providers');
  } catch (e) {
    showError('providers: ' + e.message);
    return;
  }
  state.providerRow = (providers || []).find(p => (p.account || '').toLowerCase() === state.selfAddr) || null;
  if (!state.providerRow) {
    showNotProvider('this wallet is not a registered compute provider.');
    return;
  }

  try {
    leases = await fetchAllPages('/leases');
  } catch (e) {
    showError('leases: ' + e.message);
    return;
  }
  const mine = (leases || []).filter(l => (l.provider || '').toLowerCase() === state.selfAddr);
  state.active = mine.filter(l => !isTerminal(l));
  state.past   = mine.filter(l =>  isTerminal(l));

  try {
    cert = await api(`/certificate/${encodeURIComponent(state.selfAddr)}`);
  } catch {
    cert = null;
  }
  state.cert = cert;
}

async function pollSafely() {
  if (document.visibilityState === 'hidden') return;
  try {
    await refreshAll();
    if (!state.providerRow) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
      return;
    }
    renderAll();
    persistSnapshot();
  } catch (e) {
    showError('refresh: ' + e.message);
  }
}

function renderAll() {
  setText('self-pub', state.providerRow.account);
  renderCert();
  renderUtilisation();
  renderActive();
  renderPast();
}

function renderCert() {
  const el = document.getElementById('cert-summary');
  el.innerHTML = '';
  if (!state.cert) {
    el.textContent = 'no perf certificate published';
    el.classList.add('muted');
    return;
  }
  el.classList.remove('muted');
  const c = state.cert;
  const parts = [];
  parts.push(`workload v${c.workload_version}`);
  if (typeof c.score === 'number') parts.push(`score ${c.score.toFixed(3)}`);
  if (c.price_multiplier_milli) parts.push(`price ×${formatMilli(c.price_multiplier_milli)}`);
  if (c.expires_at) parts.push(`expires ${relativeTime(c.expires_at)}`);
  el.textContent = parts.join(' · ');
}

function renderUtilisation() {
  const p = state.providerRow;
  const tbody = document.getElementById('util-tbody');
  tbody.innerHTML = '';
  const rows = [
    { res: 'vcpus', used: p.used_vcpus,    cap: p.vcpus,     unit: 'c'  },
    { res: 'memory', used: p.used_memory_mb, cap: p.memory_mb, unit: 'MB' },
    { res: 'disk',  used: p.used_disk_gb,  cap: p.disk_gb,   unit: 'GB' },
  ];
  for (const r of rows) {
    const used = Number(r.used || 0);
    const cap  = Number(r.cap  || 0);
    const pct  = cap > 0 ? Math.min(100, (used / cap) * 100) : 0;

    const tr = document.createElement('tr');
    tr.appendChild(td(r.res));
    tr.appendChild(td(`${commas(used)} ${r.unit}`));
    tr.appendChild(td(`${commas(cap)} ${r.unit}`));
    tr.appendChild(td(cap > 0 ? `${pct.toFixed(1)}%` : '–'));

    const barTd = document.createElement('td');
    const bar = document.createElement('div');
    bar.className = 'util-bar';
    const fill = document.createElement('div');
    fill.className = 'util-bar-fill' + (pct > 90 ? ' util-bar-hot' : '');
    fill.style.width = `${pct.toFixed(1)}%`;
    bar.appendChild(fill);
    barTd.appendChild(bar);
    tr.appendChild(barTd);

    tbody.appendChild(tr);
  }
  setText('active-count', `${state.providerRow.active_leases || 0} active leases · ${state.providerRow.total_leases || 0} total`);
}

function leaseSortValue(l, key) {
  switch (key) {
    case 'start_time':  return Number(l.start_time || 0);
    case 'lease_hash':  return String(l.lease_hash || '');
    case 'consumer':    return String(l.consumer || '');
    case 'resources':   return Number(l.vcpus || 0) * 1e12 + Number(l.memory_mb || 0) * 1e6 + Number(l.disk_gb || 0);
    case 'cost':        return Number(l.cost || 0);
    case 'stake':       return Number(l.stake || 0);
    case 'remaining':   return remainingNs(l);
    default:            return 0;
  }
}

function remainingNs(l) {
  if (!l.start_time) return 0;
  const endNs = Number(l.start_time) + Number(l.duration || 0) * 1e9;
  return endNs - Date.now() * 1e6;
}

function renderActive() {
  setText('active-hint', `${state.active.length}`);
  const table = document.querySelector('#active-tbody').closest('table');
  const tbody = document.getElementById('active-tbody');
  if (state.active.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="muted">no active leases</td></tr>';
    return;
  }
  makeSortableTable(table, tbody, (key, dir) => {
    const sorted = state.active.slice().sort((a, b) => {
      const va = leaseSortValue(a, key);
      const vb = leaseSortValue(b, key);
      if (va < vb) return dir === 'asc' ? -1 : 1;
      if (va > vb) return dir === 'asc' ?  1 : -1;
      return 0;
    });
    return sorted.map(activeRow);
  }, { defaultKey: 'start_time', defaultDir: 'desc' });
}

function activeRow(l) {
  const tr = document.createElement('tr');
  tr.appendChild(td(l.start_time ? `${timeOfDay(l.start_time)} · ${relativeTime(l.start_time)}` : 'pending'));
  tr.appendChild(blockLinkTd(l.lease_hash, '/leases/?hash='));
  tr.appendChild(accountLinkTd(l.consumer));
  tr.appendChild(td(resourceSummary(l)));
  tr.appendChild(td(formatAmount(l.cost, 'XUSD')));
  tr.appendChild(td(formatAmount(l.stake, 'XUSD')));
  tr.appendChild(td(formatRemaining(l)));
  return tr;
}

function formatRemaining(l) {
  if (!l.start_time) return '–';
  const remNs = remainingNs(l);
  if (remNs <= 0) return 'expiring';
  return durationString(remNs / 1e9);
}

function renderPast() {
  setText('past-hint', `${state.past.length}`);
  const table = document.querySelector('#past-tbody').closest('table');
  const tbody = document.getElementById('past-tbody');
  if (state.past.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="muted">no settled leases</td></tr>';
    return;
  }
  makeSortableTable(table, tbody, (key, dir) => {
    const sorted = state.past.slice().sort((a, b) => {
      const va = leaseSortValue(a, key);
      const vb = leaseSortValue(b, key);
      if (va < vb) return dir === 'asc' ? -1 : 1;
      if (va > vb) return dir === 'asc' ?  1 : -1;
      return 0;
    });
    return sorted.map(pastRow);
  }, { defaultKey: 'start_time', defaultDir: 'desc' });
}

function pastRow(l) {
  const tr = document.createElement('tr');
  tr.appendChild(td(l.start_time ? `${timeOfDay(l.start_time)} · ${relativeTime(l.start_time)}` : '–'));
  tr.appendChild(blockLinkTd(l.lease_hash, '/leases/?hash='));
  tr.appendChild(accountLinkTd(l.consumer));
  tr.appendChild(td(resourceSummary(l)));
  tr.appendChild(td(formatAmount(l.cost, 'XUSD')));
  tr.appendChild(td(formatAmount(l.stake, 'XUSD')));
  return tr;
}

function resourceSummary(l) {
  return `${l.vcpus || 0}c · ${l.memory_mb || 0}MB · ${l.disk_gb || 0}GB · ${durationString(l.duration || 0)}`;
}

function blockLinkTd(hash, hrefPrefix) {
  const el = document.createElement('td');
  if (!hash) { el.textContent = '–'; return el; }
  const a = document.createElement('a');
  a.href = `${hrefPrefix}${encodeURIComponent(hash)}`;
  const code = document.createElement('code');
  code.textContent = shortHash(hash);
  a.appendChild(code);
  a.title = hash;
  el.appendChild(a);
  return el;
}

function accountLinkTd(addr) {
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

function td(text) {
  const el = document.createElement('td');
  el.textContent = text == null ? '–' : String(text);
  return el;
}

function showProvider() {
  document.getElementById('not-provider-section').hidden = true;
  document.getElementById('provider-section').hidden = false;
}

function showNotProvider(msg) {
  setText('not-provider-msg', msg);
  document.getElementById('not-provider-section').hidden = false;
  document.getElementById('provider-section').hidden = true;
  if (state.pollTimer) {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
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

init();
