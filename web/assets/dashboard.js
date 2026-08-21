import { api, fetchAllPages } from './api.js';
import { shortAddr, shortHash, commas, timeOfDay, formatAmount } from './format.js';
import { barChart, sparkline } from './chart.js';
import { loadSnapshot, saveSnapshot, loadHistory, pushHistory, ageString } from './persist.js';

const POLL_MS = 5000;
const HISTORY_MAX = 240;         // 20 min at 5s cadence
const RATE_BUCKETS = 60;
const RATE_BUCKET_MS = 5000;
const RECENT_ROWS = 12;          // rows in the recent-blocks table
const RATE_MAX_BLOCKS = 1000;    // api maxPageLimit — caps the chart at ~3.3 blocks/s

const STAT_KEYS = ['peers', 'accounts', 'blocks', 'pending', 'leases', 'providers'];

let pollTimer = null;

function init() {
  // Synchronous render from cache so the page is populated before any
  // network call resolves. Replaces the previous "–" flash on every load.
  hydrateFromCache();
  refresh();
  pollTimer = setInterval(() => {
    if (document.visibilityState === 'hidden') return;
    refresh();
  }, POLL_MS);
}

function hydrateFromCache() {
  const snap = loadSnapshot('dashboard');
  if (snap && snap.value) {
    const v = snap.value;
    if (v.address) setText('address', v.address);
    if (v.node_id) setText('node-id', v.node_id);
    for (const k of STAT_KEYS) {
      if (typeof v[k] === 'number') setStat(k, v[k]);
    }
    setText('snapshot-age', `last seen ${ageString(snap.ts)}`);
  }
  renderSparklines(loadHistory('dashboard'));

  // Block rate from cached recent blocks if available.
  const blockSnap = loadSnapshot('dashboard.blocks');
  if (blockSnap && Array.isArray(blockSnap.value)) {
    renderRecentBlocks(blockSnap.value);
    renderBlockRate(blockSnap.value);
  }
}

async function refresh() {
  const errors = [];
  const sample = { ts: Date.now() };

  await Promise.allSettled([
    refreshIdentityAndStats(sample).catch(e => errors.push('node: ' + e.message)),
    refreshSecondaryStats(sample).catch(e => errors.push('aux: ' + e.message)),
    refreshBlocks().catch(e => errors.push('blocks: ' + e.message)),
  ]);

  // Persist what we have, even on partial failure.
  saveSnapshot('dashboard', {
    address: lastAddress, node_id: lastNodeId,
    peers: sample.peers, accounts: sample.accounts, blocks: sample.blocks,
    pending: sample.pending, leases: sample.leases, providers: sample.providers,
  });
  const hist = pushHistory('dashboard', sample, HISTORY_MAX);
  renderSparklines(hist);
  setText('snapshot-age', `updated ${ageString(sample.ts)}`);

  if (errors.length === 0) setStatus('ok', 'ok');
  else setStatus(errors.join(' · '), 'err');
}

let lastAddress = '';
let lastNodeId = '';

async function refreshIdentityAndStats(sample) {
  const node = await api('/node');
  lastAddress = node.address || '';
  lastNodeId  = node.id || '';
  setText('address', lastAddress || '–');
  setText('node-id', lastNodeId || '–');

  sample.peers    = Number(node.peer_count) || 0;
  sample.accounts = Number(node.accounts) || 0;
  sample.blocks   = Number(node.block_count) || 0;
  setStat('peers',    sample.peers);
  setStat('accounts', sample.accounts);
  setStat('blocks',   sample.blocks);
}

async function refreshSecondaryStats(sample) {
  const [pending, leases, providers] = await Promise.all([
    fetchAllPages('/pending').catch(() => []),
    fetchAllPages('/leases').catch(() => []),
    api('/providers').catch(() => []),
  ]);
  sample.pending   = countOf(pending);
  sample.leases    = countOf(leases);
  sample.providers = countOf(providers);
  setStat('pending',   sample.pending);
  setStat('leases',    sample.leases);
  setStat('providers', sample.providers);
}

async function refreshBlocks() {
  // Two different queries: the table wants the newest rows whatever their age,
  // the rate chart wants exactly the window it plots. One fixed slab can't serve
  // both without fetching hundreds of out-of-window blocks every poll (#798).
  const sinceNs = (Date.now() - RATE_BUCKETS * RATE_BUCKET_MS) * 1e6;
  const [recent, windowed] = await Promise.all([
    api(`/blocks/recent?limit=${RECENT_ROWS}`),
    api(`/blocks/recent?since=${sinceNs}&limit=${RATE_MAX_BLOCKS}`),
  ]);
  saveSnapshot('dashboard.blocks', recent || []);
  renderRecentBlocks(recent);
  renderBlockRate(windowed);
}

function renderSparklines(history) {
  if (!Array.isArray(history) || history.length < 2) return;
  for (const k of STAT_KEYS) {
    const host = document.getElementById('spark-' + k);
    if (!host) continue;
    const series = history.map(h => Number(h[k]) || 0);
    host.replaceChildren(sparkline(series));
    renderDelta(k, series);
  }
}

function renderDelta(key, series) {
  const el = document.getElementById('delta-' + key);
  if (!el || series.length < 2) return;
  const first = series[0];
  const last = series[series.length - 1];
  const diff = last - first;
  if (diff === 0) {
    el.textContent = '— no change';
    el.className = 'delta';
    return;
  }
  const arrow = diff > 0 ? '↑' : '↓';
  const sign  = diff > 0 ? '+' : '';
  el.textContent = `${arrow} ${sign}${commas(diff)}`;
  el.className = 'delta ' + (diff > 0 ? 'delta-up' : 'delta-down');
}

function renderRecentBlocks(blocks) {
  const tbody = document.getElementById('blocks-tbody');
  if (!tbody) return;
  tbody.innerHTML = '';
  if (!blocks || blocks.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="muted">no blocks yet</td></tr>';
    return;
  }
  const sorted = blocks.slice().sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0)).slice(0, RECENT_ROWS);
  for (const b of sorted) {
    const tr = document.createElement('tr');
    tr.classList.add('linkrow');
    tr.appendChild(td(timeOfDay(b.timestamp)));
    tr.appendChild(td(b.type || '–'));
    tr.appendChild(tdAccountLink(b.account));
    tr.appendChild(td(b.asset || '–'));
    tr.appendChild(td(blockAmount(b)));
    tr.appendChild(td(blockBalance(b)));
    tr.appendChild(tdBlockLink(b.hash));
    if (b.hash) {
      tr.style.cursor = 'pointer';
      tr.addEventListener('click', (e) => {
        if (e.target.closest('a')) return;
        location.href = `/blocks/?hash=${encodeURIComponent(b.hash)}`;
      });
    }
    tbody.appendChild(tr);
  }
}

// blockAmount returns the monetary movement for the block, or "–" for types
// that don't carry one (genesis, multisig_open, etc).
function blockAmount(b) {
  switch (b.type) {
    case 'send':
    case 'receive':
    case 'claim':
    case 'lease':
    case 'lease_accept':
    case 'lease_settle':
      return b.amount != null ? formatAmount(b.amount, b.asset) : '–';
    default:
      return '–';
  }
}

// blockBalance returns the post-block account balance for types that carry
// one. multisig_open / multisig_update don't move balance.
function blockBalance(b) {
  switch (b.type) {
    case 'multisig_open':
    case 'multisig_update':
      return '–';
    default:
      return b.balance != null ? formatAmount(b.balance, b.asset) : '–';
  }
}

function renderBlockRate(blocks) {
  const now = Date.now();
  const counts = new Array(RATE_BUCKETS).fill(0);
  for (const b of blocks || []) {
    const ms = Math.floor((b.timestamp || 0) / 1e6);
    if (!ms) continue;
    const ageMs = now - ms;
    const idx = Math.floor(ageMs / RATE_BUCKET_MS);
    if (idx >= 0 && idx < RATE_BUCKETS) {
      counts[RATE_BUCKETS - 1 - idx]++;
    }
  }
  renderChart('block-rate', barChart(counts));
}

function renderChart(id, svg) {
  const host = document.getElementById(id);
  if (!host) return;
  host.replaceChildren(svg);
}

function setStat(key, value) {
  const el = document.getElementById('stat-' + key);
  if (el) el.textContent = commas(value);
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function setStatus(text, cls) {
  const el = document.getElementById('status');
  if (!el) return;
  el.textContent = text;
  el.className = 'status ' + (cls || '');
}

function td(text) {
  const el = document.createElement('td');
  el.textContent = text;
  return el;
}

function tdBlockLink(hash) {
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

function tdAccountLink(addr) {
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

function countOf(v) {
  if (Array.isArray(v)) return v.length;
  if (v && typeof v === 'object') return Object.keys(v).length;
  return 0;
}

init();
