import { api, fetchAllPages } from './api.js';
import { shortAddr, shortHash, timeOfDay, relativeTime, commas, durationString, formatAmount, formatMilli, formatMilliUSD } from './format.js';
import { makeSortableTable } from './sortable.js';
import { loadSnapshot, saveSnapshot } from './persist.js';

const SNAP_KEY = 'leases.list';

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

async function load() {
  await refreshNode();
  const params = new URLSearchParams(location.search);
  const hash = params.get('hash');
  if (hash) {
    document.title = `lease · xe`;
    setText('page-title', `lease · ${hash.slice(0, 12)}…`);
    document.getElementById('list-section').hidden = true;
    document.getElementById('detail-section').hidden = false;
    await loadDetail(hash);
  } else {
    await loadList();
  }
}

let allLeases = [];

async function loadList() {
  const cached = loadSnapshot(SNAP_KEY);
  if (cached && Array.isArray(cached.value)) {
    allLeases = cached.value;
    renderFilteredList();
  }
  let leases;
  try {
    leases = await fetchAllPages('/leases');
  } catch (e) {
    showError(e.message);
    return;
  }
  allLeases = (leases || []).slice().sort((a, b) => (b.start_time || 0) - (a.start_time || 0));
  saveSnapshot(SNAP_KEY, allLeases);
  renderFilteredList();

  const filter = document.getElementById('state-filter');
  if (filter) {
    filter.addEventListener('change', () => renderFilteredList());
  }
}

function renderFilteredList() {
  const filter = document.getElementById('state-filter');
  const state = filter ? filter.value : '';
  const list = state ? allLeases.filter(l => l.state === state) : allLeases;
  renderList(list);
}

function leaseSortValue(l, key) {
  switch (key) {
    case 'lease_hash': return String(l.lease_hash || '');
    case 'consumer':   return String(l.consumer || '');
    case 'provider':   return String(l.provider || '');
    case 'cost':       return Number(l.cost || 0);
    case 'stake':      return Number(l.stake || 0);
    case 'resources':  return Number(l.vcpus || 0) * 1e12 + Number(l.memory_mb || 0) * 1e6 + Number(l.disk_gb || 0);
    case 'status':     return String(l.state || '');
    default:           return 0;
  }
}

function renderList(list) {
  const tbody = document.getElementById('list-tbody');
  setText('list-count', `${list.length} total`);
  if (list.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="muted">no leases</td></tr>';
    return;
  }
  const table = document.getElementById('list-table');
  makeSortableTable(table, tbody, (key, dir) => {
    const sorted = list.slice().sort((a, b) => {
      const va = leaseSortValue(a, key);
      const vb = leaseSortValue(b, key);
      if (va < vb) return dir === 'asc' ? -1 : 1;
      if (va > vb) return dir === 'asc' ?  1 : -1;
      return 0;
    });
    return sorted.map(listRow);
  }, { defaultKey: 'lease_hash', defaultDir: 'asc' });
}

function listRow(l) {
  const tr = document.createElement('tr');
  tr.classList.add('linkrow');
  tr.appendChild(blockLinkTd(l.lease_hash));
  tr.appendChild(accountLinkTd(l.consumer));
  tr.appendChild(accountLinkTd(l.provider));
  tr.appendChild(td(formatAmount(l.cost, 'XUSD')));
  tr.appendChild(td(formatAmount(l.stake, 'XUSD')));
  tr.appendChild(td(resourceSummary(l)));
  tr.appendChild(td(l.state || (l.settled ? 'settled' : 'accepted')));
  if (l.lease_hash) {
    tr.style.cursor = 'pointer';
    tr.addEventListener('click', (e) => {
      if (e.target.closest('a')) return;
      location.href = `/leases/?hash=${encodeURIComponent(l.lease_hash)}`;
    });
  }
  return tr;
}

async function loadDetail(hash) {
  let lease;
  try {
    lease = await api(`/leases/${encodeURIComponent(hash)}`);
  } catch (e) {
    showError(e.message);
    return;
  }
  const dl = document.getElementById('detail-kv');
  dl.innerHTML = '';

  const rows = [
    ['lease hash', codeLink(`/blocks/?hash=${encodeURIComponent(lease.lease_hash)}`, lease.lease_hash)],
    ['consumer', codeLink(`/accounts/?addr=${encodeURIComponent(lease.consumer)}`, lease.consumer)],
    ['provider', codeLink(`/accounts/?addr=${encodeURIComponent(lease.provider)}`, lease.provider)],
    ['vcpus', text(commas(lease.vcpus))],
    ['memory mb', text(commas(lease.memory_mb))],
    ['disk gb', text(commas(lease.disk_gb))],
    ['duration', text(durationString(lease.duration))],
    ['cost (XUSD)', text(formatAmount(lease.cost, 'XUSD'))],
    ['stake (XUSD)', text(formatAmount(lease.stake, 'XUSD'))],
    ['start time', text(lease.start_time ? `${timeOfDay(lease.start_time)} · ${relativeTime(lease.start_time)}` : '–')],
    ['state', text(lease.state || (lease.settled ? 'settled' : 'accepted'))],
  ];
  // Emission-lock economics captured at accept (#401), ×1000 fixed-point /
  // milli-USD. All omitempty (absent on legacy records).
  if (lease.locked_r) {
    rows.push(['locked r', text(formatMilli(lease.locked_r))]);
  }
  if (lease.locked_payout_cap) {
    rows.push(['locked payout cap', text(formatMilli(lease.locked_payout_cap))]);
  }
  if (lease.locked_twap_milli) {
    rows.push(['locked twap', text(formatMilliUSD(lease.locked_twap_milli))]);
  }
  if (lease.certificate_hash) {
    rows.push(['certificate', codeText(lease.certificate_hash)]);
  }
  if (lease.access_pub_key) {
    rows.push(['access pub key', codeText(lease.access_pub_key)]);
  }
  for (const [k, v] of rows) {
    const dt = document.createElement('dt');
    dt.textContent = k;
    const dd = document.createElement('dd');
    dd.appendChild(v);
    dl.appendChild(dt);
    dl.appendChild(dd);
  }
}

function resourceSummary(l) {
  return `${l.vcpus || 0}c · ${l.memory_mb || 0}MB · ${l.disk_gb || 0}GB · ${durationString(l.duration || 0)}`;
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

function codeLink(href, value) {
  const a = document.createElement('a');
  a.href = href;
  const code = document.createElement('code');
  code.textContent = value;
  a.appendChild(code);
  return a;
}

function codeText(value) {
  const c = document.createElement('code');
  c.textContent = value;
  return c;
}

function text(s) {
  const span = document.createElement('span');
  span.textContent = s == null ? '–' : String(s);
  return span;
}

function td(text) {
  const el = document.createElement('td');
  el.textContent = text == null ? '–' : String(text);
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
  el.textContent = msg;
  el.hidden = false;
  setStatus('error', 'err');
}

load();
