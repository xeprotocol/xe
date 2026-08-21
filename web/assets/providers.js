import { api } from './api.js';
import { shortAddr, timeOfDay, relativeTime, commas } from './format.js';
import { makeSortableTable } from './sortable.js';
import { loadSnapshot, saveSnapshot } from './persist.js';

const SNAP_KEY = 'providers.list';

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
  const cached = loadSnapshot(SNAP_KEY);
  if (cached && Array.isArray(cached.value)) {
    render(cached.value);
  }
  let providers;
  try {
    providers = await api('/providers');
  } catch (e) {
    showError(e.message);
    return;
  }
  const list = (providers || []).slice().sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
  saveSnapshot(SNAP_KEY, list);
  render(list);
}

function sortValue(p, key) {
  switch (key) {
    case 'account':   return String(p.account || '');
    case 'capacity':  return Number(p.vcpus || 0) * 1e12 + Number(p.memory_mb || 0) * 1e6 + Number(p.disk_gb || 0);
    case 'used':      return Number(p.used_vcpus || 0) * 1e12 + Number(p.used_memory_mb || 0) * 1e6 + Number(p.used_disk_gb || 0);
    case 'active':    return Number(p.active_leases || 0);
    case 'total':     return Number(p.total_leases || 0);
    case 'timestamp': return Number(p.timestamp || 0);
    default:          return 0;
  }
}

function render(list) {
  setText('count', `${list.length} known`);
  const tbody = document.getElementById('tbody');
  if (list.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="muted">no providers</td></tr>';
    return;
  }
  const table = document.getElementById('list-table');
  makeSortableTable(table, tbody, (key, dir) => {
    const sorted = list.slice().sort((a, b) => {
      const va = sortValue(a, key);
      const vb = sortValue(b, key);
      if (va < vb) return dir === 'asc' ? -1 : 1;
      if (va > vb) return dir === 'asc' ?  1 : -1;
      return 0;
    });
    return sorted.map(row);
  }, { defaultKey: 'timestamp', defaultDir: 'desc' });
}

function row(p) {
  const tr = document.createElement('tr');
  tr.appendChild(accountLinkTd(p.account));
  tr.appendChild(td(`${commas(p.vcpus)}c · ${commas(p.memory_mb)}MB · ${commas(p.disk_gb)}GB`));
  tr.appendChild(td(`${commas(p.used_vcpus)}c · ${commas(p.used_memory_mb)}MB · ${commas(p.used_disk_gb)}GB`));
  tr.appendChild(td(commas(p.active_leases)));
  tr.appendChild(td(commas(p.total_leases)));
  tr.appendChild(td(p.timestamp ? `${timeOfDay(p.timestamp)} · ${relativeTime(p.timestamp)}` : '–'));
  return tr;
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
