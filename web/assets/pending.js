import { api, fetchAllPages } from './api.js';
import { shortAddr, shortHash, timeOfDay, relativeTime, commas, formatAmount } from './format.js';
import { makeSortableTable } from './sortable.js';

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
  let list;
  try {
    list = await fetchAllPages('/pending');
  } catch (e) {
    showError(e.message);
    return;
  }
  list = list || [];
  setText('list-count', `${list.length}`);
  const tbody = document.getElementById('list-tbody');
  if (list.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="muted">no pending sends</td></tr>';
    return;
  }
  const rowsOf = (key, dir) => sortPending(list, key, dir).map(buildRow);
  makeSortableTable(document.querySelector('section table'), tbody, rowsOf, { defaultKey: 'amount', defaultDir: 'desc' });
}

function sortPending(list, key, dir) {
  const mul = dir === 'asc' ? 1 : -1;
  const cmp = (a, b) => {
    switch (key) {
      case 'time': return mul * ((a.Timestamp || 0) - (b.Timestamp || 0));
      case 'amount': return mul * ((a.Amount || 0) - (b.Amount || 0));
      case 'asset': return mul * String(a.Asset || '').localeCompare(String(b.Asset || ''));
      case 'source': return mul * String(a.Source || '').localeCompare(String(b.Source || ''));
      case 'destination': return mul * String(a.Destination || '').localeCompare(String(b.Destination || ''));
      case 'hash': return mul * String(a.SendHash || '').localeCompare(String(b.SendHash || ''));
      default: return 0;
    }
  };
  return list.slice().sort(cmp);
}

function buildRow(p) {
  const tr = document.createElement('tr');
  tr.classList.add('linkrow');
  tr.appendChild(td(p.Timestamp ? `${timeOfDay(p.Timestamp)} · ${relativeTime(p.Timestamp)}` : '–'));
  tr.appendChild(numTd(formatAmount(p.Amount, p.Asset)));
  tr.appendChild(td(p.Asset || '–'));
  tr.appendChild(accountLinkTd(p.Source));
  tr.appendChild(accountLinkTd(p.Destination));
  tr.appendChild(blockLinkTd(p.SendHash));
  if (p.SendHash) {
    tr.style.cursor = 'pointer';
    tr.addEventListener('click', (e) => {
      if (e.target.closest('a')) return;
      location.href = `/blocks/?hash=${encodeURIComponent(p.SendHash)}`;
    });
  }
  return tr;
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

function numTd(text) {
  const el = document.createElement('td');
  el.className = 'num';
  el.textContent = text == null ? '–' : String(text);
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
