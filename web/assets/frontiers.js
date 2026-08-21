import { fetchAllPages } from './api.js';
import { shortAddr, shortHash, commas, timeOfDay, relativeTime } from './format.js';
import { makeSortableTable } from './sortable.js';

async function load() {
  let entries;
  try {
    entries = await fetchAllPages('/frontiers');
  } catch (e) {
    showError(e.message);
    return;
  }
  const list = Array.isArray(entries) ? entries : [];
  setText('list-count', `${list.length}`);
  const tbody = document.getElementById('list-tbody');
  if (list.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="muted">no frontiers</td></tr>';
    return;
  }
  const rowsOf = (key, dir) => sortEntries(list, key, dir).map(buildRow);
  makeSortableTable(document.querySelector('section table'), tbody, rowsOf, { defaultKey: 'timestamp', defaultDir: 'desc' });
}

function sortEntries(list, key, dir) {
  const mul = dir === 'asc' ? 1 : -1;
  const cmp = (a, b) => {
    switch (key) {
      case 'account':   return mul * String(a.account).localeCompare(String(b.account));
      case 'frontier':  return mul * String(a.frontier).localeCompare(String(b.frontier));
      case 'type':      return mul * String(a.block_type || '').localeCompare(String(b.block_type || ''));
      case 'depth':     return mul * ((a.block_count || 0) - (b.block_count || 0));
      case 'timestamp': return mul * ((a.timestamp || 0) - (b.timestamp || 0));
      case 'rep':       return mul * String(a.representative || '').localeCompare(String(b.representative || ''));
      default: return 0;
    }
  };
  return list.slice().sort(cmp);
}

function buildRow(e) {
  const tr = document.createElement('tr');
  tr.classList.add('linkrow');
  tr.appendChild(accountLinkTd(e.account));
  tr.appendChild(blockLinkTd(e.frontier));
  tr.appendChild(td(e.block_type || '–'));
  tr.appendChild(numTd(commas(e.block_count || 0)));
  tr.appendChild(td(e.timestamp ? `${timeOfDay(e.timestamp)} · ${relativeTime(e.timestamp)}` : '–'));
  tr.appendChild(e.representative ? accountLinkTd(e.representative) : td('–'));
  if (e.account) {
    tr.style.cursor = 'pointer';
    tr.addEventListener('click', (ev) => {
      if (ev.target.closest('a')) return;
      location.href = `/accounts/?addr=${encodeURIComponent(e.account)}`;
    });
  }
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

function td(text) {
  const el = document.createElement('td');
  el.textContent = text == null ? '–' : String(text);
  return el;
}

function numTd(text) {
  const el = td(text);
  el.classList.add('num');
  return el;
}

function setText(id, t) {
  const el = document.getElementById(id);
  if (el) el.textContent = t;
}

function showError(msg) {
  const el = document.getElementById('error');
  el.textContent = msg;
  el.hidden = false;
}

load();
