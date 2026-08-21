import { api, fetchAllPages, fetchChainTail } from './api.js';
import { shortAddr, shortHash, timeOfDay, relativeTime, commas, formatAmount } from './format.js';
import { makeSortableTable } from './sortable.js';

const CHAIN_LIMIT = 25;

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
  const addr = params.get('addr');
  if (addr) {
    document.title = `${shortAddr(addr)} · xe`;
    setText('page-title', `account · ${shortAddr(addr)}`);
    setText('f-address', addr);
    document.getElementById('list-section').hidden = true;
    document.getElementById('detail-section').hidden = false;
    await loadDetail(addr);
  } else {
    document.title = 'accounts · xe';
    await loadList();
  }
}

async function loadList() {
  let accounts;
  try {
    accounts = await fetchAllPages('/accounts');
  } catch (e) {
    showError(e.message);
    return;
  }
  const list = accounts || [];
  setText('list-count', `${list.length}`);
  const tbody = document.getElementById('list-tbody');
  if (list.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="muted">no accounts</td></tr>';
    return;
  }
  const rowsOf = (sortKey, dir) => {
    const sorted = sortAccounts(list, sortKey, dir);
    return sorted.map(a => buildAccountRow(a));
  };
  makeSortableTable(document.querySelector('#list-section table'), tbody, rowsOf, { defaultKey: 'xe', defaultDir: 'desc' });
}

function sortAccounts(list, key, dir) {
  const mul = dir === 'asc' ? 1 : -1;
  const xe = (a) => Number((a.balances && a.balances.XE) || 0);
  const xusd = (a) => Number((a.balances && a.balances.XUSD) || 0);
  const cmp = (a, b) => {
    switch (key) {
      case 'address': return mul * String(a.address).localeCompare(String(b.address));
      case 'xe': return mul * (xe(a) - xe(b));
      case 'xusd': return mul * (xusd(a) - xusd(b));
      case 'blocks': return mul * ((a.block_count || 0) - (b.block_count || 0));
      case 'frontier': return mul * String(a.frontier || '').localeCompare(String(b.frontier || ''));
      case 'last': return mul * ((a.last_block_timestamp || 0) - (b.last_block_timestamp || 0));
      default: return 0;
    }
  };
  return list.slice().sort(cmp);
}

function buildAccountRow(a) {
  const tr = document.createElement('tr');
  tr.classList.add('linkrow');
  tr.appendChild(accountLinkTd(a.address));
  tr.appendChild(numTd(formatAmount((a.balances && a.balances.XE) || 0, 'XE')));
  tr.appendChild(numTd(formatAmount((a.balances && a.balances.XUSD) || 0, 'XUSD')));
  tr.appendChild(numTd(commas(a.block_count)));
  tr.appendChild(blockLinkTd(a.frontier));
  tr.appendChild(td(a.last_block_timestamp ? relativeTime(a.last_block_timestamp) : '–'));
  if (a.address) {
    tr.style.cursor = 'pointer';
    tr.addEventListener('click', (e) => {
      if (e.target.closest('a')) return;
      location.href = `/accounts/?addr=${encodeURIComponent(a.address)}`;
    });
  }
  return tr;
}

async function loadDetail(addr) {
  const errors = [];
  await Promise.allSettled([
    fetchBalance(addr).catch(e => errors.push('balance: ' + e.message)),
    fetchKeyset(addr),
    fetchPending(addr).catch(e => errors.push('pending: ' + e.message)),
    fetchChain(addr).catch(e => errors.push('chain: ' + e.message)),
  ]);
  if (errors.length) showError(errors.join(' · '));
}

async function fetchBalance(addr) {
  const data = await api(`/accounts/${encodeURIComponent(addr)}/balance`);
  const tbody = document.getElementById('balances-tbody');
  tbody.innerHTML = '';
  const balances = data.balances || {};
  const keys = Object.keys(balances).sort();
  if (keys.length === 0) {
    tbody.innerHTML = '<tr><td colspan="2" class="muted">no balances</td></tr>';
  } else {
    for (const asset of keys) {
      const tr = document.createElement('tr');
      tr.appendChild(td(asset));
      tr.appendChild(td(formatAmount(balances[asset], asset)));
      tbody.appendChild(tr);
    }
  }
  document.getElementById('balances-section').hidden = false;
}

async function fetchKeyset(addr) {
  let ks;
  try {
    ks = await api(`/accounts/${encodeURIComponent(addr)}/keyset`);
  } catch {
    return;
  }
  if (!ks) return;
  const dl = document.getElementById('keyset-kv');
  dl.innerHTML = '';
  for (const [k, v] of Object.entries(ks)) {
    const dt = document.createElement('dt');
    dt.textContent = k;
    const dd = document.createElement('dd');
    if (typeof v === 'object') {
      const pre = document.createElement('pre');
      pre.className = 'inline';
      pre.textContent = JSON.stringify(v, null, 2);
      dd.appendChild(pre);
    } else {
      dd.textContent = String(v);
    }
    dl.appendChild(dt);
    dl.appendChild(dd);
  }
  document.getElementById('keyset-section').hidden = false;
}

async function fetchPending(addr) {
  const data = await api(`/pending/${encodeURIComponent(addr)}`);
  const list = data.pending || [];
  const tbody = document.getElementById('pending-tbody');
  tbody.innerHTML = '';
  setText('pending-count', list.length ? String(list.length) : '');
  if (list.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="muted">none</td></tr>';
  } else {
    for (const p of list) {
      const tr = document.createElement('tr');
      tr.appendChild(td(p.Timestamp ? relativeTime(p.Timestamp) : '–'));
      tr.appendChild(td(p.Asset || '–'));
      tr.appendChild(td(formatAmount(p.Amount, p.Asset)));
      tr.appendChild(accountLinkTd(p.Source));
      tr.appendChild(blockLinkTd(p.SendHash));
      tbody.appendChild(tr);
    }
  }
  document.getElementById('pending-section').hidden = false;
}

async function fetchChain(addr) {
  const { total, blocks } = await fetchChainTail(addr, CHAIN_LIMIT);
  setText('chain-count', `${total} block${total === 1 ? '' : 's'}`);
  const recent = blocks.slice().reverse();
  const tbody = document.getElementById('chain-tbody');
  tbody.innerHTML = '';
  if (recent.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="muted">no blocks</td></tr>';
    return;
  }
  for (const b of recent) {
    const tr = document.createElement('tr');
    tr.classList.add('linkrow');
    tr.appendChild(td(timeOfDay(b.timestamp)));
    tr.appendChild(td(b.type || '–'));
    tr.appendChild(td(b.asset || '–'));
    tr.appendChild(td(formatAmount(b.balance, b.asset)));
    tr.appendChild(blockLinkTd(b.hash));
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
