import { api } from './api.js';
import { shortAddr, shortHash, timeOfDay, relativeTime, formatAmount, formatMilli, formatMilliUSD } from './format.js';
import { makeSortableTable } from './sortable.js';

const ADDRESS_KEYS = new Set(['account', 'destination', 'lessor', 'lessee', 'provider']);
const BLOCK_KEYS = new Set(['previous', 'source']);
const TIME_KEYS = new Set(['timestamp', 'expiry']);
const HASH_KEYS = new Set(['hash', 'signature']);
const AMOUNT_KEYS = new Set(['amount', 'balance', 'cost']);
const MILLI_KEYS = new Set(['locked_r', 'locked_payout_cap']);
const MILLI_USD_KEYS = new Set(['locked_twap_milli']);
const RAW_HIDE = new Set(['signature', 'pow_nonce']);

const ORDER = [
  'type', 'hash', 'account', 'previous',
  'timestamp', 'asset', 'balance', 'amount',
  'destination', 'source', 'memo',
  'cost', 'locked_r', 'locked_payout_cap', 'locked_twap_milli',
  'dims', 'expiry', 'lessor', 'lessee', 'provider',
  'keyset',
  'signature', 'pow_nonce',
];

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
    await loadDetail(hash);
  } else {
    await loadList();
  }
}

async function loadList() {
  document.title = 'blocks · xe';
  document.getElementById('list-section').hidden = false;

  let blocks;
  try {
    blocks = await api('/blocks/recent');
  } catch (e) {
    showError(e.message);
    return;
  }
  blocks = blocks || [];
  setText('list-count', `${blocks.length}`);

  const tbody = document.getElementById('list-tbody');
  if (blocks.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="muted">no blocks yet</td></tr>';
    return;
  }
  const rowsOf = (key, dir) => sortBlocks(blocks, key, dir).map(buildRow);
  makeSortableTable(document.querySelector('#list-section table'), tbody, rowsOf, { defaultKey: 'time', defaultDir: 'desc' });
}

function sortBlocks(blocks, key, dir) {
  const mul = dir === 'asc' ? 1 : -1;
  const cmp = (a, b) => {
    switch (key) {
      case 'time': return mul * ((a.timestamp || 0) - (b.timestamp || 0));
      case 'type': return mul * String(a.type || '').localeCompare(String(b.type || ''));
      case 'account': return mul * String(a.account || '').localeCompare(String(b.account || ''));
      case 'asset': return mul * String(a.asset || '').localeCompare(String(b.asset || ''));
      case 'amount': return mul * ((a.amount || 0) - (b.amount || 0));
      case 'balance': return mul * ((a.balance || 0) - (b.balance || 0));
      case 'hash': return mul * String(a.hash || '').localeCompare(String(b.hash || ''));
      default: return 0;
    }
  };
  return blocks.slice().sort(cmp);
}

function buildRow(b) {
  const tr = document.createElement('tr');
  tr.classList.add('linkrow');
  tr.appendChild(td(b.timestamp ? `${timeOfDay(b.timestamp)} · ${relativeTime(b.timestamp)}` : '–'));
  tr.appendChild(td(b.type || '–'));
  tr.appendChild(accountLinkTd(b.account));
  tr.appendChild(td(b.asset || '–'));
  tr.appendChild(numTd(blockAmount(b)));
  tr.appendChild(numTd(blockBalance(b)));
  tr.appendChild(blockLinkTd(b.hash));
  if (b.hash) {
    tr.style.cursor = 'pointer';
    tr.addEventListener('click', (e) => {
      if (e.target.closest('a')) return;
      location.href = `/blocks/?hash=${encodeURIComponent(b.hash)}`;
    });
  }
  return tr;
}

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

function blockBalance(b) {
  switch (b.type) {
    case 'multisig_open':
    case 'multisig_update':
      return '–';
    default:
      return b.balance != null ? formatAmount(b.balance, b.asset) : '–';
  }
}

async function loadDetail(hash) {
  document.getElementById('detail-section').hidden = false;

  let block;
  try {
    block = await api(`/blocks/${encodeURIComponent(hash)}`);
  } catch (e) {
    showError(e.message);
    return;
  }

  const sub = document.getElementById('page-sub');
  if (sub) { sub.textContent = shortHash(hash); sub.title = hash; sub.hidden = false; }
  render(block, hash);
}

function render(block, hash) {
  document.title = `${block.type || 'block'} · xe`;
  setText('block-type', block.type ? `· ${block.type}` : '');

  const dl = document.getElementById('fields');
  dl.innerHTML = '';

  const keys = orderedKeys(block);
  for (const k of keys) {
    const dt = document.createElement('dt');
    dt.textContent = k;
    const dd = document.createElement('dd');
    dd.appendChild(renderValue(k, block[k], block));
    dl.appendChild(dt);
    dl.appendChild(dd);
  }

  const raw = document.getElementById('raw');
  raw.textContent = JSON.stringify(block, null, 2);
  document.getElementById('raw-section').hidden = false;
}

function orderedKeys(block) {
  const have = new Set(Object.keys(block));
  const out = [];
  for (const k of ORDER) {
    if (have.has(k)) {
      out.push(k);
      have.delete(k);
    }
  }
  for (const k of have) out.push(k);
  return out;
}

function renderValue(key, value, block) {
  if (value == null) return text('–');

  if (AMOUNT_KEYS.has(key) && typeof value === 'number') {
    const asset = key === 'cost' ? 'XUSD' : (block && block.asset) || 'XE';
    return text(formatAmount(value, asset));
  }

  if (MILLI_KEYS.has(key) && typeof value === 'number') {
    return text(formatMilli(value));
  }

  if (MILLI_USD_KEYS.has(key) && typeof value === 'number') {
    return text(formatMilliUSD(value));
  }

  if (TIME_KEYS.has(key) && typeof value === 'number') {
    const span = document.createElement('span');
    span.textContent = `${timeOfDay(value)} · ${relativeTime(value)}`;
    span.title = String(value);
    return span;
  }

  if (ADDRESS_KEYS.has(key) && typeof value === 'string' && /^[0-9a-f]{64}$/i.test(value)) {
    return link(`/accounts/?addr=${encodeURIComponent(value)}`, codeText(shortAddr(value)), value);
  }

  if (BLOCK_KEYS.has(key) && typeof value === 'string' && /^[0-9a-f]{64}$/i.test(value)) {
    return link(`/blocks/?hash=${encodeURIComponent(value)}`, codeText(shortHash(value)), value);
  }

  if (HASH_KEYS.has(key) && typeof value === 'string') {
    return codeText(value);
  }

  if (typeof value === 'object') {
    const pre = document.createElement('pre');
    pre.className = 'inline';
    pre.textContent = JSON.stringify(value, null, 2);
    return pre;
  }

  if (typeof value === 'string' && /^[0-9a-f]{64}$/i.test(value)) {
    return codeText(value);
  }

  return text(String(value));
}

function link(href, child, title) {
  const a = document.createElement('a');
  a.href = href;
  a.appendChild(child);
  if (title) a.title = title;
  return a;
}

function accountLinkTd(addr) {
  const el = document.createElement('td');
  if (!addr) { el.textContent = '–'; return el; }
  el.appendChild(link(`/accounts/?addr=${encodeURIComponent(addr)}`, codeText(shortAddr(addr)), addr));
  return el;
}

function blockLinkTd(hash) {
  const el = document.createElement('td');
  if (!hash) { el.textContent = '–'; return el; }
  el.appendChild(link(`/blocks/?hash=${encodeURIComponent(hash)}`, codeText(shortHash(hash)), hash));
  return el;
}

function numTd(value) {
  const el = document.createElement('td');
  el.className = 'num';
  el.textContent = value == null ? '–' : String(value);
  return el;
}

function td(value) {
  const el = document.createElement('td');
  el.textContent = value == null ? '–' : String(value);
  return el;
}

function codeText(s) {
  const c = document.createElement('code');
  c.textContent = s;
  return c;
}

function text(s) {
  const span = document.createElement('span');
  span.textContent = s;
  return span;
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
