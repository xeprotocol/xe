import { api } from './api.js';
import { shortAddr, shortHash, relativeTime, commas } from './format.js';
import { makeSortableTable } from './sortable.js';

const POLL_MS = 5000;

async function load() {
  let node;
  try {
    node = await api('/node');
  } catch (e) {
    showError(e.message);
    return;
  }
  setText('network', node.network_id || '(no network)');
  setText('version', node.version || '');
  setStatus('ok', 'ok');

  renderSelf(node);
  renderPeers(node.peers || []);
}

function renderSelf(node) {
  const dl = document.getElementById('self-kv');
  dl.innerHTML = '';
  const rows = [
    ['peer id', codeText(node.id || '–')],
    ['address', accountLinkInline(node.address)],
    ['version', text(node.version || '–')],
    ['network', text(node.network_id || '–')],
    ['accounts', text(commas(node.accounts))],
    ['blocks', text(commas(node.block_count))],
    ['peer count', text(commas(node.peer_count))],
  ];
  for (const [k, v] of rows) {
    const dt = document.createElement('dt');
    dt.textContent = k;
    const dd = document.createElement('dd');
    dd.appendChild(v);
    dl.appendChild(dt);
    dl.appendChild(dd);
  }
}

function renderPeers(peers) {
  setText('list-count', `${peers.length}`);
  const tbody = document.getElementById('list-tbody');
  if (peers.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" class="muted">no peers connected</td></tr>';
    return;
  }
  const rowsOf = (key, dir) => sortPeers(peers, key, dir).map(buildRow);
  makeSortableTable(document.querySelector('section:last-of-type table'), tbody, rowsOf, { defaultKey: 'connected', defaultDir: 'desc' });
}

function sortPeers(peers, key, dir) {
  const mul = dir === 'asc' ? 1 : -1;
  const cmp = (a, b) => {
    switch (key) {
      case 'id': return mul * String(a.id || '').localeCompare(String(b.id || ''));
      case 'address': return mul * String(a.address || '').localeCompare(String(b.address || ''));
      case 'version': return mul * String(a.version || '').localeCompare(String(b.version || ''));
      case 'connected': return mul * ((a.connected_at || 0) - (b.connected_at || 0));
      default: return 0;
    }
  };
  return peers.slice().sort(cmp);
}

function buildRow(p) {
  const tr = document.createElement('tr');
  tr.appendChild(peerIdTd(p.id));
  tr.appendChild(td(p.address || '–'));
  tr.appendChild(td(p.version || '–'));
  tr.appendChild(td(p.connected_at ? relativeTime(p.connected_at) : '–'));
  return tr;
}

function peerIdTd(id) {
  const el = document.createElement('td');
  if (!id) { el.textContent = '–'; return el; }
  const code = document.createElement('code');
  code.textContent = shortHash(id, 16);
  code.title = id + ' (click to copy)';
  code.style.cursor = 'pointer';
  code.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(id);
      const original = code.textContent;
      code.textContent = 'copied';
      setTimeout(() => { code.textContent = original; }, 800);
    } catch {}
  });
  el.appendChild(code);
  return el;
}

function accountLinkInline(addr) {
  if (!addr) return text('–');
  const a = document.createElement('a');
  a.href = `/accounts/?addr=${encodeURIComponent(addr)}`;
  const code = document.createElement('code');
  code.textContent = addr;
  a.appendChild(code);
  return a;
}

function codeText(s) {
  const c = document.createElement('code');
  c.textContent = s;
  return c;
}

function text(s) {
  const span = document.createElement('span');
  span.textContent = s == null ? '–' : String(s);
  return span;
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
  el.textContent = msg;
  el.hidden = false;
  setStatus('error', 'err');
}

load();
setInterval(() => {
  if (document.visibilityState === 'hidden') return;
  load();
}, POLL_MS);
