import { api, fetchAllPages } from './api.js';
import { shortHash, timeOfDay, relativeTime, commas } from './format.js';

const RECENT_BLOCKS = 20;
const RECENT_EPOCHS = 20;

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
  const idx = params.get('index');
  if (idx != null && idx !== '') {
    document.title = `state-chain block ${idx} · xe`;
    setText('page-title', `statechain · block ${idx}`);
    document.getElementById('overview-section').hidden = true;
    document.getElementById('detail-section').hidden = false;
    await loadDetail(idx);
  } else {
    await loadOverview();
  }
}

async function loadOverview() {
  let tip;
  try {
    tip = await api('/statechain/tip');
  } catch (e) {
    showError('tip: ' + e.message);
    return;
  }
  renderTip(tip);

  const tipIndex = Number(tip.index || 0);
  const start = Math.max(0, tipIndex - (RECENT_BLOCKS - 1));
  let blocks;
  try {
    blocks = await api(`/statechain/blocks?start=${start}&limit=${RECENT_BLOCKS}`);
  } catch (e) {
    showError('blocks: ' + e.message);
    return;
  }
  const list = (blocks && blocks.blocks) || [];
  list.sort((a, b) => (b.index || 0) - (a.index || 0));
  renderRecentBlocks(list);
  renderRecentEpochs(list);

  document.getElementById('kv-form').addEventListener('submit', onKvLookup);
  document.getElementById('kv-browse-form').addEventListener('submit', (e) => e.preventDefault());
  document.getElementById('kv-filter').addEventListener('input', renderKvBrowse);
  document.getElementById('kv-refresh').addEventListener('click', loadKvBrowse);
  await loadKvBrowse();
}

let kvAll = {};

async function loadKvBrowse() {
  const list = document.getElementById('kv-browse-list');
  list.innerHTML = '<dt class="muted">loading…</dt>';
  try {
    kvAll = (await fetchAllPages('/statechain/kv')) || {};
  } catch (e) {
    list.innerHTML = '';
    const dt = document.createElement('dt');
    dt.className = 'muted';
    dt.textContent = `error: ${e.message}`;
    list.appendChild(dt);
    return;
  }
  renderKvBrowse();
}

function renderKvBrowse() {
  const filter = (document.getElementById('kv-filter').value || '').trim().toLowerCase();
  const keys = Object.keys(kvAll).sort();
  const matched = filter ? keys.filter(k => k.toLowerCase().includes(filter)) : keys;
  setText('kv-browse-count', matched.length === keys.length
    ? `${keys.length}`
    : `${matched.length} of ${keys.length}`);

  const list = document.getElementById('kv-browse-list');
  list.innerHTML = '';
  if (keys.length === 0) {
    const dt = document.createElement('dt');
    dt.className = 'muted';
    dt.textContent = 'no kv entries';
    list.appendChild(dt);
    return;
  }
  if (matched.length === 0) {
    const dt = document.createElement('dt');
    dt.className = 'muted';
    dt.textContent = 'no matching keys';
    list.appendChild(dt);
    return;
  }
  for (const k of matched) {
    const dt = document.createElement('dt');
    const code = document.createElement('code');
    code.textContent = k;
    dt.appendChild(code);
    const dd = document.createElement('dd');
    const pre = document.createElement('pre');
    pre.className = 'inline';
    const v = kvAll[k];
    pre.textContent = typeof v === 'object' ? JSON.stringify(v, null, 2) : String(v);
    dd.appendChild(pre);
    list.appendChild(dt);
    list.appendChild(dd);
  }
}

function renderTip(tip) {
  const dl = document.getElementById('tip-kv');
  dl.innerHTML = '';
  appendRow(dl, 'index', text(commas(tip.index)));
  appendRow(dl, 'hash', codeText(tip.hash || '–'));
  appendRow(dl, 'timestamp', text(tip.timestamp ? `${timeOfDay(tip.timestamp)} · ${relativeTime(tip.timestamp)}` : '–'));
  appendRow(dl, 'ops', text(commas((tip.ops || []).length)));
  appendRow(dl, 'signatures', text(commas((tip.signatures || []).length)));
}

function renderRecentBlocks(list) {
  const tbody = document.getElementById('sc-blocks-tbody');
  tbody.innerHTML = '';
  if (list.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="muted">no blocks</td></tr>';
    return;
  }
  for (const b of list) {
    const tr = document.createElement('tr');
    tr.classList.add('linkrow');
    const idxTd = document.createElement('td');
    const idxA = document.createElement('a');
    idxA.href = `/statechain/?index=${encodeURIComponent(b.index)}`;
    idxA.textContent = String(b.index);
    idxTd.appendChild(idxA);
    tr.appendChild(idxTd);
    tr.appendChild(td(b.timestamp ? timeOfDay(b.timestamp) : '–'));
    tr.appendChild(td(commas((b.ops || []).length)));
    tr.appendChild(td(commas((b.signatures || []).length)));
    tr.appendChild(codeTd(b.hash));
    tr.style.cursor = 'pointer';
    tr.addEventListener('click', (e) => {
      if (e.target.closest('a')) return;
      location.href = `/statechain/?index=${encodeURIComponent(b.index)}`;
    });
    tbody.appendChild(tr);
  }
}

function renderRecentEpochs(blocks) {
  const tbody = document.getElementById('epochs-tbody');
  tbody.innerHTML = '';
  const epochs = [];
  for (const b of blocks) {
    for (const op of b.ops || []) {
      if (op.action !== 'set') continue;
      if (!op.key || !op.key.startsWith('epoch.')) continue;
      if (op.value && typeof op.value === 'object') {
        epochs.push(op.value);
      }
    }
  }
  epochs.sort((a, b) => (b.epoch || 0) - (a.epoch || 0));
  const recent = epochs.slice(0, RECENT_EPOCHS);
  setText('epochs-count', recent.length ? `latest ${recent.length}` : '');
  if (recent.length === 0) {
    tbody.innerHTML = '<tr><td colspan="9" class="muted">no recent epochs in this window</td></tr>';
    return;
  }
  for (const e of recent) {
    const tr = document.createElement('tr');
    tr.appendChild(td(commas(e.epoch)));
    tr.appendChild(td(commas(e.phase)));
    tr.appendChild(td(commas(e.twap_milli_usd)));
    tr.appendChild(td(commas(e.twav_milli_usd)));
    tr.appendChild(td(commas(e.r_volume)));
    tr.appendChild(td(commas(e.r_price_floor)));
    tr.appendChild(td(commas(e.r_effective)));
    tr.appendChild(td(e.r_source || '–'));
    tr.appendChild(td(`${timeOfDay(e.start_ns)} → ${timeOfDay(e.end_ns)}`));
    tbody.appendChild(tr);
  }
}

async function onKvLookup(ev) {
  ev.preventDefault();
  const key = document.getElementById('kv-key').value.trim();
  const out = document.getElementById('kv-result');
  out.hidden = false;
  if (!key) {
    out.textContent = '(enter a key)';
    return;
  }
  out.textContent = 'loading…';
  try {
    const data = await api(`/statechain/kv/${encodeURIComponent(key).replace(/%2F/g, '/')}`);
    out.textContent = JSON.stringify(data, null, 2);
  } catch (e) {
    if (e.message === 'key not found') {
      try {
        const matches = await fetchAllPages(`/statechain/kv?prefix=${encodeURIComponent(key)}`);
        if (matches && Object.keys(matches).length > 0) {
          out.textContent = JSON.stringify(matches, null, 2);
          return;
        }
      } catch (e2) {
        out.textContent = `error: ${e2.message}`;
        return;
      }
    }
    out.textContent = `error: ${e.message}`;
  }
}

async function loadDetail(idx) {
  let block;
  try {
    block = await api(`/statechain/blocks/${encodeURIComponent(idx)}`);
  } catch (e) {
    showError(e.message);
    return;
  }

  const dl = document.getElementById('detail-kv');
  dl.innerHTML = '';
  appendRow(dl, 'index', text(commas(block.index)));
  appendRow(dl, 'hash', codeText(block.hash || '–'));
  appendRow(dl, 'previous',
    block.prev_hash && Number(block.index) > 0
      ? prevIndexLink(block.prev_hash, Number(block.index) - 1)
      : codeText(block.prev_hash || '–'));
  appendRow(dl, 'timestamp', text(block.timestamp ? `${timeOfDay(block.timestamp)} · ${relativeTime(block.timestamp)}` : '–'));

  const ops = document.getElementById('ops-tbody');
  ops.innerHTML = '';
  (block.ops || []).forEach((op, i) => {
    const tr = document.createElement('tr');
    tr.appendChild(td(String(i)));
    tr.appendChild(td(op.action || '–'));
    tr.appendChild(kvKeyTd(op.key));
    tr.appendChild(valueTd(op.value));
    ops.appendChild(tr);
  });

  const sigs = document.getElementById('sigs-tbody');
  sigs.innerHTML = '';
  (block.signatures || []).forEach(s => {
    const tr = document.createElement('tr');
    tr.appendChild(codeTd(s.public_key));
    tr.appendChild(codeTd(s.signature));
    sigs.appendChild(tr);
  });
}

function prevIndexLink(hash, prevIdx) {
  const a = document.createElement('a');
  a.href = `/statechain/?index=${encodeURIComponent(prevIdx)}`;
  const code = document.createElement('code');
  code.textContent = shortHash(hash);
  a.appendChild(code);
  a.title = hash;
  return a;
}

function kvKeyTd(key) {
  const td = document.createElement('td');
  if (!key) { td.textContent = '–'; return td; }
  const code = document.createElement('code');
  code.textContent = key;
  td.appendChild(code);
  return td;
}

function valueTd(value) {
  const td = document.createElement('td');
  if (value == null) { td.textContent = 'null'; return td; }
  const pre = document.createElement('pre');
  pre.className = 'inline';
  pre.textContent = typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value);
  td.appendChild(pre);
  return td;
}

function codeTd(s) {
  const td = document.createElement('td');
  if (!s) { td.textContent = '–'; return td; }
  const code = document.createElement('code');
  code.textContent = shortHash(s);
  code.title = s;
  td.appendChild(code);
  return td;
}

function codeText(s) {
  const c = document.createElement('code');
  c.textContent = s;
  return c;
}

function appendRow(dl, label, child) {
  const dt = document.createElement('dt');
  dt.textContent = label;
  const dd = document.createElement('dd');
  dd.appendChild(child);
  dl.appendChild(dt);
  dl.appendChild(dd);
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
