import { api, fetchAllPages } from './api.js';
import { shortAddr, shortHash, formatAmount } from './format.js';

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
  let conflicts;
  try {
    conflicts = await fetchAllPages('/conflicts');
  } catch (e) {
    showError(e.message);
    return;
  }

  const list = conflicts || [];
  setText('count', `${list.length}`);
  const host = document.getElementById('list');
  host.innerHTML = '';
  if (list.length === 0) {
    const p = document.createElement('p');
    p.className = 'muted';
    p.textContent = 'no open conflicts';
    host.appendChild(p);
    return;
  }

  list.sort((a, b) => new Date(b.detected_at).getTime() - new Date(a.detected_at).getTime());

  for (const c of list) {
    host.appendChild(renderConflict(c));
  }
}

function renderConflict(c) {
  const dl = document.createElement('dl');
  dl.className = 'kv conflict';

  appendRow(dl, 'account', accountLink(c.account_address));
  appendRow(dl, 'previous', blockLink(c.previous_hash));
  appendRow(dl, 'detected at', text(c.detected_at ? new Date(c.detected_at).toLocaleString() : '–'));

  if (c.total_weight != null) {
    appendRow(dl, 'total weight', text(`${formatAmount(c.total_weight, 'XE')} XE`));
  }

  const hashesEl = document.createElement('div');
  for (const h of c.block_hashes || []) {
    const a = document.createElement('a');
    a.href = `/blocks/?hash=${encodeURIComponent(h)}`;
    const code = document.createElement('code');
    code.textContent = shortHash(h);
    a.appendChild(code);
    a.title = h;
    a.style.display = 'block';
    hashesEl.appendChild(a);
  }
  appendRow(dl, 'competing blocks', hashesEl);

  // weight_snapshot is keyed by representative address (not block hash) —
  // per-rep voting weight in micro-XE at conflict-detection time.
  const reps = Object.entries(c.weight_snapshot || {});
  if (reps.length > 0) {
    const repsEl = document.createElement('div');
    for (const [rep, weight] of reps.sort((a, b) => b[1] - a[1])) {
      const line = document.createElement('div');
      line.appendChild(accountLink(rep));
      const note = document.createElement('span');
      note.className = 'muted';
      note.textContent = ` ${formatAmount(weight, 'XE')} XE`;
      line.appendChild(note);
      repsEl.appendChild(line);
    }
    appendRow(dl, 'rep weights', repsEl);
  }

  const wrap = document.createElement('div');
  wrap.className = 'conflict-wrap';
  wrap.appendChild(dl);
  return wrap;
}

function appendRow(dl, label, child) {
  const dt = document.createElement('dt');
  dt.textContent = label;
  const dd = document.createElement('dd');
  dd.appendChild(child);
  dl.appendChild(dt);
  dl.appendChild(dd);
}

function accountLink(addr) {
  if (!addr) return text('–');
  const a = document.createElement('a');
  a.href = `/accounts/?addr=${encodeURIComponent(addr)}`;
  const code = document.createElement('code');
  code.textContent = shortAddr(addr);
  a.appendChild(code);
  a.title = addr;
  return a;
}

function blockLink(hash) {
  if (!hash) return text('–');
  const a = document.createElement('a');
  a.href = `/blocks/?hash=${encodeURIComponent(hash)}`;
  const code = document.createElement('code');
  code.textContent = shortHash(hash);
  a.appendChild(code);
  a.title = hash;
  return a;
}

function text(s) {
  const span = document.createElement('span');
  span.textContent = s == null ? '–' : String(s);
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
