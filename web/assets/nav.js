import { api } from './api.js';

const HEX64 = /^[0-9a-fA-F]{64}$/;

const SECTIONS = {
  explorer: {
    label: 'explorer',
    home: '/',
    pages: [
      { label: 'overview',   href: '/' },
      { label: 'accounts',   href: '/accounts/' },
      { label: 'blocks',     href: '/blocks/' },
      { label: 'pending',    href: '/pending/' },
      { label: 'peers',      href: '/peers/' },
      { label: 'leases',     href: '/leases/' },
      { label: 'providers',  href: '/providers/' },
      { label: 'frontiers',  href: '/frontiers/' },
      { label: 'conflicts',  href: '/conflicts/' },
      { label: 'statechain', href: '/statechain/' },
    ],
  },
  wallet: {
    label: 'wallet',
    home: '/wallet/',
    pages: [
      { label: 'overview', href: '/wallet/' },
      { label: 'wallets',  href: '/wallet/wallets/' },
      { label: 'chat',     href: '/chat/' },
      { label: 'dao',      href: '/dao/',      gate: 'dao' },
      { label: 'provider', href: '/provider/', gate: 'provider' },
    ],
  },
};

const WALLET_PREFIXES = ['/wallet', '/dao', '/chat', '/provider'];

function activeSection(pathname) {
  return WALLET_PREFIXES.some((p) => pathname === p || pathname.startsWith(p + '/'))
    ? 'wallet' : 'explorer';
}

function isActivePage(pathname, href) {
  if (href === '/') return pathname === '/';
  return pathname === href || pathname.startsWith(href);
}

function resolveActivePage(pathname, pages) {
  let best = null;
  for (const p of pages) {
    if (isActivePage(pathname, p.href)) {
      if (!best || p.href.length > best.href.length) best = p;
    }
  }
  return best;
}

function buildHeader(section, walletEnabled) {
  const header = document.getElementById('xe-header');
  if (!header) return;
  header.innerHTML = '';

  const brand = document.createElement('div');
  brand.className = 'brand';
  const home = document.createElement('a');
  home.className = 'home';
  home.href = '/';
  const h1 = document.createElement('h1');
  h1.textContent = 'xe';
  home.appendChild(h1);
  brand.appendChild(home);

  const primary = document.createElement('nav');
  primary.className = 'nav-primary';
  for (const id of Object.keys(SECTIONS)) {
    if (id === 'wallet' && !walletEnabled) continue;
    const tab = document.createElement('a');
    tab.className = 'nav-tab' + (id === section ? ' nav-tab-active' : '');
    tab.href = SECTIONS[id].home;
    tab.textContent = SECTIONS[id].label;
    primary.appendChild(tab);
  }

  const search = document.createElement('form');
  search.id = 'search-form';
  search.className = 'search';
  search.setAttribute('role', 'search');
  search.innerHTML = `
    <input id="search-input" type="text" placeholder="address or block hash" autocomplete="off" aria-label="search">
    <button type="submit">search</button>
  `;
  search.addEventListener('submit', onSearchSubmit);

  const meta = document.createElement('div');
  meta.className = 'meta';
  meta.innerHTML = `
    <span class="net" id="network">…</span>
    <span class="ver" id="version"></span>
    <span class="status" id="status">connecting…</span>
    <a class="manifest" href="/api/" target="_blank" rel="noopener">api</a>
  `;

  header.appendChild(brand);
  header.appendChild(primary);
  header.appendChild(search);
  header.appendChild(meta);
}

function buildSubnav(section, pathname, walletEnabled) {
  const sub = document.getElementById('xe-subnav');
  if (!sub) return;
  sub.innerHTML = '';

  if (section === 'wallet' && !walletEnabled) return;

  const pages = SECTIONS[section].pages;
  const active = resolveActivePage(pathname, pages);
  for (const p of pages) {
    const a = document.createElement('a');
    a.href = p.href;
    a.textContent = p.label;
    a.className = 'nav-link' + (active && p.href === active.href ? ' nav-link-active' : '');
    if (p.gate) {
      a.dataset.gate = p.gate;
      a.hidden = true;
    }
    sub.appendChild(a);
  }
}

async function onSearchSubmit(ev) {
  ev.preventDefault();
  const input = document.getElementById('search-input');
  if (!input) return;
  input.setCustomValidity('');
  const val = input.value.trim().toLowerCase();
  if (!val) return;
  if (!HEX64.test(val)) {
    searchNotFound(input, 'enter a 64-character account address or block hash');
    return;
  }
  input.disabled = true;
  let dest = null;
  if (await apiOrNull(`/blocks/${val}`)) {
    dest = `/blocks/?hash=${val}`;
  } else {
    const chain = await apiOrNull(`/accounts/${val}/chain`);
    if (chain && chain.total > 0) dest = `/accounts/?addr=${val}`;
  }
  input.disabled = false;
  if (dest) location.href = dest;
  else searchNotFound(input, 'no account or block found for that id');
}

async function apiOrNull(path) {
  try {
    return await api(path);
  } catch {
    return null;
  }
}

function searchNotFound(input, msg) {
  input.setCustomValidity(msg);
  input.reportValidity();
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

let nodeInFlight = null;
export async function refreshNode() {
  if (nodeInFlight) return nodeInFlight;
  nodeInFlight = (async () => {
    try {
      const node = await api('/node');
      setText('network', node.network_id || '(no network)');
      setText('version', node.version || '');
      setStatus('ok', 'ok');
      return node;
    } catch (e) {
      setStatus('node: ' + e.message, 'err');
      return null;
    } finally {
      nodeInFlight = null;
    }
  })();
  return nodeInFlight;
}

function vaultField(field) {
  try {
    const raw = localStorage.getItem('xe.wallets');
    if (!raw) return [];
    const v = JSON.parse(raw);
    if (!v || !Array.isArray(v.wallets)) return [];
    return v.wallets.map((w) => (w[field] || '').toLowerCase()).filter(Boolean);
  } catch { return []; }
}

async function refreshGates() {
  const addrs = vaultField('address');
  const pubKeys = vaultField('pub_key');
  if (addrs.length === 0 && pubKeys.length === 0) return;

  reveal('dao', async () => {
    if (pubKeys.length === 0) return false;
    const ks = await api('/statechain/keyset').catch(() => null);
    if (!ks || !Array.isArray(ks.keys)) return false;
    return ks.keys.some((k) => pubKeys.includes(String(k).toLowerCase()));
  });

  reveal('provider', async () => {
    if (addrs.length === 0) return false;
    const list = await api('/providers').catch(() => null);
    if (!Array.isArray(list)) return false;
    return list.some((p) => addrs.includes(String(p.account || '').toLowerCase()));
  });
}

async function reveal(gateName, check) {
  const link = document.querySelector(`#xe-subnav [data-gate="${gateName}"]`);
  if (!link) return;
  try {
    if (await check()) link.hidden = false;
  } catch {   }
}

async function init() {
  let walletEnabled = true;
  try {
    const f = await fetch('/features.json');
    if (f.ok) {
      const j = await f.json();
      walletEnabled = j.wallet !== false;
    }
  } catch {   }

  const section = activeSection(location.pathname);
  buildHeader(section, walletEnabled);
  buildSubnav(section, location.pathname, walletEnabled);

  await refreshNode();
  await refreshGates();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
