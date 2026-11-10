const BASE = '/api';
const PAGE_LIMIT = 1000;

export function parseJsonLossless(text) {
  const safe = text.replace(
    /("(?:timestamp|pow_nonce|balance|amount|cost|stake|start_time|expires_at|locked_r|locked_payout_cap|locked_twap_milli)"\s*:\s*)(-?\d{16,})/g,
    '$1"$2"'
  );
  return JSON.parse(safe);
}

export async function api(path) {
  const res = await fetch(BASE + path);
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body && body.error) detail = body.error;
    } catch {}
    throw new Error(detail);
  }
  const text = await res.text();
  return parseJsonLossless(text);
}

export async function fetchAllPages(path) {
  const sep = path.includes('?') ? '&' : '?';
  let all = null;
  for (let offset = 0; ; offset += PAGE_LIMIT) {
    const page = await api(`${path}${sep}offset=${offset}&limit=${PAGE_LIMIT}`);
    if (Array.isArray(page)) {
      all = all || [];
      all.push(...page);
      if (page.length < PAGE_LIMIT) return all;
    } else if (page && typeof page === 'object') {
      all = all || {};
      Object.assign(all, page);
      if (Object.keys(page).length < PAGE_LIMIT) return all;
    } else {
      return all;
    }
  }
}

export async function fetchChainTail(addr, count) {
  const base = `/accounts/${encodeURIComponent(addr)}/chain`;
  let data = await api(`${base}?limit=${count}`);
  const total = (data && data.total) || 0;
  if (total > count) {
    data = await api(`${base}?offset=${total - count}&limit=${count}`);
  }
  return { total, blocks: (data && data.blocks) || [] };
}
