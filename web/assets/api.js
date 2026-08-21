const BASE = '/api';
const PAGE_LIMIT = 1000;

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
  return res.json();
}

// fetchAllPages pages through a windowed list endpoint (#627), requesting
// maximum-size pages until a short page signals the end. Array endpoints
// concatenate pages; map endpoints (e.g. /statechain/kv) merge keys.
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

// fetchChainTail returns an account chain's full length and its last `count`
// blocks. /accounts/{address}/chain windows to 100 blocks by default (#627),
// so the first request reads the total and a second request addresses the
// final window when the chain is longer than `count`. The last block of the
// returned tail is always the account's frontier.
export async function fetchChainTail(addr, count) {
  const base = `/accounts/${encodeURIComponent(addr)}/chain`;
  let data = await api(`${base}?limit=${count}`);
  const total = (data && data.total) || 0;
  if (total > count) {
    data = await api(`${base}?offset=${total - count}&limit=${count}`);
  }
  return { total, blocks: (data && data.blocks) || [] };
}
