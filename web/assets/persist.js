// persist.js — small helpers for caching last-known values + rolling history
// in localStorage. Keys are namespaced under `xe.snap.<key>` (single value)
// and `xe.hist.<key>` (rolling buffer).
//
// Pages call loadSnapshot() synchronously on init to render cached values
// before the network fetch completes — eliminating the "–" flash. Each poll
// then updates the snapshot and appends to the history buffer.

const SNAP_PREFIX = 'xe.snap.';
const HIST_PREFIX = 'xe.hist.';

export function loadSnapshot(key) {
  try {
    const raw = localStorage.getItem(SNAP_PREFIX + key);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch { return null; }
}

export function saveSnapshot(key, value) {
  try {
    localStorage.setItem(SNAP_PREFIX + key, JSON.stringify({ ts: Date.now(), value }));
  } catch { /* quota or storage disabled — ignore */ }
}

export function loadHistory(key) {
  try {
    const raw = localStorage.getItem(HIST_PREFIX + key);
    if (!raw) return [];
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr : [];
  } catch { return []; }
}

// Append one sample {ts, ...metrics} to a rolling buffer; trim to `max` entries.
export function pushHistory(key, sample, max = 200) {
  const hist = loadHistory(key);
  hist.push(sample);
  while (hist.length > max) hist.shift();
  try {
    localStorage.setItem(HIST_PREFIX + key, JSON.stringify(hist));
  } catch { /* ignore */ }
  return hist;
}

// Format an age in seconds since timestamp ms.
export function ageString(ts) {
  if (!ts) return '';
  const ago = Date.now() - ts;
  if (ago < 1000) return 'just now';
  if (ago < 60_000) return `${Math.floor(ago / 1000)}s ago`;
  if (ago < 3_600_000) return `${Math.floor(ago / 60_000)}m ago`;
  if (ago < 86_400_000) return `${Math.floor(ago / 3_600_000)}h ago`;
  return `${Math.floor(ago / 86_400_000)}d ago`;
}
