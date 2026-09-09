export function shortAddr(s, n = 8) {
  if (!s) return '';
  return s.length > 2 * n + 1 ? `${s.slice(0, n)}…${s.slice(-n)}` : s;
}

export function shortHash(s, n = 12) {
  if (!s) return '';
  return s.length > n + 1 ? `${s.slice(0, n)}…` : s;
}

export function commas(n) {
  if (n == null || Number.isNaN(n)) return '–';
  return Number(n).toLocaleString('en-US');
}

export function timeOfDay(tsNs) {
  if (!tsNs) return '–';
  const d = new Date(Math.floor(tsNs / 1e6));
  return d.toLocaleTimeString('en-GB', { hour12: false });
}

export function relativeTime(tsNs) {
  if (!tsNs) return '–';
  const ms = Math.floor(tsNs / 1e6);
  const ago = Date.now() - ms;
  if (ago < 1000) return 'just now';
  if (ago < 60_000) return `${Math.floor(ago / 1000)}s ago`;
  if (ago < 3_600_000) return `${Math.floor(ago / 60_000)}m ago`;
  if (ago < 86_400_000) return `${Math.floor(ago / 3_600_000)}h ago`;
  return `${Math.floor(ago / 86_400_000)}d ago`;
}

export function durationString(secs) {
  const s = Math.max(0, Math.floor(Number(secs) || 0));
  if (s < 60)    return `${s}s`;
  if (s < 3600)  return `${Math.floor(s / 60)}m ${s % 60}s`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`;
}

const ASSET_DECIMALS = { XE: 6, XUSD: 6 };
const DEFAULT_DECIMALS = 6;

export function assetDecimals(asset) {
  const d = ASSET_DECIMALS[asset];
  return d == null ? DEFAULT_DECIMALS : d;
}

export function formatAmount(micro, asset = 'XE') {
  if (micro == null) return '–';
  const n = Number(micro);
  if (!Number.isFinite(n) || n < 0) return '–';
  const dec = assetDecimals(asset);
  const unit = 10 ** dec;
  const frac = n % unit;
  const whole = (n - frac) / unit;
  const wholeStr = whole.toLocaleString('en-US');
  if (frac === 0) return wholeStr;
  const fracStr = String(frac).padStart(dec, '0').replace(/0+$/, '');
  return `${wholeStr}.${fracStr}`;
}

export function formatMilli(v) {
  if (v == null) return '–';
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0) return '–';
  return (n / 1000).toFixed(3);
}

export function formatMilliUSD(v) {
  const s = formatMilli(v);
  return s === '–' ? s : '$' + s;
}

export function parseAmount(str, asset = 'XE') {
  const dec = assetDecimals(asset);
  const s = String(str);
  if (s === '') throw new Error('amount must be a non-negative decimal');
  if (s[0] === '-') throw new Error('amount must be non-negative');
  if (s[0] === '+') throw new Error('amount must be a non-negative decimal');

  let whole = s, frac = '', hasDot = false;
  const dot = s.indexOf('.');
  if (dot >= 0) {
    whole = s.slice(0, dot);
    frac = s.slice(dot + 1);
    hasDot = true;
    if (whole === '') throw new Error('amount must be a non-negative decimal');
  }
  if (hasDot && frac === '') throw new Error('amount must be a non-negative decimal');
  if (frac.length > dec) throw new Error(`amount exceeds ${asset} precision (max ${dec} decimals)`);
  if (!/^[0-9]+$/.test(whole) || (frac !== '' && !/^[0-9]+$/.test(frac))) {
    throw new Error('amount must be a non-negative decimal');
  }

  const unit = 10 ** dec;
  const wholeVal = Number(whole);
  const fracVal = frac === '' ? 0 : Number(frac.padEnd(dec, '0'));
  const total = wholeVal * unit + fracVal;
  if (!Number.isSafeInteger(total)) throw new Error('amount overflows micro-units');
  return total;
}
