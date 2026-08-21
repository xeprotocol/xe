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

// Block timestamps are unix nanoseconds.
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

// ---- Amount formatting (XE / XUSD micro-units) ----
//
// On-chain amounts — balances, send amounts, lease cost/stake, pending sends —
// are uint64 micro-units: one whole token = 10^decimals micro-units. These two
// helpers mirror core/amount.go (FormatAmount / ParseAmount) so the UI renders
// and accepts exactly the decimal strings the node and CLI use. The 2^53 / 10⁶
// safe-integer ceiling (~9B tokens) sits comfortably above realistic supply, so
// plain Number arithmetic stays exact across every on-chain amount.

const ASSET_DECIMALS = { XE: 6, XUSD: 6 };
const DEFAULT_DECIMALS = 6;

export function assetDecimals(asset) {
  const d = ASSET_DECIMALS[asset];
  return d == null ? DEFAULT_DECIMALS : d;
}

// formatAmount renders micro-units as a human decimal string: the integer part
// is grouped with thousands separators, trailing-zero fractional digits are
// trimmed, and the decimal point is dropped for whole-token amounts. Mirrors
// core.FormatAmount for the fractional part. null / NaN / negative → '–'.
//
//   formatAmount(1_234_567,   'XE')   → '1.234567'
//   formatAmount(1_230_000,   'XE')   → '1.23'
//   formatAmount(100_000_000, 'XUSD') → '100'
//   formatAmount(1,           'XE')   → '0.000001'
//   formatAmount(0,           'XE')   → '0'
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

// ---- Milli-scale formatting (×1000 fixed-point) ----
//
// Some API fields are uint64 fixed-point at ×1000, NOT micro-units, and must
// not go through formatAmount: emission-lock economics (locked_r,
// locked_payout_cap — #401), certificate price multipliers
// (price_multiplier_milli), and milli-USD prices (locked_twap_milli).

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

// parseAmount converts a decimal token string into micro-units (a Number) using
// the asset's precision. Mirrors core.ParseAmount: rejects a sign, whitespace,
// thousands separators, scientific notation, or more than `decimals` fractional
// digits — no silent truncation. Throws on invalid input; callers trim
// surrounding whitespace first.
//
//   parseAmount('1',        'XE') → 1_000_000
//   parseAmount('1.234567', 'XE') → 1_234_567
//   parseAmount('0.000001', 'XE') → 1
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
