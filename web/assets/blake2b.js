// Pure-JS BLAKE2b (RFC 7693), unkeyed, digest length 1-64 bytes.
//
// 64-bit words are represented as (lo, hi) 32-bit pairs — BigInt arithmetic
// is far too slow for the PoW hot loop, which calls this ~2M times per block
// solve. The compress() body keeps the 16-word work vector in local uint32
// variables and manually inlines the G mixing function (~1.5x faster in V8
// than Uint32Array state); the repetition is mechanical and machine-generated,
// and BLAKE2b is a frozen spec, so it never needs editing. Verified against
// RFC 7693 and Go golang.org/x/crypto/blake2b vectors.
//
// All scratch state is module-level and reused across calls; blake2b() is
// synchronous and completes before returning, so this is safe.

// IV: fractional parts of sqrt of first 8 primes, as (lo, hi) pairs.
const IV = new Uint32Array([
  0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85,
  0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a,
  0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c,
  0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19,
]);

// Message schedule with every index pre-doubled to address (lo, hi) pairs.
const SIGMA = new Uint8Array([
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
  11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
  7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
  9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
  2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
  12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
  13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
  6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
  10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
].map(x => x * 2));

const m = new Uint32Array(32); // message block, 16 words
const h = new Uint32Array(16); // chain state, 8 words
const block = new Uint8Array(128);

// One compression: 12 rounds of 8 G mixes (4 column steps then 4 diagonal
// steps). Each G block below is: a += b; a += mx; d = rotr64(d^a, 32);
// c += d; b = rotr64(b^c, 24); a += b; a += my; d = rotr64(d^a, 16);
// c += d; b = rotr64(b^c, 63). Rotations act on the 32-bit halves
// (rotr 32 = swap halves, rotr 63 = rotl 1). t is the byte counter as a
// JS number (inputs are < 2^53 bytes, and XOR truncates mod 2^32).
function compress(t, last) {
  let v0l = h[0] >>> 0, v0h = h[1] >>> 0;
  let v1l = h[2] >>> 0, v1h = h[3] >>> 0;
  let v2l = h[4] >>> 0, v2h = h[5] >>> 0;
  let v3l = h[6] >>> 0, v3h = h[7] >>> 0;
  let v4l = h[8] >>> 0, v4h = h[9] >>> 0;
  let v5l = h[10] >>> 0, v5h = h[11] >>> 0;
  let v6l = h[12] >>> 0, v6h = h[13] >>> 0;
  let v7l = h[14] >>> 0, v7h = h[15] >>> 0;
  let v8l = IV[0], v8h = IV[1];
  let v9l = IV[2], v9h = IV[3];
  let v10l = IV[4], v10h = IV[5];
  let v11l = IV[6], v11h = IV[7];
  let v12l = IV[8], v12h = IV[9];
  let v13l = IV[10], v13h = IV[11];
  let v14l = IV[12], v14h = IV[13];
  let v15l = IV[14], v15h = IV[15];
  v12l = (v12l ^ t) >>> 0;
  v12h = (v12h ^ (t / 0x100000000)) >>> 0;
  if (last) {
    v14l = (~v14l) >>> 0;
    v14h = (~v14h) >>> 0;
  }
  for (let i = 0; i < 32; i++) {
    const o = i * 4;
    m[i] = block[o] | (block[o + 1] << 8) | (block[o + 2] << 16) | (block[o + 3] << 24);
  }
  let o = 0, x0 = 0, x1 = 0, mi = 0, mx0 = 0, mx1 = 0, my0 = 0, my1 = 0;
  for (let r = 0; r < 12; r++) {
    const s = r * 16;
    // G(v0, v4, v8, v12) with m[sigma[0]], m[sigma[1]]
    mi = SIGMA[s]; mx0 = m[mi]; mx1 = m[mi + 1]; mi = SIGMA[s + 1]; my0 = m[mi]; my1 = m[mi + 1];
    o = v0l + v4l; v0h = (v0h + v4h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v0l = o >>> 0;
    o = v0l + mx0; v0h = (v0h + mx1 + (o >= 0x100000000 ? 1 : 0)) >>> 0; v0l = o >>> 0;
    x0 = v12l ^ v0l; x1 = v12h ^ v0h; v12l = x1 >>> 0; v12h = x0 >>> 0;
    o = v8l + v12l; v8h = (v8h + v12h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v8l = o >>> 0;
    x0 = v4l ^ v8l; x1 = v4h ^ v8h;
    v4l = ((x0 >>> 24) ^ (x1 << 8)) >>> 0; v4h = ((x1 >>> 24) ^ (x0 << 8)) >>> 0;
    o = v0l + v4l; v0h = (v0h + v4h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v0l = o >>> 0;
    o = v0l + my0; v0h = (v0h + my1 + (o >= 0x100000000 ? 1 : 0)) >>> 0; v0l = o >>> 0;
    x0 = v12l ^ v0l; x1 = v12h ^ v0h;
    v12l = ((x0 >>> 16) ^ (x1 << 16)) >>> 0; v12h = ((x1 >>> 16) ^ (x0 << 16)) >>> 0;
    o = v8l + v12l; v8h = (v8h + v12h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v8l = o >>> 0;
    x0 = v4l ^ v8l; x1 = v4h ^ v8h;
    v4l = ((x1 >>> 31) ^ (x0 << 1)) >>> 0; v4h = ((x0 >>> 31) ^ (x1 << 1)) >>> 0;
    // G(v1, v5, v9, v13) with m[sigma[2]], m[sigma[3]]
    mi = SIGMA[s + 2]; mx0 = m[mi]; mx1 = m[mi + 1]; mi = SIGMA[s + 3]; my0 = m[mi]; my1 = m[mi + 1];
    o = v1l + v5l; v1h = (v1h + v5h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v1l = o >>> 0;
    o = v1l + mx0; v1h = (v1h + mx1 + (o >= 0x100000000 ? 1 : 0)) >>> 0; v1l = o >>> 0;
    x0 = v13l ^ v1l; x1 = v13h ^ v1h; v13l = x1 >>> 0; v13h = x0 >>> 0;
    o = v9l + v13l; v9h = (v9h + v13h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v9l = o >>> 0;
    x0 = v5l ^ v9l; x1 = v5h ^ v9h;
    v5l = ((x0 >>> 24) ^ (x1 << 8)) >>> 0; v5h = ((x1 >>> 24) ^ (x0 << 8)) >>> 0;
    o = v1l + v5l; v1h = (v1h + v5h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v1l = o >>> 0;
    o = v1l + my0; v1h = (v1h + my1 + (o >= 0x100000000 ? 1 : 0)) >>> 0; v1l = o >>> 0;
    x0 = v13l ^ v1l; x1 = v13h ^ v1h;
    v13l = ((x0 >>> 16) ^ (x1 << 16)) >>> 0; v13h = ((x1 >>> 16) ^ (x0 << 16)) >>> 0;
    o = v9l + v13l; v9h = (v9h + v13h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v9l = o >>> 0;
    x0 = v5l ^ v9l; x1 = v5h ^ v9h;
    v5l = ((x1 >>> 31) ^ (x0 << 1)) >>> 0; v5h = ((x0 >>> 31) ^ (x1 << 1)) >>> 0;
    // G(v2, v6, v10, v14) with m[sigma[4]], m[sigma[5]]
    mi = SIGMA[s + 4]; mx0 = m[mi]; mx1 = m[mi + 1]; mi = SIGMA[s + 5]; my0 = m[mi]; my1 = m[mi + 1];
    o = v2l + v6l; v2h = (v2h + v6h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v2l = o >>> 0;
    o = v2l + mx0; v2h = (v2h + mx1 + (o >= 0x100000000 ? 1 : 0)) >>> 0; v2l = o >>> 0;
    x0 = v14l ^ v2l; x1 = v14h ^ v2h; v14l = x1 >>> 0; v14h = x0 >>> 0;
    o = v10l + v14l; v10h = (v10h + v14h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v10l = o >>> 0;
    x0 = v6l ^ v10l; x1 = v6h ^ v10h;
    v6l = ((x0 >>> 24) ^ (x1 << 8)) >>> 0; v6h = ((x1 >>> 24) ^ (x0 << 8)) >>> 0;
    o = v2l + v6l; v2h = (v2h + v6h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v2l = o >>> 0;
    o = v2l + my0; v2h = (v2h + my1 + (o >= 0x100000000 ? 1 : 0)) >>> 0; v2l = o >>> 0;
    x0 = v14l ^ v2l; x1 = v14h ^ v2h;
    v14l = ((x0 >>> 16) ^ (x1 << 16)) >>> 0; v14h = ((x1 >>> 16) ^ (x0 << 16)) >>> 0;
    o = v10l + v14l; v10h = (v10h + v14h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v10l = o >>> 0;
    x0 = v6l ^ v10l; x1 = v6h ^ v10h;
    v6l = ((x1 >>> 31) ^ (x0 << 1)) >>> 0; v6h = ((x0 >>> 31) ^ (x1 << 1)) >>> 0;
    // G(v3, v7, v11, v15) with m[sigma[6]], m[sigma[7]]
    mi = SIGMA[s + 6]; mx0 = m[mi]; mx1 = m[mi + 1]; mi = SIGMA[s + 7]; my0 = m[mi]; my1 = m[mi + 1];
    o = v3l + v7l; v3h = (v3h + v7h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v3l = o >>> 0;
    o = v3l + mx0; v3h = (v3h + mx1 + (o >= 0x100000000 ? 1 : 0)) >>> 0; v3l = o >>> 0;
    x0 = v15l ^ v3l; x1 = v15h ^ v3h; v15l = x1 >>> 0; v15h = x0 >>> 0;
    o = v11l + v15l; v11h = (v11h + v15h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v11l = o >>> 0;
    x0 = v7l ^ v11l; x1 = v7h ^ v11h;
    v7l = ((x0 >>> 24) ^ (x1 << 8)) >>> 0; v7h = ((x1 >>> 24) ^ (x0 << 8)) >>> 0;
    o = v3l + v7l; v3h = (v3h + v7h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v3l = o >>> 0;
    o = v3l + my0; v3h = (v3h + my1 + (o >= 0x100000000 ? 1 : 0)) >>> 0; v3l = o >>> 0;
    x0 = v15l ^ v3l; x1 = v15h ^ v3h;
    v15l = ((x0 >>> 16) ^ (x1 << 16)) >>> 0; v15h = ((x1 >>> 16) ^ (x0 << 16)) >>> 0;
    o = v11l + v15l; v11h = (v11h + v15h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v11l = o >>> 0;
    x0 = v7l ^ v11l; x1 = v7h ^ v11h;
    v7l = ((x1 >>> 31) ^ (x0 << 1)) >>> 0; v7h = ((x0 >>> 31) ^ (x1 << 1)) >>> 0;
    // G(v0, v5, v10, v15) with m[sigma[8]], m[sigma[9]]
    mi = SIGMA[s + 8]; mx0 = m[mi]; mx1 = m[mi + 1]; mi = SIGMA[s + 9]; my0 = m[mi]; my1 = m[mi + 1];
    o = v0l + v5l; v0h = (v0h + v5h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v0l = o >>> 0;
    o = v0l + mx0; v0h = (v0h + mx1 + (o >= 0x100000000 ? 1 : 0)) >>> 0; v0l = o >>> 0;
    x0 = v15l ^ v0l; x1 = v15h ^ v0h; v15l = x1 >>> 0; v15h = x0 >>> 0;
    o = v10l + v15l; v10h = (v10h + v15h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v10l = o >>> 0;
    x0 = v5l ^ v10l; x1 = v5h ^ v10h;
    v5l = ((x0 >>> 24) ^ (x1 << 8)) >>> 0; v5h = ((x1 >>> 24) ^ (x0 << 8)) >>> 0;
    o = v0l + v5l; v0h = (v0h + v5h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v0l = o >>> 0;
    o = v0l + my0; v0h = (v0h + my1 + (o >= 0x100000000 ? 1 : 0)) >>> 0; v0l = o >>> 0;
    x0 = v15l ^ v0l; x1 = v15h ^ v0h;
    v15l = ((x0 >>> 16) ^ (x1 << 16)) >>> 0; v15h = ((x1 >>> 16) ^ (x0 << 16)) >>> 0;
    o = v10l + v15l; v10h = (v10h + v15h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v10l = o >>> 0;
    x0 = v5l ^ v10l; x1 = v5h ^ v10h;
    v5l = ((x1 >>> 31) ^ (x0 << 1)) >>> 0; v5h = ((x0 >>> 31) ^ (x1 << 1)) >>> 0;
    // G(v1, v6, v11, v12) with m[sigma[10]], m[sigma[11]]
    mi = SIGMA[s + 10]; mx0 = m[mi]; mx1 = m[mi + 1]; mi = SIGMA[s + 11]; my0 = m[mi]; my1 = m[mi + 1];
    o = v1l + v6l; v1h = (v1h + v6h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v1l = o >>> 0;
    o = v1l + mx0; v1h = (v1h + mx1 + (o >= 0x100000000 ? 1 : 0)) >>> 0; v1l = o >>> 0;
    x0 = v12l ^ v1l; x1 = v12h ^ v1h; v12l = x1 >>> 0; v12h = x0 >>> 0;
    o = v11l + v12l; v11h = (v11h + v12h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v11l = o >>> 0;
    x0 = v6l ^ v11l; x1 = v6h ^ v11h;
    v6l = ((x0 >>> 24) ^ (x1 << 8)) >>> 0; v6h = ((x1 >>> 24) ^ (x0 << 8)) >>> 0;
    o = v1l + v6l; v1h = (v1h + v6h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v1l = o >>> 0;
    o = v1l + my0; v1h = (v1h + my1 + (o >= 0x100000000 ? 1 : 0)) >>> 0; v1l = o >>> 0;
    x0 = v12l ^ v1l; x1 = v12h ^ v1h;
    v12l = ((x0 >>> 16) ^ (x1 << 16)) >>> 0; v12h = ((x1 >>> 16) ^ (x0 << 16)) >>> 0;
    o = v11l + v12l; v11h = (v11h + v12h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v11l = o >>> 0;
    x0 = v6l ^ v11l; x1 = v6h ^ v11h;
    v6l = ((x1 >>> 31) ^ (x0 << 1)) >>> 0; v6h = ((x0 >>> 31) ^ (x1 << 1)) >>> 0;
    // G(v2, v7, v8, v13) with m[sigma[12]], m[sigma[13]]
    mi = SIGMA[s + 12]; mx0 = m[mi]; mx1 = m[mi + 1]; mi = SIGMA[s + 13]; my0 = m[mi]; my1 = m[mi + 1];
    o = v2l + v7l; v2h = (v2h + v7h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v2l = o >>> 0;
    o = v2l + mx0; v2h = (v2h + mx1 + (o >= 0x100000000 ? 1 : 0)) >>> 0; v2l = o >>> 0;
    x0 = v13l ^ v2l; x1 = v13h ^ v2h; v13l = x1 >>> 0; v13h = x0 >>> 0;
    o = v8l + v13l; v8h = (v8h + v13h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v8l = o >>> 0;
    x0 = v7l ^ v8l; x1 = v7h ^ v8h;
    v7l = ((x0 >>> 24) ^ (x1 << 8)) >>> 0; v7h = ((x1 >>> 24) ^ (x0 << 8)) >>> 0;
    o = v2l + v7l; v2h = (v2h + v7h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v2l = o >>> 0;
    o = v2l + my0; v2h = (v2h + my1 + (o >= 0x100000000 ? 1 : 0)) >>> 0; v2l = o >>> 0;
    x0 = v13l ^ v2l; x1 = v13h ^ v2h;
    v13l = ((x0 >>> 16) ^ (x1 << 16)) >>> 0; v13h = ((x1 >>> 16) ^ (x0 << 16)) >>> 0;
    o = v8l + v13l; v8h = (v8h + v13h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v8l = o >>> 0;
    x0 = v7l ^ v8l; x1 = v7h ^ v8h;
    v7l = ((x1 >>> 31) ^ (x0 << 1)) >>> 0; v7h = ((x0 >>> 31) ^ (x1 << 1)) >>> 0;
    // G(v3, v4, v9, v14) with m[sigma[14]], m[sigma[15]]
    mi = SIGMA[s + 14]; mx0 = m[mi]; mx1 = m[mi + 1]; mi = SIGMA[s + 15]; my0 = m[mi]; my1 = m[mi + 1];
    o = v3l + v4l; v3h = (v3h + v4h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v3l = o >>> 0;
    o = v3l + mx0; v3h = (v3h + mx1 + (o >= 0x100000000 ? 1 : 0)) >>> 0; v3l = o >>> 0;
    x0 = v14l ^ v3l; x1 = v14h ^ v3h; v14l = x1 >>> 0; v14h = x0 >>> 0;
    o = v9l + v14l; v9h = (v9h + v14h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v9l = o >>> 0;
    x0 = v4l ^ v9l; x1 = v4h ^ v9h;
    v4l = ((x0 >>> 24) ^ (x1 << 8)) >>> 0; v4h = ((x1 >>> 24) ^ (x0 << 8)) >>> 0;
    o = v3l + v4l; v3h = (v3h + v4h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v3l = o >>> 0;
    o = v3l + my0; v3h = (v3h + my1 + (o >= 0x100000000 ? 1 : 0)) >>> 0; v3l = o >>> 0;
    x0 = v14l ^ v3l; x1 = v14h ^ v3h;
    v14l = ((x0 >>> 16) ^ (x1 << 16)) >>> 0; v14h = ((x1 >>> 16) ^ (x0 << 16)) >>> 0;
    o = v9l + v14l; v9h = (v9h + v14h + (o >= 0x100000000 ? 1 : 0)) >>> 0; v9l = o >>> 0;
    x0 = v4l ^ v9l; x1 = v4h ^ v9h;
    v4l = ((x1 >>> 31) ^ (x0 << 1)) >>> 0; v4h = ((x0 >>> 31) ^ (x1 << 1)) >>> 0;
  }
  h[0] ^= v0l ^ v8l; h[1] ^= v0h ^ v8h;
  h[2] ^= v1l ^ v9l; h[3] ^= v1h ^ v9h;
  h[4] ^= v2l ^ v10l; h[5] ^= v2h ^ v10h;
  h[6] ^= v3l ^ v11l; h[7] ^= v3h ^ v11h;
  h[8] ^= v4l ^ v12l; h[9] ^= v4h ^ v12h;
  h[10] ^= v5l ^ v13l; h[11] ^= v5h ^ v13h;
  h[12] ^= v6l ^ v14l; h[13] ^= v6h ^ v14h;
  h[14] ^= v7l ^ v15l; h[15] ^= v7h ^ v15h;
}

// blake2b hashes input (Uint8Array) to an outlen-byte digest (1-64).
// Pass a preallocated `out` of exactly outlen bytes to avoid the per-call
// allocation in hot loops; otherwise a fresh Uint8Array is returned.
export function blake2b(input, outlen, out) {
  if (!(input instanceof Uint8Array)) throw new TypeError('blake2b: input must be Uint8Array');
  if (!Number.isInteger(outlen) || outlen < 1 || outlen > 64) {
    throw new Error('blake2b: outlen must be 1-64');
  }
  h.set(IV);
  h[0] ^= 0x01010000 ^ outlen; // param block: digest length, fanout 1, depth 1

  let t = 0; // bytes compressed so far
  let c = 0; // fill level of block buffer
  let i = 0;
  const n = input.length;
  // Compress only while more input remains: the final block is flagged below.
  while (n - i > 128 - c) {
    const take = 128 - c;
    block.set(input.subarray(i, i + take), c);
    i += take;
    t += 128;
    compress(t, false);
    c = 0;
  }
  block.set(input.subarray(i), c);
  c += n - i;

  t += c;
  block.fill(0, c);
  compress(t, true);

  const digest = out !== undefined ? out : new Uint8Array(outlen);
  for (let j = 0; j < outlen; j++) {
    digest[j] = h[j >> 2] >>> (8 * (j & 3)); // little-endian word serialization
  }
  return digest;
}
