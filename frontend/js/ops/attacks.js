// Cryptanalysis: recover a key without being given it. An attack never becomes a chain step itself;
// it proposes keyed steps (e.g. "Vigenère, key TELEGRAPH") that the user can add.

import { latin1, utf8 } from '../core/bytes.js';
import { englishFitness, letterCounts, chiSquared, indexOfCoincidence, flagRegex } from '../core/score.js';
import { caesar, vigenere, xorBytes } from './classical.js';
import { toHex } from '../core/bytes.js';

const AFFINE_A = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25];

function judge(output, ctx) {
  const text = latin1(output);
  const flag = (text.match(flagRegex(ctx.flagPrefix)) || [null])[0];
  return { flag, score: flag ? 1 : englishFitness(output) };
}

const SAMPLE = 4096; // bytes used to rank keys; full outputs are built only for the best candidates
const KEEP = 60;

function rank(cands) {
  return cands.sort((a, b) => b.score - a.score);
}

/** Ranks keys on a sample, then recomputes the top candidates on the full data. */
function rankSampled(bytes, cands, full, ctx) {
  rank(cands);
  const top = cands.slice(0, KEEP);
  if (bytes.length > SAMPLE) {
    for (const c of top) {
      c.output = full(c);
      const j = judge(c.output, ctx);
      if (j.flag) {
        c.flag = j.flag;
        c.score = 1;
      }
    }
    rank(top);
  }
  return top;
}

/* ---------- Brute force: small key spaces ---------- */
function caesarBrute(bytes, ctx) {
  const sample = bytes.subarray(0, SAMPLE);
  const cands = [];
  for (let s = 1; s < 26; s++) {
    const output = caesar(sample, s);
    cands.push({ opId: 'caesar', params: { shift: s }, output, ...judge(output, ctx), label: s === 13 ? 'shift 13 (ROT13)' : `shift ${s}` });
  }
  return { summary: 'Tried all 25 shifts and ranked them by English fitness.', candidates: rankSampled(bytes, cands, (c) => caesar(bytes, c.params.shift), ctx) };
}

function affineDecrypt(bytes, a, b) {
  let inv = 1;
  for (let x = 1; x < 26; x++) if ((a * x) % 26 === 1) inv = x;
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    const c = bytes[i];
    if (c >= 65 && c <= 90) out[i] = 65 + ((((inv * (c - 65 - b)) % 26) + 26) % 26);
    else if (c >= 97 && c <= 122) out[i] = 97 + ((((inv * (c - 97 - b)) % 26) + 26) % 26);
    else out[i] = c;
  }
  return out;
}

function affineBrute(full, ctx) {
  const bytes = full.subarray(0, SAMPLE);
  const cands = [];
  for (const a of AFFINE_A) {
    let inv = 1;
    for (let x = 1; x < 26; x++) if ((a * x) % 26 === 1) inv = x;
    for (let b = 0; b < 26; b++) {
      if (a === 1 && b === 0) continue;
      const out = new Uint8Array(bytes.length);
      for (let i = 0; i < bytes.length; i++) {
        const c = bytes[i];
        if (c >= 65 && c <= 90) out[i] = 65 + ((((inv * (c - 65 - b)) % 26) + 26) % 26);
        else if (c >= 97 && c <= 122) out[i] = 97 + ((((inv * (c - 97 - b)) % 26) + 26) % 26);
        else out[i] = c;
      }
      cands.push({ opId: 'affine', params: { a: String(a), b }, output: out, ...judge(out, ctx), label: `a = ${a}, b = ${b}` });
    }
  }
  return { summary: 'Tried all 311 non-trivial affine keys.', candidates: rankSampled(full, cands, (c) => affineDecrypt(full, Number(c.params.a), c.params.b), ctx) };
}

/** Weighting for single-byte XOR columns: rewards letters and spaces, punishes control bytes. */
function byteTextScore(bytes) {
  let s = 0;
  for (const b of bytes) {
    if (b === 32) s += 2;
    else if ((b >= 97 && b <= 122) || (b >= 65 && b <= 90)) s += 1.5;
    else if (b >= 48 && b <= 57) s += 0.6;
    else if (b >= 33 && b <= 126) s += 0.2;
    else if (b === 10 || b === 13 || b === 9) s += 0.2;
    else s -= 3;
  }
  return s / Math.max(1, bytes.length);
}

function xorSingleBrute(full, ctx) {
  const bytes = full.subarray(0, SAMPLE);
  const cands = [];
  for (let k = 1; k < 256; k++) {
    const output = xorBytes(bytes, Uint8Array.of(k));
    const j = judge(output, ctx);
    const raw = byteTextScore(output);
    cands.push({ opId: 'xor', params: { key: k.toString(16).padStart(2, '0'), keyFormat: 'hex' }, output, flag: j.flag, score: j.flag ? 1 : Math.max(0, Math.min(1, 0.5 * j.score + 0.5 * Math.max(0, raw / 1.6))), label: `key 0x${k.toString(16).padStart(2, '0')}` });
  }
  return { summary: 'Tried all 255 single-byte keys and ranked outputs by text likelihood.', candidates: rankSampled(full, cands, (c) => xorBytes(full, Uint8Array.of(parseInt(c.params.key, 16))), ctx) };
}

/* ---------- Vigenère: index of coincidence + Kasiski + chi-squared ---------- */
function gcd(a, b) {
  while (b) [a, b] = [b, a % b];
  return a;
}

function kasiski(letters) {
  const pos = new Map();
  const factors = new Map();
  for (let i = 0; i + 3 <= letters.length; i++) {
    const tri = letters.substr(i, 3);
    if (pos.has(tri)) {
      const d = i - pos.get(tri);
      for (let f = 2; f <= 20; f++) if (d % f === 0) factors.set(f, (factors.get(f) || 0) + 1);
    }
    pos.set(tri, i);
  }
  return [...factors.entries()].sort((a, b) => b[1] - a[1] || a[0] - b[0]).slice(0, 4);
}

function columnIoc(letters, len) {
  let sum = 0;
  for (let c = 0; c < len; c++) {
    const counts = new Array(26).fill(0);
    let n = 0;
    for (let i = c; i < letters.length; i += len) {
      counts[letters.charCodeAt(i) - 65]++;
      n++;
    }
    sum += indexOfCoincidence(counts, n);
  }
  return sum / len;
}

function vigenereRecover(bytes, ctx) {
  const letters = latin1(bytes.subarray(0, 65536)).toUpperCase().replace(/[^A-Z]/g, '');
  if (letters.length < 30) return { summary: `Only ${letters.length} letters; Vigenère key recovery needs at least about 30.`, candidates: [] };
  const maxLen = Math.min(20, Math.floor(letters.length / 4));
  const iocs = [];
  for (let len = 1; len <= maxLen; len++) iocs.push({ len, ioc: columnIoc(letters, len) });
  const best = Math.max(...iocs.map((x) => x.ioc));
  // Prefer the shortest length close to the best IoC, so multiples of the true length don't win.
  const lengths = iocs
    .filter((x) => x.ioc >= best * 0.9)
    .sort((a, b) => a.len - b.len)
    .slice(0, 3);
  const kas = kasiski(letters);
  const cands = lengths.map(({ len, ioc }) => {
    let key = '';
    for (let c = 0; c < len; c++) {
      let col = '';
      for (let i = c; i < letters.length; i += len) col += letters[i];
      const colBytes = utf8(col);
      let bestShift = 0;
      let bestChi = Infinity;
      for (let s = 0; s < 26; s++) {
        const { counts, total } = letterCounts(caesar(colBytes, s));
        const chi = chiSquared(counts, total);
        if (chi < bestChi) {
          bestChi = chi;
          bestShift = s;
        }
      }
      key += String.fromCharCode(65 + bestShift);
    }
    const output = vigenere(bytes, key, true);
    return { opId: 'vigenere', params: { key, mode: 'decrypt' }, output, ...judge(output, ctx), label: `key ${key} (length ${len}, IoC ${ioc.toFixed(3)})` };
  });
  const kasText = kas.length ? ` Kasiski repeats favour lengths ${kas.map(([f]) => f).join(', ')}.` : '';
  return { summary: `Estimated key length from column index of coincidence, then chose each key letter by χ² against English.${kasText}`, candidates: rank(cands) };
}

/* ---------- Repeating-key XOR: Hamming distance + per-column single-byte ---------- */
function hamming(a, b) {
  let d = 0;
  for (let i = 0; i < a.length; i++) {
    let x = a[i] ^ b[i];
    while (x) {
      d += x & 1;
      x >>= 1;
    }
  }
  return d;
}

function xorRepeatingRecover(full, ctx) {
  const bytes = full.subarray(0, 16384);
  if (bytes.length < 16) return { summary: 'Too short for repeating-key XOR analysis (needs at least 16 bytes).', candidates: [] };
  const sizes = [];
  for (let k = 2; k <= Math.min(40, Math.floor(bytes.length / 2)); k++) {
    const blocks = Math.min(8, Math.floor(bytes.length / k));
    let d = 0;
    let pairs = 0;
    for (let i = 0; i < blocks - 1; i++) {
      d += hamming(bytes.subarray(i * k, (i + 1) * k), bytes.subarray((i + 1) * k, (i + 2) * k)) / k;
      pairs++;
    }
    if (pairs) sizes.push({ k, d: d / pairs });
  }
  sizes.sort((a, b) => a.d - b.d);
  const cands = sizes.slice(0, 4).map(({ k, d }) => {
    const key = new Uint8Array(k);
    for (let c = 0; c < k; c++) {
      const col = [];
      for (let i = c; i < bytes.length; i += k) col.push(bytes[i]);
      const colBytes = Uint8Array.from(col);
      let best = 0;
      let bestScore = -Infinity;
      for (let x = 0; x < 256; x++) {
        const s = byteTextScore(xorBytes(colBytes, Uint8Array.of(x)));
        if (s > bestScore) {
          bestScore = s;
          best = x;
        }
      }
      key[c] = best;
    }
    const output = xorBytes(full, key);
    const j = judge(output, ctx);
    return { opId: 'xor', params: { key: toHex(key), keyFormat: 'hex' }, output, flag: j.flag, score: j.flag ? 1 : Math.min(1, 0.5 * j.score + 0.5 * Math.max(0, byteTextScore(output) / 1.6)), label: `key 0x${toHex(key)} (length ${k}, distance ${d.toFixed(2)})` };
  });
  return { summary: 'Ranked key lengths by normalised Hamming distance, then solved each column as single-byte XOR.', candidates: rank(cands) };
}

/* ---------- Known-plaintext XOR from the flag prefix ---------- */
function knownPlaintextXor(bytes, ctx) {
  const prefix = (ctx.flagPrefix || '').trim();
  if (!prefix) return { summary: 'Set a flag prefix (e.g. CTF{) to use it as known plaintext.', candidates: [] };
  const known = utf8(prefix.endsWith('{') ? prefix : prefix + '{');
  if (bytes.length < known.length) return { summary: 'Data is shorter than the flag prefix.', candidates: [] };
  const k = known.map((p, i) => bytes[i] ^ p);
  const cands = [];
  for (let period = 1; period <= k.length; period++) {
    let ok = true;
    for (let i = period; i < k.length; i++) if (k[i] !== k[i % period]) ok = false;
    if (!ok) continue;
    const key = k.slice(0, period);
    const output = xorBytes(bytes, key);
    const j = judge(output, ctx);
    cands.push({ opId: 'xor', params: { key: toHex(key), keyFormat: 'hex' }, output, ...j, label: `key 0x${toHex(key)} (period ${period})` });
  }
  const note = cands.length && cands[0].params.key.length / 2 === known.length ? ' The key may be longer than the prefix, so later bytes can still be wrong.' : '';
  return { summary: `XORed the first ${known.length} bytes with "${utf8ToStr(known)}" and kept key periods consistent with them.${note}`, candidates: rank(cands) };
}

const utf8ToStr = (b) => latin1(b);

export const attacks = [
  { id: 'caesar-brute', name: 'Caesar brute force', target: 'caesar', summary: 'Try all 25 shifts; rank by English fitness.', needs: 'letters', run: caesarBrute },
  { id: 'affine-brute', name: 'Affine brute force', target: 'affine', summary: 'Try all 311 keys; rank by English fitness.', needs: 'letters', run: affineBrute },
  { id: 'vigenere-recover', name: 'Vigenère key recovery', target: 'vigenere', summary: 'Index of coincidence and Kasiski for length, χ² per letter.', needs: 'letters', run: vigenereRecover },
  { id: 'xor-single', name: 'Single-byte XOR', target: 'xor', summary: 'Try all 255 one-byte keys.', needs: 'bytes', run: xorSingleBrute },
  { id: 'xor-repeating', name: 'Repeating-key XOR', target: 'xor', summary: 'Hamming distance for length, then solve columns.', needs: 'bytes', run: xorRepeatingRecover },
  { id: 'xor-known', name: 'Known-plaintext XOR', target: 'xor', summary: 'Derive key bytes from the flag prefix.', needs: 'bytes', run: knownPlaintextXor },
];

export const attackById = Object.fromEntries(attacks.map((a) => [a.id, a]));
