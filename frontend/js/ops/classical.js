// Classical ciphers and XOR (Module C). These need a key (or use a fixed one).
// Applying them here means decrypting with a key you supply or one an attack recovered;
// recovering the key itself is the job of attacks.js.

import { latin1, fromLatin1, utf8, toHex } from '../core/bytes.js';
import { OpError } from './encodings.js';

const AFFINE_A = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25];
const modInv26 = (a) => {
  for (let x = 1; x < 26; x++) if ((a * x) % 26 === 1) return x;
  throw new OpError(`a = ${a} has no inverse mod 26; choose a value coprime with 26.`);
};

function mapLetters(bytes, fn) {
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b >= 65 && b <= 90) out[i] = 65 + fn(b - 65);
    else if (b >= 97 && b <= 122) out[i] = 97 + fn(b - 97);
    else out[i] = b;
  }
  return out;
}

export const caesar = (bytes, shift) => mapLetters(bytes, (x) => (((x - shift) % 26) + 26) % 26);

export function vigenere(bytes, key, decrypt = true) {
  const k = (key || '').toUpperCase().replace(/[^A-Z]/g, '');
  if (!k) throw new OpError('Key must contain at least one letter.');
  let j = 0;
  return mapLetters(bytes, (x) => {
    const s = k.charCodeAt(j++ % k.length) - 65;
    return (((x + (decrypt ? -s : s)) % 26) + 26) % 26;
  });
}

export function xorBytes(bytes, key) {
  if (!key.length) throw new OpError('XOR key is empty.');
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) out[i] = bytes[i] ^ key[i % key.length];
  return out;
}

export function parseXorKey(p) {
  if (p.keyFormat === 'text') return utf8(p.key || '');
  const t = (p.key || '').replace(/0x/gi, '').replace(/[\s,:]/g, '');
  if (!/^[0-9a-fA-F]*$/.test(t) || t.length % 2) throw new OpError('Hex key must be an even number of hex digits, e.g. 5a or 6b3379.');
  const out = new Uint8Array(t.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(t.substr(i * 2, 2), 16);
  return out;
}

const pyStr = (s) => JSON.stringify(s);

export const classicalOps = [
  {
    id: 'caesar',
    name: 'Caesar shift',
    kind: 'cipher',
    summary: 'Shift letters back by a fixed amount. 25 possible keys.',
    params: [{ id: 'shift', label: 'Shift', type: 'number', min: 1, max: 25, default: 3 }],
    apply: (bytes, p) => caesar(bytes, Number(p.shift) || 0),
    explain: (p) => (Number(p.shift) === 13 ? 'ROT13 (Caesar shift 13)' : `Caesar shift ${p.shift}`),
    keyLabel: (p) => `shift ${p.shift}`,
    python: (p) => ({ helpers: ['caesar'], code: `data = caesar(data, ${Number(p.shift) || 0})` }),
  },
  {
    id: 'rot13',
    name: 'ROT13',
    kind: 'cipher',
    summary: 'Caesar shift 13. Applying it twice returns the original.',
    params: [],
    apply: (bytes) => caesar(bytes, 13),
    explain: () => 'ROT13',
    python: () => ({ helpers: ['caesar'], code: 'data = caesar(data, 13)' }),
  },
  {
    id: 'rot47',
    name: 'ROT47',
    kind: 'cipher',
    summary: 'Rotates every printable ASCII character (! to ~) by 47.',
    params: [],
    detect(p) {
      if (!p.isText || p.length < 6) return null;
      const sym = (p.ascii.match(/[!-/:-@[-`{-~]/g) || []).length / p.length;
      return sym > 0.15 && p.english < 0.35 ? { confidence: 0.25, reason: `${Math.round(sym * 100)}% punctuation, typical of ROT47 output` } : null;
    },
    apply(bytes) {
      const out = new Uint8Array(bytes.length);
      for (let i = 0; i < bytes.length; i++) {
        const b = bytes[i];
        out[i] = b >= 33 && b <= 126 ? 33 + ((b - 33 + 47) % 94) : b;
      }
      return out;
    },
    explain: () => 'ROT47',
    python: () => ({ code: 'data = bytes(33 + (b - 33 + 47) % 94 if 33 <= b <= 126 else b for b in data)' }),
  },
  {
    id: 'atbash',
    name: 'Atbash',
    kind: 'cipher',
    summary: 'Mirror the alphabet: A↔Z, B↔Y. No key.',
    params: [],
    apply: (bytes) => mapLetters(bytes, (x) => 25 - x),
    explain: () => 'Atbash',
    python: () => ({ helpers: ['atbash'], code: 'data = atbash(data)' }),
  },
  {
    id: 'affine',
    name: 'Affine',
    kind: 'cipher',
    summary: 'Decrypt E(x) = a·x + b mod 26. 311 non-trivial keys.',
    params: [
      { id: 'a', label: 'a', type: 'select', options: AFFINE_A.map((a) => [String(a), String(a)]), default: '5' },
      { id: 'b', label: 'b', type: 'number', min: 0, max: 25, default: 8 },
    ],
    apply(bytes, p) {
      const a = Number(p.a);
      const b = Number(p.b) || 0;
      const inv = modInv26(a);
      return mapLetters(bytes, (y) => (((inv * (y - b)) % 26) + 26) % 26);
    },
    explain: (p) => `Affine decrypt (a = ${p.a}, b = ${p.b})`,
    keyLabel: (p) => `a = ${p.a}, b = ${p.b}`,
    python: (p) => ({ helpers: ['affine'], code: `data = affine_decrypt(data, ${Number(p.a)}, ${Number(p.b) || 0})` }),
  },
  {
    id: 'vigenere',
    name: 'Vigenère',
    kind: 'cipher',
    summary: 'Repeating-key letter shifts. Key advances on letters only.',
    params: [
      { id: 'key', label: 'Key', type: 'text', default: 'KEY', placeholder: 'letters' },
      { id: 'mode', label: 'Direction', type: 'select', options: [['decrypt', 'Decrypt'], ['encrypt', 'Encrypt']], default: 'decrypt' },
    ],
    apply: (bytes, p) => vigenere(bytes, p.key, p.mode !== 'encrypt'),
    explain: (p) => `Vigenère ${p.mode === 'encrypt' ? 'encrypt' : 'decrypt'} (key ${String(p.key || '').toUpperCase()})`,
    keyLabel: (p) => `key ${String(p.key || '').toUpperCase()}`,
    python: (p) => ({ helpers: ['vigenere'], code: `data = vigenere(data, ${pyStr(String(p.key || '').toUpperCase())}, decrypt=${p.mode === 'encrypt' ? 'False' : 'True'})` }),
  },
  {
    id: 'xor',
    name: 'XOR with key',
    kind: 'cipher',
    summary: 'Repeating-key XOR over raw bytes. Self-inverse.',
    params: [
      { id: 'key', label: 'Key', type: 'text', default: '5a', placeholder: 'hex or text' },
      { id: 'keyFormat', label: 'Key as', type: 'select', options: [['hex', 'Hex'], ['text', 'Text']], default: 'hex' },
    ],
    apply: (bytes, p) => xorBytes(bytes, parseXorKey(p)),
    explain: (p) => `XOR with ${p.keyFormat === 'text' ? `"${p.key}"` : `0x${String(p.key).replace(/^0x/i, '')}`}`,
    keyLabel: (p) => (p.keyFormat === 'text' ? `key "${p.key}"` : `key 0x${String(p.key).replace(/^0x/i, '')}`),
    python(p) {
      const key = p.keyFormat === 'text' ? `${pyStr(p.key)}.encode()` : `bytes.fromhex(${pyStr(toHex(parseXorKey(p)))})`;
      return { code: `key = ${key}\ndata = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))` };
    },
  },
  {
    id: 'substitution',
    name: 'Substitution (known key)',
    kind: 'cipher',
    summary: 'Undo a known 26-letter substitution alphabet.',
    params: [{ id: 'alphabet', label: 'Cipher alphabet', type: 'text', default: 'QWERTYUIOPASDFGHJKLZXCVBNM', placeholder: '26 letters for A–Z' }],
    apply(bytes, p) {
      const alpha = String(p.alphabet || '').toUpperCase().replace(/[^A-Z]/g, '');
      if (alpha.length !== 26 || new Set(alpha).size !== 26) throw new OpError('Cipher alphabet must contain each letter A–Z exactly once.');
      const inverse = new Array(26);
      for (let i = 0; i < 26; i++) inverse[alpha.charCodeAt(i) - 65] = i;
      return mapLetters(bytes, (x) => inverse[x]);
    },
    explain: (p) => `Substitution decrypt (${String(p.alphabet).toUpperCase().slice(0, 6)}…)`,
    keyLabel: (p) => `alphabet ${String(p.alphabet).toUpperCase()}`,
    python: (p) => ({ helpers: ['substitution'], code: `data = substitution_decrypt(data, ${pyStr(String(p.alphabet || '').toUpperCase())})` }),
  },
];

export const transformOps = [
  {
    id: 'reverse',
    name: 'Reverse',
    kind: 'transform',
    summary: 'Reverse the byte order.',
    params: [],
    detect(p) {
      if (!p.isText) return null;
      const t = p.ascii.trim();
      if (/^\}[\s\S]*\{[A-Za-z0-9_]{2,16}$/.test(t)) return { confidence: 0.9, reason: 'Starts with } and ends with {PREFIX, like a flag written backwards' };
      if (/=+[A-Za-z0-9+/]{4,}$/.test(t) && /^=/.test(t)) return { confidence: 0.6, reason: 'Starts with = padding, like reversed Base64' };
      return null;
    },
    apply: (bytes) => Uint8Array.from(bytes).reverse(),
    explain: () => 'Reverse',
    python: () => ({ code: 'data = data[::-1]' }),
  },
];
