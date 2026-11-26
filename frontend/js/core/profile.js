// Input intelligence (Module A): a profile of one layer's bytes, computed before any operation runs.

import { tryUtf8, printableRatio, latin1 } from './bytes.js';
import { letterCounts, chiSquared, indexOfCoincidence, englishFitness, flagRegex, FLAG_SHAPE } from './score.js';

const MAGIC = [
  { name: 'PNG image', hex: '89504e470d0a1a0a' },
  { name: 'JPEG image', hex: 'ffd8ff' },
  { name: 'GIF image', hex: '47494638' },
  { name: 'PDF document', hex: '25504446' },
  { name: 'ZIP archive', hex: '504b0304' },
  { name: 'gzip stream', hex: '1f8b08' },
  { name: '7-Zip archive', hex: '377abcaf271c' },
  { name: 'RAR archive', hex: '52617221' },
  { name: 'bzip2 stream', hex: '425a68' },
  { name: 'xz stream', hex: 'fd377a585a00' },
  { name: 'ELF executable', hex: '7f454c46' },
  { name: 'Windows PE / DOS executable', hex: '4d5a' },
  { name: 'Java class file', hex: 'cafebabe' },
  { name: 'SQLite database', hex: '53514c69746520666f726d6174203300' },
  { name: 'RIFF container (WAV/AVI/WebP)', hex: '52494646' },
  { name: 'OGG container', hex: '4f676753' },
  { name: 'PEM block', hex: '2d2d2d2d2d424547494e' },
];

export function detectMagic(bytes) {
  for (const m of MAGIC) {
    const n = m.hex.length / 2;
    if (bytes.length < n) continue;
    let ok = true;
    for (let i = 0; i < n; i++) {
      if (bytes[i] !== parseInt(m.hex.substr(i * 2, 2), 16)) {
        ok = false;
        break;
      }
    }
    if (ok) return m.name;
  }
  // zlib: CMF 0x78, header checksum divisible by 31.
  if (bytes.length > 2 && bytes[0] === 0x78 && ((bytes[0] << 8) | bytes[1]) % 31 === 0) return 'zlib stream';
  if (bytes.length > 262 && latin1(bytes.subarray(257, 262)) === 'ustar') return 'tar archive';
  return null;
}

/** Hash identification by length and format. Hashes are one-way: this names candidates, it never reverses them. */
export function identifyHash(s) {
  const t = s.trim();
  if (!t || t.length > 200 || /\s/.test(t)) return [];
  const out = [];
  const crypt = [
    [/^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$/, 'bcrypt', 'Deliberately slow; dictionary checks are expensive.'],
    [/^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$/, 'MD5-crypt', 'Unix crypt with salt.'],
    [/^\$apr1\$/, 'Apache APR1 MD5', 'htpasswd format.'],
    [/^\$5\$/, 'SHA-256-crypt', 'Unix crypt with salt.'],
    [/^\$6\$/, 'SHA-512-crypt', 'Unix crypt with salt.'],
    [/^\$argon2(id|i|d)\$/, 'Argon2', 'Memory-hard; dictionary checks are expensive.'],
    [/^\$y\$/, 'yescrypt', 'Modern Linux shadow format.'],
    [/^\*[0-9A-F]{40}$/i, 'MySQL 4.1+', 'SHA-1 of SHA-1, prefixed with *.'],
  ];
  for (const [re, name, note] of crypt) if (re.test(t)) out.push({ name, note });
  if (out.length) return out;
  if (!/^[0-9a-fA-F]+$/.test(t)) return [];
  const byLen = {
    8: [['CRC32', 'Checksum, not a cryptographic hash.'], ['Adler-32', 'Checksum.']],
    16: [['MySQL 3.23', 'Legacy password hash.'], ['64-bit value', 'Could also be a raw key or ID.']],
    32: [['MD5', 'Most common 128-bit hash in CTFs.'], ['NTLM', 'Windows password hash; same length as MD5.'], ['MD4', '']],
    40: [['SHA-1', ''], ['RIPEMD-160', '']],
    56: [['SHA-224', ''], ['SHA3-224', '']],
    64: [['SHA-256', ''], ['SHA3-256', ''], ['BLAKE2s-256', '']],
    96: [['SHA-384', ''], ['SHA3-384', '']],
    128: [['SHA-512', ''], ['SHA3-512', ''], ['BLAKE2b-512', '']],
  };
  return (byLen[t.length] || []).map(([name, note]) => ({ name, note }));
}

/** Finds n, e, c values written as "n = 123" lines (decimal or 0x hex). */
export function parseRsaParams(text) {
  if (!text || text.length > 20000) return null;
  const grab = (key) => {
    const m = text.match(new RegExp(`(?:^|\\n|\\s)${key}\\s*[=:]\\s*(0x[0-9a-fA-F]+|\\d+)`, 'i'));
    return m ? m[1] : null;
  };
  const n = grab('n');
  const e = grab('e');
  const c = grab('c') || grab('ct');
  if (!n || !e) return null;
  try {
    const big = (v) => BigInt(v);
    const N = big(n);
    const E = big(e);
    const C = c ? big(c) : null;
    return { n: N, e: E, c: C, bits: N.toString(2).length };
  } catch {
    return null;
  }
}

function charsetLabel(s, isText) {
  const t = s.replace(/\s+/g, '');
  const spaced = / /.test(s.trim());
  if (!isText) return 'Binary data';
  if (!t) return 'Whitespace only';
  if (/^[01]+$/.test(t)) return 'Binary digits (0–1)';
  if (/^[.\-/_|]+$/.test(t)) return 'Morse symbols';
  if (/^[0-9a-fA-F]+$/.test(t)) return /^[0-9]+$/.test(t) ? 'Decimal digits' : 'Hex digits (0–9, a–f)';
  if (/^[A-Za-z]+$/.test(t)) return 'Letters only';
  if (spaced) return /[A-Za-z]{2,}/.test(t) ? 'Printable text' : 'Symbols and digits';
  if (/^[A-Z2-7]+=*$/.test(t)) return 'Base32 alphabet';
  if (/^[1-9A-HJ-NP-Za-km-z]+$/.test(t)) return 'Base58 alphabet';
  if (/^[A-Za-z0-9+/]+=*$/.test(t)) return 'Base64 alphabet';
  if (/^[A-Za-z0-9_-]+=*$/.test(t)) return 'URL-safe Base64 alphabet';
  if (/^[A-Za-z]+$/.test(t)) return 'Letters only';
  if (/^[\x21-\x75]+$/.test(t) && !/[a-z]{4,}/.test(t)) return 'Ascii85 range (! to u)';
  return 'Printable text';
}

/** Full profile used by the Inspector. Cheap enough to run on every layer. */
export function profileBytes(bytes, { flagPrefix = '' } = {}) {
  const text = tryUtf8(bytes);
  const isUtf8 = text !== null;
  const printable = printableRatio(bytes, isUtf8);
  const isText = bytes.length === 0 || printable >= 0.9;
  const ascii = latin1(bytes);

  const histogram = new Array(256).fill(0);
  for (let i = 0; i < bytes.length; i++) histogram[bytes[i]]++;
  let entropy = 0;
  for (const c of histogram) {
    if (!c) continue;
    const p = c / bytes.length;
    entropy -= p * Math.log2(p);
  }
  let distinct = 0;
  for (const c of histogram) if (c) distinct++;

  const { counts: letters, total: letterTotal } = letterCounts(bytes);
  const ioc = indexOfCoincidence(letters, letterTotal);
  const chi2 = chiSquared(letters, letterTotal);

  const re = flagRegex(flagPrefix);
  const flagMatch = isText ? (ascii.match(re) || [null])[0] : null;
  const flagShape = !flagMatch && isText ? (ascii.match(FLAG_SHAPE) || [null])[0] : null;

  const magic = detectMagic(bytes);
  const rsa = isText ? parseRsaParams(ascii) : null;

  let ecbRepeats = 0;
  if (!isText && bytes.length >= 32 && bytes.length % 16 === 0) {
    const seen = new Set();
    for (let i = 0; i < bytes.length; i += 16) {
      const block = ascii.substr(i, 16);
      if (seen.has(block)) ecbRepeats++;
      seen.add(block);
    }
  }

  return {
    length: bytes.length,
    isUtf8,
    isText,
    printable,
    entropy,
    distinct,
    lines: isText && bytes.length ? ascii.split('\n').length : 0,
    histogram,
    letters,
    letterTotal,
    letterShare: bytes.length ? letterTotal / bytes.length : 0,
    ioc,
    chi2,
    english: isText ? englishFitness(bytes) : 0,
    charset: rsa ? 'Numeric parameters (n, e, c)' : charsetLabel(ascii.slice(0, 20000), isText),
    magic,
    // A compressed stream is another layer, not a result.
    magicTerminal: magic && !/gzip|zlib/.test(magic) ? magic : null,
    flagMatch,
    flagShape,
    hashes: isText ? identifyHash(ascii) : [],
    rsa,
    ecbRepeats,
    ascii,
  };
}
