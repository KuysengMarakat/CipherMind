// Encodings (Module B): public, keyless representations. Decoding always succeeds if the format is right.
// Each op follows the plugin interface from the proposal: detect / apply / explain, plus python() for solve scripts.

import { latin1, fromLatin1, toHex, utf8 } from '../core/bytes.js';

export class OpError extends Error {}

const strip = (s) => s.replace(/\s+/g, '');
const modeParam = { id: 'mode', label: 'Direction', type: 'select', options: [['decode', 'Decode'], ['encode', 'Encode']], default: 'decode' };
const isDecode = (p) => (p.mode || 'decode') === 'decode';
const dirName = (p, noun) => `${noun} ${isDecode(p) ? 'decode' : 'encode'}`;
const clamp = (x) => Math.max(0, Math.min(1, x));

/* ---------- Base64 ---------- */
function b64decode(text) {
  let t = strip(text).replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(t)) throw new OpError('Contains characters outside the Base64 alphabet.');
  t = t.replace(/=+$/, '');
  if (t.length % 4 === 1) throw new OpError(`Length ${t.length} cannot be Base64 (one character too many or too few).`);
  t += '='.repeat((4 - (t.length % 4)) % 4);
  return fromLatin1(atob(t));
}

/* ---------- Base32 (RFC 4648) ---------- */
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32decode(text) {
  const t = strip(text).toUpperCase().replace(/=+$/, '');
  if (!/^[A-Z2-7]*$/.test(t)) throw new OpError('Contains characters outside the Base32 alphabet (A–Z, 2–7).');
  const out = [];
  let bits = 0;
  let value = 0;
  for (const ch of t) {
    value = (value << 5) | B32.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}
function b32encode(bytes) {
  let out = '';
  let bits = 0;
  let value = 0;
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  while (out.length % 8) out += '=';
  return out;
}

/* ---------- Base58 (Bitcoin alphabet) ---------- */
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58decode(text) {
  const t = strip(text);
  if (!/^[1-9A-HJ-NP-Za-km-z]*$/.test(t)) throw new OpError('Contains characters outside the Base58 alphabet (no 0, O, I or l).');
  let n = 0n;
  for (const ch of t) n = n * 58n + BigInt(B58.indexOf(ch));
  const bytes = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  let zeros = 0;
  while (zeros < t.length && t[zeros] === '1') zeros++;
  return new Uint8Array([...new Array(zeros).fill(0), ...bytes]);
}
function b58encode(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = '';
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    out = '1' + out;
  }
  return out;
}

/* ---------- Ascii85 (Adobe) ---------- */
function a85decode(text) {
  let t = strip(text);
  if (t.startsWith('<~')) t = t.slice(2);
  if (t.endsWith('~>')) t = t.slice(0, -2);
  t = t.replace(/z/g, '!!!!!');
  if (!/^[!-u]*$/.test(t)) throw new OpError('Contains characters outside the Ascii85 range (! to u).');
  const out = [];
  for (let i = 0; i < t.length; i += 5) {
    const chunk = t.slice(i, i + 5);
    const pad = 5 - chunk.length;
    const full = chunk + 'u'.repeat(pad);
    let v = 0;
    for (const ch of full) v = v * 85 + (ch.charCodeAt(0) - 33);
    if (v > 0xffffffff) throw new OpError('Group value overflows 32 bits; not valid Ascii85.');
    const four = [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255];
    out.push(...four.slice(0, 4 - pad));
  }
  return new Uint8Array(out);
}
function a85encode(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 4) {
    const chunk = bytes.subarray(i, i + 4);
    const pad = 4 - chunk.length;
    let v = 0;
    for (let j = 0; j < 4; j++) v = v * 256 + (chunk[j] || 0);
    if (v === 0 && pad === 0) {
      out += 'z';
      continue;
    }
    let s = '';
    for (let j = 0; j < 5; j++) {
      s = String.fromCharCode((v % 85) + 33) + s;
      v = Math.floor(v / 85);
    }
    out += s.slice(0, 5 - pad);
  }
  return out;
}

/* ---------- Base85 (RFC 1924, Python base64.b85*) ---------- */
const B85 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~';
function b85decode(text) {
  const t = strip(text);
  for (const ch of t) if (B85.indexOf(ch) < 0) throw new OpError(`Character "${ch}" is not in the RFC 1924 Base85 alphabet.`);
  const out = [];
  for (let i = 0; i < t.length; i += 5) {
    const chunk = t.slice(i, i + 5);
    const pad = 5 - chunk.length;
    let v = 0;
    for (const ch of chunk + '~'.repeat(pad)) v = v * 85 + B85.indexOf(ch);
    if (v > 0xffffffff) throw new OpError('Group value overflows 32 bits; not valid Base85.');
    out.push(...[(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].slice(0, 4 - pad));
  }
  return new Uint8Array(out);
}
function b85encode(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 4) {
    const chunk = bytes.subarray(i, i + 4);
    const pad = 4 - chunk.length;
    let v = 0;
    for (let j = 0; j < 4; j++) v = v * 256 + (chunk[j] || 0);
    let s = '';
    for (let j = 0; j < 5; j++) {
      s = B85[v % 85] + s;
      v = Math.floor(v / 85);
    }
    out += s.slice(0, 5 - pad);
  }
  return out;
}

/* ---------- Hex / binary / octal / decimal ---------- */
function cleanHex(text) {
  return text.replace(/0x/gi, '').replace(/\\x/gi, '').replace(/[\s:,-]+/g, '');
}
function hexdecode(text) {
  const t = cleanHex(text);
  if (!/^[0-9a-fA-F]*$/.test(t)) throw new OpError('Contains characters that are not hex digits.');
  if (t.length % 2) throw new OpError(`Odd number of hex digits (${t.length}); one digit is missing or extra.`);
  const out = new Uint8Array(t.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(t.substr(i * 2, 2), 16);
  return out;
}
function bindecode(text) {
  const t = strip(text);
  if (!/^[01]*$/.test(t)) throw new OpError('Contains characters other than 0 and 1.');
  if (t.length % 8) throw new OpError(`${t.length} bits is not a whole number of bytes.`);
  const out = new Uint8Array(t.length / 8);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(t.substr(i * 8, 8), 2);
  return out;
}
function radixDecode(text, radix, name) {
  const tokens = text.trim().split(/[\s,;]+/).filter(Boolean);
  const re = radix === 8 ? /^[0-7]{1,3}$/ : /^\d{1,3}$/;
  return new Uint8Array(
    tokens.map((tok) => {
      if (!re.test(tok)) throw new OpError(`"${tok}" is not a ${name} byte value.`);
      const v = parseInt(tok, radix);
      if (v > 255) throw new OpError(`${tok} is larger than one byte (255).`);
      return v;
    })
  );
}

/* ---------- URL / HTML / Morse ---------- */
function urldecode(text, plusAsSpace) {
  const out = [];
  const s = text;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === '%' && /^[0-9a-fA-F]{2}$/.test(s.substr(i + 1, 2))) {
      out.push(parseInt(s.substr(i + 1, 2), 16));
      i += 2;
    } else if (ch === '+' && plusAsSpace) out.push(32);
    else {
      const c = s.charCodeAt(i);
      if (c < 0x80) out.push(c);
      else out.push(...utf8(ch));
    }
  }
  return new Uint8Array(out);
}
function urlencode(bytes) {
  let out = '';
  for (const b of bytes) {
    const c = String.fromCharCode(b);
    out += /[A-Za-z0-9\-_.~]/.test(c) ? c : '%' + b.toString(16).toUpperCase().padStart(2, '0');
  }
  return out;
}
const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', lbrace: '{', rbrace: '}', lcub: '{', rcub: '}', lowbar: '_', sol: '/', colon: ':', period: '.', excl: '!', num: '#', dollar: '$', percnt: '%', equals: '=' };
function htmldecode(text) {
  return text.replace(/&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z]+);/g, (m, body) => {
    if (body[0] === '#') {
      const cp = body[1] === 'x' || body[1] === 'X' ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
      return cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
    }
    return ENTITIES[body] ?? m;
  });
}
const MORSE = {
  '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
  '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
  '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
  '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9', '.-.-.-': '.',
  '--..--': ',', '..--..': '?', '-.-.--': '!', '-..-.': '/', '-.--.': '(', '-.--.-': ')', '---...': ':', '-...-': '=',
  '.-.-.': '+', '-....-': '-', '..--.-': '_', '.--.-.': '@', '.----.': "'", '.-..-.': '"',
};
function morsedecode(text) {
  const t = text.replace(/_/g, '-').trim();
  if (!/^[.\-/|\s]+$/.test(t)) throw new OpError('Morse input may only contain dots, dashes, spaces and / separators.');
  const words = t.split(/\s*[/|]\s*|\s{3,}/);
  return utf8(
    words
      .map((w) =>
        w
          .split(/\s+/)
          .filter(Boolean)
          .map((sym) => {
            if (!(sym in MORSE)) throw new OpError(`"${sym}" is not a Morse letter.`);
            return MORSE[sym];
          })
          .join('')
      )
      .join(' ')
  );
}

/* ---------- Helpers for detection ---------- */
function compact(profile) {
  return profile.ascii.trim();
}

/* ---------- Op definitions ---------- */
export const encodingOps = [
  {
    id: 'base64',
    name: 'Base64',
    kind: 'encoding',
    summary: 'A–Z a–z 0–9 + / with = padding. URL-safe - _ accepted.',
    params: [modeParam],
    detect(p) {
      const t = compact(p);
      if (t.length < 4 || /\s/.test(t.replace(/\n/g, ''))) return null;
      const s = strip(t);
      if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(s)) return null;
      const reasons = ['only Base64 alphabet characters'];
      let c = 0.45;
      if (s.length % 4 === 0) { c += 0.2; reasons.push(`length ${s.length} is a multiple of 4`); }
      else if (s.length % 4 === 1) return null;
      if (/=$/.test(s)) { c += 0.2; reasons.push('ends in = padding'); }
      if (/[a-z]/.test(s) && /[A-Z]/.test(s) && /[0-9+/]/.test(s)) c += 0.1;
      if (/^[0-9a-fA-F]+$/.test(s)) { c -= 0.3; reasons.push('but every character is also a hex digit'); }
      if (/^[A-Za-z]+$/.test(s) && s.length < 16) c -= 0.25;
      return { confidence: clamp(c), reason: capital(reasons.join('; ')) };
    },
    apply(bytes, p) {
      return isDecode(p) ? b64decode(latin1(bytes)) : utf8(btoa(latin1(bytes)));
    },
    explain: (p) => dirName(p, 'Base64'),
    python: (p) =>
      isDecode(p)
        ? { imports: ['base64'], helpers: ['b64'], code: 'data = b64decode_lenient(data)' }
        : { imports: ['base64'], code: 'data = base64.b64encode(data)' },
  },
  {
    id: 'base32',
    name: 'Base32',
    kind: 'encoding',
    summary: 'A–Z 2–7 with = padding, in groups of 8.',
    params: [modeParam],
    detect(p) {
      if (/ /.test(compact(p))) return null;
      const s = strip(compact(p));
      if (s.length < 8 || !/^[A-Z2-7]+=*$/.test(s)) return null;
      const reasons = ['only uppercase A–Z and 2–7'];
      let c = 0.55;
      if (s.length % 8 === 0) { c += 0.2; reasons.push(`length ${s.length} is a multiple of 8`); }
      if (/=$/.test(s)) { c += 0.15; reasons.push('ends in = padding'); }
      if (/^[A-Z]+$/.test(s)) c -= 0.2;
      return { confidence: clamp(c), reason: capital(reasons.join('; ')) };
    },
    apply: (bytes, p) => (isDecode(p) ? b32decode(latin1(bytes)) : utf8(b32encode(bytes))),
    explain: (p) => dirName(p, 'Base32'),
    python: (p) =>
      isDecode(p)
        ? { imports: ['base64'], code: 'data = base64.b32decode(data.strip().upper() + b"=" * (-len(data.strip()) % 8))' }
        : { imports: ['base64'], code: 'data = base64.b32encode(data)' },
  },
  {
    id: 'base58',
    name: 'Base58',
    kind: 'encoding',
    summary: 'Bitcoin alphabet: Base64 without 0 O I l + /.',
    params: [modeParam],
    detect(p) {
      if (/ /.test(compact(p))) return null;
      const s = strip(compact(p));
      if (s.length < 6 || !/^[1-9A-HJ-NP-Za-km-z]+$/.test(s)) return null;
      if (!/[a-z]/.test(s) || !/[A-Z]/.test(s)) return { confidence: 0.15, reason: 'Fits the Base58 alphabet but uses only one letter case' };
      return { confidence: 0.5, reason: 'Mixed case with no 0, O, I, l, + or /, which fits Base58' };
    },
    apply: (bytes, p) => (isDecode(p) ? b58decode(latin1(bytes)) : utf8(b58encode(bytes))),
    explain: (p) => dirName(p, 'Base58'),
    python: (p) =>
      isDecode(p) ? { helpers: ['b58'], code: 'data = b58decode(data)' } : { helpers: ['b58'], code: 'data = b58encode(data)' },
  },
  {
    id: 'ascii85',
    name: 'Ascii85',
    kind: 'encoding',
    summary: 'Adobe variant, characters ! to u, optional <~ ~>.',
    params: [modeParam],
    detect(p) {
      if (/ /.test(compact(p))) return null;
      const s = strip(compact(p));
      if (s.length < 5) return null;
      if (/^<~[\s\S]*~>$/.test(s)) return { confidence: 0.95, reason: 'Wrapped in <~ ~> delimiters' };
      if (!/^[!-uz]+$/.test(s)) return null;
      const punct = (s.match(/[!-/:-@[-`]/g) || []).length / s.length;
      if (punct < 0.12) return null;
      return { confidence: 0.4, reason: `All characters fall in ! to u; ${Math.round(punct * 100)}% punctuation` };
    },
    apply: (bytes, p) => (isDecode(p) ? a85decode(latin1(bytes)) : utf8(a85encode(bytes))),
    explain: (p) => dirName(p, 'Ascii85'),
    python: (p) =>
      isDecode(p)
        ? { imports: ['base64'], code: 'data = base64.a85decode(data.strip().removeprefix(b"<~").removesuffix(b"~>"))' }
        : { imports: ['base64'], code: 'data = base64.a85encode(data)' },
  },
  {
    id: 'base85',
    name: 'Base85 (RFC 1924)',
    kind: 'encoding',
    summary: 'Python base64.b85 / Git alphabet.',
    params: [modeParam],
    detect(p) {
      if (/ /.test(compact(p))) return null;
      const s = strip(compact(p));
      if (s.length < 5 || !/^[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]+$/.test(s)) return null;
      if (!/[!#$%&()*+\-;<=>?@^_`{|}~]/.test(s)) return null;
      return { confidence: 0.3, reason: 'Fits the RFC 1924 Base85 alphabet' };
    },
    apply: (bytes, p) => (isDecode(p) ? b85decode(latin1(bytes)) : utf8(b85encode(bytes))),
    explain: (p) => dirName(p, 'Base85'),
    python: (p) =>
      isDecode(p) ? { imports: ['base64'], code: 'data = base64.b85decode(data.strip())' } : { imports: ['base64'], code: 'data = base64.b85encode(data)' },
  },
  {
    id: 'hex',
    name: 'Hexadecimal',
    kind: 'encoding',
    summary: '0–9 a–f, two digits per byte. Spaces, 0x and \\x are ignored.',
    params: [modeParam],
    detect(p) {
      const raw = compact(p);
      const t = cleanHex(raw);
      if (t.length < 4 || !/^[0-9a-fA-F]+$/.test(t)) return null;
      if (t.length % 2) return { confidence: 0.2, reason: `Hex digits only, but odd length (${t.length})` };
      if (/^\d+$/.test(t)) return { confidence: 0.35, reason: 'Even number of digits; could be hex or decimal' };
      return { confidence: 0.92, reason: `Only 0–9 and a–f; even length (${t.length} digits = ${t.length / 2} bytes)` };
    },
    apply: (bytes, p) => (isDecode(p) ? hexdecode(latin1(bytes)) : utf8(toHex(bytes))),
    explain: (p) => dirName(p, 'Hex'),
    python: (p) =>
      isDecode(p)
        ? { imports: ['re'], code: 'data = bytes.fromhex(re.sub(r"0x|\\\\x|[\\s:,-]", "", data.decode()))' }
        : { code: 'data = data.hex().encode()' },
  },
  {
    id: 'binary',
    name: 'Binary',
    kind: 'encoding',
    summary: '8-bit groups of 0 and 1.',
    params: [modeParam],
    detect(p) {
      const s = strip(compact(p));
      if (s.length < 8 || !/^[01]+$/.test(s)) return null;
      return s.length % 8 === 0
        ? { confidence: 0.96, reason: `Only 0 and 1; ${s.length} bits = ${s.length / 8} bytes` }
        : { confidence: 0.25, reason: `Only 0 and 1, but ${s.length} bits is not a whole number of bytes` };
    },
    apply(bytes, p) {
      if (isDecode(p)) return bindecode(latin1(bytes));
      return utf8(Array.from(bytes, (b) => b.toString(2).padStart(8, '0')).join(' '));
    },
    explain: (p) => dirName(p, 'Binary'),
    python: (p) =>
      isDecode(p)
        ? { code: 'bits = "".join(data.decode().split())\ndata = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))' }
        : { code: 'data = " ".join(f"{b:08b}" for b in data).encode()' },
  },
  {
    id: 'octal',
    name: 'Octal bytes',
    kind: 'encoding',
    summary: 'Space-separated values 000–377.',
    params: [],
    detect(p) {
      const t = compact(p);
      const tokens = t.split(/[\s,]+/);
      if (tokens.length < 3 || !tokens.every((x) => /^[0-7]{3}$/.test(x))) return null;
      return { confidence: 0.75, reason: `${tokens.length} three-digit groups using only 0–7` };
    },
    apply: (bytes) => radixDecode(latin1(bytes), 8, 'octal'),
    explain: () => 'Octal decode',
    python: () => ({ code: 'data = bytes(int(t, 8) for t in data.replace(b",", b" ").split())' }),
  },
  {
    id: 'decimal',
    name: 'Decimal bytes',
    kind: 'encoding',
    summary: 'Space- or comma-separated values 0–255.',
    params: [],
    detect(p) {
      const t = compact(p);
      const tokens = t.split(/[\s,;]+/);
      if (tokens.length < 3 || !tokens.every((x) => /^\d{1,3}$/.test(x) && +x <= 255)) return null;
      const printable = tokens.filter((x) => +x >= 32 && +x <= 126).length / tokens.length;
      return { confidence: 0.5 + 0.4 * printable, reason: `${tokens.length} values in 0–255; ${Math.round(printable * 100)}% fall in the printable ASCII range` };
    },
    apply: (bytes) => radixDecode(latin1(bytes), 10, 'decimal'),
    explain: () => 'Decimal decode',
    python: () => ({ imports: ['re'], code: 'data = bytes(int(t) for t in re.split(r"[\\s,;]+", data.decode().strip()))' }),
  },
  {
    id: 'url',
    name: 'URL encoding',
    kind: 'encoding',
    summary: 'Percent-encoding such as %7B and %20.',
    params: [modeParam, { id: 'plus', label: '+ means space', type: 'select', options: [['no', 'No'], ['yes', 'Yes']], default: 'no' }],
    detect(p) {
      const t = compact(p);
      const n = (t.match(/%[0-9a-fA-F]{2}/g) || []).length;
      if (!n) return null;
      return { confidence: clamp(0.5 + n / 10), reason: `${n} percent-encoded sequence${n > 1 ? 's' : ''} such as ${t.match(/%[0-9a-fA-F]{2}/)[0]}` };
    },
    apply: (bytes, p) => (isDecode(p) ? urldecode(latin1(bytes), p.plus === 'yes') : utf8(urlencode(bytes))),
    explain: (p) => dirName(p, 'URL'),
    python: (p) =>
      isDecode(p)
        ? { imports: ['urllib.parse'], code: p.plus === 'yes' ? 'data = urllib.parse.unquote_plus(data.decode()).encode()' : 'data = urllib.parse.unquote_to_bytes(data)' }
        : { imports: ['urllib.parse'], code: 'data = urllib.parse.quote_from_bytes(data, safe="").encode()' },
  },
  {
    id: 'html',
    name: 'HTML entities',
    kind: 'encoding',
    summary: '&#123; &#x7b; &amp; and common named entities.',
    params: [],
    detect(p) {
      const n = (compact(p).match(/&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z]+);/g) || []).length;
      return n ? { confidence: clamp(0.5 + n / 10), reason: `${n} HTML entit${n > 1 ? 'ies' : 'y'}` } : null;
    },
    apply: (bytes) => utf8(htmldecode(latin1(bytes))),
    explain: () => 'HTML entity decode',
    python: () => ({ imports: ['html'], code: 'data = html.unescape(data.decode()).encode()' }),
  },
  {
    id: 'morse',
    name: 'Morse code',
    kind: 'encoding',
    summary: 'Dots and dashes; letters split by spaces, words by /.',
    params: [],
    detect(p) {
      const t = compact(p);
      if (t.length < 3 || !/^[.\-_/|\s]+$/.test(t) || !/[.\-]/.test(t)) return null;
      return { confidence: 0.95, reason: 'Only dots, dashes, spaces and separators' };
    },
    apply: (bytes) => morsedecode(latin1(bytes)),
    explain: () => 'Morse decode',
    python: () => ({ helpers: ['morse'], code: 'data = morse_decode(data)' }),
  },
];

function capital(s) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

export const helpersForTest = { b64decode, b32decode, b32encode, b58decode, b58encode, a85decode, a85encode, b85decode, b85encode, hexdecode, morsedecode, htmldecode };
