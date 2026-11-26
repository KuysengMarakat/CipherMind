// Byte helpers. Every layer in CipherMind is a Uint8Array; text is only a view of it.

const encoder = new TextEncoder();
const strictDecoder = new TextDecoder('utf-8', { fatal: true });
const looseDecoder = new TextDecoder('utf-8');

export const utf8 = (str) => encoder.encode(str);

/** Decode as UTF-8, or return null if the bytes are not valid UTF-8. */
export function tryUtf8(bytes) {
  try {
    return strictDecoder.decode(bytes);
  } catch {
    return null;
  }
}

export const utf8Loose = (bytes) => looseDecoder.decode(bytes);

/** One character per byte (ISO-8859-1). Safe for any byte sequence. */
export function latin1(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 8192) {
    out += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192));
  }
  return out;
}

export function fromLatin1(str) {
  const out = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) out[i] = str.charCodeAt(i) & 0xff;
  return out;
}

export function toHex(bytes, sep = '') {
  const parts = new Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) parts[i] = bytes[i].toString(16).padStart(2, '0');
  return parts.join(sep);
}

export function bytesEqual(a, b) {
  if (a === b) return true;
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** FNV-1a 32-bit plus length: cheap identity key for caching and duplicate-state detection. */
export function hashBytes(bytes) {
  let h = 0x811c9dc5;
  for (let i = 0; i < bytes.length; i++) {
    h ^= bytes[i];
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16) + ':' + bytes.length;
}

const isPrintableAscii = (b) => (b >= 0x20 && b <= 0x7e) || b === 0x09 || b === 0x0a || b === 0x0d;

/** Share of bytes that render as text. Multi-byte UTF-8 counts as printable when the whole input is valid UTF-8. */
export function printableRatio(bytes, validUtf8) {
  if (!bytes.length) return 0;
  let n = 0;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (isPrintableAscii(b) || (validUtf8 && b >= 0x80)) n++;
  }
  return n / bytes.length;
}

/** True when the bytes are best shown as text rather than as a hex dump. */
export function looksTextual(bytes) {
  if (!bytes.length) return true;
  const valid = tryUtf8(bytes) !== null;
  return printableRatio(bytes, valid) >= 0.9;
}

/** Text used for display: UTF-8 when valid, otherwise one char per byte. */
export function displayText(bytes) {
  const s = tryUtf8(bytes);
  return s !== null ? s : latin1(bytes);
}

export function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10240 ? 1 : 0)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function bytesToBase64(bytes) {
  return btoa(latin1(bytes));
}

export function base64ToBytes(b64) {
  return fromLatin1(atob(b64));
}
