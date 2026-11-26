// Plaintext scoring: how much a byte sequence looks like readable English or a flag.
// These are soft signals (Module F in the proposal). Hard checks live in checks.js.

import { tryUtf8, printableRatio, latin1 } from './bytes.js';

// Relative letter frequencies of English text (percent), A–Z.
export const ENGLISH_FREQ = [
  8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406,
  6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.36, 0.15, 1.974, 0.074,
];

const COMMON_BIGRAMS = new Set(
  'th he in er an re nd on en at ou ed ha to or it is hi es ng ve st nt ar te se of al le ea ti as ne co me de ri ro li ra io'.split(' ')
);

export function letterCounts(bytes) {
  const counts = new Array(26).fill(0);
  let total = 0;
  for (let i = 0; i < bytes.length; i++) {
    let b = bytes[i];
    if (b >= 97 && b <= 122) b -= 32;
    if (b >= 65 && b <= 90) {
      counts[b - 65]++;
      total++;
    }
  }
  return { counts, total };
}

/** Chi-squared distance between observed letter counts and English. Lower is more English-like. */
export function chiSquared(counts, total) {
  if (!total) return Infinity;
  let chi = 0;
  for (let i = 0; i < 26; i++) {
    const expected = (ENGLISH_FREQ[i] / 100) * total;
    const d = counts[i] - expected;
    chi += (d * d) / expected;
  }
  return chi;
}

/** Index of coincidence over letters. English ≈ 0.067, uniformly random letters ≈ 0.038. */
export function indexOfCoincidence(counts, total) {
  if (total < 2) return 0;
  let sum = 0;
  for (const c of counts) sum += c * (c - 1);
  return sum / (total * (total - 1));
}

function bigramScore(text) {
  const lower = text.toLowerCase();
  let hits = 0;
  let pairs = 0;
  for (let i = 0; i < lower.length - 1; i++) {
    const a = lower.charCodeAt(i);
    const b = lower.charCodeAt(i + 1);
    if (a >= 97 && a <= 122 && b >= 97 && b <= 122) {
      pairs++;
      if (COMMON_BIGRAMS.has(lower[i] + lower[i + 1])) hits++;
    }
  }
  return pairs ? hits / pairs : 0;
}

// Frequent English words plus words common in CTF plaintexts. Helps short phrases where letter statistics are weak.
const COMMON_WORDS = new Set(
  ('the be to of and a in that have i it for not on with he as you do at this but his by from they we say her she or an will my one all would there their what so up out if about who get which go me when make can like time no just him know take people into year your good some could them see other than then now look only come its over think also back after use two how our work first well way even new want because any these give day most us is are was were been has had did said very here more where why may such each find must own under last long great little right still own old big high small large next early young few public same able ' +
    'hello world flag key secret password message cipher crypto code text hidden answer win congrats congratulations correct found decode decrypt encrypted plain welcome nice done')
    .split(' ')
    .filter(Boolean)
);

function wordScore(text) {
  const words = text.toLowerCase().match(/[a-z]{2,}/g);
  if (!words || words.length < 2) return 0;
  let hits = 0;
  for (const w of words) if (COMMON_WORDS.has(w)) hits++;
  return hits / words.length;
}

/**
 * English fitness in 0..1. Combines printable ratio, monogram chi-squared per letter,
 * common-bigram share and the presence of word spacing. Short strings are scored cautiously.
 */
export function englishFitness(bytes) {
  if (!bytes.length) return 0;
  const valid = tryUtf8(bytes) !== null;
  const pr = printableRatio(bytes, valid);
  if (pr < 0.9) return pr * 0.15;
  const { counts, total } = letterCounts(bytes);
  if (total < 4) return 0.25 * pr;
  const text = latin1(bytes);
  const chiPerLetter = chiSquared(counts, total) / total;
  const mono = Math.exp(-chiPerLetter * 2.2);
  const bi = Math.min(1, bigramScore(text) / 0.38);
  const spaces = (text.match(/ /g) || []).length;
  const wordy = spaces > 0 && total / Math.max(spaces, 1) < 9 ? 1 : 0.6;
  const letterShare = total / bytes.length;
  const lengthTrust = Math.min(1, total / 25);
  const raw = 0.45 * bi + 0.35 * mono + 0.2 * wordy;
  // Blend towards a neutral 0.35 for short inputs where statistics are unreliable,
  // unless most of the words are common English words.
  const words = wordScore(text);
  const blended = Math.max(raw * lengthTrust + 0.35 * (1 - lengthTrust), words >= 0.5 ? 0.45 + 0.4 * words : 0);
  return Math.max(0, Math.min(1, blended * (0.6 + 0.4 * Math.min(1, letterShare / 0.6)) * pr));
}

/** Escape a user string for use inside a RegExp. */
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export const COMMON_FLAG_PREFIXES = ['CTF', 'flag', 'FLAG', 'picoCTF', 'HTB', 'THM', 'DUCTF', 'CSCTF'];

/** Builds the regex for a hard flag match. An empty prefix accepts the common CTF prefixes. */
export function flagRegex(prefix) {
  const p = (prefix || '').trim().replace(/\{+$/, '');
  const alt = p ? escapeRe(p) : COMMON_FLAG_PREFIXES.map(escapeRe).join('|');
  return new RegExp(`(?:${alt})\\{[\\x20-\\x7c\\x7e]{1,200}?\\}`);
}

/** Generic “something{...}” shape. Only a soft signal: PGS{...} has the shape but is not a flag. */
export const FLAG_SHAPE = /[A-Za-z0-9_]{2,16}\{[\x20-\x7c\x7e]{3,200}?\}/;

/** English fitness at or above this counts as "reads as English" (a soft signal, never "verified"). */
export const READABLE = 0.5;
