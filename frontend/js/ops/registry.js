// Operation registry: the browser-side mirror of the engine's plugin registry.
// When the Python engine is connected, its /plugins list can extend or replace these.

import { encodingOps, OpError } from './encodings.js';
import { classicalOps, transformOps } from './classical.js';
import { compressionOps } from './compression.js';
import { attacks } from './attacks.js';

export { OpError };

// Text encodings cannot apply to binary data, so their detect() is skipped for it.
for (const op of encodingOps) {
  const detect = op.detect;
  if (detect) op.detect = (p) => (p.isText ? detect(p) : null);
}

export const operations = [...encodingOps, ...classicalOps, ...transformOps, ...compressionOps];
export const opById = Object.fromEntries(operations.map((op) => [op.id, op]));

export function defaultParams(op) {
  const p = {};
  for (const param of op.params || []) p[param.id] = param.default;
  return p;
}

/** Library groups. Kinds are kept apart on purpose: encoding ≠ encryption ≠ hashing. */
export const libraryGroups = [
  {
    id: 'encoding',
    title: 'Encodings',
    note: 'Keyless and public. Decoding always works once the format is right.',
    items: encodingOps.map((op) => ({ type: 'op', op })),
  },
  {
    id: 'cipher',
    title: 'Ciphers with a key',
    note: 'Decrypt when you know the key, or after an attack recovers it.',
    items: classicalOps.map((op) => ({ type: 'op', op })),
  },
  {
    id: 'attack',
    title: 'Attacks',
    note: 'Recover a key from the selected layer. Results are ranked guesses; you choose one to add.',
    items: attacks.map((attack) => ({ type: 'attack', attack })),
  },
  {
    id: 'compression',
    title: 'Decompress',
    note: 'Undo gzip, zlib and deflate.',
    items: compressionOps.map((op) => ({ type: 'op', op })),
  },
  {
    id: 'transform',
    title: 'Rearrange',
    note: 'Reorder bytes without changing them.',
    items: transformOps.map((op) => ({ type: 'op', op })),
  },
  {
    id: 'hash',
    title: 'Hashes',
    note: 'One-way. A hash can be identified, and guesses checked against it, but never decoded.',
    items: [
      { type: 'inspect', id: 'hash-id', name: 'Identify hash type', summary: 'Shown in the Inspector for the selected layer.', section: 'signals' },
      { type: 'engine', id: 'hash-dict', name: 'Dictionary check', summary: 'Test a wordlist against a hash you are authorised to test.' },
    ],
  },
  {
    id: 'engine',
    title: 'Needs the CipherMind engine',
    note: 'Planned in the Python engine. Not available in the browser.',
    items: [
      { type: 'engine', id: 'beam-search', name: 'Full beam search', summary: 'Depth 8, beam 50, backtracking, solve-script export.' },
      { type: 'engine', id: 'substitution-solve', name: 'Substitution solver', summary: 'Quadgram hill climbing with random restarts.' },
      { type: 'engine', id: 'rsa-checks', name: 'RSA weakness checks', summary: 'Small e root, Håstad, common modulus, Wiener, Fermat, shared GCD.' },
      { type: 'engine', id: 'aes-usage', name: 'AES usage checks', summary: 'ECB block repetition, key or nonce reuse.' },
      { type: 'engine', id: 'math', name: 'Modular arithmetic', summary: 'GCD, inverse, CRT, integer roots, factoring attempts.' },
    ],
  },
];

export const KIND_LABEL = {
  encoding: 'Encoding',
  cipher: 'Cipher',
  compression: 'Decompress',
  transform: 'Rearrange',
};
