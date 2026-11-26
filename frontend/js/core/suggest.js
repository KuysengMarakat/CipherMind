// "What to try next" for one layer: cheap detection, a trial run, and a score for the result.
// Everything here is computed locally from the data. Nothing is invented.

import { hashBytes, bytesEqual, latin1 } from './bytes.js';
import { profileBytes } from './profile.js';
import { operations, defaultParams } from '../ops/registry.js';
import { attackById } from '../ops/attacks.js';
import { formatHint } from './pipeline.js';
import { flagRegex, READABLE } from './score.js';

const cache = new Map();

/** Plaintext-likeness only: used for attack outputs and final ranking, where "looks encoded" is not progress. */
export function plaintextScore(profile) {
  if (profile.flagMatch) return { score: 1, why: 'output matches the flag format' };
  if (profile.magicTerminal) return { score: 0.9, why: `output is a ${profile.magicTerminal}` };
  if (profile.flagShape) return { score: Math.max(0.7, profile.english), why: 'output has a flag-like shape' };
  if (!profile.isText) return { score: 0, why: 'output is binary noise' };
  return { score: profile.english, why: profile.english >= READABLE ? 'output reads as English' : 'output is printable' };
}

/** How much closer to a solution an output looks: plaintext, a flag, a file, or another recognisable layer. */
export function progressOf(profile) {
  if (profile.flagMatch) return { score: 1, why: 'output matches the flag format' };
  if (profile.magicTerminal) return { score: 0.9, why: `output is a ${profile.magicTerminal}` };
  let encoded = 0;
  let encodedName = '';
  for (const op of operations) {
    if (!op.detect || op.kind === 'cipher') continue;
    const d = op.detect(profile);
    if (d && d.confidence > encoded) {
      encoded = d.confidence;
      encodedName = op.name;
    }
  }
  const english = profile.isText ? profile.english : 0;
  const shape = profile.flagShape ? 0.7 : 0;
  const best = Math.max(english, encoded * 0.8, shape);
  let why = 'output is binary noise';
  if (best === shape && shape) why = 'output has a flag-like shape';
  else if (best === encoded * 0.8 && encoded > 0.5) why = `output looks like ${encodedName}`;
  else if (english >= READABLE) why = 'output reads as English';
  else if (profile.isText) why = 'output is printable';
  return { score: best, why };
}

export function levelOf(c) {
  if (c >= 0.7) return 'high';
  if (c >= 0.45) return 'medium';
  return 'low';
}

async function tryOp(bytes, op, params, ctx) {
  try {
    const out = await op.apply(bytes, params);
    if (!out || !out.length || bytesEqual(out, bytes)) return null;
    return { out, profile: profileBytes(out, ctx) };
  } catch {
    return null;
  }
}

function attackSuggestion(attackId, bytes, ctx, why) {
  const attack = attackById[attackId];
  const res = attack.run(bytes, ctx);
  const best = res.candidates[0];
  if (!best) return null;
  const profile = profileBytes(best.output, ctx);
  return { best, profile, attack, why };
}

/**
 * Returns ranked suggestions for the next step after `bytes`.
 * Each: { opId, params, confidence, level, reason, outcome, output, profile, source, attackId? }
 */
export async function suggestNext(bytes, ctx = {}) {
  const key = hashBytes(bytes) + '|' + (ctx.flagPrefix || '');
  if (cache.has(key)) return cache.get(key);
  const profile = profileBytes(bytes, ctx);
  const baseline = plaintextScore(profile).score;
  const out = [];

  for (const op of operations) {
    if (!op.detect) continue;
    const d = op.detect(profile);
    if (!d || d.confidence < 0.1) continue;
    const params = defaultParams(op);
    const trial = await tryOp(bytes, op, params, ctx);
    if (!trial) continue;
    const prog = progressOf(trial.profile);
    // A clear format match is worth trying even when the output is binary (encrypted data, a file).
    const confidence = Math.min(1, Math.max(0.75 * d.confidence, 0.55 * d.confidence + 0.45 * prog.score));
    out.push({ opId: op.id, params, confidence, reason: d.reason, outcome: prog.why, output: trial.out, profile: trial.profile, source: 'detect' });
  }

  // Classical attacks only make sense on letter-heavy text that is not already English.
  // Skip them when the data clearly looks like an encoding (Base64 letters are not cipher letters),
  // and require some text structure: word spacing or a flag-like shape.
  const letterHeavy = profile.isText && profile.letterTotal >= 6 && profile.letterShare >= 0.35;
  const looksEncoded = formatHint(profile);
  const textLike = /[ \n]/.test(profile.ascii.trim()) || !!profile.flagShape;
  if (letterHeavy && textLike && !looksEncoded && profile.english < READABLE && !profile.flagMatch && bytes.length <= 262144) {
    const tries = [['caesar-brute', 'Brute-forced all 25 Caesar shifts']];
    if (profile.letterTotal >= 60 && profile.ioc < 0.058) tries.push(['vigenere-recover', `Letter IoC ${profile.ioc.toFixed(3)} is below English (0.067), suggesting a polyalphabetic cipher`]);
    for (const [id, why] of tries) {
      const s = attackSuggestion(id, bytes, ctx, why);
      if (!s) continue;
      const prog = plaintextScore(s.profile);
      if (prog.score < Math.max(0.45, baseline + 0.15)) continue;
      out.push({ opId: s.best.opId, params: s.best.params, confidence: Math.min(1, 0.35 + 0.6 * prog.score), reason: `${s.why}; best key: ${s.best.label}`, outcome: prog.why, output: s.best.output, profile: s.profile, source: 'attack', attackId: id });
    }
    // Atbash has a single key, so just try it.
    const atbash = operations.find((o) => o.id === 'atbash');
    const t = await tryOp(bytes, atbash, {}, ctx);
    if (t) {
      const prog = plaintextScore(t.profile);
      if (prog.score >= Math.max(0.5, baseline + 0.15)) out.push({ opId: 'atbash', params: {}, confidence: 0.3 + 0.6 * prog.score, reason: 'Mirrored alphabet produces better text', outcome: prog.why, output: t.out, profile: t.profile, source: 'attack' });
    }
  }

  // XOR attacks for binary-looking data.
  if (!profile.isText && bytes.length >= 4 && bytes.length <= 8192 && !profile.magic) {
    const tries = [['xor-single', 'Tried all 255 single-byte XOR keys']];
    if (ctx.flagPrefix) tries.unshift(['xor-known', `Used the flag prefix ${ctx.flagPrefix} as known plaintext`]);
    if (bytes.length >= 24) tries.push(['xor-repeating', 'Estimated a repeating XOR key from Hamming distances']);
    for (const [id, why] of tries) {
      const s = attackSuggestion(id, bytes, ctx, why);
      if (!s) continue;
      const prog = plaintextScore(s.profile);
      if (prog.score < 0.45) continue;
      out.push({ opId: s.best.opId, params: s.best.params, confidence: Math.min(1, 0.3 + 0.65 * prog.score), reason: `${s.why}; best: ${s.best.label}`, outcome: prog.why, output: s.best.output, profile: s.profile, source: 'attack', attackId: id });
    }
  }

  // Same output from two routes: keep the stronger suggestion.
  const seen = new Map();
  for (const s of out) {
    const h = hashBytes(s.output);
    if (!seen.has(h) || seen.get(h).confidence < s.confidence) seen.set(h, s);
  }
  const ranked = [...seen.values()].sort((a, b) => b.confidence - a.confidence);
  for (const s of ranked) s.level = levelOf(s.confidence);
  if (cache.size > 200) cache.delete(cache.keys().next().value);
  cache.set(key, ranked);
  return ranked;
}

export function flagIn(bytes, prefix) {
  return (latin1(bytes).match(flagRegex(prefix)) || [null])[0];
}
