// Runs a chain of steps over the input and describes every layer.

import { hashBytes } from './bytes.js';
import { profileBytes } from './profile.js';
import { opById, operations } from '../ops/registry.js';
import { READABLE } from './score.js';

const cache = new Map();
const CACHE_LIMIT = 400;

function cacheKey(prevHash, step) {
  return `${prevHash}|${step.opId}|${JSON.stringify(step.params || {})}`;
}

async function applyStep(bytes, prevHash, step) {
  const key = cacheKey(prevHash, step);
  if (cache.has(key)) return cache.get(key);
  const op = opById[step.opId];
  let result;
  const t0 = performance.now();
  try {
    if (!op) throw new Error(`"${step.opId}" runs only on the CipherMind engine, which is not connected.`);
    const out = await op.apply(bytes, step.params || {});
    result = { bytes: out, error: null, ms: performance.now() - t0 };
  } catch (err) {
    result = { bytes: null, error: err.message || String(err), ms: performance.now() - t0 };
  }
  if (cache.size > CACHE_LIMIT) cache.delete(cache.keys().next().value);
  cache.set(key, result);
  return result;
}

/** Best keyless format guess for a layer, without applying anything. */
export function formatHint(profile) {
  let best = null;
  for (const op of operations) {
    if (!op.detect || op.kind === 'cipher') continue;
    const d = op.detect(profile);
    if (d && (!best || d.confidence > best.confidence)) best = { op, ...d };
  }
  return best && best.confidence >= 0.6 ? best : null;
}

export function layerStatus(layer) {
  if (layer.disabled) return { id: 'skipped', label: 'Skipped' };
  if (layer.blocked) return { id: 'blocked', label: 'Waiting on failed step' };
  if (layer.error) return { id: 'failed', label: 'Failed' };
  const p = layer.profile;
  if (!p.length) return { id: 'empty', label: 'Empty' };
  if (p.flagMatch) return { id: 'flag', label: 'Flag found' };
  if (p.magicTerminal) return { id: 'file', label: p.magicTerminal };
  if (p.flagShape) return { id: 'shape', label: 'Flag shape, wrong prefix' };
  const hint = layer.hint;
  if (hint) return { id: 'encoded', label: `Looks like ${hint.op.name}` };
  if (p.isText && p.english >= READABLE) return { id: 'readable', label: 'Reads as English' };
  if (p.isText) return { id: 'text', label: 'Printable text' };
  return { id: 'binary', label: 'Binary data' };
}

/**
 * Evaluates the chain. Layer 0 is the input; layer i is the output of steps[i-1].
 * Disabled steps pass data through unchanged. After a failure, later layers are marked blocked.
 */
export async function runChain(inputBytes, steps, ctx) {
  const layers = [];
  const inputProfile = profileBytes(inputBytes, ctx);
  layers.push({ index: 0, step: null, bytes: inputBytes, profile: inputProfile, hint: formatHint(inputProfile) });
  let current = inputBytes;
  let currentHash = hashBytes(inputBytes);
  let failed = false;
  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    if (failed) {
      layers.push({ index: i + 1, step, bytes: null, blocked: true });
      continue;
    }
    if (step.disabled) {
      layers.push({ index: i + 1, step, bytes: current, disabled: true, profile: layers[layers.length - 1].profile });
      continue;
    }
    const r = await applyStep(current, currentHash, step);
    if (r.error) {
      failed = true;
      layers.push({ index: i + 1, step, bytes: null, error: r.error });
      continue;
    }
    current = r.bytes;
    currentHash = hashBytes(current);
    const profile = profileBytes(current, ctx);
    layers.push({ index: i + 1, step, bytes: current, profile, hint: formatHint(profile), ms: r.ms });
  }
  for (const l of layers) l.status = layerStatus(l);
  return layers;
}

/** Status of the chain as a whole, using the proposal's three labels. */
export function resultStatus(layers) {
  const last = [...layers].reverse().find((l) => !l.disabled);
  if (!last || last.error || last.blocked) {
    return { id: 'unsolved', label: 'Unsolved', detail: 'The last step failed, so there is no result yet.' };
  }
  const p = last.profile;
  if (p.flagMatch) return { id: 'verified', label: 'Verified', detail: `Flag pattern matched: ${p.flagMatch}`, value: p.flagMatch };
  if (p.magicTerminal) return { id: 'verified', label: 'Verified', detail: `Recognised file signature: ${p.magicTerminal}` };
  if (p.flagShape) return { id: 'partial', label: 'Partially verified', detail: `Has the shape of a flag (${p.flagShape}) but not the expected prefix.` };
  if (p.isText && p.english >= READABLE) return { id: 'partial', label: 'Partially verified', detail: 'Reads as English, but no hard check confirms it.' };
  return { id: 'unsolved', label: 'Unsolved', detail: last.hint ? `Another layer is likely: ${last.hint.reason.toLowerCase()}.` : 'No convincing plaintext yet.' };
}
