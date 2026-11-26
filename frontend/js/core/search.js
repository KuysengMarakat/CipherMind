// Local quick search: a small beam search in the browser that expands states with suggestNext().
// It is a real search over real operations, but much smaller than the planned Python engine
// (no backtracking, no substitution solver, no RSA). The UI labels it as such.

import { hashBytes } from './bytes.js';
import { suggestNext, progressOf, plaintextScore } from './suggest.js';
import { profileBytes } from './profile.js';
import { runChain, resultStatus } from './pipeline.js';

export const LOCAL_BUDGET = { maxDepth: 6, beamWidth: 8, branch: 5, timeMs: 4000 };

const tick = () => new Promise((r) => setTimeout(r, 0));

export async function localSearch(inputBytes, ctx, { onProgress, signal } = {}) {
  const budget = { ...LOCAL_BUDGET, ...(ctx.budget || {}) };
  const t0 = performance.now();
  const seen = new Set([hashBytes(inputBytes)]);
  let beam = [{ bytes: inputBytes, chain: [], score: progressOf(profileBytes(inputBytes, ctx)).score }];
  const finished = [];
  const explored_ = []; // every state seen, so a good early result is not lost when the beam moves on
  let explored = 0;
  let depth = 0;
  let stopReason = 'Search space exhausted';

  outer: for (depth = 1; depth <= budget.maxDepth; depth++) {
    const next = [];
    for (const state of beam) {
      if (signal?.aborted) {
        stopReason = 'Stopped by you';
        break outer;
      }
      if (performance.now() - t0 > budget.timeMs) {
        stopReason = `Time budget (${budget.timeMs / 1000}s) used up`;
        break outer;
      }
      const suggestions = await suggestNext(state.bytes, ctx);
      for (const s of suggestions.slice(0, budget.branch)) {
        const h = hashBytes(s.output);
        if (seen.has(h)) continue;
        seen.add(h);
        explored++;
        const child = {
          bytes: s.output,
          chain: [...state.chain, { opId: s.opId, params: s.params, note: s.source === 'attack' ? s.reason : undefined }],
          score: progressOf(s.profile).score,
          profile: s.profile,
        };
        child.plain = plaintextScore(s.profile).score;
        explored_.push(child);
        if (s.profile.flagMatch || s.profile.magicTerminal) finished.push(child);
        else next.push(child);
      }
      onProgress?.({ depth, explored, elapsed: performance.now() - t0 });
      await tick();
    }
    if (finished.length) {
      stopReason = 'Found a result that passes a hard check';
      break;
    }
    if (!next.length) break;
    next.sort((a, b) => b.score - a.score);
    beam = next.slice(0, budget.beamWidth);
  }
  if (depth > budget.maxDepth) stopReason = `Depth limit (${budget.maxDepth}) reached`;

  const pool = finished.length ? finished : explored_.filter((c) => c.plain >= 0.3);
  const unique = new Map();
  for (const c of pool) {
    const h = hashBytes(c.bytes);
    if (!unique.has(h) || unique.get(h).chain.length > c.chain.length) unique.set(h, c);
  }
  const ranked = [...unique.values()].sort((a, b) => b.plain - a.plain || a.chain.length - b.chain.length).slice(0, 6);

  // Verification: re-run each chain from the original input and confirm the same output.
  const candidates = [];
  for (const c of ranked) {
    const layers = await runChain(inputBytes, c.chain.map((s) => ({ ...s })), ctx);
    const status = resultStatus(layers);
    const last = layers[layers.length - 1];
    const reproduced = last.bytes && hashBytes(last.bytes) === hashBytes(c.bytes);
    candidates.push({
      chain: c.chain,
      bytes: c.bytes,
      status: reproduced ? status : { id: 'unsolved', label: 'Unsolved', detail: 'Re-running the chain did not reproduce this output.' },
      score: c.score,
    });
  }
  return { candidates, explored, depth: Math.min(depth, budget.maxDepth), elapsed: performance.now() - t0, stopReason, engine: 'local' };
}
