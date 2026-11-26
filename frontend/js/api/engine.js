// Client for the planned CipherMind engine (Python, served through FastAPI).
// The contract is documented in frontend/README.md. Until the engine exists, every call
// fails cleanly and the UI falls back to the browser-side operations.

import { bytesToBase64, base64ToBytes } from '../core/bytes.js';

const URL_KEY = 'ciphermind.engineUrl';

// The engine URL comes from the user's saved setting, or from <meta name="ciphermind-engine">
// which the backend can fill in when it serves this page. With neither, no request is made.
function configuredUrl() {
  try {
    const saved = localStorage.getItem(URL_KEY);
    if (saved) return saved;
  } catch {
    /* storage unavailable */
  }
  return document.querySelector('meta[name="ciphermind-engine"]')?.content?.trim() || '';
}

export const engine = {
  baseUrl: configuredUrl(),
  status: 'unknown', // 'unknown' | 'checking' | 'online' | 'offline'
  info: null,

  setBaseUrl(url) {
    this.baseUrl = (url || '').replace(/\/+$/, '');
    try {
      localStorage.setItem(URL_KEY, this.baseUrl);
    } catch {
      /* not persisted */
    }
  },

  async request(path, { method = 'GET', body, timeout = 1500, signal } = {}) {
    if (location.protocol === 'file:') throw new Error('Opened from a file; no engine can be reached.');
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeout);
    signal?.addEventListener('abort', () => ctrl.abort());
    try {
      const res = await fetch(this.baseUrl + path, {
        method,
        headers: body ? { 'Content-Type': 'application/json' } : undefined,
        body: body ? JSON.stringify(body) : undefined,
        signal: ctrl.signal,
      });
      const type = res.headers.get('content-type') || '';
      if (!res.ok) throw new Error(`Engine answered ${res.status} ${res.statusText}`);
      if (!type.includes('json')) throw new Error('Engine URL did not return JSON.');
      return await res.json();
    } finally {
      clearTimeout(timer);
    }
  },

  /** GET /health → { status: "ok", version } */
  async checkHealth() {
    if (!this.baseUrl) {
      this.status = 'offline';
      return this.status;
    }
    this.status = 'checking';
    try {
      const info = await this.request('/health');
      this.info = info;
      this.status = info && info.status === 'ok' ? 'online' : 'offline';
    } catch {
      this.info = null;
      this.status = 'offline';
    }
    return this.status;
  },

  /**
   * POST /solve. Maps the engine's response into the same shape the local search returns,
   * so the results dialog does not care where candidates came from.
   */
  async solve(inputBytes, { flagPrefix, maxDepth = 8, beamWidth = 50, timeLimitS = 30 }, signal) {
    const res = await this.request('/solve', {
      method: 'POST',
      timeout: (timeLimitS + 5) * 1000,
      signal,
      body: { input_b64: bytesToBase64(inputBytes), flag_prefix: flagPrefix || null, max_depth: maxDepth, beam_width: beamWidth, time_limit_s: timeLimitS },
    });
    const labels = { verified: 'Verified', partial: 'Partially verified', unsolved: 'Unsolved' };
    return {
      engine: 'remote',
      explored: res.stats?.states_explored ?? null,
      elapsed: res.stats?.elapsed_ms ?? null,
      depth: res.stats?.max_depth_reached ?? null,
      stopReason: res.stats?.stop_reason ?? '',
      candidates: (res.candidates || []).map((c) => ({
        chain: (c.chain || []).map((s) => ({ opId: s.plugin, params: s.params || {}, note: s.explanation || undefined })),
        bytes: base64ToBytes(c.output_b64 || ''),
        status: { id: c.status, label: labels[c.status] || c.status, detail: c.status_detail || '' },
        score: c.score ?? null,
        nextStep: c.next_step || null,
      })),
    };
  },
};
