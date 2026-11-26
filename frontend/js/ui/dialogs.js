// Dialogs: auto-solve results, solve script, examples, help, engine connection, engine-only info.

import { h, $ } from './dom.js';
import { icon } from './icons.js';
import { opById } from '../ops/registry.js';
import { examples } from '../examples.js';
import { previewOf, stepTitle } from './format.js';
import { LOCAL_BUDGET } from '../core/search.js';

function shell(dlg, title, body, foot) {
  const id = `${dlg.id}-title`;
  dlg.replaceChildren(
    h(
      'div',
      { class: 'dlg-head' },
      h('h2', { id }, title),
      h('button', { class: 'btn-icon', type: 'button', 'aria-label': 'Close', html: icon('close'), onclick: () => dlg.close() })
    ),
    h('div', { class: 'dlg-body' }, body),
    ...(foot ? [h('div', { class: 'dlg-foot' }, foot)] : [])
  );
}

export function openDialog(dlg) {
  if (!dlg.open) dlg.showModal();
}

// Close on backdrop click.
export function initDialogs() {
  document.querySelectorAll('dialog').forEach((d) =>
    d.addEventListener('click', (e) => {
      if (e.target === d) d.close();
    })
  );
}

/* ---------- Auto-solve ---------- */

export function showSolveRunning(engineOnline, onStop) {
  const dlg = $('#dlg-solve');
  shell(
    dlg,
    'Auto-solve',
    [
      sourceNote(engineOnline),
      h('div', { class: 'solve-progress', id: 'solve-progress' }, h('span', { class: 'spinner' }), h('span', { id: 'solve-progress-text' }, 'Starting search…')),
    ],
    [h('button', { class: 'btn', type: 'button', html: `${icon('stop', { size: 14 })}<span>Stop</span>`, onclick: onStop })]
  );
  openDialog(dlg);
}

function sourceNote(engineOnline) {
  return engineOnline
    ? h('p', { class: 'dlg-note' }, 'Running on the CipherMind engine: beam search with backtracking across every engine plugin.')
    : h(
        'p',
        { class: 'dlg-note is-local' },
        h('strong', {}, 'Engine offline, so this is the local quick search. '),
        `It runs in your browser with real operations: depth up to ${LOCAL_BUDGET.maxDepth}, beam ${LOCAL_BUDGET.beamWidth}, ${LOCAL_BUDGET.timeMs / 1000} s. It covers the encodings, Caesar, Atbash, Vigenère and XOR attacks shown in the library. The full engine adds backtracking, the substitution solver and RSA checks.`
      );
}

export function updateSolveProgress({ depth, explored, elapsed }) {
  const t = $('#solve-progress-text');
  if (t) t.textContent = `Depth ${depth}, ${explored} states explored, ${(elapsed / 1000).toFixed(1)} s`;
}

const STATUS_TONE = { verified: 'ok', partial: 'warn', unsolved: 'muted' };

export function showSolveResults(res, engineOnline, onLoad) {
  const dlg = $('#dlg-solve');
  const items = res.candidates.filter((c) => c.status.id !== 'unsolved' || c.chain.length);
  const verified = items.filter((c) => c.status.id === 'verified');
  const body = [sourceNote(engineOnline)];
  if (!items.length) {
    body.push(
      h('p', {}, h('strong', {}, 'Unsolved. '), 'No chain produced readable text, a flag or a known file within the budget.'),
      h('p', { class: 'empty-note' }, 'Look at the Checks section for this input: it may be a hash (one-way), RSA parameters (engine), or a cipher that needs a key you have to find elsewhere in the challenge.')
    );
  } else {
    body.push(
      h(
        'p',
        { class: 'empty-note', style: 'margin-bottom:8px' },
        verified.length ? `${verified.length} verified result${verified.length > 1 ? 's' : ''}. Every chain below was re-run from the original input.` : 'No verified result. These are the best leads, not answers.'
      )
    );
    for (const c of items) {
      const pv = previewOf(c.bytes, 300);
      body.push(
        h(
          'div',
          { class: 'solve-cand' },
          h(
            'div',
            { class: 'solve-path' },
            h('span', { class: 'chip', 'data-tone': STATUS_TONE[c.status.id] }, c.status.label),
            c.chain.map((s, i) => [i ? h('span', { class: 'sep', 'aria-hidden': 'true' }, '›') : null, h('span', { class: 'step' }, opById[s.opId] ? stepTitle(s) : `${s.opId} (engine)`)])
          ),
          h('button', { class: 'btn btn-sm', type: 'button', onclick: () => onLoad(c) }, 'Load chain'),
          h('div', { class: 'solve-out' }, pv.text),
          c.status.detail ? h('div', { class: 'solve-detail' }, c.status.detail) : null
        )
      );
    }
  }
  const stats = [];
  if (res.explored !== null) stats.push(`${res.explored} states explored`);
  if (res.depth !== null) stats.push(`depth ${res.depth}`);
  if (res.elapsed !== null) stats.push(`${(res.elapsed / 1000).toFixed(2)} s`);
  body.push(h('p', { class: 'solve-stats' }, `${stats.join(', ')}. Stopped: ${res.stopReason.charAt(0).toLowerCase()}${res.stopReason.slice(1)}.`));
  shell(dlg, 'Auto-solve', body, [h('button', { class: 'btn', type: 'button', onclick: () => dlg.close() }, 'Close')]);
  openDialog(dlg);
}

/* ---------- Script ---------- */

function highlightPython(code) {
  const frag = document.createDocumentFragment();
  const re = /("""[\s\S]*?"""|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|#[^\n]*|\b(?:def|return|import|for|in|if|elif|else|try|except|while|and|or|not|is|None|True|False)\b)/g;
  let last = 0;
  for (const m of code.matchAll(re)) {
    frag.append(code.slice(last, m.index));
    const t = m[0];
    const cls = t.startsWith('#') ? 'c' : /^["']/.test(t) ? 's' : 'k';
    frag.append(h('span', { class: cls }, t));
    last = m.index + t.length;
  }
  frag.append(code.slice(last));
  return frag;
}

export function showScript(code, { onCopy, onDownload, stepCount }) {
  const dlg = $('#dlg-script');
  shell(
    dlg,
    'Solve script',
    [
      h('p', { class: 'empty-note', style: 'margin-bottom:12px' }, stepCount ? `Python 3 reproduction of the ${stepCount}-step chain, standard library only. Paste it into a write-up or run it to check the result.` : 'The chain has no steps yet, so this script only prints the input.'),
      h('pre', { class: 'code-block', tabindex: '0' }, highlightPython(code)),
    ],
    [
      h('button', { class: 'btn', type: 'button', html: `${icon('download', { size: 14 })}<span>Save solve.py</span>`, onclick: onDownload }),
      h('button', { class: 'btn btn-primary', type: 'button', html: `${icon('copy', { size: 14 })}<span>Copy script</span>`, onclick: onCopy }),
    ]
  );
  openDialog(dlg);
}

/* ---------- Examples ---------- */

export function showExamples(onPick) {
  const dlg = $('#dlg-examples');
  shell(
    dlg,
    'Examples',
    [
      h('p', { class: 'empty-note', style: 'margin-bottom:12px' }, 'Each sample was generated with Python, so the answer is known. Loading one replaces the current input and steps; Undo brings them back.'),
      h(
        'div',
        { class: 'examples' },
        examples.map((ex) =>
          h(
            'button',
            { class: 'example-btn', type: 'button', onclick: () => { dlg.close(); onPick(ex); } },
            h('strong', {}, ex.title),
            h('span', {}, ex.flagPrefix ? `prefix ${ex.flagPrefix}` : ''),
            h('span', { style: 'grid-column:1/-1' }, ex.description),
            h('code', {}, ex.input.slice(0, 90))
          )
        )
      ),
    ]
  );
  openDialog(dlg);
}

/* ---------- Help ---------- */

export function showHelp() {
  const dlg = $('#dlg-help');
  const term = (t, d) => [h('dt', {}, t), h('dd', {}, d)];
  const key = (k, d) => [h('dt', {}, k.split('+').map((x, i) => [i ? '+' : '', h('kbd', {}, x)])), h('dd', {}, d)];
  shell(dlg, 'How CipherMind works', [
    h('h3', { class: 'help-h' }, 'The workflow'),
    h('p', {}, 'Paste the challenge into the input. Each step you add takes the layer above it and produces a new layer, so the chain reads top to bottom from ciphertext to answer. Select any layer to inspect it; suggestions in the Inspector are always for the selected layer.'),
    h('h3', { class: 'help-h' }, 'Terms, kept apart on purpose'),
    h(
      'dl',
      { class: 'terms' },
      term('Decoding', 'Reversing a public format such as Base64 or hex. There is no secret, so it always works once the format is identified.'),
      term('Decryption', 'Reversing encryption with the right key. Without the key it is not possible.'),
      term('Cryptanalysis', 'Recovering the plaintext or key without being given the key, by exploiting a weakness. In CipherMind these are the Attacks; they propose keys, they never sit in the chain themselves.'),
      term('Brute force', 'Trying every key. Only practical for tiny key spaces, such as the 25 Caesar shifts.'),
      term('Known plaintext', 'Using part of the answer you already know, such as the flag prefix, to derive the key. Very effective against XOR and Vigenère.'),
      term('Hashing', 'A one-way function. A hash can be identified and guesses can be checked against it, but it cannot be decoded.')
    ),
    h('h3', { class: 'help-h' }, 'Result labels'),
    h(
      'dl',
      { class: 'terms' },
      term('Verified', 'A hard check passed: the flag pattern matched or a known file signature was found, and the chain reproduces it from the input.'),
      term('Partially verified', 'The output looks right (reads as English, or has a flag shape with a different prefix) but no hard check confirms it.'),
      term('Unsolved', 'No convincing result yet. The Inspector lists the best leads.')
    ),
    h('h3', { class: 'help-h' }, 'Keyboard'),
    h(
      'dl',
      { class: 'keys' },
      key('Ctrl+Z', 'Undo a chain change'),
      key('Ctrl+Shift+Z', 'Redo'),
      key('Ctrl+Enter', 'Auto-solve'),
      key('/', 'Find an operation'),
      key('↑/↓', 'Move between layers when a layer name has focus'),
      key('Alt+↑', 'Move the selected step up (Alt+↓ moves it down)'),
      key('Delete', 'Remove the focused step'),
      key('?', 'This help')
    ),
    h('h3', { class: 'help-h' }, 'What runs where'),
    h(
      'table',
      { class: 'where' },
      h('thead', {}, h('tr', {}, h('th', {}, 'Feature'), h('th', {}, 'Browser now'), h('th', {}, 'Python engine'))),
      h(
        'tbody',
        {},
        [
          ['Encodings, classical ciphers, XOR, decompression', 'Yes, real', 'Yes'],
          ['Profile, entropy, IoC, hash identification', 'Yes, real', 'Yes'],
          ['Caesar, affine, Vigenère, XOR key recovery', 'Yes, real', 'Yes'],
          ['Next-layer suggestions', 'Yes, local heuristics', 'Yes, plugin detect()'],
          ['Auto-solve', 'Small beam search', 'Full beam search, backtracking'],
          ['Substitution solver, RSA and AES checks, dictionary checks', 'No', 'Planned'],
        ].map((r) => h('tr', {}, r.map((c) => h('td', {}, c))))
      )
    ),
  ]);
  openDialog(dlg);
}

/* ---------- Engine ---------- */

export function showEngine(engine, onSave) {
  const dlg = $('#dlg-engine');
  const input = h('input', { class: 'field', type: 'text', value: engine.baseUrl, placeholder: '/api or http://127.0.0.1:8000/api', spellcheck: 'false', id: 'engine-url' });
  const status = h('p', { class: 'empty-note', id: 'engine-test' }, statusText(engine));
  shell(
    dlg,
    'Engine connection',
    [
      h('p', {}, 'The Python engine is not built yet. Until it answers, everything you see runs in the browser and Auto-solve uses the local quick search. When FastAPI serves this page it can fill in the engine URL for you; otherwise enter it here.'),
      h('div', { class: 'form-row' }, h('label', { for: 'engine-url' }, 'Engine base URL'), input),
      h('pre', { class: 'endpoint-list' }, 'GET  {base}/health   → { "status": "ok", "version": "…" }\nGET  {base}/plugins  → [{ "id", "name", "kind", "params" }]\nPOST {base}/solve    → candidates with chain, status, output_b64'),
      status,
    ],
    [
      h('button', { class: 'btn', type: 'button', onclick: () => dlg.close() }, 'Close'),
      h(
        'button',
        {
          class: 'btn btn-primary',
          type: 'button',
          onclick: async () => {
            status.textContent = 'Testing…';
            await onSave(input.value.trim());
            status.textContent = statusText(engine);
          },
        },
        'Save and test'
      ),
    ]
  );
  openDialog(dlg);
}

function statusText(engine) {
  if (engine.status === 'online') return `Connected${engine.info?.version ? `, engine version ${engine.info.version}` : ''}.`;
  if (location.protocol === 'file:') return 'Not connected: the page was opened as a file. Serve the folder over HTTP to reach an engine.';
  if (!engine.baseUrl) return 'No engine URL set, so nothing is contacted. Everything runs in the browser.';
  return `Not connected: nothing answered at ${engine.baseUrl}/health.`;
}

export function showEngineOnly(item) {
  const dlg = $('#dlg-info');
  shell(
    dlg,
    item.name,
    [
      h('p', {}, item.summary),
      h('p', { class: 'dlg-note' }, 'This is planned for the CipherMind Python engine and is not implemented in the browser. The workbench does not simulate it, so it will not produce output until the engine is connected.'),
    ],
    [h('button', { class: 'btn', type: 'button', onclick: () => dlg.close() }, 'Close')]
  );
  openDialog(dlg);
}
