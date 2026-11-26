// Inspector: everything about the selected layer. Analysis (what to try, checks, profile, distribution,
// attacks), Data (full output in text, hex or Base64) and Compare (any two layers side by side).

import { h, $, $$, preserveFocus } from './dom.js';
import { icon } from './icons.js';
import { opById } from '../ops/registry.js';
import { attacks } from '../ops/attacks.js';
import { ENGLISH_FREQ, READABLE } from '../core/score.js';
import { displayText, toHex, bytesToBase64, looksTextual } from '../core/bytes.js';
import { formatBytes, stepTitle, previewOf, confidenceEl, pluralize } from './format.js';
import { helpersForTest as enc } from '../ops/encodings.js';

let H = {};
const expanded = new Set(); // layer keys whose low-confidence suggestions are shown
const openSections = { profile: true, dist: true, attacks: false };
let dataLimit = 16384;

export function initInspector(handlers) {
  H = handlers;
  $$('.tabs [role="tab"]').forEach((t) => t.addEventListener('click', () => H.onTab(t.dataset.tab)));
  $('.tabs').addEventListener('keydown', (e) => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
    const tabs = $$('.tabs [role="tab"]');
    const i = tabs.indexOf(document.activeElement);
    if (i < 0) return;
    const next = tabs[(i + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length];
    next.focus();
    H.onTab(next.dataset.tab);
  });
}

const layerKey = (state, layer) => (layer.index === 0 ? 'input' : state.steps[layer.index - 1]?.uid) + ':' + (layer.bytes?.length ?? 'x');

function layerName(state, i) {
  return i === 0 ? 'Input' : stepTitle(state.steps[i - 1]);
}

/* ---------- Analysis ---------- */

function headEl(state, layer, total) {
  const kicker = layer.index === 0 ? 'Input' : `Layer ${layer.index} of ${total}`;
  const title = layer.index === 0 ? 'Input' : layerName(state, layer.index);
  const lbl = layer.status.label;
  const sub = layer.bytes ? `${formatBytes(layer.bytes.length)}, ${lbl.charAt(0).toLowerCase()}${lbl.slice(1)}` : lbl;
  return h('header', { class: 'insp-head' }, h('div', { class: 'insp-kicker' }, kicker), h('h2', { class: 'insp-title' }, title), h('p', { class: 'insp-sub' }, sub));
}

function suggestionsSection(state, layer, suggestions) {
  const sec = h('section', { class: 'section', 'aria-labelledby': 'sec-next' });
  sec.append(h('h3', { class: 'section-title', id: 'sec-next' }, 'What to try next', h('span', { class: 'section-hint' }, 'Local checks, ranked')));
  if (layer.profile.flagMatch) {
    sec.append(h('p', { class: 'empty-note' }, 'This layer contains the flag. Nothing further to undo; copy it from the result below the chain.'));
    return sec;
  }
  if (suggestions === null) {
    sec.append(h('p', { class: 'loading-note' }, h('span', { class: 'spinner' }), 'Trying likely formats on this layer…'));
    return sec;
  }
  if (!suggestions.length) {
    const p = layer.profile;
    let msg = 'No encoding or cipher was recognised here.';
    if (p.flagMatch) msg = 'This layer already contains the flag.';
    else if (p.isText && p.english >= READABLE) msg = 'This layer already reads as English, so nothing obvious is left to undo.';
    else if (p.rsa) msg = 'These look like RSA parameters, which the browser cannot attack. See Checks below.';
    sec.append(h('p', { class: 'empty-note' }, msg, ' You can still pick any operation from the library.'));
    return sec;
  }
  const key = layerKey(state, layer);
  const strong = suggestions.filter((s) => s.level !== 'low');
  const weak = suggestions.filter((s) => s.level === 'low');
  const showWeak = expanded.has(key) || !strong.length;
  const shown = [...strong.slice(0, 4), ...(showWeak ? weak : [])];
  for (const s of shown) {
    const op = opById[s.opId];
    const p = previewOf(s.output, 160);
    sec.append(
      h(
        'div',
        { class: 'sugg' },
        h('div', { class: 'sugg-name' }, op.explain(s.params), s.source === 'attack' ? h('span', { class: 'tag', title: 'The key was recovered by an attack, not given' }, 'key recovered') : null),
        h(
          'div',
          { class: 'sugg-side' },
          confidenceEl(s.confidence, s.level),
          h('button', { class: 'btn btn-sm', type: 'button', onclick: () => H.onApplySuggestion(s, layer.index), 'aria-label': `Apply ${op.explain(s.params)}` }, 'Apply')
        ),
        h('p', { class: 'sugg-why' }, `${s.reason}. ${s.outcome.charAt(0).toUpperCase()}${s.outcome.slice(1)}.`),
        h('div', { class: `sugg-out${p.binary ? ' is-binary' : ''}` }, p.text)
      )
    );
  }
  if (weak.length && strong.length) {
    sec.append(
      h(
        'button',
        {
          class: 'btn btn-quiet btn-sm more-btn',
          type: 'button',
          onclick: () => {
            expanded.has(key) ? expanded.delete(key) : expanded.add(key);
            H.onRerender();
          },
        },
        expanded.has(key) ? 'Hide low-confidence guesses' : `Show ${pluralize(weak.length, 'low-confidence guess', 'low-confidence guesses')}`
      )
    );
  }
  return sec;
}

function check(tone, iconName, main, sub) {
  return h('li', { class: 'check', 'data-tone': tone }, h('span', { html: icon(iconName) }), h('div', {}, h('span', { class: 'check-main' }, main), sub ? h('span', { class: 'check-sub' }, sub) : null));
}

function checksSection(state, layer) {
  const p = layer.profile;
  const list = h('ul', { class: 'checks' });
  const prefix = state.flagPrefix?.trim();
  if (p.flagMatch) list.append(check('ok', 'check', ['Flag pattern matched: ', h('code', {}, p.flagMatch)], 'A hard check: this counts as verified.'));
  else if (p.flagShape) list.append(check('warn', 'dot', ['Flag-shaped text, wrong prefix: ', h('code', {}, p.flagShape)], `Expected ${prefix ? prefix : 'a common prefix'}. Often one more layer (such as ROT13) is left.`));
  else list.append(check('none', 'cross', `No flag pattern${prefix ? ` for ${prefix}` : ''}`, null));

  if (p.magic) list.append(check(p.magicTerminal ? 'ok' : 'info', 'file', `File signature: ${p.magic}`, p.magicTerminal ? 'A hard check: recognised file format.' : 'A compressed stream: decompress it to reach the next layer.'));

  list.append(
    check(
      'none',
      'dot',
      p.isUtf8 ? `Valid UTF-8, ${Math.round(p.printable * 100)}% printable` : `Not valid UTF-8, ${Math.round(p.printable * 100)}% printable`,
      p.isText ? null : 'Shown as hex. Binary output usually means a key or format guess was wrong, or that XOR or compression comes next.'
    )
  );

  if (p.hashes.length) {
    let note = 'Hashes are one-way: they cannot be decoded. A dictionary check (engine) can test guesses against hashes you are authorised to test.';
    const t = p.ascii.trim();
    if (/^[0-9a-fA-F]+$/.test(t) && t.length % 2 === 0) {
      try {
        if (looksTextual(enc.hexdecode(t))) note = 'It also decodes from hex to readable text, so it is more likely hex-encoded data than a hash.';
      } catch {
        /* not hex */
      }
    }
    list.append(
      check('info', 'lock', ['Same format as a hash', h('span', { class: 'hash-list' }, p.hashes.map((x) => h('span', { class: 'chip', title: x.note || '' }, x.name)))], note)
    );
  }

  if (p.rsa) {
    const { e, c, bits } = p.rsa;
    const cBits = c !== null ? c.toString(2).length : null;
    let sub = 'RSA weakness checks (small-e root, Wiener, Fermat and others) run in the CipherMind engine, not in the browser.';
    if (e <= 17n && cBits !== null && cBits < bits - 8) sub = `e is ${e} and c is only ${cBits} bits against a ${bits}-bit n, which fits the small-exponent root case (mᵉ < n). Testing it needs the engine.`;
    list.append(check('info', 'key', `RSA parameters: ${bits}-bit n, e = ${e}${c !== null ? ', c present' : ''}`, sub));
  }

  if (p.ecbRepeats) list.append(check('warn', 'dot', `${pluralize(p.ecbRepeats, 'repeated 16-byte block')}`, 'Identical ciphertext blocks are typical of AES in ECB mode. The key cannot be recovered from this alone.'));

  return h('section', { class: 'section', 'aria-labelledby': 'sec-checks' }, h('h3', { class: 'section-title', id: 'sec-checks' }, 'Checks', h('span', { class: 'section-hint' }, 'Hard evidence first')), list);
}

function gauge(value, max, marks = []) {
  return h(
    'div',
    { class: 'gauge', 'aria-hidden': 'true' },
    h('i', { style: `width:${Math.min(100, (value / max) * 100)}%` }),
    marks.map((m) => h('b', { style: `left:${(m.at / max) * 100}%`, title: m.label }))
  );
}

function details(id, title, hint, ...content) {
  const d = h('details', { class: 'section', open: openSections[id] }, h('summary', {}, title, hint ? h('span', { class: 'section-hint' }, hint) : null), ...content);
  d.addEventListener('toggle', () => (openSections[id] = d.open));
  return d;
}

function profileSection(layer) {
  const p = layer.profile;
  const stat = (label, value, extra) => h('div', { class: 'stat' }, h('dt', {}, label), h('dd', {}, value, extra || null));
  const iocOk = p.letterTotal >= 20;
  return details(
    'profile',
    'Profile',
    null,
    h(
      'dl',
      { class: 'stats' },
      stat('Length', formatBytes(p.length), p.lines > 1 ? h('small', {}, ` ${pluralize(p.lines, 'line')}`) : null),
      stat('Character set', p.charset),
      stat('Entropy', [p.entropy.toFixed(2), h('small', {}, ' bits per byte')], gauge(p.entropy, 8)),
      stat('Printable', `${Math.round(p.printable * 100)}%`, gauge(p.printable, 1)),
      stat(
        'Index of coincidence',
        iocOk ? p.ioc.toFixed(4) : h('small', {}, `needs 20+ letters (${p.letterTotal})`),
        iocOk ? gauge(p.ioc, 0.09, [{ at: 0.0385, label: 'Random letters 0.038' }, { at: 0.0667, label: 'English 0.067' }]) : null
      ),
      stat('Distinct bytes', `${p.distinct} of 256`)
    ),
    iocOk ? h('p', { class: 'empty-note', style: 'margin-top:10px;font-size:12px' }, 'IoC marks: random letters 0.038, English 0.067. Near English with odd letter frequencies suggests a transposition or monoalphabetic substitution; near random suggests a polyalphabetic cipher.') : null
  );
}

function distSection(state, layer) {
  const p = layer.profile;
  const view = state.distView === 'bytes' || p.letterTotal < 10 ? 'bytes' : 'letters';
  const seg = h(
    'div',
    { class: 'seg', role: 'group', 'aria-label': 'Distribution view' },
    ['letters', 'bytes'].map((v) => h('button', { type: 'button', 'aria-pressed': String(view === v), disabled: v === 'letters' && p.letterTotal < 10, onclick: () => H.onDistView(v) }, v === 'letters' ? 'Letters A–Z' : 'All bytes'))
  );
  let chart;
  if (view === 'letters') {
    const obs = p.letters.map((c) => (c / p.letterTotal) * 100);
    const max = Math.max(13, ...obs);
    chart = [
      h(
        'div',
        { class: 'dist', role: 'img', 'aria-label': 'Letter frequencies compared with English' },
        obs.map((o, i) => h('div', { class: 'dist-col', title: `${String.fromCharCode(65 + i)}: ${o.toFixed(1)}% (English ${ENGLISH_FREQ[i].toFixed(1)}%)` }, h('i', { style: `height:${(o / max) * 100}%` }), h('b', { style: `bottom:${(ENGLISH_FREQ[i] / max) * 100}%` })))
      ),
      h('div', { class: 'dist-labels', 'aria-hidden': 'true' }, [...'ABCDEFGHIJKLMNOPQRSTUVWXYZ'].map((c) => h('span', {}, c))),
      h('div', { class: 'legend' }, h('span', { class: 'l-obs' }, `This layer (${p.letterTotal} letters)`), h('span', { class: 'l-exp' }, 'English')),
    ];
  } else {
    const max = Math.max(1, ...p.histogram);
    chart = [
      h('div', { class: 'dist-bytes', role: 'img', 'aria-label': 'Byte value histogram' }, p.histogram.map((c) => h('i', { style: `height:${(c / max) * 100}%` }))),
      h('div', { class: 'dist-axis', 'aria-hidden': 'true' }, [[0, '00'], [0x20, '20 space'], [0x7f, '7f'], [0xff, 'ff']].map(([v, l]) => h('span', { style: `left:${(v / 255) * 100}%` }, l))),
    ];
  }
  return details('dist', 'Character distribution', null, seg, ...chart);
}

function attacksSection(state, layer, attackResult) {
  const p = layer.profile;
  const btns = h(
    'div',
    { class: 'attack-btns' },
    attacks.map((a) => {
      let reason = '';
      if (a.needs === 'letters' && p.letterTotal < 6) reason = 'Needs letters';
      if (a.id === 'xor-known' && !state.flagPrefix?.trim()) reason = 'Set a flag prefix first';
      return h('button', { class: 'btn btn-sm', type: 'button', disabled: !!reason, title: reason || a.summary, onclick: () => H.onRunAttack(a.id, layer.index) }, a.name);
    })
  );
  const content = [h('p', { class: 'empty-note', style: 'margin-bottom:10px;font-size:12px' }, 'Attacks recover a key from this layer. Pick a candidate to add it as a keyed step after this layer.'), btns];
  const key = layerKey(state, layer);
  if (attackResult && attackResult.layerKey === key) {
    const { attack, result } = attackResult;
    const shown = result.candidates.slice(0, attackResult.all ? 60 : 6);
    content.push(
      h(
        'div',
        { class: 'attack-result', id: 'attack-result' },
        h('p', { class: 'attack-summary' }, h('strong', {}, attack.name), `: ${result.summary}`),
        result.candidates.length ? null : h('p', { class: 'empty-note' }, 'No candidates.'),
        shown.map((c) => {
          const pv = previewOf(c.output, 120);
          const level = c.flag ? 'high' : c.score >= 0.6 ? 'high' : c.score >= 0.4 ? 'medium' : 'low';
          return h(
            'div',
            { class: `cand${c.flag ? ' is-flag' : ''}` },
            h('div', { class: 'cand-label' }, c.label, c.flag ? h('span', { class: 'chip', 'data-tone': 'ok' }, 'flag') : null),
            h('div', { class: 'sugg-side' }, confidenceEl(c.score, level), h('button', { class: 'btn btn-sm', type: 'button', onclick: () => H.onUseCandidate(c, attack, layer.index) }, 'Use')),
            h('div', { class: 'cand-out', title: pv.text }, pv.text)
          );
        }),
        result.candidates.length > shown.length ? h('button', { class: 'btn btn-quiet btn-sm more-btn', type: 'button', onclick: () => H.onAttackShowAll() }, `Show all ${result.candidates.length}`) : null
      )
    );
  }
  return details('attacks', 'Attacks', 'Key recovery', ...content);
}

function renderAnalysis(root, state, layers, extras) {
  const layer = layers[state.selected];
  root.append(headEl(state, layer, layers.length - 1));
  if (layer.error || layer.blocked) {
    root.append(
      h(
        'section',
        { class: 'section' },
        h('h3', { class: 'section-title' }, 'This step failed'),
        h('p', { class: 'empty-note', style: 'color:var(--bad)' }, layer.error || 'An earlier step failed, so this one did not run.'),
        h('p', { class: 'empty-note', style: 'margin-top:8px' }, 'Check the step’s parameters, remove it, or select the previous layer to see what it actually received.')
      )
    );
    return;
  }
  if (!layer.profile.length) {
    root.append(h('p', { class: 'empty-note' }, 'Nothing to analyse yet. Paste or import some data into the input.'));
    return;
  }
  root.append(suggestionsSection(state, layer, extras.selectedSuggestions), checksSection(state, layer), profileSection(layer), distSection(state, layer), attacksSection(state, layer, extras.attackResult));
}

/* ---------- Data ---------- */

function hexdump(bytes, limit) {
  const n = Math.min(bytes.length, limit);
  const frag = document.createDocumentFragment();
  for (let off = 0; off < n; off += 16) {
    const row = bytes.subarray(off, Math.min(off + 16, n));
    frag.append(h('span', { class: 'off' }, off.toString(16).padStart(8, '0')), '  ');
    let hex = '';
    for (let i = 0; i < 16; i++) hex += i < row.length ? row[i].toString(16).padStart(2, '0') + (i === 7 ? '  ' : ' ') : i === 7 ? '    ' : '   ';
    frag.append(hex, ' ');
    let asc = '';
    for (const b of row) asc += b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.';
    frag.append(h('span', { class: 'asc' }, asc), '\n');
  }
  return frag;
}

function renderData(root, state, layers) {
  const layer = layers[state.selected];
  root.append(headEl(state, layer, layers.length - 1));
  if (!layer.bytes) {
    root.append(h('p', { class: 'empty-note' }, 'This layer has no output because the step failed.'));
    return;
  }
  const b = layer.bytes;
  const view = state.dataView;
  const seg = h(
    'div',
    { class: 'seg', role: 'group', 'aria-label': 'Data format' },
    [['text', 'Text'], ['hex', 'Hex'], ['base64', 'Base64']].map(([v, l]) => h('button', { type: 'button', 'aria-pressed': String(view === v), onclick: () => H.onDataView(v) }, l))
  );
  const wrap = h('label', { class: 'toggle' }, h('input', { type: 'checkbox', checked: state.wrap, onchange: (e) => H.onWrap(e.target.checked) }), 'Wrap');
  const textValue = () => (view === 'hex' ? toHex(b) : view === 'base64' ? bytesToBase64(b) : displayText(b));
  root.append(
    h(
      'div',
      { class: 'toolbar' },
      seg,
      view !== 'hex' ? wrap : null,
      h('span', { class: 'spacer' }),
      h('button', { class: 'btn btn-sm', type: 'button', html: `${icon('copy', { size: 14 })}<span>Copy</span>`, onclick: () => H.onCopy(textValue(), view === 'text' ? 'Copied text' : `Copied as ${view === 'hex' ? 'hex' : 'Base64'}`) }),
      h('button', { class: 'btn btn-sm', type: 'button', html: `${icon('download', { size: 14 })}<span>Save</span>`, onclick: () => H.onDownload(b, state.selected) })
    )
  );
  const pre = h('pre', { class: `dataview${view === 'hex' ? ' hexdump' : state.wrap ? ' wrap' : ''}`, tabindex: '0', 'aria-label': 'Layer data' });
  if (view === 'hex') {
    pre.append(hexdump(b, dataLimit));
  } else {
    const t = textValue();
    pre.textContent = t.length > 400000 ? t.slice(0, 400000) : t;
    if (!t.length) pre.textContent = '(empty)';
  }
  root.append(pre);
  if (view === 'hex' && b.length > dataLimit) {
    root.append(
      h(
        'p',
        { class: 'truncated-note' },
        `Showing the first ${formatBytes(dataLimit)} of ${formatBytes(b.length)}. `,
        h('button', { class: 'btn btn-quiet btn-sm', type: 'button', onclick: () => { dataLimit = b.length; H.onRerender(); } }, 'Show everything')
      )
    );
  }
  if (view === 'text' && !looksTextual(b)) root.append(h('p', { class: 'truncated-note' }, 'This layer is mostly binary; each byte is shown as one character. The Hex view is easier to read.'));
}

/* ---------- Compare ---------- */

function renderCompare(root, state, layers) {
  const usable = layers.filter((l) => l.bytes);
  let a = state.compare.a ?? 0;
  let b = state.compare.b ?? (state.selected || layers.length - 1);
  if (!layers[a]?.bytes) a = 0;
  if (!layers[b]?.bytes) b = usable[usable.length - 1].index;
  const select = (which, value) =>
    h(
      'select',
      { class: 'field', 'data-focus-key': `cmp-${which}`, onchange: (e) => H.onCompare(which, Number(e.target.value)) },
      usable.map((l) => h('option', { value: l.index, selected: l.index === value }, `${l.index}. ${layerName(state, l.index)}`))
    );
  root.append(
    h('header', { class: 'insp-head' }, h('div', { class: 'insp-kicker' }, 'Compare layers'), h('h2', { class: 'insp-title' }, `${a === 0 ? 'Input' : `Layer ${a}`} and ${b === 0 ? 'input' : `layer ${b}`}`)),
    h('div', { class: 'compare-pick' }, h('label', {}, 'Left', select('a', a)), h('label', {}, 'Right', select('b', b)))
  );
  const A = layers[a];
  const B = layers[b];
  const pct = A.bytes.length ? Math.round(((B.bytes.length - A.bytes.length) / A.bytes.length) * 100) : 0;
  const delta = [];
  delta.push(`${formatBytes(A.bytes.length)} to ${formatBytes(B.bytes.length)}${pct ? ` (${pct > 0 ? '+' : ''}${pct}%)` : ''}`);
  delta.push(`entropy ${A.profile.entropy.toFixed(2)} to ${B.profile.entropy.toFixed(2)}`);
  delta.push(`printable ${Math.round(A.profile.printable * 100)}% to ${Math.round(B.profile.printable * 100)}%`);
  root.append(h('p', { class: 'compare-delta' }, delta.join('; ') + '.'));

  const asHex = state.hexCompare || !looksTextual(A.bytes) || !looksTextual(B.bytes);
  root.append(
    h('div', { class: 'toolbar' }, h('label', { class: 'toggle' }, h('input', { type: 'checkbox', checked: asHex, disabled: !looksTextual(A.bytes) || !looksTextual(B.bytes), onchange: (e) => H.onHexCompare(e.target.checked) }), 'Show as hex'))
  );
  const fmt = (bytes) => (asHex ? toHex(bytes.subarray(0, 8192), ' ') : displayText(bytes.subarray(0, 40000)));
  const ta = fmt(A.bytes);
  const tb = fmt(B.bytes);
  const paneB = h('pre', { class: 'dataview wrap' });
  if (ta.length === tb.length && ta.length <= 20000 && !asHex) {
    // Same length (e.g. a Caesar shift): highlight the characters that changed.
    let changed = 0;
    let run = '';
    let runMarked = false;
    const flush = () => {
      if (!run) return;
      paneB.append(runMarked ? h('mark', {}, run) : run);
      run = '';
    };
    for (let i = 0; i < tb.length; i++) {
      const diff = ta[i] !== tb[i];
      if (diff) changed++;
      if (diff !== runMarked) {
        flush();
        runMarked = diff;
      }
      run += tb[i];
    }
    flush();
    root.append(h('p', { class: 'compare-delta' }, `Same length: ${pluralize(changed, 'character')} changed (highlighted).`));
  } else paneB.textContent = tb || '(empty)';
  root.append(
    h(
      'div',
      { class: 'compare-panes' },
      h('div', { class: 'compare-pane' }, h('h3', {}, h('span', {}, layerName(state, a)), h('span', {}, formatBytes(A.bytes.length))), h('pre', { class: 'dataview wrap' }, ta || '(empty)')),
      h('div', { class: 'compare-pane' }, h('h3', {}, h('span', {}, layerName(state, b)), h('span', {}, formatBytes(B.bytes.length))), paneB)
    )
  );
}

export function renderInspector(state, layers, extras) {
  $$('.tabs [role="tab"]').forEach((t) => {
    const on = t.dataset.tab === state.tab;
    t.setAttribute('aria-selected', String(on));
    t.tabIndex = on ? 0 : -1;
  });
  const root = $('#inspector-body');
  root.setAttribute('aria-labelledby', `tab-${state.tab}`);
  const viewKey = `${state.tab}:${state.selected}:${state.steps[state.selected - 1]?.uid ?? 'input'}`;
  if (root.dataset.view !== viewKey) {
    root.dataset.view = viewKey;
    root.scrollTop = 0;
  }
  preserveFocus(root, () => {
    root.replaceChildren();
    if (state.tab === 'data') renderData(root, state, layers);
    else if (state.tab === 'compare') renderCompare(root, state, layers);
    else renderAnalysis(root, state, layers, extras);
  });
}

export function openSection(id) {
  openSections[id] = true;
}

export function resetDataLimit() {
  dataLimit = 16384;
}

