// The chain: input at the top, one row per step, each showing what that layer's data looks like.

import { h, $, $$ } from './dom.js';
import { icon, iconEl } from './icons.js';
import { opById } from '../ops/registry.js';
import { formatBytes, stepTitle, stepKey, previewOf, previewNode, STATUS_TONE, confidenceEl, pluralize } from './format.js';
import { toHex } from '../core/bytes.js';
import { examples } from '../examples.js';

let H = {};
const rows = new Map(); // uid -> li
let dragUid = null;

export function initChain(handlers) {
  H = handlers;
  const editor = $('#input-editor');
  editor.addEventListener('input', () => H.onInput(editor.value));
  editor.addEventListener('focus', () => H.onSelect(0, { keepFocus: true }));

  $('#btn-import').innerHTML = `${icon('upload')}<span>Import</span>`;
  $('#btn-import').addEventListener('click', () => $('#file-input').click());
  $('#file-input').addEventListener('change', (e) => {
    const f = e.target.files[0];
    if (f) H.onFile(f);
    e.target.value = '';
  });
  $('#btn-examples').addEventListener('click', () => H.onExamples());
  $('#btn-clear').addEventListener('click', () => H.onClear());

  const wrap = $('#editor-wrap');
  wrap.addEventListener('dragover', (e) => {
    if (![...(e.dataTransfer?.types || [])].includes('Files')) return;
    e.preventDefault();
    wrap.classList.add('is-dragover');
  });
  wrap.addEventListener('dragleave', () => wrap.classList.remove('is-dragover'));
  wrap.addEventListener('drop', (e) => {
    wrap.classList.remove('is-dragover');
    const f = e.dataTransfer?.files?.[0];
    if (!f) return;
    e.preventDefault();
    H.onFile(f);
  });

  const list = $('#layers');
  list.addEventListener('click', onListClick);
  list.addEventListener('keydown', onListKey);
  list.addEventListener('dragover', onDragOver);
  list.addEventListener('drop', onDrop);
  list.addEventListener('dragend', clearDrag);
}

function onListClick(e) {
  const actionBtn = e.target.closest('[data-action]');
  const li = e.target.closest('.layer');
  if (!li) return;
  const idx = Number(li.dataset.index);
  if (actionBtn) {
    const uid = li.dataset.uid;
    const a = actionBtn.dataset.action;
    if (a === 'up') H.onMove(uid, -1);
    else if (a === 'down') H.onMove(uid, 1);
    else if (a === 'toggle') H.onToggle(uid);
    else if (a === 'remove') H.onRemove(uid);
    else if (a === 'inspect') H.onInspect(idx);
    return;
  }
  if (e.target.closest('.params, .layer-input .editor-wrap, .layer-tools, .empty-start')) return;
  if (li.classList.contains('layer-input') && !e.target.closest('.layer-select')) return;
  H.onSelect(idx);
}

function onListKey(e) {
  const sel = e.target.closest('.layer-select');
  if (!sel) return;
  const li = sel.closest('.layer');
  const idx = Number(li.dataset.index);
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    e.preventDefault();
    if (e.altKey && li.dataset.uid) {
      H.onMove(li.dataset.uid, e.key === 'ArrowDown' ? 1 : -1);
      return;
    }
    const target = idx + (e.key === 'ArrowDown' ? 1 : -1);
    const next = $(`.layer[data-index="${target}"] .layer-select`);
    if (next) {
      H.onSelect(target);
      next.focus();
    }
  } else if ((e.key === 'Delete' || e.key === 'Backspace') && li.dataset.uid) {
    e.preventDefault();
    H.onRemove(li.dataset.uid);
  }
}

/* ---------- Drag to reorder ---------- */
function onDragStart(e, uid) {
  dragUid = uid;
  e.dataTransfer.effectAllowed = 'move';
  e.dataTransfer.setData('text/plain', uid);
  rows.get(uid)?.classList.add('is-dragging');
}
function onDragOver(e) {
  if (!dragUid) return;
  const li = e.target.closest('.layer:not(.layer-input)');
  if (!li) return;
  e.preventDefault();
  $$('.layer.drop-before, .layer.drop-after').forEach((x) => x.classList.remove('drop-before', 'drop-after'));
  const r = li.getBoundingClientRect();
  li.classList.add(e.clientY < r.top + r.height / 2 ? 'drop-before' : 'drop-after');
}
function onDrop(e) {
  if (!dragUid) return;
  const li = e.target.closest('.layer:not(.layer-input)');
  e.preventDefault();
  if (li && li.dataset.uid !== dragUid) {
    const before = li.classList.contains('drop-before');
    const order = $$('.layer[data-uid]').map((x) => x.dataset.uid);
    const from = order.indexOf(dragUid);
    let to = order.indexOf(li.dataset.uid) + (before ? 0 : 1);
    if (from < to) to--;
    H.onMoveTo(dragUid, to);
  }
  clearDrag();
}
function clearDrag() {
  dragUid = null;
  $$('.layer.is-dragging, .layer.drop-before, .layer.drop-after').forEach((x) => x.classList.remove('is-dragging', 'drop-before', 'drop-after'));
}

/* ---------- Rows ---------- */
function buildRow(step) {
  const li = h('li', { class: 'layer', 'data-uid': step.uid });
  const handle = h('button', { class: 'btn-icon sm drag-handle', type: 'button', draggable: 'true', 'aria-label': 'Drag to reorder', title: 'Drag to reorder (or Alt+↑/↓)', html: icon('grip') });
  handle.addEventListener('dragstart', (e) => onDragStart(e, step.uid));
  li.append(
    h('div', { class: 'rail', 'aria-hidden': 'true' }, h('span', { class: 'node' })),
    h(
      'div',
      { class: 'layer-body' },
      h(
        'div',
        { class: 'layer-head' },
        h('button', { class: 'layer-select', type: 'button' }, h('span', { class: 'layer-no' }), h('span', { class: 'layer-name' })),
        h('span', { class: 'layer-key' }),
        h('span', { class: 'layer-size' }, h('span', { class: 'sizebar', 'aria-hidden': 'true' }, h('i')), h('span', { class: 'size-text' })),
        h('span', { class: 'chip status-chip' }),
        h(
          'div',
          { class: 'layer-tools' },
          h('button', { class: 'btn-icon sm only-narrow', type: 'button', 'data-action': 'inspect', 'aria-label': 'Inspect this layer', title: 'Inspect', html: icon('inspect') }),
          h('button', { class: 'btn-icon sm', type: 'button', 'data-action': 'up', 'aria-label': 'Move step up', title: 'Move up (Alt+↑)', html: icon('up') }),
          h('button', { class: 'btn-icon sm', type: 'button', 'data-action': 'down', 'aria-label': 'Move step down', title: 'Move down (Alt+↓)', html: icon('down') }),
          h('button', { class: 'btn-icon sm', type: 'button', 'data-action': 'toggle', 'aria-label': 'Skip this step', title: 'Skip / include step', html: icon('pause') }),
          handle,
          h('button', { class: 'btn-icon sm', type: 'button', 'data-action': 'remove', 'aria-label': 'Remove step', title: 'Remove (Delete)', html: icon('close') })
        )
      ),
      h('div', { class: 'layer-preview' }),
      h('p', { class: 'layer-error', hidden: true }),
      h('p', { class: 'layer-note', hidden: true }),
      h('div', { class: 'params', hidden: true })
    )
  );
  return li;
}

function paramControl(step, param) {
  const value = step.params?.[param.id] ?? param.default;
  const key = `param-${step.uid}-${param.id}`;
  const id = `p-${step.uid}-${param.id}`;
  let ctl;
  if (param.type === 'select') {
    ctl = h('select', { class: 'field', id, 'data-focus-key': key }, param.options.map(([v, label]) => h('option', { value: v, selected: String(v) === String(value) }, label)));
    ctl.addEventListener('change', () => H.onParam(step.uid, { [param.id]: ctl.value }));
  } else if (param.type === 'number') {
    ctl = h('input', { class: 'field', id, type: 'number', min: param.min, max: param.max, step: 1, value, 'data-focus-key': key, inputmode: 'numeric' });
    ctl.addEventListener('input', () => {
      if (ctl.value === '') return;
      let v = Math.round(Number(ctl.value));
      if (param.min !== undefined) v = Math.max(param.min, v);
      if (param.max !== undefined) v = Math.min(param.max, v);
      H.onParam(step.uid, { [param.id]: v }, 'num');
    });
  } else {
    ctl = h('input', { class: `field${param.id === 'alphabet' ? ' wide' : ''}`, id, type: 'text', value, placeholder: param.placeholder || '', spellcheck: 'false', autocomplete: 'off', 'data-focus-key': key });
    ctl.addEventListener('input', () => H.onParam(step.uid, { [param.id]: ctl.value }, 'text'));
  }
  return h('label', { class: 'param', for: id }, param.label, ctl);
}

function updateRow(li, layer, step, ctx) {
  const op = opById[step.opId];
  const status = layer.status;
  li.dataset.index = String(layer.index);
  li.dataset.status = status.id;
  li.classList.toggle('is-selected', ctx.selected === layer.index);
  li.classList.toggle('is-disabled', !!step.disabled);
  li.setAttribute('aria-current', ctx.selected === layer.index ? 'step' : 'false');

  const sel = li.querySelector('.layer-select');
  sel.dataset.focusKey = `sel-${step.uid}`;
  sel.setAttribute('aria-label', `Layer ${layer.index}: ${stepTitle(step)}. ${status.label}`);
  li.querySelector('.layer-no').textContent = String(layer.index);
  li.querySelector('.layer-name').textContent = op ? stepTitle(step) : `${step.opId} (engine only)`;
  const key = stepKey(step);
  const keyEl = li.querySelector('.layer-key');
  keyEl.textContent = key;
  keyEl.hidden = !key || ctx.selected === layer.index;

  const sizeText = li.querySelector('.size-text');
  const bar = li.querySelector('.sizebar > i');
  if (layer.bytes && !layer.disabled) {
    sizeText.textContent = formatBytes(layer.bytes.length);
    bar.style.width = `${Math.max(2, (layer.bytes.length / ctx.maxLen) * 100)}%`;
  } else {
    sizeText.textContent = layer.disabled ? 'skipped' : '—';
    bar.style.width = '0';
  }

  const chip = li.querySelector('.status-chip');
  chip.textContent = status.label;
  chip.dataset.tone = STATUS_TONE[status.id] ?? '';

  const prev = li.querySelector('.layer-preview');
  const err = li.querySelector('.layer-error');
  if (layer.error) {
    prev.hidden = true;
    err.hidden = false;
    err.textContent = layer.error;
  } else if (layer.blocked) {
    prev.hidden = true;
    err.hidden = false;
    err.textContent = 'Not run: an earlier step failed.';
    err.style.color = 'var(--muted)';
  } else {
    err.hidden = true;
    err.style.color = '';
    prev.hidden = false;
    const p = previewOf(layer.bytes, ctx.selected === layer.index ? 900 : 260);
    prev.classList.toggle('is-binary', p.binary);
    prev.classList.toggle('is-flag', !!layer.profile?.flagMatch);
    prev.replaceChildren(previewNode(p.text || ' ', layer.profile?.flagMatch));
  }

  const note = li.querySelector('.layer-note');
  note.hidden = !step.note;
  if (step.note) note.replaceChildren(iconEl('key', { size: 13 }), h('span', {}, step.note));

  const upBtn = li.querySelector('[data-action="up"]');
  const downBtn = li.querySelector('[data-action="down"]');
  upBtn.disabled = layer.index === 1;
  downBtn.disabled = layer.index === ctx.total;
  const tg = li.querySelector('[data-action="toggle"]');
  tg.setAttribute('aria-label', step.disabled ? 'Include this step' : 'Skip this step');
  tg.setAttribute('aria-pressed', step.disabled ? 'true' : 'false');

  // Parameter editor: only on the selected row, rebuilt when params change from elsewhere (undo, attack).
  const params = li.querySelector('.params');
  const selected = ctx.selected === layer.index && op && op.params?.length;
  params.hidden = !selected;
  if (selected) {
    const sig = JSON.stringify(step.params);
    if (params.dataset.sig !== sig && !params.contains(document.activeElement)) {
      params.replaceChildren(...op.params.map((p) => paramControl(step, p)));
      params.dataset.sig = sig;
    }
  } else if (params.childElementCount) {
    params.replaceChildren();
    params.dataset.sig = '';
  }
}

function renderInput(state, layer) {
  const li = $('#layer-input');
  li.dataset.status = layer.status.id;
  li.classList.toggle('is-selected', state.selected === 0);
  const editor = $('#input-editor');
  const bin = $('#binary-input');
  const isBinary = !!state.input.binary;
  editor.hidden = isBinary;
  bin.hidden = !isBinary;
  if (!isBinary && editor.value !== state.input.text) editor.value = state.input.text;
  if (isBinary) {
    const b = layer.bytes;
    bin.replaceChildren(
      h('div', {}, h('strong', {}, state.input.fileName || 'Binary file'), ` loaded as ${formatBytes(b.length)} of binary data. It is shown as hex and cannot be edited as text.`),
      h('pre', {}, toHex(b.subarray(0, 96), ' ') + (b.length > 96 ? ' …' : '')),
      h('button', { class: 'btn btn-sm', type: 'button', onclick: () => H.onClear() }, 'Clear and type instead')
    );
  }
  const p = layer.profile;
  const textLen = isBinary ? null : state.input.text.length;
  $('#input-size').replaceChildren(h('span', { class: 'sizebar', 'aria-hidden': 'true' }, h('i', { style: `width:${p.length ? 100 : 0}%` })), formatBytes(p.length));
  const chip = $('#input-status');
  chip.textContent = p.length ? layer.status.label : '';
  chip.dataset.tone = STATUS_TONE[layer.status.id] ?? '';
  const meta = $('#input-meta');
  if (!p.length) meta.textContent = 'Paste text, drop a file, or open an example.';
  else {
    const parts = [];
    if (textLen !== null) parts.push(pluralize(textLen, 'character'));
    if (p.lines > 1) parts.push(pluralize(p.lines, 'line'));
    parts.push(p.charset);
    if (state.input.fileName) parts.push(`from ${state.input.fileName}`);
    meta.textContent = parts.join(', ');
  }

  const empty = $('#empty-start');
  const showEmpty = !p.length && !state.steps.length;
  empty.hidden = !showEmpty;
  if (showEmpty && !empty.childElementCount) {
    empty.append(
      h('h2', {}, 'Start with a challenge'),
      h('p', {}, 'Paste the ciphertext above. CipherMind profiles it, suggests what the next layer might be and lets you peel layers one at a time, or search for the whole chain with Auto-solve.'),
      h(
        'div',
        { class: 'example-list' },
        examples.slice(0, 4).map((ex) => h('button', { class: 'example-btn', type: 'button', onclick: () => H.onLoadExample(ex) }, h('strong', {}, ex.title), h('span', {}, ex.description)))
      ),
      h('p', { style: 'margin:10px 0 0' }, h('button', { class: 'btn btn-quiet btn-sm', type: 'button', onclick: () => H.onExamples() }, `All ${examples.length} examples`))
    );
  }
}

function renderEnd(state, layers, extras) {
  const end = $('#chain-end');
  const last = layers[layers.length - 1];
  const hasInput = layers[0].profile.length > 0;
  end.replaceChildren();
  if (!hasInput) return;

  const r = extras.result;
  const resultEl = h(
    'div',
    { class: 'result', 'data-status': r.id, role: 'status' },
    h('span', { class: 'result-label', html: `${icon(r.id === 'verified' ? 'check' : r.id === 'partial' ? 'dot' : 'cross', { size: 14 })}${r.label}` }),
    h('span', { class: 'result-detail' }, r.value ? ['Flag pattern matched: ', h('code', {}, r.value)] : r.detail),
    r.value ? h('button', { class: 'btn btn-sm', type: 'button', html: `${icon('copy', { size: 14 })}<span>Copy flag</span>`, onclick: () => H.onCopy(r.value, 'Flag copied') }) : h('span')
  );
  if (state.steps.length) end.append(resultEl);

  if (r.id === 'verified') return;
  const next = h('div', { class: 'next' });
  next.append(h('p', { class: 'next-title' }, `Next layer after ${last.index === 0 ? 'the input' : `layer ${last.index}`}`));
  const list = h('div', { class: 'next-list' });
  if (last.error || last.blocked) {
    list.append(h('span', { class: 'empty-note' }, 'Fix or remove the failed step to continue.'));
  } else if (extras.nextSuggestions === null) {
    list.append(h('span', { class: 'loading-note' }, h('span', { class: 'spinner' }), 'Checking formats…'));
  } else {
    const top = extras.nextSuggestions.filter((s) => s.level !== 'low').slice(0, 3);
    for (const s of top) {
      const op = opById[s.opId];
      list.append(
        h(
          'button',
          { class: 'next-btn', type: 'button', title: s.reason, onclick: () => H.onApplySuggestion(s, last.index) },
          iconEl('plus', { size: 14 }),
          op.explain(s.params),
          confidenceEl(s.confidence, s.level)
        )
      );
    }
    if (!top.length) list.append(h('span', { class: 'empty-note' }, extras.nextSuggestions.length ? 'Only low-confidence guesses. See the Inspector for details.' : 'No format recognised.'));
  }
  const hashes = last.profile?.hashes || [];
  if (hashes.length && !(extras.nextSuggestions || []).some((s) => s.profile?.isText)) {
    next.append(
      h('p', { class: 'next-hash', html: `${icon('lock', { size: 13 })}<span>Same format as ${hashes.map((x) => x.name).slice(0, 3).join(', ')}. If it is a hash, it is one-way and cannot be decoded.</span>` })
    );
  }
  list.append(h('button', { class: 'next-btn add', type: 'button', onclick: () => H.onAddStep(last.index) }, iconEl('library', { size: 14 }), 'Choose operation'));
  next.append(list);
  end.append(next);
}

export function renderChain(state, layers, extras) {
  renderInput(state, layers[0]);
  const list = $('#layers');
  list.classList.toggle('single', state.steps.length === 0);
  const maxLen = Math.max(1, ...layers.filter((l) => l.bytes && !l.disabled).map((l) => l.bytes.length));
  const ctx = { selected: state.selected, maxLen, total: state.steps.length };
  const live = new Set();
  let prev = $('#layer-input');
  state.steps.forEach((step, i) => {
    live.add(step.uid);
    let li = rows.get(step.uid);
    if (!li) {
      li = buildRow(step);
      rows.set(step.uid, li);
    }
    updateRow(li, layers[i + 1], step, ctx);
    if (prev.nextElementSibling !== li) prev.after(li);
    prev = li;
  });
  for (const [uid, li] of rows) {
    if (!live.has(uid)) {
      li.remove();
      rows.delete(uid);
    }
  }
  const n = state.steps.length;
  $('#chain-summary').textContent = n ? `${pluralize(n, 'step')}, ${extras.result.label.toLowerCase()}` : layers[0].profile.length ? 'No steps yet' : '';
  renderEnd(state, layers, extras);
}

export function scrollLayerIntoView(index) {
  const li = $(`.layer[data-index="${index}"]`);
  li?.scrollIntoView({ block: 'nearest', behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
}
