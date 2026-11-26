// Operation library: grouped by what an operation *is*, so encodings, ciphers, attacks and hashes are never mixed.

import { h, $ } from './dom.js';
import { icon } from './icons.js';
import { libraryGroups } from '../ops/registry.js';

let handlers = {};

export function initLibrary(opts) {
  handlers = opts;
  $('.library-search-icon').innerHTML = icon('search');
  const input = $('#library-filter');
  input.addEventListener('input', () => render(input.value));
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const first = $('#library-groups .lib-item');
      if (first) first.click();
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      $('#library-groups .lib-item')?.focus();
    } else if (e.key === 'Escape') {
      input.value = '';
      render('');
      handlers.onEscape?.();
    }
  });
  $('#library-groups').addEventListener('keydown', (e) => {
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
    const items = [...document.querySelectorAll('#library-groups .lib-item')];
    const i = items.indexOf(document.activeElement);
    if (i < 0) return;
    e.preventDefault();
    const next = items[i + (e.key === 'ArrowDown' ? 1 : -1)];
    if (next) next.focus();
    else if (e.key === 'ArrowUp') input.focus();
  });
  render('');
}

function matches(item, q) {
  if (!q) return true;
  const name = item.op?.name || item.attack?.name || item.name;
  const sum = item.op?.summary || item.attack?.summary || item.summary || '';
  return `${name} ${sum} ${item.op?.id || item.attack?.id || item.id}`.toLowerCase().includes(q);
}

function itemEl(item) {
  if (item.type === 'op') {
    const op = item.op;
    const tag = op.params?.length ? (op.params.some((p) => p.id === 'key' || p.id === 'shift' || p.id === 'alphabet' || p.id === 'a') ? 'needs key' : '') : '';
    return h(
      'button',
      { class: 'lib-item', type: 'button', 'data-type': 'op', onclick: () => handlers.onOp(op) },
      h('span', { class: 'lib-item-name' }, op.name),
      h('span', { class: 'lib-item-tag' }, tag),
      h('span', { class: 'lib-item-sum' }, op.summary)
    );
  }
  if (item.type === 'attack') {
    const a = item.attack;
    return h(
      'button',
      { class: 'lib-item', type: 'button', 'data-type': 'attack', onclick: () => handlers.onAttack(a) },
      h('span', { class: 'lib-item-name' }, a.name),
      h('span', { class: 'lib-item-tag' }, 'runs on layer'),
      h('span', { class: 'lib-item-sum' }, a.summary)
    );
  }
  if (item.type === 'inspect') {
    return h(
      'button',
      { class: 'lib-item', type: 'button', 'data-type': 'inspect', onclick: () => handlers.onInspect(item) },
      h('span', { class: 'lib-item-name' }, item.name),
      h('span', { class: 'lib-item-tag' }, ''),
      h('span', { class: 'lib-item-sum' }, item.summary)
    );
  }
  return h(
    'button',
    { class: 'lib-item', type: 'button', 'data-type': 'engine', onclick: () => handlers.onEngine(item) },
    h('span', { class: 'lib-item-name' }, item.name),
    h('span', { class: 'lib-item-tag', html: icon('lock', { size: 12 }) }),
    h('span', { class: 'lib-item-sum' }, item.summary)
  );
}

function render(query) {
  const q = query.trim().toLowerCase();
  const root = $('#library-groups');
  root.replaceChildren();
  let count = 0;
  for (const g of libraryGroups) {
    const items = g.items.filter((it) => matches(it, q));
    if (!items.length) continue;
    count += items.length;
    root.append(
      h(
        'section',
        { class: 'lib-group', 'aria-label': g.title },
        h('h2', { class: 'lib-group-title' }, g.title),
        q ? null : h('p', { class: 'lib-group-note' }, g.note),
        items.map(itemEl)
      )
    );
  }
  if (!count) root.append(h('p', { class: 'lib-empty' }, `No operation matches “${query}”. Try a name such as base64, xor or vigenere.`));
}

export function setLibraryTarget(text) {
  $('#library-target').textContent = text;
}
