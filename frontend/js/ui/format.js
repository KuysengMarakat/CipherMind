// Shared presentation helpers.

import { h } from './dom.js';
import { looksTextual, displayText, toHex, formatBytes } from '../core/bytes.js';
import { opById } from '../ops/registry.js';

export { formatBytes };

export function stepTitle(step) {
  const op = opById[step.opId];
  if (!op) return step.opId;
  return op.explain(step.params || {});
}

export function stepKey(step) {
  const op = opById[step.opId];
  return op && op.keyLabel ? op.keyLabel(step.params || {}) : '';
}

/** Short preview: text when it reads as text, spaced hex otherwise. */
export function previewOf(bytes, max = 400) {
  if (!bytes) return { text: '', binary: false };
  if (looksTextual(bytes)) {
    const t = displayText(bytes.length > max * 4 ? bytes.subarray(0, max * 4) : bytes);
    return { text: t.length > max ? t.slice(0, max) + '…' : t, binary: false };
  }
  const n = Math.min(bytes.length, Math.floor(max / 3));
  return { text: toHex(bytes.subarray(0, n), ' ') + (bytes.length > n ? ' …' : ''), binary: true };
}

export function confidenceEl(confidence, level) {
  const on = Math.max(1, Math.round(confidence * 5));
  const words = { high: 'High', medium: 'Medium', low: 'Low' };
  return h(
    'span',
    { class: 'conf', 'data-level': level, title: `Confidence ${Math.round(confidence * 100)}%` },
    h('span', { class: 'conf-bar', 'aria-hidden': 'true' }, [0, 1, 2, 3, 4].map((i) => h('i', { class: i < on ? 'on' : '' }))),
    words[level]
  );
}

export const STATUS_TONE = {
  flag: 'ok',
  file: 'ok',
  failed: 'bad',
  encoded: 'accent',
  shape: 'warn',
  readable: '',
  text: '',
  binary: 'muted',
  blocked: 'muted',
  skipped: 'muted',
  empty: 'muted',
};

export function pluralize(n, word, plural = word + 's') {
  return `${n} ${n === 1 ? word : plural}`;
}

/** Wraps a flag match in <mark> inside a preview node. */
export function previewNode(text, flag) {
  if (!flag || !text.includes(flag)) return document.createTextNode(text);
  const i = text.indexOf(flag);
  const frag = document.createDocumentFragment();
  frag.append(text.slice(0, i), h('mark', {}, flag), text.slice(i + flag.length));
  return frag;
}
