import { h, $ } from './dom.js';
import { icon } from './icons.js';

/** Short confirmation at the bottom of the screen. Optional action, e.g. Undo. */
export function toast(message, { tone = 'ok', action, onAction, ms = 3200 } = {}) {
  const root = $('#toasts');
  const el = h(
    'div',
    { class: 'toast', 'data-tone': tone },
    h('span', { html: icon(tone === 'bad' ? 'cross' : 'check', { size: 14 }) }),
    h('span', {}, message),
    action ? h('button', { class: 'btn btn-sm', type: 'button', onclick: () => { onAction(); el.remove(); } }, action) : null
  );
  root.append(el);
  while (root.children.length > 3) root.firstChild.remove();
  setTimeout(() => el.remove(), ms);
}
