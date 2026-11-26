// Tiny DOM helpers. No framework: h() builds elements, escapeHtml() guards every user-controlled string.

export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (k === 'html') el.innerHTML = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (v === true) el.setAttribute(k, '');
    else el.setAttribute(k, v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

export function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

/** Re-render a region while keeping keyboard focus on the element with the same data-focus-key. */
export function preserveFocus(root, render) {
  const active = document.activeElement;
  const key = active && root.contains(active) ? active.dataset.focusKey : null;
  const sel = key && 'selectionStart' in active ? [active.selectionStart, active.selectionEnd] : null;
  const scroll = root.scrollTop;
  render();
  root.scrollTop = scroll;
  if (key) {
    const next = root.querySelector(`[data-focus-key="${CSS.escape(key)}"]`);
    if (next) {
      next.focus({ preventScroll: true });
      if (sel && 'setSelectionRange' in next) {
        try {
          next.setSelectionRange(sel[0], sel[1]);
        } catch {
          /* not a text input */
        }
      }
    }
  }
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = h('textarea', { style: 'position:fixed;opacity:0' }, text);
    document.body.append(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return ok;
  }
}

export function download(name, bytes, type = 'application/octet-stream') {
  const url = URL.createObjectURL(new Blob([bytes], { type }));
  const a = h('a', { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
