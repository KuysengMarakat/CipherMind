// Inline 16px stroke icons. Decorative unless a label is given by the caller.

const paths = {
  undo: '<path d="M6 4 3 7l3 3"/><path d="M3 7h6.5a3.5 3.5 0 0 1 0 7H8"/>',
  redo: '<path d="m10 4 3 3-3 3"/><path d="M13 7H6.5a3.5 3.5 0 0 0 0 7H8"/>',
  up: '<path d="m4 10 4-4 4 4"/>',
  down: '<path d="m4 6 4 4 4-4"/>',
  close: '<path d="m4 4 8 8M12 4l-8 8"/>',
  grip: '<circle cx="6" cy="4" r=".9"/><circle cx="10" cy="4" r=".9"/><circle cx="6" cy="8" r=".9"/><circle cx="10" cy="8" r=".9"/><circle cx="6" cy="12" r=".9"/><circle cx="10" cy="12" r=".9"/>',
  pause: '<path d="M8 2.5a5.5 5.5 0 1 0 0 11 5.5 5.5 0 0 0 0-11Z"/><path d="M4.2 4.2l7.6 7.6"/>',
  copy: '<rect x="5.5" y="5.5" width="8" height="8" rx="1.5"/><path d="M10.5 5.5V4a1.5 1.5 0 0 0-1.5-1.5H4A1.5 1.5 0 0 0 2.5 4v5A1.5 1.5 0 0 0 4 10.5h1.5"/>',
  upload: '<path d="M8 10.5V2.5M5 5.5l3-3 3 3"/><path d="M2.5 10v2a1.5 1.5 0 0 0 1.5 1.5h8a1.5 1.5 0 0 0 1.5-1.5v-2"/>',
  download: '<path d="M8 2.5v8M5 7.5l3 3 3-3"/><path d="M2.5 10v2a1.5 1.5 0 0 0 1.5 1.5h8a1.5 1.5 0 0 0 1.5-1.5v-2"/>',
  plus: '<path d="M8 3v10M3 8h10"/>',
  search: '<circle cx="7" cy="7" r="4.25"/><path d="m10.2 10.2 3.3 3.3"/>',
  code: '<path d="m5.5 4.5-3 3.5 3 3.5M10.5 4.5l3 3.5-3 3.5"/>',
  play: '<path d="M5 3.5v9l7.5-4.5z"/>',
  help: '<circle cx="8" cy="8" r="5.75"/><path d="M6.4 6.3a1.7 1.7 0 0 1 3.3.6c0 1.2-1.7 1.4-1.7 2.6"/><circle cx="8" cy="11.4" r=".5"/>',
  check: '<path d="m3.5 8.5 3 3 6-7"/>',
  cross: '<path d="m4.5 4.5 7 7M11.5 4.5l-7 7"/>',
  dot: '<circle cx="8" cy="8" r="2"/>',
  library: '<path d="M3 3v10M6 3v10M9.5 3.3l3 9.4"/>',
  inspect: '<circle cx="7" cy="7" r="4.25"/><path d="m10.2 10.2 3.3 3.3M5 7h4"/>',
  chain: '<rect x="3" y="2.5" width="10" height="3" rx="1"/><rect x="3" y="10.5" width="10" height="3" rx="1"/><path d="M8 5.5v5"/>',
  file: '<path d="M4 2.5h5l3 3v8H4z"/><path d="M9 2.5v3h3"/>',
  lock: '<rect x="3.5" y="7" width="9" height="6.5" rx="1.5"/><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2"/>',
  key: '<circle cx="5.5" cy="10.5" r="2.75"/><path d="m7.5 8.5 5.5-5.5M11 5l1.5 1.5"/>',
  external: '<path d="M9 3h4v4M13 3 7.5 8.5"/><path d="M11 9.5V12a1.5 1.5 0 0 1-1.5 1.5h-5A1.5 1.5 0 0 1 3 12V7a1.5 1.5 0 0 1 1.5-1.5H7"/>',
  stop: '<rect x="4" y="4" width="8" height="8" rx="1"/>',
};

export function icon(name, { size = 16, label } = {}) {
  const a = label ? `role="img" aria-label="${label}"` : 'aria-hidden="true"';
  return `<svg class="icon icon-${name}" width="${size}" height="${size}" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" ${a}>${paths[name] || ''}</svg>`;
}

export function iconEl(name, opts) {
  const t = document.createElement('template');
  t.innerHTML = icon(name, opts);
  return t.content.firstChild;
}
