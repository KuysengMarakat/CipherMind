// Application state with undo/redo. Only the chain (input + steps) is part of history;
// view state (selected layer, open tab) is not, so undo never just moves the selection.

const STORAGE_KEY = 'ciphermind.session.v1';
const HISTORY_LIMIT = 200;

let uidCounter = 0;
export const newUid = () => `s${Date.now().toString(36)}${(uidCounter++).toString(36)}`;

const blank = () => ({
  input: { text: '', binary: null, fileName: null }, // binary: base64 string when a non-text file was imported
  steps: [], // { uid, opId, params, disabled?, note? }
  flagPrefix: 'CTF{',
  selected: 0, // layer index: 0 = input, i = output of steps[i-1]
  tab: 'analysis',
  dataView: 'text',
  wrap: true,
  distView: 'letters',
  compare: { a: 0, b: null },
  attackRun: null, // { attackId, layerUid }
  mobilePane: 'chain',
  libraryOpen: false,
  hexCompare: false,
});

let state = blank();
const past = [];
const future = [];
let lastCoalesce = null;
let lastCoalesceAt = 0;
const listeners = new Set();

const snapshot = (s) => JSON.stringify({ input: s.input, steps: s.steps, flagPrefix: s.flagPrefix });

export const getState = () => state;

export function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function emit(meta) {
  for (const fn of listeners) fn(state, meta);
}

/**
 * Update state. `history: true` records an undo point; `coalesce` merges a burst of
 * edits with the same key (typing, dragging a number) into one undo point.
 */
export function update(patch, { history = false, coalesce = null, reason = '' } = {}) {
  const next = typeof patch === 'function' ? patch(state) : { ...state, ...patch };
  if (next === state) return;
  // A change that leaves the chain as it was (e.g. moving the first step up) is not an undo point.
  if (history && snapshot(next) === snapshot(state)) history = false;
  if (history) {
    const now = Date.now();
    const merging = coalesce && coalesce === lastCoalesce && now - lastCoalesceAt < 1200;
    if (!merging) {
      past.push(snapshot(state));
      if (past.length > HISTORY_LIMIT) past.shift();
    }
    future.length = 0;
    lastCoalesce = coalesce;
    lastCoalesceAt = now;
  }
  state = clampSelection(next);
  emit({ reason, history });
  if (history) persist();
}

function clampSelection(s) {
  const max = s.steps.length;
  return s.selected > max ? { ...s, selected: max } : s;
}

function restore(snap) {
  const data = JSON.parse(snap);
  state = clampSelection({ ...state, ...data });
  lastCoalesce = null;
  emit({ reason: 'history', history: true });
  persist();
}

export function undo() {
  if (!past.length) return false;
  future.push(snapshot(state));
  restore(past.pop());
  return true;
}

export function redo() {
  if (!future.length) return false;
  past.push(snapshot(state));
  restore(future.pop());
  return true;
}

export const canUndo = () => past.length > 0;
export const canRedo = () => future.length > 0;

let persistTimer = null;
function persist() {
  clearTimeout(persistTimer);
  persistTimer = setTimeout(() => {
    try {
      localStorage.setItem(STORAGE_KEY, snapshot(state));
    } catch {
      /* storage may be unavailable (private mode, file://); the session simply isn't kept */
    }
  }, 300);
}

export function loadSaved() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return false;
    const data = JSON.parse(raw);
    if (!data || !data.input || !Array.isArray(data.steps)) return false;
    state = clampSelection({ ...state, ...data, selected: data.steps.length });
    return true;
  } catch {
    return false;
  }
}

/* ---------- Chain helpers ---------- */

export function insertStep(step, afterLayer = state.selected, { select = true } = {}) {
  update(
    (s) => {
      const steps = [...s.steps];
      const at = Math.min(afterLayer, steps.length);
      steps.splice(at, 0, { uid: newUid(), ...step });
      return { ...s, steps, selected: select ? at + 1 : s.selected };
    },
    { history: true, reason: 'insert' }
  );
}

export function replaceChain(steps, { select = 'last' } = {}) {
  update(
    (s) => ({ ...s, steps: steps.map((st) => ({ uid: newUid(), ...st })), selected: select === 'last' ? steps.length : 0 }),
    { history: true, reason: 'replace' }
  );
}

export function removeStep(uid) {
  update(
    (s) => {
      const idx = s.steps.findIndex((x) => x.uid === uid);
      if (idx < 0) return s;
      const steps = s.steps.filter((x) => x.uid !== uid);
      const layer = idx + 1;
      let selected = s.selected;
      if (selected >= layer) selected = Math.max(0, selected - 1);
      return { ...s, steps, selected };
    },
    { history: true, reason: 'remove' }
  );
}

export function moveStep(uid, delta) {
  update(
    (s) => {
      const idx = s.steps.findIndex((x) => x.uid === uid);
      const to = idx + delta;
      if (idx < 0 || to < 0 || to >= s.steps.length) return s;
      const steps = [...s.steps];
      const [item] = steps.splice(idx, 1);
      steps.splice(to, 0, item);
      return { ...s, steps, selected: to + 1 };
    },
    { history: true, reason: 'move' }
  );
}

export function moveStepTo(uid, toIndex) {
  update(
    (s) => {
      const idx = s.steps.findIndex((x) => x.uid === uid);
      if (idx < 0 || idx === toIndex) return s;
      const steps = [...s.steps];
      const [item] = steps.splice(idx, 1);
      steps.splice(Math.max(0, Math.min(toIndex, steps.length)), 0, item);
      return { ...s, steps, selected: steps.indexOf(item) + 1 };
    },
    { history: true, reason: 'move' }
  );
}

export function patchStep(uid, patch, { coalesce } = {}) {
  update(
    (s) => ({ ...s, steps: s.steps.map((x) => (x.uid === uid ? { ...x, ...patch, params: { ...x.params, ...(patch.params || {}) } } : x)) }),
    { history: true, coalesce: coalesce ? `${uid}:${coalesce}` : null, reason: 'param' }
  );
}

export function setInputText(text) {
  update((s) => ({ ...s, input: { text, binary: null, fileName: s.input.fileName && s.input.binary === null ? s.input.fileName : null } }), {
    history: true,
    coalesce: 'input',
    reason: 'input',
  });
}
