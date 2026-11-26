// CipherMind workbench: wires state, computation and rendering together.

import * as store from './state/store.js';
import { $, $$, copyText, download } from './ui/dom.js';
import { icon } from './ui/icons.js';
import { utf8, tryUtf8, looksTextual, base64ToBytes, bytesToBase64, hashBytes, formatBytes } from './core/bytes.js';
import { runChain, resultStatus } from './core/pipeline.js';
import { suggestNext } from './core/suggest.js';
import { localSearch } from './core/search.js';
import { buildScript } from './core/script.js';
import { opById, defaultParams } from './ops/registry.js';
import { attackById } from './ops/attacks.js';
import { engine } from './api/engine.js';
import { initLibrary, setLibraryTarget } from './ui/library.js';
import { initChain, renderChain, scrollLayerIntoView } from './ui/chain.js';
import { initInspector, renderInspector, resetDataLimit, openSection } from './ui/inspector.js';
import { initDialogs, showSolveRunning, updateSolveProgress, showSolveResults, showScript, showExamples, showHelp, showEngine, showEngineOnly } from './ui/dialogs.js';
import { toast } from './ui/toast.js';
import { stepTitle } from './ui/format.js';

const MAX_FILE = 20 * 1024 * 1024;
const narrow = () => matchMedia('(max-width: 860px)').matches;
const drawerMode = () => matchMedia('(max-width: 1240px)').matches && !narrow();

const derived = {
  layers: null,
  result: null,
  nextSuggestions: null,
  nextKey: null,
  selectedSuggestions: null,
  selectedKey: null,
  attackResult: null,
};

/* ---------- Input bytes (memoised: the input is re-read on every compute) ---------- */
let inputMemo = { key: null, bytes: new Uint8Array() };
function inputBytes(s) {
  const key = s.input.binary ? 'b:' + s.input.binary.length + s.input.binary.slice(0, 64) : 't:' + s.input.text;
  if (inputMemo.key !== key) inputMemo = { key, bytes: s.input.binary ? base64ToBytes(s.input.binary) : utf8(s.input.text) };
  return inputMemo.bytes;
}

/* ---------- Compute → render ---------- */
let seq = 0;
let timer = null;

function schedule(meta = {}) {
  clearTimeout(timer);
  timer = setTimeout(compute, meta.reason === 'input' ? 140 : 0);
}

async function compute() {
  const my = ++seq;
  const s = store.getState();
  const ctx = { flagPrefix: s.flagPrefix };
  const layers = await runChain(inputBytes(s), s.steps, ctx);
  if (my !== seq) return;
  derived.layers = layers;
  derived.result = resultStatus(layers);

  const last = layers[layers.length - 1];
  const sel = layers[Math.min(s.selected, layers.length - 1)];
  const usable = (l) => l && l.bytes && !l.error && !l.blocked && l.profile?.length;
  const nk = usable(last) ? hashBytes(last.bytes) + s.flagPrefix : 'none';
  const sk = usable(sel) ? hashBytes(sel.bytes) + s.flagPrefix : 'none';
  if (nk !== derived.nextKey) derived.nextSuggestions = nk === 'none' ? [] : null;
  if (sk !== derived.selectedKey) derived.selectedSuggestions = sk === 'none' ? [] : null;
  render();

  const [ns, ss] = await Promise.all([nk === 'none' ? [] : suggestNext(last.bytes, ctx), sk === 'none' ? [] : suggestNext(sel.bytes, ctx)]);
  if (my !== seq) return;
  const changed = derived.nextKey !== nk || derived.selectedKey !== sk || derived.nextSuggestions === null || derived.selectedSuggestions === null;
  derived.nextSuggestions = ns;
  derived.selectedSuggestions = ss;
  derived.nextKey = nk;
  derived.selectedKey = sk;
  if (changed) render();
}

function render() {
  const s = store.getState();
  if (!derived.layers) return;
  const layers = derived.layers;
  if (s.selected > layers.length - 1) return;
  const extras = { result: derived.result, nextSuggestions: derived.nextSuggestions, selectedSuggestions: derived.selectedSuggestions, attackResult: derived.attackResult };
  renderChain(s, layers, extras);
  renderInspector(s, layers, extras);
  renderHeader(s);
}

function renderHeader(s) {
  if (s.selected > s.steps.length) return;
  $('#btn-undo').disabled = !store.canUndo();
  $('#btn-redo').disabled = !store.canRedo();
  const fp = $('#flag-prefix');
  if (document.activeElement !== fp && fp.value !== s.flagPrefix) fp.value = s.flagPrefix;
  const sel = s.selected;
  setLibraryTarget(
    sel === 0
      ? s.steps.length ? 'Adds a step right after the input.' : 'Adds the first step after the input.'
      : sel < s.steps.length
        ? `Inserts after layer ${sel}, before layer ${sel + 1}.`
        : `Adds after layer ${sel}: ${stepTitle(s.steps[sel - 1])}.`
  );
  document.body.dataset.pane = s.mobilePane;
  $$('.pane-switch button').forEach((b) => b.setAttribute('aria-current', String(b.dataset.pane === s.mobilePane)));
  document.body.classList.toggle('library-open', s.libraryOpen);
  $('#library-scrim').hidden = !(s.libraryOpen && drawerMode());
  $('#btn-library').setAttribute('aria-expanded', String(s.libraryOpen));
}

// Header, pane and drawer state apply at once (focus depends on visibility); the chain recomputes after.
store.subscribe((s, meta) => {
  renderHeader(s);
  schedule(meta);
});

/* ---------- Actions ---------- */
const view = (patch) => store.update(patch, { reason: 'view' });

function selectLayer(i, { keepFocus } = {}) {
  const s = store.getState();
  if (s.selected === i) return;
  resetDataLimit();
  view({ selected: i, compare: { a: s.compare.a, b: null } });
  if (!keepFocus) requestAnimationFrame(() => scrollLayerIntoView(i));
}

function loadExample(ex) {
  store.update((s) => ({ ...s, input: { text: ex.input, binary: null, fileName: null }, steps: [], selected: 0, flagPrefix: ex.flagPrefix, mobilePane: 'chain' }), { history: true, reason: 'example' });
  derived.attackResult = null;
  toast(`Loaded example: ${ex.title}`, { action: 'Undo', onAction: store.undo });
}

async function loadFile(file) {
  if (file.size > MAX_FILE) {
    toast(`${file.name} is ${formatBytes(file.size)}; the limit is ${formatBytes(MAX_FILE)}.`, { tone: 'bad' });
    return;
  }
  const bytes = new Uint8Array(await file.arrayBuffer());
  const text = tryUtf8(bytes);
  const asText = text !== null && looksTextual(bytes) && bytes.length <= 2 * 1024 * 1024;
  store.update(
    (s) => ({ ...s, input: asText ? { text, binary: null, fileName: file.name } : { text: '', binary: bytesToBase64(bytes), fileName: file.name }, steps: [], selected: 0 }),
    { history: true, reason: 'file' }
  );
  toast(`Loaded ${file.name} (${formatBytes(bytes.length)}${asText ? '' : ', binary'})`, { action: 'Undo', onAction: store.undo });
}

function clearAll() {
  const s = store.getState();
  if (!s.input.text && !s.input.binary && !s.steps.length) return;
  store.update((st) => ({ ...st, input: { text: '', binary: null, fileName: null }, steps: [], selected: 0 }), { history: true, reason: 'clear' });
  derived.attackResult = null;
  toast('Cleared input and steps', { action: 'Undo', onAction: store.undo });
  $('#input-editor').focus();
}

function addOp(op) {
  const s = store.getState();
  const after = s.selected;
  store.insertStep({ opId: op.id, params: defaultParams(op) }, after);
  if (narrow()) view({ mobilePane: 'chain' });
  if (drawerMode()) view({ libraryOpen: false });
  toast(`Added ${op.explain(defaultParams(op))} after ${after === 0 ? 'the input' : `layer ${after}`}`);
  requestAnimationFrame(() => scrollLayerIntoView(after + 1));
}

function applySuggestion(sug, afterIndex) {
  const s = store.getState();
  store.insertStep({ opId: sug.opId, params: { ...sug.params }, note: sug.source === 'attack' ? sug.reason : undefined }, afterIndex);
  const op = opById[sug.opId];
  if (afterIndex < s.steps.length) toast(`Inserted ${op.explain(sug.params)} after layer ${afterIndex}; later steps now run on its output`);
  requestAnimationFrame(() => scrollLayerIntoView(afterIndex + 1));
}

function runAttack(attackId, layerIndex) {
  const layers = derived.layers;
  const layer = layers?.[layerIndex];
  if (!layer?.bytes) return;
  const attack = attackById[attackId];
  const s = store.getState();
  const result = attack.run(layer.bytes, { flagPrefix: s.flagPrefix });
  const key = (layerIndex === 0 ? 'input' : s.steps[layerIndex - 1].uid) + ':' + layer.bytes.length;
  derived.attackResult = { layerKey: key, attack, result, all: false };
  openSection('attacks');
  view({ tab: 'analysis', selected: layerIndex, mobilePane: narrow() ? 'inspector' : s.mobilePane, libraryOpen: drawerMode() ? false : s.libraryOpen });
  render();
  setTimeout(() => document.getElementById('attack-result')?.scrollIntoView({ block: 'start' }), 30);
}

async function autoSolve() {
  const s = store.getState();
  const bytes = inputBytes(s);
  if (!bytes.length) {
    toast('Paste or import some input first', { tone: 'bad' });
    $('#input-editor').focus();
    return;
  }
  const ctrl = new AbortController();
  const online = engine.status === 'online';
  showSolveRunning(online, () => ctrl.abort());
  let res;
  try {
    res = online ? await engine.solve(bytes, { flagPrefix: s.flagPrefix }, ctrl.signal) : await localSearch(bytes, { flagPrefix: s.flagPrefix }, { onProgress: updateSolveProgress, signal: ctrl.signal });
  } catch (err) {
    toast(`Engine request failed (${err.message}). Ran the local search instead.`, { tone: 'bad', ms: 5000 });
    engine.status = 'offline';
    updateEnginePill();
    res = await localSearch(bytes, { flagPrefix: s.flagPrefix }, { onProgress: updateSolveProgress, signal: ctrl.signal });
  }
  showSolveResults(res, online && engine.status === 'online', (c) => {
    store.replaceChain(c.chain.map((st) => ({ opId: st.opId, params: st.params, note: st.note })));
    $('#dlg-solve').close();
    toast(`Loaded a ${c.chain.length}-step chain (${c.status.label.toLowerCase()})`, { action: 'Undo', onAction: store.undo });
  });
}

function openScript() {
  const s = store.getState();
  const code = buildScript(inputBytes(s), s.steps);
  showScript(code, {
    stepCount: s.steps.filter((x) => !x.disabled).length,
    onCopy: async () => toast((await copyText(code)) ? 'Script copied' : 'Copy failed: select the text and copy it manually', { tone: 'ok' }),
    onDownload: () => download('solve.py', new TextEncoder().encode(code), 'text/x-python'),
  });
}

function openLibrary() {
  if (narrow()) view({ mobilePane: 'library' });
  else if (drawerMode()) view({ libraryOpen: true });
  requestAnimationFrame(() => {
    const f = $('#library-filter');
    f.focus();
    f.select();
  });
}

function updateEnginePill() {
  const pill = $('#engine-pill');
  pill.dataset.state = engine.status;
  const label = { online: 'Engine connected', offline: 'Engine offline', checking: 'Checking engine', unknown: 'Engine' }[engine.status];
  pill.querySelector('.engine-label').textContent = label;
  pill.title = engine.status === 'online' ? `Connected to ${engine.baseUrl}` : 'Engine not connected: operations run in the browser. Click for details.';
  pill.setAttribute('aria-label', label);
}

/* ---------- Boot ---------- */
function bindHeader() {
  $('#btn-undo').innerHTML = icon('undo');
  $('#btn-redo').innerHTML = icon('redo');
  $('#btn-help').innerHTML = icon('help');
  $('#btn-script').innerHTML = `${icon('code')}<span class="btn-script-label">Solve script</span>`;
  $('#btn-solve').innerHTML = `${icon('play', { size: 14 })}<span class="btn-solve-label">Auto-solve</span>`;
  $('#btn-library').innerHTML = `${icon('library')}<span>Library</span>`;
  $('#btn-solve').setAttribute('aria-label', 'Auto-solve');
  $('#btn-script').setAttribute('aria-label', 'Solve script');

  $('#btn-undo').addEventListener('click', store.undo);
  $('#btn-redo').addEventListener('click', store.redo);
  $('#btn-help').addEventListener('click', showHelp);
  $('#btn-script').addEventListener('click', openScript);
  $('#btn-solve').addEventListener('click', autoSolve);
  $('#btn-library').addEventListener('click', () => (store.getState().libraryOpen ? view({ libraryOpen: false }) : openLibrary()));
  $('#library-scrim').addEventListener('click', () => view({ libraryOpen: false }));
  $('#engine-pill').addEventListener('click', () =>
    showEngine(engine, async (url) => {
      engine.setBaseUrl(url);
      updateEnginePill();
      await engine.checkHealth();
      updateEnginePill();
    })
  );
  $('#flag-prefix').addEventListener('input', (e) => store.update({ flagPrefix: e.target.value }, { history: true, coalesce: 'flag', reason: 'flag' }));
  $$('.pane-switch button').forEach((b) => b.addEventListener('click', () => view({ mobilePane: b.dataset.pane })));
}

function bindKeys() {
  document.addEventListener('keydown', (e) => {
    if (e.defaultPrevented) return;
    const t = e.target;
    const typing = t.matches?.('input, textarea, select, [contenteditable]');
    const mod = e.ctrlKey || e.metaKey;
    if (mod && e.key === 'Enter') {
      e.preventDefault();
      autoSolve();
      return;
    }
    if (document.querySelector('dialog[open]')) return;
    if (mod && !typing && e.key.toLowerCase() === 'z') {
      e.preventDefault();
      e.shiftKey ? store.redo() : store.undo();
    } else if (mod && !typing && e.key.toLowerCase() === 'y') {
      e.preventDefault();
      store.redo();
    } else if (!typing && !mod && e.key === '/') {
      e.preventDefault();
      openLibrary();
    } else if (!typing && e.key === '?') {
      e.preventDefault();
      showHelp();
    } else if (e.key === 'Escape' && store.getState().libraryOpen) {
      view({ libraryOpen: false });
    } else if (!typing && e.altKey && (e.key === 'ArrowUp' || e.key === 'ArrowDown')) {
      const s = store.getState();
      const step = s.steps[s.selected - 1];
      if (step) {
        e.preventDefault();
        store.moveStep(step.uid, e.key === 'ArrowUp' ? -1 : 1);
      }
    }
  });
}

function boot() {
  bindHeader();
  bindKeys();
  initDialogs();
  initLibrary({
    onOp: addOp,
    onAttack: (a) => runAttack(a.id, store.getState().selected),
    onEngine: showEngineOnly,
    onInspect: () => {
      view({ tab: 'analysis', mobilePane: narrow() ? 'inspector' : store.getState().mobilePane, libraryOpen: false });
      setTimeout(() => document.getElementById('sec-checks')?.scrollIntoView({ block: 'start' }), 30);
    },
    onEscape: () => view({ libraryOpen: false }),
  });
  initChain({
    onInput: (text) => store.setInputText(text),
    onSelect: selectLayer,
    onFile: loadFile,
    onExamples: () => showExamples(loadExample),
    onLoadExample: loadExample,
    onClear: clearAll,
    onMove: (uid, d) => store.moveStep(uid, d),
    onMoveTo: (uid, to) => store.moveStepTo(uid, to),
    onToggle: (uid) => {
      const step = store.getState().steps.find((x) => x.uid === uid);
      store.patchStep(uid, { disabled: !step.disabled });
    },
    onRemove: (uid) => {
      const step = store.getState().steps.find((x) => x.uid === uid);
      store.removeStep(uid);
      toast(`Removed ${stepTitle(step)}`, { action: 'Undo', onAction: store.undo });
    },
    // Editing a key by hand means it is no longer the one an attack recovered.
    onParam: (uid, params, coalesce) => store.patchStep(uid, { params, note: undefined }, { coalesce: coalesce || 'select' }),
    onInspect: (i) => {
      selectLayer(i);
      view({ mobilePane: 'inspector' });
    },
    onApplySuggestion: applySuggestion,
    onAddStep: (after) => {
      selectLayer(after);
      openLibrary();
    },
    onCopy: async (text, msg) => toast((await copyText(text)) ? msg : 'Copy failed', { tone: 'ok' }),
  });
  initInspector({
    onTab: (tab) => view({ tab }),
    onDistView: (distView) => view({ distView }),
    onDataView: (dataView) => view({ dataView }),
    onWrap: (wrap) => view({ wrap }),
    onCompare: (which, v) => view({ compare: { ...store.getState().compare, [which]: v } }),
    onHexCompare: (hexCompare) => view({ hexCompare }),
    onApplySuggestion: applySuggestion,
    onRunAttack: runAttack,
    onUseCandidate: (c, attack, layerIndex) => {
      store.insertStep({ opId: c.opId, params: { ...c.params }, note: `Recovered with ${attack.name}: ${c.label}` }, layerIndex);
      requestAnimationFrame(() => scrollLayerIntoView(layerIndex + 1));
    },
    onAttackShowAll: () => {
      if (derived.attackResult) derived.attackResult.all = true;
      render();
    },
    onCopy: async (text, msg) => toast((await copyText(text)) ? msg : 'Copy failed', { tone: 'ok' }),
    onDownload: (bytes, i) => download(i === 0 ? 'input.bin' : `layer-${i}.bin`, bytes),
    onRerender: render,
  });

  store.loadSaved();
  schedule();
  engine.status = engine.baseUrl ? 'checking' : 'offline';
  updateEnginePill();
  engine.checkHealth().then(updateEnginePill);
  matchMedia('(max-width: 1240px)').addEventListener('change', render);
}

boot();
