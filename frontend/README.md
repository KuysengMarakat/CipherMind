# CipherMind workbench (frontend)

Browser interface for CipherMind, the multi-layer cryptanalysis toolkit described in
`CipherMind_Project_Proposal_v1.0.pdf`. Plain HTML, CSS and JavaScript modules: no build step,
no npm packages, no CDN. Fonts are bundled so it also works offline during a competition.

## Run it

Browsers block JavaScript modules on `file://` pages, so serve the folder:

```bash
cd frontend
python -m http.server 8000
# open http://localhost:8000
```

Tests for the core logic (Node 18 or later, no packages):

```bash
node tests/core.test.mjs
```

## How the interface is organised

| Area | Purpose |
| --- | --- |
| **Chain** (centre) | Input at the top, one row per step. Each row shows the layer's size, a status (flag found, looks like Base64, binary, failed…) and a preview. A rail connects the layers so the order of operations is always visible. Select a row to edit its parameters; reorder by dragging, Alt+↑/↓ or the arrow buttons; skip or remove steps. |
| **Next layer** (end of chain) | Top suggestions for the last layer, one click to add. |
| **Result** (end of chain) | Verified / Partially verified / Unsolved, using the definitions in Section 3.5 of the proposal. |
| **Inspector** (right) | For the selected layer. *Analysis*: ranked suggestions with confidence and reason, hard checks (flag, file signature, hash shape, RSA parameters, ECB repeats), profile (entropy, IoC, printable ratio), letter or byte distribution, and attacks. *Data*: full output as text, hex dump or Base64, with copy and save. *Compare*: any two layers side by side, with changed characters highlighted when lengths match. |
| **Library** (left) | Operations grouped by what they are: encodings, ciphers with a key, attacks, decompression, rearrange, hashes (identify only) and engine-only features. |
| **Auto-solve** | Searches for the whole chain. Uses the engine when connected, otherwise a smaller local search, and says which one ran. |
| **Solve script** | Standard-library Python 3 script that reproduces the chain (Module G). |

Encoding, decryption, cryptanalysis and hashing are kept separate on purpose. Attacks never sit in the
chain. They recover a key, then add a keyed step with a note on how the key was found. Hashes can be
identified but there is no "decode" for them.

## What is real and what is not

Everything below runs on real data. There is no mock output anywhere in the UI.

| Implemented in the browser | Notes |
| --- | --- |
| Base64 (incl. URL-safe), Base32, Base58, Ascii85, Base85 (RFC 1924), hex, binary, octal, decimal, URL, HTML entities, Morse, reverse | Decode; most also encode |
| Caesar, ROT13, ROT47, Atbash, affine, Vigenère, repeating-key XOR, known-key substitution | |
| gzip, zlib, raw deflate | Browser `DecompressionStream` |
| Caesar and affine brute force, Vigenère key recovery (IoC + Kasiski + χ²), single-byte XOR, repeating-key XOR (Hamming), known-plaintext XOR from the flag prefix | Keys ranked on a 4 KB sample for speed |
| Profile: entropy, IoC, χ², printable ratio, charset, file signatures, flag match, hash identification, RSA parameter parsing, ECB block repeats | |
| Local quick search | Beam search over the suggestions above: depth 6, beam 8, 4 s. Every candidate is re-run from the input before it is labelled |
| Undo/redo, session saved in `localStorage`, file import (text or binary, drag and drop), copy, save, solve-script export | |

| Not in the browser (needs the Python engine) | What the UI does |
| --- | --- |
| Full beam search with backtracking | Auto-solve falls back to the local search and labels it |
| Substitution solver (quadgram hill climbing) | Listed under *Needs the CipherMind engine*; opening it explains it is not available |
| RSA weakness checks, AES usage checks, modular arithmetic | RSA parameters are parsed and the likely weakness is described (e.g. small e with a short c), but no attack is run |
| Hash dictionary checks | Hash type is identified only |

The examples in `js/examples.js` were generated with Python's standard library (the RSA primes with
SymPy), so each expected answer is known. `tests/core.test.mjs` checks that the local search solves them.

## File structure

```
frontend/
  index.html               page shell
  css/tokens.css           colours, type, spacing, fonts
  css/app.css              layout and components, responsive rules
  assets/fonts/            Atkinson Hyperlegible Next + Mono (SIL OFL)
  js/main.js               wires state, computation and rendering
  js/state/store.js        state, undo/redo, persistence, chain edits
  js/core/bytes.js         byte and text helpers
  js/core/profile.js       layer profile (Module A) and hard checks
  js/core/score.js         English fitness, IoC, χ², flag regex
  js/core/pipeline.js      runs the chain, layer and result status
  js/core/suggest.js       next-step suggestions for a layer
  js/core/search.js        local beam search
  js/core/script.js        Python solve-script generator
  js/ops/registry.js       operation registry and library groups
  js/ops/encodings.js      Module B operations
  js/ops/classical.js      Module C operations
  js/ops/compression.js    decompression
  js/ops/attacks.js        key recovery
  js/api/engine.js         client for the Python engine
  js/ui/*.js               chain, inspector, library, dialogs, toasts, helpers
  js/examples.js           sample challenges
  tests/core.test.mjs      Node tests for the core
```

Each operation follows the plugin interface from Section 3.1 of the proposal: `detect(profile)` returns
`{ confidence, reason }`, `apply(bytes, params)` returns new bytes, `explain(params)` returns a one-line
description, and `python(params)` returns code for the solve script. Using the same operation IDs in the
Python plugins keeps the two sides interchangeable.

## Connecting the Python engine

The page contacts an engine only when a URL is configured, so no failing requests appear in the console
before the engine exists. Configure it either way:

* in the page: click the engine status in the top bar and enter the base URL, or
* from the server: set `<meta name="ciphermind-engine" content="/api">` in `index.html` (FastAPI can serve
  the file with that value filled in).

Serving both from FastAPI:

```python
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

app = FastAPI()

@app.get("/api/health")
def health():
    return {"status": "ok", "version": "0.1.0"}

# ... /api/plugins and /api/solve ...

app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
```

### Endpoints the frontend expects

`GET {base}/health`

```json
{ "status": "ok", "version": "0.1.0" }
```

`POST {base}/solve`

Request:

```json
{
  "input_b64": "NTU0NTY0…",
  "flag_prefix": "CTF{",
  "max_depth": 8,
  "beam_width": 50,
  "time_limit_s": 30
}
```

Response:

```json
{
  "candidates": [
    {
      "status": "verified",
      "status_detail": "Flag pattern matched: CTF{l4y3r5_0f_c0d3}",
      "score": 0.98,
      "output_b64": "Q1RGe2w0eTNyNV8wZl9jMGQzfQ==",
      "chain": [
        { "plugin": "hex", "params": { "mode": "decode" }, "explanation": "Input used only 0-9 and a-f; even length" },
        { "plugin": "base64", "params": { "mode": "decode" }, "explanation": "Base64 alphabet with == padding" },
        { "plugin": "caesar", "params": { "shift": 13 }, "explanation": "Only shift that matched the flag format" }
      ],
      "next_step": null
    }
  ],
  "stats": { "states_explored": 412, "elapsed_ms": 380, "max_depth_reached": 3, "stop_reason": "Found a verified result" }
}
```

`status` is `verified`, `partial` or `unsolved`. When `plugin` matches a browser operation ID (`hex`,
`base64`, `caesar`, `vigenere`, `xor`…), the loaded chain runs and can be edited in the browser. Any other
plugin is shown as "engine only".

`GET {base}/plugins` is reserved for listing engine plugins (`id`, `name`, `kind`, `params`) so the
library can show them. The frontend does not call it yet.

### Suggested next integration steps

1. Implement `/health` and `/solve` with the shapes above; the auto-solve dialog needs no changes.
2. Add `/plugins`, then merge engine-only plugins into `libraryGroups` in `js/ops/registry.js` and add an
   `/apply` endpoint so the chain can run them step by step.
3. Port the scoring thresholds in `js/core/score.js` to the engine's validator, or the reverse, so both
   sides label results the same way.
4. Use the examples and `tests/core.test.mjs` as the first entries of the benchmark.

## Browser support

Current Chrome, Edge, Firefox and Safari. Layout adapts at 1240 px (library becomes a drawer) and 860 px
(one panel at a time with a switcher). Keyboard: Ctrl+Z / Ctrl+Shift+Z, Ctrl+Enter, `/`, `?`, arrow keys
on layer names, Alt+↑/↓, Delete. Reduced-motion settings are respected.
