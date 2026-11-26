// Core logic tests. Run from the frontend folder with:  node tests/core.test.mjs
// Needs Node 18+ (for DecompressionStream). No packages required.

import assert from 'node:assert/strict';
import { examples } from '../js/examples.js';
import { utf8, displayText } from '../js/core/bytes.js';
import { localSearch } from '../js/core/search.js';
import { runChain, resultStatus } from '../js/core/pipeline.js';
import { opById } from '../js/ops/registry.js';
import { helpersForTest as enc } from '../js/ops/encodings.js';
import { profileBytes } from '../js/core/profile.js';

let passed = 0;
async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`ok   ${name}`);
  } catch (err) {
    console.log(`FAIL ${name}\n     ${err.message}`);
    process.exitCode = 1;
  }
}

const expected = {
  worked: 'CTF{l4y3r5_0f_c0d3}',
  vigenere_b32: 'CTF{kasiski_was_here}',
  xor1: 'flag{single_byte_xor_is_not_encryption}',
  xor_rep_b64: 'CTF{r3p34t1ng_x0r_l34ks_th3_k3y}',
  gzip_b64: 'flag{gz1p_1n51d3_b64}',
  b58_url: 'picoCTF{ur1_3nc0d1ng_1s_n0t_3ncrypt10n}',
  a85: 'CTF{asc11_85_1s_b4s3_85}',
};

for (const ex of examples) {
  if (!(ex.id in expected)) continue;
  await test(`local search solves "${ex.title}"`, async () => {
    const res = await localSearch(utf8(ex.input), { flagPrefix: ex.flagPrefix });
    const best = res.candidates[0];
    assert.ok(best, 'no candidate');
    assert.equal(best.status.id, 'verified');
    assert.ok(displayText(best.bytes).includes(expected[ex.id]), `output was ${displayText(best.bytes).slice(0, 80)}`);
  });
}

await test('hash example is not reported as solved', async () => {
  const ex = examples.find((e) => e.id === 'md5');
  const res = await localSearch(utf8(ex.input), { flagPrefix: '' });
  assert.ok(!res.candidates.some((c) => c.status.id === 'verified'));
  assert.ok(profileBytes(utf8(ex.input)).hashes.some((h) => h.name === 'MD5'));
});

await test('RSA parameters are recognised but not attacked', async () => {
  const ex = examples.find((e) => e.id === 'rsa');
  const p = profileBytes(utf8(ex.input));
  assert.equal(p.rsa.e, 3n);
  const res = await localSearch(utf8(ex.input), { flagPrefix: ex.flagPrefix });
  assert.ok(!res.candidates.some((c) => c.status.id === 'verified'));
});

await test('manual chain: hex → base64 → rot13 is verified', async () => {
  const layers = await runChain(utf8(examples[0].input), [{ opId: 'hex', params: { mode: 'decode' } }, { opId: 'base64', params: { mode: 'decode' } }, { opId: 'rot13', params: {} }], { flagPrefix: 'CTF{' });
  assert.equal(resultStatus(layers).id, 'verified');
});

await test('failed step blocks later steps', async () => {
  const layers = await runChain(utf8('not hex!'), [{ opId: 'hex', params: { mode: 'decode' } }, { opId: 'rot13', params: {} }], {});
  assert.ok(layers[1].error);
  assert.ok(layers[2].blocked);
  assert.equal(resultStatus(layers).id, 'unsolved');
});

await test('encode/decode round trips', async () => {
  const data = new Uint8Array(Array.from({ length: 257 }, (_, i) => (i * 37) % 256));
  for (const id of ['base64', 'base32', 'base58', 'ascii85', 'base85', 'hex', 'binary', 'url']) {
    const op = opById[id];
    const encoded = await op.apply(data, { mode: 'encode' });
    const decoded = await op.apply(encoded, { mode: 'decode' });
    assert.deepEqual([...decoded], [...data], `${id} round trip`);
  }
});

await test('classical ciphers invert correctly', async () => {
  const text = utf8('Attack at dawn, CTF{x}!');
  const v = await opById.vigenere.apply(text, { key: 'LEMON', mode: 'encrypt' });
  assert.equal(displayText(v), 'Lxfopv ef rnhr, OHS{i}!');
  assert.equal(displayText(await opById.vigenere.apply(v, { key: 'LEMON', mode: 'decrypt' })), 'Attack at dawn, CTF{x}!');
  assert.equal(displayText(await opById.rot13.apply(await opById.rot13.apply(text, {}), {})), 'Attack at dawn, CTF{x}!');
  assert.equal(displayText(await opById.atbash.apply(utf8('abc XYZ'), {})), 'zyx CBA');
  const x = await opById.xor.apply(text, { key: 'k3y', keyFormat: 'text' });
  assert.equal(displayText(await opById.xor.apply(x, { key: '6b3379', keyFormat: 'hex' })), 'Attack at dawn, CTF{x}!');
});

await test('morse and html entity decoding', () => {
  assert.equal(displayText(enc.morsedecode('.... .. / - .... . .-. .')), 'HI THERE');
  assert.equal(enc.htmldecode('&#67;&#x54;F&lbrace;ok&rbrace; &amp;'), 'CTF{ok} &');
});

console.log(`\n${passed} passed${process.exitCode ? ', some failed' : ''}`);
