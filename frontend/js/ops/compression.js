// Decompression via the browser's built-in DecompressionStream (no dependency).

import { OpError } from './encodings.js';

async function decompress(bytes, format) {
  if (typeof DecompressionStream === 'undefined') throw new OpError('This browser has no DecompressionStream support.');
  try {
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  } catch (err) {
    throw new OpError(`Not a valid ${format === 'deflate' ? 'zlib' : format} stream (${err.message || 'corrupt data'}).`);
  }
}

export const compressionOps = [
  {
    id: 'gunzip',
    name: 'gzip',
    kind: 'compression',
    summary: 'Decompress a gzip stream (starts 1f 8b).',
    params: [],
    detect: (p) => (p.magic === 'gzip stream' ? { confidence: 0.98, reason: 'Starts with the gzip signature 1f 8b 08' } : null),
    apply: (bytes) => decompress(bytes, 'gzip'),
    explain: () => 'gzip decompress',
    python: () => ({ imports: ['gzip'], code: 'data = gzip.decompress(data)' }),
  },
  {
    id: 'zlib',
    name: 'zlib',
    kind: 'compression',
    summary: 'Decompress a zlib stream (starts 78 01 / 9c / da).',
    params: [],
    detect: (p) => (p.magic === 'zlib stream' ? { confidence: 0.85, reason: 'Starts with a valid zlib header (78 xx)' } : null),
    apply: (bytes) => decompress(bytes, 'deflate'),
    explain: () => 'zlib decompress',
    python: () => ({ imports: ['zlib'], code: 'data = zlib.decompress(data)' }),
  },
  {
    id: 'inflate',
    name: 'Raw deflate',
    kind: 'compression',
    summary: 'Deflate data with no header, as used inside ZIP entries.',
    params: [],
    apply: (bytes) => decompress(bytes, 'deflate-raw'),
    explain: () => 'Raw deflate decompress',
    python: () => ({ imports: ['zlib'], code: 'data = zlib.decompress(data, -15)' }),
  },
];
