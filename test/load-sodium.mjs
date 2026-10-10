/**
 * Loads the bundled browser `libsodium.js` into Node so the crypto paths can be
 * exercised in tests.
 *
 * The bundle is UMD. Under Node it detects `exports` and assigns the module
 * object directly onto that object, rather than onto `global`. The
 * `crypto_*` functions are attached only after the `ready` promise settles, so
 * we await it, then publish the result onto `globalThis.sodium` — which is
 * exactly where `core/crypto.mjs` looks for it.
 *
 * Returns null when the bundle cannot be loaded, so callers can skip crypto
 * tests rather than failing them spuriously.
 */

import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

function looksLikeSodium(mod) {
  return !!mod && typeof mod.crypto_box_seal === 'function';
}

export async function loadSodium() {
  if (looksLikeSodium(globalThis.sodium)) {
    await globalThis.sodium.ready;
    return globalThis.sodium;
  }

  let src;
  try {
    src = readFileSync(join(here, '..', 'libsodium.js'), 'utf8');
  } catch {
    return null;
  }

  try {
    const req = createRequire(import.meta.url);
    const shim = {};
    // The bundle needs a CommonJS-shaped scope: it reads exports/module/
    // require/__dirname at the UMD tail.
    // eslint-disable-next-line no-new-func
    new Function('exports', 'module', 'require', '__dirname', '__filename', 'process', src)(
      shim, { exports: shim }, req, here, 'libsodium.js', process,
    );
    // The module object is the exports object itself; crypto_* appear on ready.
    await shim.ready;
    if (!looksLikeSodium(shim)) return null;
    globalThis.sodium = shim;
    return shim;
  } catch {
    return null;
  }
}