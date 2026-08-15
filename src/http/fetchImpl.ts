import type { FetchFn } from '../types.js';

/**
 * `node-fetch` v3 is ESM-only. TypeScript downlevels a static
 * `import fetch from 'node-fetch'` to `require('node-fetch')` in the CommonJS
 * build, which throws ERR_REQUIRE_ESM on Node < 22.12. Building the dynamic
 * import through `new Function` keeps it a genuine `import()` in both outputs.
 *
 * node-fetch (rather than the global `fetch`) is required here because the
 * seed/snode clients pass a custom `https.Agent` for TLS pinning and for the
 * self-signed certificates used by storage nodes; undici's global `fetch`
 * silently ignores the `agent` option.
 */
const dynamicImport: (specifier: string) => Promise<any> = new Function(
  'specifier',
  'return import(specifier);'
) as (specifier: string) => Promise<any>;

let pending: Promise<FetchFn> | null = null;

export function loadNodeFetch(): Promise<FetchFn> {
  if (!pending) {
    pending = dynamicImport('node-fetch')
      .then(mod => (mod.default ?? mod) as FetchFn)
      .catch(error => {
        pending = null;
        throw error;
      });
  }
  return pending;
}

/** A `FetchFn` that resolves node-fetch lazily on first use. */
export const defaultFetch: FetchFn = async (input, init) => (await loadNodeFetch())(input, init);
