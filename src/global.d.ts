// Intentionally empty.
//
// This file used to contain `declare module 'node-fetch'` whose body did
// `import { RequestInit, Response } from 'node-fetch'` -- a self-referential
// declaration that resolved to `any` and shadowed the real types shipped by
// node-fetch. src/types/node-fetch.d.ts was a byte-identical duplicate.
// node-fetch is now loaded dynamically in src/http/fetchImpl.ts.
export {};
