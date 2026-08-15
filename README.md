# bchat-sdk (Node.js)

Minimal Node.js SDK that mirrors the core networking pieces of the BChat desktop app: seed-node discovery, storage node (snode) RPC, sealed-box message envelopes, and optional on-disk persistence. Suitable for server-side tooling, bots, and integration tests.

## Install

```bash
npm install bchat-sdk
```

Requires Node.js 18 or newer. The package ships both a CommonJS and an ES module build.

## Quick start

```ts
import { BchatSDK, createIdentity, BchatProtocolEncryption, FileStore } from 'bchat-sdk';

// One 25-word seed produces the BChat ID *and* the Beldex wallet address,
// exactly as the desktop app does on registration.
const account = await createIdentity('mainnet');
// account.mnemonic      -> 25 words, the only thing to back up
// account.bchatId       -> 'bd' + 64 hex
// account.walletAddress -> 97-char Beldex address

const sdk = new BchatSDK({
  seedNodes: [
    'https://publicnode1.rpcnode.stream/',
    'https://publicnode2.rpcnode.stream/',
    'https://publicnode3.rpcnode.stream/',
  ],
  account: {
    x25519: account.x25519,
    ed25519: account.ed25519,
  },
  persistence: new FileStore('./.bchat-cache'),
});

// Pull a randomized pool of storage nodes
await sdk.refreshSnodePool();

// Send a message. The payload is sealed-box encrypted to the recipient's
// x25519 key by default; pass `encrypt: false` to send it as-is.
await sdk.sendMessage({
  recipientPubKey: account.bchatId, // bare hex or a bd/05-prefixed ID both work
  payload: 'hello world',
});

// Receive messages (retrieve is signed with your ed25519 key). When a
// `persistence` store is configured, `lastHash` is read from and written back
// to it automatically.
const messages = await sdk.getMessages({
  pubKey: account.x25519.publicKey,
  ed25519PrivHex: account.ed25519.privateKey,
  ed25519PubHex: account.ed25519.publicKey,
});
console.log(messages);
```

## CLI

After building (`npm run build`), a CLI is available:

```bash
# Generate keys (writes with 0600 permissions)
bchat-sdk create-account --output account.json

# Send a message
bchat-sdk send \
  --recipient <RECIPIENT_PUBKEY> \
  --message "hello world" \
  --account account.json \
  --insecure   # add this if you hit self-signed cert errors

# Receive messages (stores last hash + messages under .bchat-cache)
bchat-sdk receive \
  --account account.json \
  --cache .bchat-cache
```

> `account.json` contains private keys. Keep it out of version control — the
> repository's `.gitignore` covers `account*.json` and `.bchat-cache/`.

## Example apps

- [`examples/chat`](./examples/chat) — interactive terminal chat client.
- [`examples/api`](./examples/api) — HTTP service exposing send/receive as JSON,
  for driving BChat from a non-Node app.

```bash
npm run example:chat -- --peer bd<their-id>
npm run example:api
```

## API

- `new BchatSDK(options)`
  - `seedNodes: string[]` **required** — base URLs ending with `/` for seed nodes.
  - `fetch?: (input, init) => Promise<Response>` — custom fetch. Defaults to `node-fetch`, loaded lazily; the global `fetch` is **not** used because undici ignores the `agent` option this SDK relies on for TLS configuration.
  - `timeoutMs?: number` — per-request timeout (defaults: seed 5s, snode 10s).
  - `logger?: {info,warn,error}` — defaults to `console`.
  - `insecureTls?: boolean` — disables certificate verification for this SDK's requests only (scoped to its `https.Agent`; it does not touch `NODE_TLS_REJECT_UNAUTHORIZED`).
  - `persistence?: Persistence` — e.g. `new FileStore(dir)`.
  - `account?: { x25519, ed25519? }` — hex keypairs used for decryption.
  - `encryption?: EncryptionProvider` — override the default sealed-box implementation.

- `refreshSnodePool(): Promise<Snode[]>` — fetches and caches the snode pool from seeds. Concurrent calls share one in-flight request.
- `getSnodePool(): Promise<Snode[]>` — returns cached pool or fetches once if empty.
- `getSwarm(pubKey: string): Promise<Snode[]>` — resolve swarm members for a pubkey via storage nodes.
- `call(method: string, params: any): Promise<string>` — invoke a storage_rpc on a random snode.
- `sendMessage(params: SendMessageParams): Promise<string|boolean>` — encrypts (unless `encrypt: false`), base64-wraps the payload, and calls `store` on up to 3 swarm nodes, returning the first hash/ok.
- `getMessages(params: GetMessagesParams): Promise<any[]>` — signs a `retrieve` call (if ed25519 keys provided) and returns the messages array from the first responsive snode.
- `createIdentity(network?)` / `identityFromMnemonic(phrase, network?)` /
  `generateMnemonic()` — mint or restore a full identity. The BChat ID comes
  from `crypto_sign_seed_keypair(seed)` and the wallet from the CryptoNote
  deterministic scheme over the *same* seed, so both are functions of the
  recovery phrase alone.
- `encodeAddress` / `decodeAddress` / `deriveWalletKeys` — Beldex address
  helpers, with checksum verification.
- `createAccount(): Promise<AccountKeys>` / `accountFromEd25519(ed)` — a
  keys-only identity with no wallet, for non-BChat peers.
- `FileStore` — JSON-on-disk persistence for last hash + received messages. Writes are serialized per key and committed atomically.
- `normalizeX25519Hex(value)` — validate/strip a `bd`/`05` prefix from an account ID.
- `retry(fn, options)` / `AbortError` — the internal backoff helper, exported for reuse.

## Identity model

A BChat identity is one 32-byte seed, expressed as a 25-word Electrum-style
recovery phrase:

```
mnemonic ──► seed (32 bytes) ──┬──► crypto_sign_seed_keypair ──► ed25519 ──► x25519 ──► BChat ID ('bd' + hex)
                               └──► sc_reduce32 ──► spend key ──► keccak256 ──► view key ──► Beldex address
```

Both branches start from the same seed, which is why a given phrase always
restores the same ID *and* the same wallet — and why changing only the wallet
address string cannot change the BChat ID.

The network prefix (`0xd1` mainnet, `53` testnet) is what makes mainnet
addresses 97 characters and testnet ones 95 — the lengths bchat-desktop
hardcodes when slicing the address off a received message.

## Notes / parity with bchat-desktop

- Seed discovery uses `get_n_master_nodes` with the same field set as desktop (public_ip, storage_port, pubkeys) and shuffles results. Every configured seed is tried before the call fails.
- Swarm resolution mirrors `get_mnodes_for_pubkey` and filters out `0.0.0.0` entries.
- The certificate bundle copied from bchat-desktop (cross-signed ISRG Root X1) expired on 2024-09-30, so the system trust store is appended to it rather than replaced.
- Onion routing is not implemented; `Transport` is the extension point (`DirectTransport` is the default).
- **The BChat application protocol is implemented** by
  `BchatProtocolEncryption`: protobuf `Content`/`Envelope`/`WebSocketMessage`,
  the 160-byte padding scheme, and sealed-sender signing/verification. Messages
  interoperate with the official clients in both directions. Pass it as the
  `encryption` option; it requires your Beldex wallet address, which BChat
  embeds in every payload. Closed groups and attachments are still unsupported.
  `SealedBoxEncryption` remains the default for non-BChat peers.
- `retrieve`'s `lastHash` is snode-relative, so `SnodeClient` pins each pubkey's
  retrieval to one swarm member and rotates only on persistent failure; it also
  de-duplicates message hashes across polls.

## Development

```bash
npm install
npm run typecheck
npm run lint     # ESLint 9 flat config, see eslint.config.mjs
npm test
npm run build
```

Building and testing requires Node `^20.19` or `>=22.12` (a vitest 4 requirement).
The published package itself still supports Node 18+.

`libsodium-wrappers-sumo` is pinned to `0.7.15`: `0.7.16` publishes an `exports.import` entry that points at a `.mjs` file missing from the tarball, which breaks every native-ESM consumer.

## License

MIT
