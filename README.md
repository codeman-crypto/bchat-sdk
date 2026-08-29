# @bdxi/bchat-sdk (Node.js)

Minimal Node.js SDK that mirrors the core pieces of the BChat desktop app: seed-node discovery, storage node (snode) RPC, the real BChat wire protocol (messages interoperate with the official clients), BNS name resolution (`codeman.bdx` → BChat ID), and optional on-disk persistence. Suitable for server-side tooling, bots, and integration tests.

## Install

```bash
npm install @bdxi/bchat-sdk
```

Requires Node.js 18 or newer. The package ships both a CommonJS and an ES module build.

## Quick start

```ts
import { BchatSDK, createIdentity, BchatProtocolEncryption, FileStore } from '@bdxi/bchat-sdk';

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
  // The real BChat wire protocol: interoperable with the official clients,
  // and carries your display name. Omit this to fall back to plain sealed
  // boxes for non-BChat peers.
  encryption: new BchatProtocolEncryption({
    ed25519: account.ed25519,
    beldexAddress: account.walletAddress,
    network: 'mainnet',
    displayName: 'codeman',
  }),
});

// Pull a randomized pool of storage nodes
await sdk.refreshSnodePool();

// Send a message, end-to-end encrypted to the recipient. Pass
// `encrypt: false` to store the payload as-is.
await sdk.sendMessage({
  recipientPubKey: '<recipient BChat ID or BNS name>', // bare hex or a bd/05-prefixed ID both work
  payload: 'hello world',
});

// BNS names work anywhere a recipient ID is expected. The name is resolved
// against multiple storage nodes (they must all agree) before encrypting.
await sdk.sendMessage({ recipientPubKey: 'yourname.bdx', payload: 'hello' });

// Or resolve explicitly ("yourname" and "yourname.bdx" are equivalent):
const bchatId = await sdk.resolveBnsName('yourname');

// Change the display name recipients see; applies from the next message
// (the profile rides inside every message, so there is no announcement
// round trip). Pass '' or nothing to clear it.
sdk.setDisplayName('codeman');

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
npm run example:chat -- --peer bd<their-id>    # or --peer codeman.bdx
npm run example:api
```

## API

- `new BchatSDK(options)`
  - `seedNodes: string[]` **required** — base URLs ending with `/` for seed nodes.
  - `fetch?: (input, init) => Promise<Response>` — custom fetch. Defaults to `node-fetch`, loaded lazily; the global `fetch` is **not** used because undici ignores the `agent` option this SDK relies on for TLS configuration.
  - `timeoutMs?: number` — per-request timeout (defaults: seed 5s, snode 10s).
  - `logger?: {info,warn,error}` — defaults to `console`.
  - `allowSelfSignedStorageNodes?: boolean` — accept self-signed certificates **from storage nodes only**; seed nodes stay verified. Required to reach the live network.
  - `insecureTls?: boolean` — disables certificate verification for *every* request this SDK makes, seeds included. Scoped to its own `https.Agent`; it does not touch `NODE_TLS_REJECT_UNAUTHORIZED`. Prefer the option above.
  - `allowPrivateNodes?: boolean` — permit loopback/RFC1918 node addresses. Off by default to prevent SSRF via a hostile swarm response.
  - `persistence?: Persistence` — e.g. `new FileStore(dir)`.
  - `account?: { x25519, ed25519? }` — hex keypairs used for decryption.
  - `encryption?: EncryptionProvider` — override the default sealed-box implementation.

- `refreshSnodePool(): Promise<Snode[]>` — fetches and caches the snode pool from seeds. Concurrent calls share one in-flight request.
- `getSnodePool(): Promise<Snode[]>` — returns cached pool or fetches once if empty.
- `getSwarm(pubKey: string): Promise<Snode[]>` — resolve swarm members for a pubkey via storage nodes.
- `call(method: string, params: any): Promise<string>` — invoke a storage_rpc on a random snode.
- `sendMessage(params: SendMessageParams): Promise<string|boolean>` — encrypts (unless `encrypt: false`), base64-wraps the payload, and calls `store` on up to 3 swarm nodes, returning the first hash/ok. `recipientPubKey` accepts a BChat ID, a bare x25519 key, or a BNS name — names resolve before encrypting, so the payload is sealed for the key the name actually maps to.
- `getMessages(params: GetMessagesParams): Promise<any[]>` — signs a `retrieve` call (if ed25519 keys provided) and returns the messages array from the first responsive snode.
- `resolveBnsName(name: string): Promise<string>` — resolve a BNS name (`codeman` or `codeman.bdx`) to the BChat ID tagged to it. Validated against 3 random storage nodes that must all agree; results are cached for 5 minutes under both spellings.
- `setDisplayName(name?: string)` / `getDisplayName()` — change the profile name recipients see, effective from the next message. Empty/undefined clears it. Requires an encryption provider that carries sender profiles (`BchatProtocolEncryption` does; plain sealed boxes don't).
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
- `isBnsName(value)` / `looksLikeBchatId(value)` / `normalizeBnsName(name)` — classify and validate recipient strings; `bnsNameHashBase64` and `decryptBnsRecord` expose the BNS wire primitives for direct `SnodeClient.resolveBns` use.
- `retry(fn, options)` / `AbortError` — the internal backoff helper, exported for reuse.

## Security model

**What this SDK protects.** Message *bodies* are end-to-end encrypted with
sealed boxes to the recipient's X25519 key, and every incoming payload's
signature is verified before its sender ID is reported. A network observer
cannot read message contents.

**What it does not protect.** There is currently **no metadata privacy against a
network observer**, for two reasons:

- Storage nodes are not cryptographically authenticated. Every `Snode` carries a
  `pubkey_ed25519`, but the SDK does not yet verify node responses against it,
  so TLS is the only thing distinguishing a real node from an impostor.
- Onion routing is not implemented. Requests go directly to storage nodes, so
  whoever carries the traffic learns which pubkeys you poll, who you write to,
  and when.

Treat the transport as confidential-but-observable. If your threat model needs
metadata privacy, this SDK is not sufficient today.

Other properties worth knowing:

- **No forward secrecy.** `crypto_box_seal` encrypts to a long-term recipient
  key. Anyone who later obtains a recovery phrase can decrypt every message ever
  sent to that ID, including traffic recorded earlier. This is inherent to the
  BChat/Session envelope format, not a choice this SDK makes.
- **`unverifiedSenderWalletAddress` is a claim, not a fact.** It is inside the
  signed region, but the sender signs their own claim and nothing binds it to
  the authenticated `senderBchatId`. Never use it as a payment destination
  without out-of-band confirmation.
- **TLS verification is on by default, and scoped.** BChat storage nodes serve
  self-signed certificates by design — there is no PKI for them — so reaching
  the live network requires `allowSelfSignedStorageNodes: true`. That option is
  deliberately separate from `insecureTls`: enabling it does **not** stop
  verifying the seed nodes, which do have real certificates. The SDK never
  downgrades on its own; it reports a clear error instead.
- **Node addresses are validated.** Only literal, publicly routable IPs are
  accepted from seed and swarm responses, so a hostile node cannot redirect
  requests or reach loopback/metadata endpoints. Set `allowPrivateNodes: true`
  to talk to a node on your own machine.

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
- **BNS resolution mirrors desktop's `getBchatIDForOnsName`**: the name is
  hashed with blake2b-32 and sent as `beldexd_request` → `bns_resolve`
  (type 0); the returned `encrypted_value` decrypts with a key derived from
  the name itself (XChaCha20-Poly1305, or legacy Argon2id for pre-hardfork
  records). Records are keyed by the exact registered string, so the SDK
  tries the name as given and the alternate `.bdx` form. The lookup is made
  to 3 random snodes that must all decrypt to the same ID.
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
