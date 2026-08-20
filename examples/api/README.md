# bchat-api

An HTTP service wrapping `@bdxi/bchat-sdk`, so an app in any language can send and
receive BChat messages over JSON. Uses the real BChat wire protocol, so messages
interoperate with the official clients.

Built on `node:http` — no Express, no added dependencies.

```bash
npm install
npm run example:api
```

On first run it mints an identity at `./api-account.json` (mode `0600`), prints
the 25-word recovery phrase, and generates a bearer token:

```
bchat-api listening on http://127.0.0.1:8080
  bchat id : bd7d1c8f…763a
  wallet   : bxdCRURD…1yvL
  pool     : 3127 storage nodes

  bearer token (generated): 4f3c…
```

Pass `--token` to pin your own instead.

## Endpoints

Every route except `/health` requires `Authorization: Bearer <token>`.

| Route | Purpose |
| --- | --- |
| `GET /health` | pool size, poller status, last error. Unauthenticated so a load balancer can probe it. |
| `GET /identity` | your BChat ID, wallet address, network, display name. Public fields only. |
| `POST /messages` | send: `{ "to": "bd…", "body": "hi" }` |
| `GET /messages?since=N` | messages received since cursor `N` |
| `GET /messages/history` | everything cached on disk, including raw payloads |

### Send

```bash
curl -X POST localhost:8080/messages \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"to":"bd<recipient-id>","body":"hello over http"}'
```

```json
{ "sent": true, "hash": "d4f1…", "to": "bd…" }
```

`202` means the storage node accepted it. `hash` is the storage hash, or `null`
if the node acknowledged without returning one.

### Receive

A background loop polls the swarm continuously, so this returns from memory
rather than blocking on a network round trip. Poll it with the cursor from the
previous response:

```bash
curl -H "Authorization: Bearer $TOKEN" "localhost:8080/messages?since=0"
```

```json
{
  "messages": [
    {
      "seq": 1,
      "hash": "d4f1…",
      "from": "bd…",
      "displayName": "Alice",
      "body": "hello over http",
      "sentAt": 1767000000000,
      "receivedAt": 1767000000512,
      "decrypted": true
    }
  ],
  "cursor": 1
}
```

`from` is derived from the verified payload signature, so it is authenticated —
not something the sender can claim. `decrypted: false` means the payload could
not be opened (a closed-group message, or one not addressed to you); `body` is
then absent.

`seq` is a monotonic in-memory counter that resets when the process restarts.
The on-disk cursor is separate and survives restarts, so no message is
re-delivered — use `/messages/history` for the durable record.

## Options

| Flag | Default | Notes |
| --- | --- | --- |
| `-a, --account <file>` | `./api-account.json` | created if missing |
| `-p, --port <n>` | `8080` | |
| `-H, --host <addr>` | `127.0.0.1` | loopback by default, on purpose |
| `-t, --token <secret>` | generated | DEPRECATED — prefer `BCHAT_API_TOKEN` |
| `-c, --cache <dir>` | `./.bchat-api-cache` | cursor + message log |
| `--network <name>` | `mainnet` | `mainnet` or `testnet` |
| `--display-name <name>` | — | shown to recipients |
| `-i, --poll-interval <ms>` | `5000` | minimum 500 |
| `-n, --namespace <n>` | `0` | `0` user, `-10` closed groups |
| `--seeds <urls>` | five public nodes | comma-separated |
| `--strict-tls` | off | require valid storage-node certs (fails against the live network) |
| `--insecure` | off | LOCAL DEV ONLY — skips all TLS verification and allows private-IP nodes |
| `-v, --verbose` | off | SDK discovery/retry logging |

## Security

**This process holds your recovery phrase in memory and on disk.** Anyone who
can reach the port and present the token can send as you and read everything you
receive.

- It binds to `127.0.0.1` by default. Binding elsewhere prints a warning — put
  it behind TLS and a trusted network if you do.
- Prefer `BCHAT_API_TOKEN` over `--token`: process arguments are visible to
  other local users via `ps` and are recorded in shell history.
- The bearer token is compared in constant time.
- Internal errors are logged server-side and returned as an opaque
  `internal error (ref <id>)`, so snode IPs and filesystem paths do not leak to
  clients.
- Request bodies are capped at 64 KB.
- `/identity` returns public fields only; the mnemonic and private keys are
  never served over HTTP.
- `api-account.json` is written `0600` and is covered by `.gitignore`.

## Limits

- Polling, not push — there is no webhook or streaming endpoint.
- The in-memory inbox is capped at 5,000 messages and `/messages` returns at
  most 500 per call — page with the returned `cursor` and check `hasMore`.
  `/messages/history` takes `?offset=` and `?limit=`.
- Single identity per process.
- No closed-group or attachment support (see the SDK README).
