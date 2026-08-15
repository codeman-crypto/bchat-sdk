# bchat-chat

An interactive terminal chat client built on `bchat-sdk`. It runs against the
live BChat storage-node network.

```bash
npm install
npm run example:chat
```

On first run it mints an identity at `./chat-account.json` (mode `0600`) and
prints a **25-word recovery phrase** plus your BChat ID and Beldex wallet
address — all three derived from one seed, the same way the desktop app does it.
Write the phrase down; it restores everything.

Share your BChat ID with whoever you want to talk to, then set their ID as your
peer:

```
/peer bd<their-64-hex-id>
```

Anything you type that doesn't start with `/` is sent to the current peer.

```bash
# start with a peer already set, polling every 2s
npm run example:chat -- --peer bd<their-id> --poll-interval 2000

# see the SDK's discovery and retry logging
npm run example:chat -- --verbose
```

## Commands

| Command | Effect |
| --- | --- |
| `/id` | print your BChat ID |
| `/peer <id>` | switch conversation partner |
| `/help` | list commands |
| `/quit` | exit |

## Options

| Flag | Default | Notes |
| --- | --- | --- |
| `-a, --account <file>` | `./chat-account.json` | created if missing |
| `-p, --peer <bchatId>` | — | accepts bare 64-hex or a `bd`/`05`-prefixed ID |
| `-c, --cache <dir>` | `./.bchat-chat-cache` | `FileStore` cursor + message log |
| `-n, --namespace <n>` | `0` | `0` user, `-10` closed groups |
| `-i, --poll-interval <ms>` | `5000` | minimum 500 |
| `--network <name>` | `mainnet` | `mainnet` or `testnet` |
| `--display-name <name>` | — | shown to the recipient |
| `--seeds <urls>` | the five public nodes | comma-separated |
| `--insecure` | off | disables TLS verification |
| `-v, --verbose` | off | surfaces SDK logging |

## What it demonstrates

- **Identity** — `createIdentity()` / `identityFromMnemonic()`. One seed yields
  the ed25519 signing keys, the x25519 routing keys, the BChat ID and the Beldex
  wallet address.
- **Addressing** — send and receive use the *same* ID string (`account.bchatId`).
  Storage nodes key the mailbox on that string, so mixing the prefixed ID with
  the bare hex key polls a different, empty mailbox.
- **Encryption** — `BchatProtocolEncryption` builds the full BChat payload
  (protobuf, padding, sealed-sender signature) before it leaves the process, and
  verifies the signature on the way back in.
- **Receiving** — a poll loop calls `sdk.getMessages()`, which reads the
  persisted cursor and writes the new one back, so each poll only returns what
  arrived since the last one, including across restarts.
- **Logging** — the SDK logs discovery and retries to `console` by default; the
  example routes that behind `--verbose` so it doesn't shred the transcript.

## Interoperability with the official BChat app

This example speaks the **real BChat wire protocol**, so it exchanges messages
with the official mobile and desktop clients in both directions.

Outgoing, in order:

1. build a `Content` protobuf containing a `DataMessage` (body, timestamp, profile)
2. pad it with `0x80` + zeroes to one byte below a multiple of 160
3. prepend your Beldex wallet address, then sign
   `walletAddress ‖ padded ‖ senderEd25519Pub ‖ recipientX25519Pub` with your Ed25519 key
4. `crypto_box_seal(walletAddress ‖ padded ‖ senderEd25519Pub ‖ signature)` to the recipient
5. wrap in an `Envelope` protobuf (`type: BCHAT_MESSAGE`)
6. wrap that in a `WebSocketMessage` protobuf, base64, `store`

Incoming is the exact inverse, and the signature is verified *before* the sender
is trusted — so the `sender` on a received message is authenticated, not
self-asserted.

### Why the wallet address matters

bchat-desktop prepends your Beldex wallet address to every message before
signing, and slices it back off on receipt using a **hardcoded length**: 97
bytes on mainnet, 95 on testnet. It does not look for a delimiter. A message
sent without the address — or with one of the wrong length — is silently
mis-sliced by the receiving client and decodes to garbage.

The address is derived from your recovery phrase automatically, so there is
nothing to pass in. `BchatProtocolEncryption` still validates the length and
refuses to construct rather than emit a payload that fails on the far end.

### Restoring an identity

```bash
npm run build
node dist/cjs/cli.js create-account --mnemonic "<your 25 words>" -o account.json
```

Only the first three characters of each word are significant, so typos past
that point are harmless — but the final checksum word is verified.

### Still not implemented

- **Closed groups** (`CLOSED_GROUP_MESSAGE`) need the group's rotating
  encryption keypairs; those messages are reported as undecryptable.
- **Attachments** — `AttachmentPointer` is not encoded or fetched.
- **Onion routing.** Requests go direct to storage nodes, so a network observer
  sees which swarm you talk to and when, even though contents stay encrypted.
- Receipts, typing indicators, and reactions are parsed only far enough to be
  ignored.

## Caveats

- Polling, not push. There is no server-side subscription.
- Both sides must be online-ish within the message TTL (14 days by default).
- Deleting the cache directory replays the whole mailbox on the next poll.
