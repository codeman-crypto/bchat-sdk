#!/usr/bin/env node
/**
 * bchat-api -- a small HTTP service wrapping bchat-sdk.
 *
 * Exposes send/receive over JSON so a non-Node app can talk to the BChat
 * network. Uses the real BChat wire protocol, so messages interoperate with the
 * official clients.
 *
 *   POST /messages          { "to": "bd...", "body": "hi" }  -> { hash }
 *   GET  /messages?since=N                                   -> new messages
 *   GET  /messages/history                                   -> everything cached on disk
 *   GET  /identity                                           -> your public identity
 *   GET  /health                                             -> pool + poller status
 *
 * Built on node:http rather than Express so the example adds no dependencies
 * and stays about the SDK rather than about a web framework.
 */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Buffer } from 'node:buffer';
import { Command } from 'commander';
import {
  BELDEX_ADDRESS_LENGTH,
  BchatProtocolEncryption,
  BchatSDK,
  FileStore,
  createIdentity,
  identityFromMnemonic,
  normalizeX25519Hex,
  type BchatIdentity,
  type BeldexNetwork,
  type Logger,
} from '../../src/index.js';

const DEFAULT_SEEDS = [
  'https://publicnode1.rpcnode.stream/',
  'https://publicnode2.rpcnode.stream/',
  'https://publicnode3.rpcnode.stream/',
  'https://publicnode4.rpcnode.stream/',
  'https://publicnode5.rpcnode.stream/',
];

const MAX_BODY_BYTES = 64 * 1024;

const program = new Command()
  .name('bchat-api')
  .description('HTTP API for sending and receiving BChat messages')
  .option('-a, --account <file>', 'identity JSON; created if missing', './api-account.json')
  .option('-p, --port <n>', 'port to listen on', '8080')
  .option(
    '-H, --host <addr>',
    'interface to bind. Defaults to loopback: this process holds your recovery phrase',
    '127.0.0.1'
  )
  .option('-c, --cache <dir>', 'message/cursor cache directory', './.bchat-api-cache')
  .option('-t, --token <secret>', 'bearer token; generated and printed if omitted')
  .option('--network <name>', 'beldex network: mainnet or testnet', 'mainnet')
  .option('--display-name <name>', 'name shown to recipients')
  .option('-i, --poll-interval <ms>', 'how often to check for new messages', '5000')
  .option('-n, --namespace <n>', 'storage namespace', '0')
  .option('--seeds <urls>', 'comma-separated seed node URLs', DEFAULT_SEEDS.join(','))
  .option('--insecure', 'disable TLS verification (self-signed certs)', false)
  .option('-v, --verbose', 'log SDK discovery/retry activity', false)
  .parse();

const opts = program.opts();

const port = Number(opts.port);
const namespace = Number(opts.namespace);
const pollInterval = Number(opts.pollInterval);
const network = String(opts.network) as BeldexNetwork;

if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('--port is invalid');
if (!Number.isInteger(namespace)) throw new Error('--namespace must be an integer');
if (!Number.isFinite(pollInterval) || pollInterval < 500) {
  throw new Error('--poll-interval must be at least 500ms');
}
if (!(network in BELDEX_ADDRESS_LENGTH)) {
  throw new Error('--network must be "mainnet" or "testnet"');
}

const seedNodes = String(opts.seeds)
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);
if (!seedNodes.length) throw new Error('--seeds must list at least one URL');

// --------------------------------------------------------------------- state

/** A message as handed back over HTTP. */
type ApiMessage = {
  /** monotonic cursor; pass the highest value back as ?since= */
  seq: number;
  hash?: string;
  from?: string;
  displayName?: string;
  body?: string;
  sentAt?: number;
  receivedAt: number;
  /** false when the payload could not be decrypted (closed group, or not ours) */
  decrypted: boolean;
};

const inbox: ApiMessage[] = [];
let seq = 0;
let poolSize = 0;
let lastPollAt: number | null = null;
let lastPollError: string | null = null;

// ------------------------------------------------------------------ identity

async function loadOrCreateIdentity(path: string): Promise<BchatIdentity> {
  const file = resolve(path);

  if (existsSync(file)) {
    const parsed = JSON.parse(readFileSync(file, 'utf8')) as Partial<BchatIdentity>;
    if (!parsed?.mnemonic) {
      throw new Error(`${file} has no recovery phrase; delete it to mint a new identity`);
    }
    return identityFromMnemonic(parsed.mnemonic, network);
  }

  const identity = await createIdentity(network);
  writeFileSync(file, `${JSON.stringify(identity, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  console.log(`created a new identity at ${file}`);
  console.log('\nrecovery phrase — write this down, it restores your ID and wallet:');
  console.log(`  ${identity.mnemonic}\n`);
  return identity;
}

// ----------------------------------------------------------------- http utils

const send = (res: ServerResponse, status: number, payload: unknown) => {
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  res.end(body);
};

const fail = (res: ServerResponse, status: number, error: string) => send(res, status, { error });

function readJsonBody(req: IncomingMessage): Promise<any> {
  return new Promise((resolvePromise, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;

    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error(`request body exceeds ${MAX_BODY_BYTES} bytes`));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('error', reject);
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8').trim();
      if (!raw) return resolvePromise({});
      try {
        resolvePromise(JSON.parse(raw));
      } catch {
        reject(new Error('request body is not valid JSON'));
      }
    });
  });
}

/** Constant-time bearer check, so the token can't be recovered by timing. */
function authorized(req: IncomingMessage, token: string): boolean {
  const header = req.headers.authorization ?? '';
  const provided = header.startsWith('Bearer ') ? header.slice(7) : '';
  const a = Buffer.from(provided);
  const b = Buffer.from(token);
  return a.length === b.length && timingSafeEqual(a, b);
}

// ----------------------------------------------------------------------- main

async function main() {
  const identity = await loadOrCreateIdentity(opts.account);
  const token: string = opts.token || randomBytes(24).toString('hex');
  const store = new FileStore(opts.cache);

  const logger: Logger = opts.verbose
    ? console
    : { info: () => {}, warn: () => {}, error: (...a) => console.error(...a) };

  const sdk = new BchatSDK({
    seedNodes,
    account: { x25519: identity.x25519, ed25519: identity.ed25519 },
    persistence: store,
    encryption: new BchatProtocolEncryption({
      ed25519: identity.ed25519,
      beldexAddress: identity.walletAddress,
      network,
      displayName: opts.displayName,
    }),
    insecureTls: Boolean(opts.insecure),
    logger,
  });

  console.log('discovering storage nodes…');
  poolSize = (await sdk.refreshSnodePool()).length;

  // ---- background receive loop -------------------------------------------
  // Polling happens continuously so GET /messages can answer from memory
  // instead of blocking the caller on a network round trip.
  let running = true;
  const poll = async () => {
    while (running) {
      try {
        const messages = await sdk.getMessages({
          pubKey: identity.bchatId,
          namespace,
          ed25519PrivHex: identity.ed25519.privateKey,
          ed25519PubHex: identity.ed25519.publicKey,
        });

        for (const message of messages) {
          inbox.push({
            seq: ++seq,
            hash: message.hash,
            from: message.sender,
            displayName: message.displayName,
            body: message.plaintext,
            sentAt: message.sentAt,
            receivedAt: Date.now(),
            decrypted: message.plaintext !== undefined,
          });
        }

        lastPollAt = Date.now();
        lastPollError = null;
      } catch (e: any) {
        lastPollError = e?.message || String(e);
        logger.warn('poll failed:', lastPollError);
      }
      await new Promise(r => setTimeout(r, pollInterval));
    }
  };

  // ---- routes -------------------------------------------------------------
  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    const route = `${req.method} ${url.pathname}`;

    try {
      // /health is unauthenticated so a load balancer can probe it; it exposes
      // no keys and no message content.
      if (route === 'GET /health') {
        return send(res, 200, {
          status: 'ok',
          poolSize,
          received: inbox.length,
          lastPollAt,
          lastPollError,
        });
      }

      if (!authorized(req, token)) {
        res.setHeader('WWW-Authenticate', 'Bearer');
        return fail(res, 401, 'missing or invalid bearer token');
      }

      if (route === 'GET /identity') {
        // Public fields only -- never the mnemonic or private keys.
        return send(res, 200, {
          bchatId: identity.bchatId,
          walletAddress: identity.walletAddress,
          network: identity.network,
          displayName: opts.displayName ?? null,
        });
      }

      if (route === 'POST /messages') {
        const body = await readJsonBody(req);
        const to = typeof body.to === 'string' ? body.to.trim() : '';
        const text = typeof body.body === 'string' ? body.body : '';

        if (!to) return fail(res, 400, 'field "to" is required (recipient BChat ID)');
        if (!text) return fail(res, 400, 'field "body" is required (message text)');

        try {
          normalizeX25519Hex(to, 'to');
        } catch (e: any) {
          return fail(res, 400, e.message);
        }

        const result = await sdk.sendMessage({
          recipientPubKey: to,
          payload: text,
          namespace,
        });

        return send(res, 202, {
          sent: true,
          hash: typeof result === 'string' ? result : null,
          to,
        });
      }

      if (route === 'GET /messages') {
        const sinceRaw = url.searchParams.get('since');
        const since = sinceRaw === null ? 0 : Number(sinceRaw);
        if (!Number.isInteger(since) || since < 0) {
          return fail(res, 400, '"since" must be a non-negative integer');
        }

        const messages = inbox.filter(m => m.seq > since);
        return send(res, 200, {
          messages,
          // feed this back as ?since= on the next call
          cursor: inbox.length ? inbox[inbox.length - 1]!.seq : since,
        });
      }

      if (route === 'GET /messages/history') {
        return send(res, 200, { messages: await store.listMessages(identity.bchatId) });
      }

      return fail(res, 404, `no route for ${route}`);
    } catch (e: any) {
      logger.error('request failed:', e?.message || e);
      return fail(res, 500, e?.message || 'internal error');
    }
  });

  server.listen(port, opts.host, () => {
    console.log(`\nbchat-api listening on http://${opts.host}:${port}`);
    console.log(`  bchat id : ${identity.bchatId}`);
    console.log(`  wallet   : ${identity.walletAddress}`);
    console.log(`  pool     : ${poolSize} storage nodes`);
    if (!opts.token) console.log(`\n  bearer token (generated): ${token}`);
    if (opts.host !== '127.0.0.1' && opts.host !== 'localhost') {
      console.warn(
        `\n  WARNING: bound to ${opts.host}, not loopback. This process holds your ` +
          `recovery phrase — put it behind TLS and a trusted network.`
      );
    }
    console.log('');
    void poll();
  });

  const shutdown = () => {
    running = false;
    server.close(() => process.exit(0));
    // don't hang forever on keep-alive sockets
    setTimeout(() => process.exit(0), 2_000).unref();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch(e => {
  console.error(`fatal: ${e?.message || e}`);
  process.exit(1);
});
