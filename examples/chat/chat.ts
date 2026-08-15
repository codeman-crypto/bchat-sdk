#!/usr/bin/env node
/**
 * bchat-chat -- an interactive terminal chat client built on bchat-sdk.
 *
 * Demonstrates, end to end:
 *   - creating (or reloading) an identity whose x25519 keys derive from ed25519
 *   - discovering the storage-node pool from seed nodes
 *   - sealed-box encrypting outbound messages to a peer's BChat ID
 *   - a polling receive loop that signs `retrieve` with the ed25519 key
 *   - FileStore persistence so the cursor survives restarts
 *
 * Run it against the live network:
 *   npm run example:chat -- --peer bd<recipient-64-hex>
 */
import { createInterface, type Interface } from 'node:readline';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Command } from 'commander';
import {
  BchatProtocolEncryption,
  BELDEX_ADDRESS_LENGTH,
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
  'https://publicnode1.rpcnode.stream',
  'https://publicnode2.rpcnode.stream',
  'https://publicnode3.rpcnode.stream',
  'https://publicnode4.rpcnode.stream',
  'https://publicnode5.rpcnode.stream',
];

// ---------------------------------------------------------------- formatting

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code: string, s: string) => (useColor ? `\u001b[${code}m${s}\u001b[0m` : s);
const dim = (s: string) => paint('2', s);
const bold = (s: string) => paint('1', s);
const cyan = (s: string) => paint('36', s);
const green = (s: string) => paint('32', s);
const yellow = (s: string) => paint('33', s);
const red = (s: string) => paint('31', s);

const shortId = (id: string) => `${id.slice(0, 8)}…${id.slice(-4)}`;
const clockOf = (ms: number) => new Date(ms).toTimeString().slice(0, 5);

// ------------------------------------------------------------------- options

const program = new Command()
  .name('bchat-chat')
  .description('Interactive terminal chat over the BChat storage node network')
  .option('-a, --account <file>', 'account JSON; created if missing', './chat-account.json')
  .option('-p, --peer <bchatId>', 'recipient BChat ID (or set it later with /peer)')
  .option('-c, --cache <dir>', 'cursor + message cache directory', './.bchat-chat-cache')
  .option('-n, --namespace <n>', 'storage namespace (0 user, -10 closed groups)', '0')
  .option('-i, --poll-interval <ms>', 'how often to check for new messages', '5000')
  .option('--seeds <urls>', 'comma-separated seed node URLs', DEFAULT_SEEDS.join(','))
  .option('--insecure', 'disable TLS verification (self-signed certs)', false)
  .option('-v, --verbose', 'show SDK retry/discovery logging', false)
  .option('--network <name>', 'beldex network: mainnet or testnet', 'mainnet')
  .option('--display-name <name>', 'name shown to the recipient')
  .parse();

const opts = program.opts();

const namespace = Number(opts.namespace);
const pollInterval = Number(opts.pollInterval);
if (!Number.isInteger(namespace)) throw new Error(`--namespace must be an integer`);
if (!Number.isFinite(pollInterval) || pollInterval < 500) {
  throw new Error('--poll-interval must be at least 500ms');
}

const network = String(opts.network) as BeldexNetwork;
if (!(network in BELDEX_ADDRESS_LENGTH)) {
  throw new Error('--network must be "mainnet" or "testnet"');
}

const seedNodes = String(opts.seeds)
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);
if (!seedNodes.length) throw new Error('--seeds must list at least one URL');

// ------------------------------------------------------------------- account

async function loadOrCreateAccount(path: string): Promise<BchatIdentity> {
  const file = resolve(path);

  if (existsSync(file)) {
    const parsed = JSON.parse(readFileSync(file, 'utf8')) as Partial<BchatIdentity>;
    if (!parsed?.mnemonic) {
      throw new Error(
        `${file} has no recovery phrase. Delete it to mint a new identity, or ` +
          `restore one with: bchat-sdk create-account --mnemonic "<25 words>"`
      );
    }
    // Everything is re-derived from the phrase, so the file only really needs
    // to hold that one field.
    return identityFromMnemonic(parsed.mnemonic, network);
  }

  const identity = await createIdentity(network);
  // 0600: this file holds the recovery phrase and private keys.
  writeFileSync(file, `${JSON.stringify(identity, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  console.log(dim(`created a new identity at ${file}`));
  console.log(yellow('\nrecovery phrase — write this down, it restores both your ID and wallet:'));
  console.log(`  ${bold(identity.mnemonic)}\n`);
  return identity;
}

// ---------------------------------------------------------------------- main

async function main() {
  const account = await loadOrCreateAccount(opts.account);
  let peer: string | undefined = opts.peer;
  if (peer) peer = validatePeer(peer);

  const store = new FileStore(opts.cache);

  // The SDK logs pool discovery and every retry to `console` by default, which
  // would shred the chat transcript. Route it behind --verbose instead.
  const logger: Logger = opts.verbose
    ? { info: printSystem, warn: printSystem, error: printError }
    : { info: () => {}, warn: () => {}, error: () => {} };

  // The real BChat wire protocol: protobuf Content -> padding -> sealed-sender
  // signature -> Envelope -> WebSocketMessage. This is what makes messages
  // readable by the official BChat clients.
  const encryption = new BchatProtocolEncryption({
    ed25519: account.ed25519,
    beldexAddress: account.walletAddress,
    network,
    displayName: opts.displayName,
  });

  const sdk = new BchatSDK({
    seedNodes,
    account: { x25519: account.x25519, ed25519: account.ed25519 },
    persistence: store,
    encryption,
    insecureTls: Boolean(opts.insecure),
    logger,
  });

  banner(account, peer);

  // `rl` stays undefined until we are ready to handle input: createInterface()
  // starts draining stdin immediately, so building it before the 'line'
  // listener is attached silently swallows anything typed (or piped) during
  // seed discovery. write() falls back to console.log while it is undefined.
  let rl: Interface | undefined;
  let running = true;
  /** count of messages that arrived but were not readable by this example */
  let foreign = 0;

  printSystem('discovering storage nodes…');
  const pool = await sdk.refreshSnodePool();
  printSystem(`connected to a pool of ${pool.length} storage nodes`);

  // ---- receive loop -------------------------------------------------------
  // getMessages() reads the persisted cursor and writes the new one back, so
  // each poll only returns what arrived since the last one -- including across
  // restarts. The very first run pulls whatever is already in the mailbox.
  const poll = async () => {
    while (running) {
      try {
        const messages = await sdk.getMessages({
          // Must be the *same string form* a sender addresses us by. Storage
          // nodes key the mailbox on the pubKey string, so retrieving with the
          // bare 64-hex key while peers send to the prefixed `bd…` ID silently
          // polls a different (empty) mailbox.
          pubKey: account.bchatId,
          namespace,
          ed25519PrivHex: account.ed25519.privateKey,
          ed25519PubHex: account.ed25519.publicKey,
        });
        for (const message of messages) renderIncoming(message);
      } catch (e: any) {
        printError(`receive failed: ${e?.message || e}`);
      }
      await sleep(pollInterval);
    }
  };

  // ---- send ---------------------------------------------------------------
  const send = async (text: string) => {
    if (!peer) {
      printError('no peer set -- use /peer <bchatId> first');
      return;
    }
    try {
      // The body goes out as-is; BchatProtocolEncryption wraps it in a
      // DataMessage, pads it, signs it and seals it to `peer`.
      const result = await sdk.sendMessage({
        recipientPubKey: peer,
        payload: text,
        namespace,
      });
      printOutgoing(text, typeof result === 'string' ? result : undefined);
    } catch (e: any) {
      printError(`send failed: ${e?.message || e}`);
    }
  };

  // ---- input --------------------------------------------------------------
  rl = createInterface({ input: process.stdin, output: process.stdout, prompt: prompt() });

  rl.on('line', line => {
    const input = line.trim();
    rl?.pause();

    const done = () => {
      if (running && rl) {
        rl.setPrompt(prompt());
        rl.resume();
        rl.prompt();
      }
    };

    if (!input) return done();

    if (input.startsWith('/')) {
      const [command, ...rest] = input.slice(1).split(/\s+/);
      const argument = rest.join(' ');

      switch (command) {
        case 'quit':
        case 'exit':
          running = false;
          rl?.close();
          return;
        case 'id':
          printSystem(`your BChat ID: ${bold(account.bchatId)}`);
          return done();
        case 'peer':
          if (!argument) {
            printSystem(peer ? `chatting with ${bold(peer)}` : 'no peer set');
            return done();
          }
          try {
            peer = validatePeer(argument);
            printSystem(`now chatting with ${bold(peer)}`);
          } catch (e: any) {
            printError(e.message);
          }
          return done();
        case 'help':
          help();
          return done();
        default:
          printError(`unknown command /${command} -- try /help`);
          return done();
      }
    }

    void send(input).then(done);
  });

  rl.on('close', () => {
    running = false;
    if (foreign) {
      console.log(yellow(`\n${foreign} incoming message(s) could not be decrypted.`));
    }
    console.log(dim('bye'));
    process.exit(0);
  });

  process.on('SIGINT', () => rl?.close());

  rl.prompt();
  void poll();

  // ---- rendering helpers --------------------------------------------------

  function prompt() {
    return peer ? `${cyan(shortId(peer))} ${dim('›')} ` : `${dim('(no peer) ›')} `;
  }

  /** Print above the prompt without mangling whatever is half-typed. */
  function write(line: string) {
    if (!process.stdout.isTTY) {
      // Piped/redirected: no cursor control, so just append the line.
      console.log(line);
      return;
    }
    process.stdout.write('\r\u001b[K');
    console.log(line);
    if (running) rl?.prompt(true);
  }

  function renderIncoming(message: any) {
    // `plaintext` is set by the SDK when the sealed box opened with our keys.
    if (!message?.plaintext) {
      foreign++;
      write(
        dim(
          `[${clockOf(Date.now())}] (1 message could not be decrypted` +
            `${foreign === 1 ? ' — a closed-group message, or not addressed to you' : ''})`
        )
      );
      return;
    }

    // `sender` is derived from the ed25519 key the payload signature was
    // verified against, so unlike the old self-asserted JSON envelope it cannot
    // be forged.
    const from: string = message.sender ?? 'unknown';
    const label = message.displayName ? `${message.displayName} (${shortId(from)})` : shortId(from);
    const at: number = message.sentAt ?? Date.now();

    write(`${dim(`[${clockOf(at)}]`)} ${cyan(label)} ${message.plaintext}`);
  }

  function printOutgoing(text: string, hash?: string) {
    const suffix = hash ? dim(` (${hash.slice(0, 8)})`) : '';
    write(`${dim(`[${clockOf(Date.now())}]`)} ${green('you')} ${text}${suffix}`);
  }

  function printSystem(...args: any[]) {
    write(dim(`· ${args.join(' ')}`));
  }

  function printError(...args: any[]) {
    write(red(`! ${args.join(' ')}`));
  }
}

// -------------------------------------------------------------------- misc

function validatePeer(value: string): string {
  // Throws on bad hex / wrong length, and accepts a bd- or 05-prefixed ID.
  normalizeX25519Hex(value, 'peer BChat ID');
  return value.trim().toLowerCase();
}

function banner(account: BchatIdentity, peer?: string) {
  console.log(bold('\nbchat-chat'));
  console.log(`${dim('your id  ')} ${bold(account.bchatId)}`);
  console.log(`${dim('peer     ')} ${peer ? bold(peer) : yellow('none -- set one with /peer <id>')}`);
  console.log(`${dim('wallet   ')} ${account.walletAddress}`);
  console.log(`${dim('protocol ')} BChat (interoperable with the official clients)`);
  console.log(dim('type /help for commands\n'));
}

function help() {
  console.log(
    [
      `  ${bold('/id')}            show your BChat ID (share it so others can message you)`,
      `  ${bold('/peer <id>')}     switch conversation partner`,
      `  ${bold('/help')}          this list`,
      `  ${bold('/quit')}          exit`,
      '',
      dim('  anything else is sent to the current peer'),
    ].join('\n')
  );
}

const sleep = (ms: number) => new Promise<void>(r => setTimeout(r, ms));

main().catch(e => {
  console.error(red(`\nfatal: ${e?.message || e}`));
  process.exit(1);
});
