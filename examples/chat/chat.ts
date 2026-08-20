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
 *   npm run example:chat -- --peer codeman.bdx        # or a BNS name
 */
import { createInterface, type Interface } from 'node:readline';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Command } from 'commander';
import {
  BchatProtocolEncryption,
  BELDEX_ADDRESS_LENGTH,
  BchatSDK,
  FileStore,
  createIdentity,
  identityFromMnemonic,
  isBnsName,
  normalizeBnsName,
  normalizeX25519Hex,
  writeSecretFile,
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

const MAX_DISPLAY_NAME = 32;
const QUOTE_PREVIEW = 48;

const formatBytes = (n: number): string => {
  if (!Number.isFinite(n) || n < 0) return '?';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
};

const formatDuration = (seconds: number): string => {
  if (seconds % 86400 === 0) return `${seconds / 86400}d`;
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
};

/**
 * Message bodies and display names are arbitrary bytes chosen by the sender.
 * Written straight to a terminal they can erase lines, repaint the transcript
 * to forge this client's own system messages, rewrite the window title, or —
 * on terminals with OSC 52 — write to the system clipboard.
 *
 * Keep tab and newline; replace the rest of C0/C1 including ESC.
 */
const sanitize = (value: unknown): string => {
  if (typeof value !== 'string') return '';
  // eslint-disable-next-line no-control-regex -- matching control characters is the entire point
  return value.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, '\uFFFD');
};
const clockOf = (ms: number) => new Date(ms).toTimeString().slice(0, 5);

// ------------------------------------------------------------------- options

const program = new Command()
  .name('bchat-chat')
  .description('Interactive terminal chat over the BChat storage node network')
  .option('-a, --account <file>', 'account JSON; created if missing', './chat-account.json')
  .option('-p, --peer <bchatId>', 'recipient BChat ID or BNS name (or set it later with /peer)')
  .option('-c, --cache <dir>', 'cursor + message cache directory', './.bchat-chat-cache')
  .option('-n, --namespace <n>', 'storage namespace (0 user, -10 closed groups)', '0')
  .option('-i, --poll-interval <ms>', 'how often to check for new messages', '5000')
  .option('--seeds <urls>', 'comma-separated seed node URLs', DEFAULT_SEEDS.join(','))
  .option(
    '--strict-tls',
    'require valid certificates from storage nodes too (they are self-signed, ' +
      'so this will fail against the live network)',
    false
  )
  .option(
    '--insecure',
    'LOCAL DEV ONLY: skip all TLS verification and allow private-IP nodes',
    false
  )
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
        `${file} has no recovery phrase. Delete it to mint a new identity, or restore ` +
          `one without exposing the phrase on the command line:\n` +
          `  bchat-sdk create-account --mnemonic-stdin -o ${path}`
      );
    }
    // Everything is re-derived from the phrase, so the file only really needs
    // to hold that one field.
    return identityFromMnemonic(parsed.mnemonic, network);
  }

  const identity = await createIdentity(network);
  // 0600, and refuses to overwrite: writeFileSync's `mode` is ignored when the
  // path already exists, which would leave the phrase world-readable.
  writeSecretFile(file, `${JSON.stringify(identity, null, 2)}\n`);
  console.log(dim(`created a new identity at ${file}`));
  console.log(yellow('\nrecovery phrase — write this down, it restores both your ID and wallet:'));
  console.log(`  ${bold(identity.mnemonic)}\n`);
  return identity;
}

// ---------------------------------------------------------------------- main

async function main() {
  const account = await loadOrCreateAccount(opts.account);
  // A BNS name passes shape-validation here and resolves to the real ID once
  // the snode pool is up (network access is needed for the lookup).
  let peer: string | undefined = opts.peer;
  if (peer) peer = isBnsName(peer.trim()) ? peer.trim().toLowerCase() : validatePeer(peer);

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
    // Storage nodes are self-signed by design, so accept them unless the user
    // explicitly asks otherwise. Seed node certificates are still verified.
    allowSelfSignedStorageNodes: !opts.strictTls,
    allowPrivateNodes: Boolean(opts.insecure),
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

  // A peer given as a BNS name resolves eagerly, so the prompt shows the real
  // ID and a typo'd name fails loudly here instead of on the first send.
  if (peer && isBnsName(peer)) {
    const name = normalizeBnsName(peer);
    try {
      printSystem(`resolving BNS name ${name}…`);
      peer = await sdk.resolveBnsName(name);
      printSystem(`${name} → ${bold(peer)}`);
    } catch (e: any) {
      printError(`could not resolve "${name}": ${e?.message || e}`);
      peer = undefined;
    }
  }

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
          void setPeer(argument).then(done);
          return;
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

  /** Switch conversation partner; BNS names are resolved on the spot. */
  async function setPeer(value: string) {
    try {
      if (isBnsName(value.trim())) {
        const name = normalizeBnsName(value);
        printSystem(`resolving BNS name ${name}…`);
        const id = await sdk.resolveBnsName(name);
        peer = id;
        printSystem(`now chatting with ${bold(id)} ${dim(`(${name})`)}`);
      } else {
        peer = validatePeer(value);
        printSystem(`now chatting with ${bold(peer)}`);
      }
    } catch (e: any) {
      printError(e.message);
    }
  }

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
    const from: string = message.sender ?? 'unknown';
    const name = sanitize(message.displayName).slice(0, MAX_DISPLAY_NAME);
    const label = name ? `${name} (${shortId(from)})` : shortId(from);
    const at: number = message.sentAt ?? Date.now();
    const stamp = dim(`[${clockOf(at)}]`);
    const note = (text: string) => write(`${stamp} ${cyan(label)} ${dim(text)}`);

    // Our own message, mirrored here from another device.
    if (message.syncTarget) {
      if (opts.verbose) note(`sync copy of a message to ${shortId(String(message.syncTarget))}`);
      return;
    }

    switch (message.kind) {
      case 'message':
        renderDataMessage(message, stamp, label);
        return;

      case 'reaction': {
        const emoji = sanitize(message.reaction?.emoji).slice(0, 8) || '(none)';
        note(`${message.reaction?.action === 1 ? 'removed reaction' : 'reacted'} ${emoji}`);
        return;
      }

      case 'unsend':
        // The peer deleted a message they had sent.
        note('deleted a message');
        return;

      case 'dataExtraction':
        note(message.dataExtraction?.type === 1 ? 'took a screenshot' : 'saved media');
        return;

      case 'messageRequestResponse':
        note(
          message.messageRequestResponse?.isApproved
            ? 'accepted your message request'
            : 'declined your message request'
        );
        return;

      case 'call':
        note('started a call (not supported by this client)');
        return;

      // Low-signal chatter: shown only with --verbose.
      case 'typing':
        if (opts.verbose) note(message.typing?.action === 1 ? 'stopped typing' : 'is typing…');
        return;
      case 'receipt':
        if (opts.verbose) note(`read ${message.receipt?.timestamps?.length ?? 0} message(s)`);
        return;
      case 'configuration':
        if (opts.verbose) note('sent a configuration message');
        return;

      default:
        break;
    }

    foreign++;
    write(
      dim(
        `${stamp} (1 message could not be decrypted` +
          `${foreign === 1 ? ' — a closed-group message, or not addressed to you' : ''})`
      )
    );
  }

  /** Everything a DataMessage can carry, in the order a reader cares about. */
  function renderDataMessage(message: any, stamp: string, label: string) {
    const lines: string[] = [];

    if (message.quote) {
      const who = message.quote.author ? shortId(String(message.quote.author)) : 'unknown';
      const excerpt = sanitize(message.quote.text).replace(/\s+/g, ' ').trim();
      const preview = excerpt
        ? `${excerpt.slice(0, QUOTE_PREVIEW)}${excerpt.length > QUOTE_PREVIEW ? '…' : ''}`
        : '(no text)';
      write(`${stamp} ${dim(`\u21B3 replying to ${who}: "${preview}"`)}`);
    }

    if (message.isExpirationTimerUpdate) {
      const secs = Number(message.expireTimer ?? 0);
      write(
        `${stamp} ${cyan(label)} ${dim(
          secs > 0 ? `set disappearing messages to ${formatDuration(secs)}` : 'turned off disappearing messages'
        )}`
      );
      return;
    }

    if (message.payment) {
      // Sender-asserted, like every other field in the payload. Never treat it
      // as proof that a transfer happened.
      const amount = sanitize(message.payment.amount).slice(0, 32) || '?';
      const txn = sanitize(message.payment.txnId).slice(0, 16);
      lines.push(`${yellow('payment notification')} ${amount} BDX${txn ? dim(` txn ${txn}…`) : ''}`);
      lines.push(dim('  (unverified — the sender asserts this; check the chain yourself)'));
    }

    for (const a of message.attachments ?? []) {
      const kind = a.isVoiceMessage ? 'voice message' : sanitize(a.contentType) || 'file';
      const named = sanitize(a.fileName).slice(0, 48);
      const dims = a.width && a.height ? ` ${a.width}x${a.height}` : '';
      lines.push(
        `${dim('[attachment]')} ${kind}${dims}${named ? ` "${named}"` : ''}` +
          `${a.size ? dim(` ${formatBytes(a.size)}`) : ''}`
      );
      const caption = sanitize(a.caption);
      if (caption) lines.push(`  ${caption}`);
    }

    if (message.openGroupInvitation) {
      const gname = sanitize(message.openGroupInvitation.name).slice(0, 48) || 'a group';
      lines.push(`${dim('[invitation]')} to join ${gname}`);
    }

    if (message.sharedContact) {
      const cname = sanitize(message.sharedContact.name).slice(0, 48) || 'a contact';
      lines.push(`${dim('[contact]')} ${cname}`);
    }

    const body = sanitize(message.plaintext);
    if (body) lines.push(body);

    for (const p of message.previews ?? []) {
      const title = sanitize(p.title).slice(0, 60);
      const url = sanitize(p.url).slice(0, 60);
      if (title || url) lines.push(dim(`  \u2197 ${title || url}`));
    }

    if (!lines.length) lines.push(dim('(empty message)'));
    for (const line of lines) write(`${stamp} ${cyan(label)} ${line}`);
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
  if (!opts.strictTls) {
    console.log(
      dim('           storage-node certificates are self-signed and not verified;') +
        dim(' seed nodes are')
    );
  }
  console.log(dim('type /help for commands\n'));
}

function help() {
  console.log(
    [
      `  ${bold('/id')}            show your BChat ID (share it so others can message you)`,
      `  ${bold('/peer <id>')}     switch conversation partner (BChat ID or BNS name)`,
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
