#!/usr/bin/env node
import { Command } from 'commander';
import { writeFileSync, readFileSync } from 'fs';
import {
  BchatProtocolEncryption,
  BELDEX_ADDRESS_LENGTH,
  BchatSDK,
  createIdentity,
  identityFromMnemonic,
  FileStore,
  SealedBoxEncryption,
  type BeldexNetwork,
  type EncryptionProvider,
} from './index.js';

const DEFAULT_SEEDS = [
  'https://publicnode1.rpcnode.stream/',
  'https://publicnode2.rpcnode.stream/',
  'https://publicnode3.rpcnode.stream/',
  'https://publicnode4.rpcnode.stream/',
  'https://publicnode5.rpcnode.stream/',
];

const program = new Command();
program
  .name('bchat-sdk')
  .description('CLI for interacting with BChat storage nodes (seed discovery, send/receive)')
  .version('0.1.0');

const loadJson = (path?: string) => {
  if (!path) return undefined;
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (e: any) {
    throw new Error(`could not read account JSON at ${path}: ${e?.message || e}`);
  }
};

const parseNamespace = (value: string): number => {
  const ns = Number(value);
  if (!Number.isInteger(ns)) {
    // Number('abc') is NaN, which used to be forwarded to the snode as
    // `namespace: null` after JSON.stringify.
    throw new Error(`--namespace must be an integer, got "${value}"`);
  }
  return ns;
};

const fail = (message: string): never => {
  console.error(`error: ${message}`);
  process.exit(1);
};

/**
 * With a wallet address we can speak the real BChat protocol, which is what the
 * official clients understand. Without one we fall back to a bare sealed box,
 * which only ever interoperates with other bchat-sdk users.
 */
const buildEncryption = (account: any, opts: any): EncryptionProvider => {
  // An account minted by `create-account` already carries its wallet address,
  // derived from the same seed as the BChat ID.
  opts.walletAddress = opts.walletAddress ?? account?.walletAddress;
  opts.network = opts.network ?? account?.network ?? 'mainnet';

  if (!opts.walletAddress) {
    console.error(
      'warning: no --wallet-address given, falling back to raw sealed boxes. ' +
        'Messages will NOT be readable by the official BChat clients.'
    );
    return new SealedBoxEncryption();
  }

  const network = String(opts.network ?? 'mainnet') as BeldexNetwork;
  if (!(network in BELDEX_ADDRESS_LENGTH)) {
    fail('--network must be "mainnet" or "testnet"');
  }

  return new BchatProtocolEncryption({
    ed25519: account.ed25519,
    beldexAddress: opts.walletAddress,
    network,
    displayName: opts.displayName,
  });
};

const protocolOptions = (command: Command) =>
  command
    .option('-w, --wallet-address <address>', 'your Beldex wallet address (required for BChat-app interop)')
    .option('--network <name>', 'beldex network: mainnet or testnet', 'mainnet')
    .option('--display-name <name>', 'name shown to the recipient');

program
  .command('create-account')
  .description('Generate a recovery phrase, BChat ID and Beldex wallet address')
  .option('-o, --output <file>', 'write JSON to file (defaults to stdout)')
  .option('--network <name>', 'beldex network: mainnet or testnet', 'mainnet')
  .option('--mnemonic <phrase>', 'restore from an existing 25-word phrase instead of generating')
  .action(async opts => {
    const network = String(opts.network) as BeldexNetwork;
    const acct = opts.mnemonic
      ? await identityFromMnemonic(opts.mnemonic, network as any)
      : await createIdentity(network as any);
    const json = JSON.stringify(acct, null, 2);
    // `--output` was declared but the action ignored its options entirely, so
    // the flag was accepted and silently did nothing.
    if (opts.output) {
      writeFileSync(opts.output, `${json}\n`, { encoding: 'utf8', mode: 0o600 });
      console.error(`wrote account to ${opts.output}`);
    } else {
      console.log(json);
    }
  });

protocolOptions(
  program
    .command('send')
    .description('Send an encrypted message to a recipient')
)
  .requiredOption('-r, --recipient <pubkey>', 'recipient x25519 pubkey (BChat ID)')
  .requiredOption('-m, --message <text>', 'plaintext message')
  .requiredOption('-a, --account <json>', 'path to account JSON with x25519/ed25519')
  .option('--namespace <ns>', 'namespace (0 user, -10 closed groups)', '0')
  .option('--insecure', 'allow self-signed TLS (rejectUnauthorized=false)', false)
  .action(async opts => {
    const account = loadJson(opts.account);
    if (!account?.x25519?.publicKey || !account?.x25519?.privateKey) {
      fail('account JSON must include x25519.publicKey/privateKey');
    }

    const sdk = new BchatSDK({
      seedNodes: DEFAULT_SEEDS,
      account: { x25519: account.x25519, ed25519: account.ed25519 },
      encryption: buildEncryption(account, opts),
      insecureTls: opts.insecure,
    });

    await sdk.refreshSnodePool();
    const result = await sdk.sendMessage({
      recipientPubKey: opts.recipient,
      payload: opts.message,
      namespace: parseNamespace(opts.namespace),
    });
    console.log(JSON.stringify({ result }, null, 2));
  });

protocolOptions(
  program
    .command('receive')
    .description('Retrieve messages for an account')
)
  .requiredOption('-a, --account <json>', 'path to account JSON with x25519/ed25519')
  .option('-c, --cache <dir>', 'directory to store last hash/messages', '.bchat-cache')
  .option('--namespace <ns>', 'namespace (0 user, -10 closed groups)', '0')
  .option('--insecure', 'allow self-signed TLS (rejectUnauthorized=false)', false)
  .action(async opts => {
    const account = loadJson(opts.account);
    if (
      !account?.x25519?.publicKey ||
      !account?.x25519?.privateKey ||
      !account?.ed25519?.privateKey
    ) {
      fail('account JSON must include x25519 and ed25519 keys');
    }

    const store = new FileStore(opts.cache);

    const sdk = new BchatSDK({
      seedNodes: DEFAULT_SEEDS,
      account: { x25519: account.x25519, ed25519: account.ed25519 },
      persistence: store,
      encryption: buildEncryption(account, opts),
      insecureTls: opts.insecure,
    });

    // The mailbox is keyed by whatever pubKey string senders address, which is
    // the prefixed BChat ID -- not the bare x25519 hex.
    const mailboxId: string = account.bchatId || account.x25519.publicKey;

    await sdk.refreshSnodePool();
    // lastHash is resolved from the store inside the SDK, and the new cursor is
    // persisted there too, so the CLI no longer keeps its own second copy of
    // that bookkeeping (which used `Array.prototype.findLast`, unavailable on
    // the Node 18 baseline this package claims to support).
    const messages = await sdk.getMessages({
      pubKey: mailboxId,
      namespace: parseNamespace(opts.namespace),
      ed25519PrivHex: account.ed25519.privateKey,
      ed25519PubHex: account.ed25519.publicKey,
    });

    console.log(JSON.stringify({ messages }, null, 2));
  });

// parseAsync() rejections were previously unhandled: the CLI printed a warning
// and exited 0 on failure.
program.parseAsync(process.argv).catch((e: any) => {
  console.error(`error: ${e?.message || e}`);
  process.exit(1);
});
