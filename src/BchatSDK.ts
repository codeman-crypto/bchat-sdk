import { SeedNodeClient } from './seed/SeedNodeClient.js';
import { SnodeClient } from './snode/SnodeClient.js';
import {
  EncryptionProvider,
  FetchFn,
  GetMessagesParams,
  SDKOptions,
  SendMessageParams,
  Snode,
} from './types.js';
import { defaultFetch } from './http/fetchImpl.js';
import { DirectTransport } from './transport/DirectTransport.js';
import { BchatRpc } from './snode/bchatRpc.js';
import { SealedBoxEncryption } from './crypto/encryption.js';
import type { Persistence } from './persistence/Store.js';

export class BchatSDK {
  private seedClient: SeedNodeClient;
  private snodeClient: SnodeClient;
  private encryption: EncryptionProvider;
  private cachedPool: Snode[] = [];
  private refreshInFlight: Promise<Snode[]> | null = null;

  constructor(private opts: SDKOptions) {
    const fetchImpl: FetchFn = opts.fetch ?? defaultFetch;
    const logger = opts.logger ?? console;

    // The previous implementation set process.env.NODE_TLS_REJECT_UNAUTHORIZED
    // = '0' here, disabling certificate verification for the entire host
    // process (every other HTTPS client in the app) and never restoring it.
    // `insecureTls` is now confined to the https.Agent instances this SDK owns.
    if (opts.insecureTls) {
      logger.warn(
        'bchat-sdk: insecureTls enabled - TLS certificate verification is disabled for SDK requests'
      );
    }

    this.seedClient = new SeedNodeClient({ ...opts, fetch: fetchImpl, logger });

    const rpc = new BchatRpc(fetchImpl, logger, opts.timeoutMs ?? 10_000, opts.insecureTls);
    const transport = new DirectTransport(rpc);
    this.encryption = opts.encryption ?? new SealedBoxEncryption();
    const persistence: Persistence | undefined = opts.persistence;
    const account = opts.account
      ? { pub: opts.account.x25519.publicKey, priv: opts.account.x25519.privateKey }
      : undefined;

    this.snodeClient = new SnodeClient(
      () => this.getSnodePool(),
      fetchImpl,
      logger,
      opts.timeoutMs ?? 10_000,
      {
        transport,
        encryption: this.encryption,
        persistence,
        account,
        insecureTls: opts.insecureTls,
      }
    );
  }

  /**
   * Refresh snode pool from seed nodes.
   *
   * Concurrent callers share one in-flight request; previously every parallel
   * send/receive triggered its own full seed round-trip.
   */
  async refreshSnodePool(): Promise<Snode[]> {
    if (!this.refreshInFlight) {
      this.refreshInFlight = this.seedClient
        .fetchSnodePool()
        .then(pool => {
          this.cachedPool = pool;
          return pool;
        })
        .finally(() => {
          this.refreshInFlight = null;
        });
    }
    return this.refreshInFlight;
  }

  /** Returns cached pool or fetches if empty */
  async getSnodePool(): Promise<Snode[]> {
    if (!this.cachedPool.length) {
      await this.refreshSnodePool();
    }
    return this.cachedPool;
  }

  /** Resolve swarm for a pubkey */
  async getSwarm(pubKey: string) {
    return this.snodeClient.getSnodesForPubkey(pubKey);
  }

  /** Generic storage_rpc call against a random snode */
  async call(method: string, params: any) {
    return this.snodeClient.call(method, params);
  }

  /** Store a message envelope on the recipient's swarm */
  async sendMessage(params: SendMessageParams) {
    // Sealed-box encryption is anonymous: it only needs the *recipient's*
    // public key. Gating it on `this.opts.account` (as before) meant a sender
    // configured without an account silently transmitted plaintext.
    if (params.encrypt === false) {
      return this.snodeClient.storeMessage(params);
    }

    const bytes =
      typeof params.payload === 'string'
        ? Buffer.from(params.payload, 'utf8')
        : Buffer.from(params.payload);
    const sealed = await this.encryption.encryptForRecipient(bytes, params.recipientPubKey);
    return this.snodeClient.storeMessage({ ...params, payload: sealed });
  }

  /** Retrieve messages for pubKey after lastHash (requires ed25519 key for signing) */
  async getMessages(params: GetMessagesParams) {
    return this.snodeClient.retrieveMessages(params);
  }
}
