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
import { bnsCandidateNames, isBnsName, looksLikeBchatId, normalizeBnsName } from './snode/bns.js';

/** how long a resolved BNS name -> BChat ID mapping stays cached */
const BNS_CACHE_TTL_MS = 5 * 60_000;

export class BchatSDK {
  private seedClient: SeedNodeClient;
  private snodeClient: SnodeClient;
  private encryption: EncryptionProvider;
  private cachedPool: Snode[] = [];
  private refreshInFlight: Promise<Snode[]> | null = null;
  private bnsCache = new Map<string, { id: string; at: number }>();

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

    const rpc = new BchatRpc(fetchImpl, logger, opts.timeoutMs ?? 10_000, {
      insecureTls: opts.insecureTls,
      allowSelfSignedStorageNodes: opts.allowSelfSignedStorageNodes,
      allowPrivateNodes: opts.allowPrivateNodes,
    });
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
        allowSelfSignedStorageNodes: opts.allowSelfSignedStorageNodes,
        allowPrivateNodes: opts.allowPrivateNodes,
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

  /**
   * Resolve a BNS name ("codeman" or "codeman.bdx") to the BChat ID tagged to it.
   *
   * The lookup is validated against multiple storage nodes (they must all
   * agree) and the result is cached for a few minutes.
   */
  async resolveBnsName(name: string): Promise<string> {
    const key = normalizeBnsName(name);
    const hit = this.bnsCache.get(key);
    if (hit && Date.now() - hit.at < BNS_CACHE_TTL_MS) return hit.id;

    const id = await this.snodeClient.resolveBns(key);
    // Cache under both forms so "codeman" and "codeman.bdx" share one entry.
    for (const candidate of bnsCandidateNames(key)) {
      this.bnsCache.set(candidate, { id, at: Date.now() });
    }
    return id;
  }

  /**
   * Accepts either a BChat ID / x25519 pubkey (returned unchanged) or a BNS
   * name (resolved on the fly). Values that are neither pass through so the
   * downstream key validation reports its usual, more specific error.
   */
  private async resolveRecipient(recipient: string): Promise<string> {
    if (!recipient || looksLikeBchatId(recipient)) return recipient;
    if (isBnsName(recipient)) return this.resolveBnsName(recipient);
    return recipient;
  }

  /** Generic storage_rpc call against a random snode */
  async call(method: string, params: any) {
    return this.snodeClient.call(method, params);
  }

  /**
   * Store a message envelope on the recipient's swarm.
   *
   * `recipientPubKey` accepts a BChat ID / x25519 pubkey or a BNS name; a
   * name is resolved (with multi-snode validation) before encrypting, so the
   * message is sealed for the key the name actually maps to.
   */
  async sendMessage(params: SendMessageParams) {
    const recipientPubKey = await this.resolveRecipient(params.recipientPubKey);

    // Sealed-box encryption is anonymous: it only needs the *recipient's*
    // public key. Gating it on `this.opts.account` (as before) meant a sender
    // configured without an account silently transmitted plaintext.
    if (params.encrypt === false) {
      return this.snodeClient.storeMessage({ ...params, recipientPubKey });
    }

    const bytes =
      typeof params.payload === 'string'
        ? Buffer.from(params.payload, 'utf8')
        : Buffer.from(params.payload);
    const sealed = await this.encryption.encryptForRecipient(bytes, recipientPubKey);
    return this.snodeClient.storeMessage({ ...params, recipientPubKey, payload: sealed });
  }

  /** Retrieve messages for pubKey after lastHash (requires ed25519 key for signing) */
  async getMessages(params: GetMessagesParams) {
    return this.snodeClient.retrieveMessages(params);
  }
}
