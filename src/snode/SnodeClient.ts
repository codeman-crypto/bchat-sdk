import shuffle from 'lodash.shuffle';
import { Buffer } from 'buffer';
import sodium from 'libsodium-wrappers-sumo';
import { BchatRpc } from './bchatRpc.js';
import {
  EncryptionProvider,
  FetchFn,
  GetMessagesParams,
  Logger,
  SendMessageParams,
  Snode,
} from '../types.js';
import { Transport } from '../transport/Transport.js';
import { DirectTransport } from '../transport/DirectTransport.js';
import { SealedBoxEncryption } from '../crypto/encryption.js';
import { AbortError, retry } from '../util/retry.js';
import { isUsableSnode, type AddressPolicy } from './validate.js';
import type { Persistence } from '../persistence/Store.js';

const DEFAULT_TIMEOUT = 10_000;
const DEFAULT_CONNECTIONS = 3;
const DEFAULT_TTL_MS = 14 * 24 * 60 * 60 * 1000; // 14 days

const parseJson = (body: string, context: string): any => {
  try {
    return JSON.parse(body);
  } catch {
    throw new Error(`${context}: snode returned non-JSON body: ${body.slice(0, 200)}`);
  }
};

const DEFAULT_SWARM_TTL_MS = 60_000;
/** cap on the per-pubkey replay-guard set */
const SEEN_HASH_LIMIT = 2_000;
/** cap on how many distinct pubkeys keep cached swarm/pin/replay state */
const MAX_TRACKED_PUBKEYS = 512;

const sameNode = (a: Snode, b: Snode) => a.ip === b.ip && a.port === b.port;

export type SnodeClientOptions = AddressPolicy & {
  /** accept self-signed certificates from storage nodes (not seed nodes) */
  allowSelfSignedStorageNodes?: boolean;
  transport?: Transport;
  encryption?: EncryptionProvider;
  persistence?: Persistence;
  account?: { pub: string; priv: string };
  insecureTls?: boolean;
  /** how long a resolved swarm stays cached (default 60s) */
  swarmTtlMs?: number;
};

export class SnodeClient {
  private rpc: BchatRpc;
  private logger: Logger;
  private transport: Transport;
  private encryption: EncryptionProvider;
  private persistence?: Persistence;
  private accountX25519?: { pub: string; priv: string };
  private swarmTtlMs: number;
  private swarms = new Map<string, { nodes: Snode[]; fetchedAt: number }>();
  /** the swarm member retrieval is currently pinned to, per pubkey */
  private pinned = new Map<string, Snode>();
  /** message hashes already returned to the caller, per pubkey */
  private seen = new Map<string, Set<string>>();
  private policy: AddressPolicy;

  constructor(
    private pool: () => Promise<Snode[]>,
    fetch: FetchFn,
    logger: Logger = console,
    timeoutMs = DEFAULT_TIMEOUT,
    opts?: SnodeClientOptions
  ) {
    // `insecureTls` used to be dropped here, so swarm lookups and generic
    // call() went out through an RPC client that ignored the option entirely.
    this.policy = { allowPrivateNodes: opts?.allowPrivateNodes };
    this.rpc = new BchatRpc(fetch, logger, timeoutMs, {
      insecureTls: opts?.insecureTls,
      allowSelfSignedStorageNodes: opts?.allowSelfSignedStorageNodes,
      allowPrivateNodes: opts?.allowPrivateNodes,
    });
    this.logger = logger;
    this.transport = opts?.transport ?? new DirectTransport(this.rpc);
    this.encryption = opts?.encryption ?? new SealedBoxEncryption();
    this.persistence = opts?.persistence;
    this.accountX25519 = opts?.account;
    this.swarmTtlMs = opts?.swarmTtlMs ?? DEFAULT_SWARM_TTL_MS;
  }

  /**
   * Resolves the swarm list for a pubkey by asking random snodes until one
   * returns a valid list.
   *
   * Results are cached for `swarmTtlMs`. Besides saving a round trip on every
   * poll, a *stable* swarm ordering is what lets retrieval stay pinned to one
   * node -- see retrieveMessages().
   */
  async getSnodesForPubkey(pubKey: string, opts?: { forceRefresh?: boolean }): Promise<Snode[]> {
    if (!pubKey) throw new Error('pubKey is required');

    const cached = this.swarms.get(pubKey);
    if (!opts?.forceRefresh && cached && Date.now() - cached.fetchedAt < this.swarmTtlMs) {
      return cached.nodes;
    }

    const nodes = await this.resolveSwarm(pubKey);
    this.swarms.set(pubKey, { nodes, fetchedAt: Date.now() });
    this.evictStaleTracking();
    return nodes;
  }

  /** Drop cached swarm/pin state for a pubkey (or all of them). */
  forgetSwarm(pubKey?: string) {
    if (pubKey) {
      this.swarms.delete(pubKey);
      this.pinned.delete(pubKey);
      return;
    }
    this.swarms.clear();
    this.pinned.clear();
  }

  private async resolveSwarm(pubKey: string): Promise<Snode[]> {
    const pool = shuffle(await this.pool());
    if (!pool.length) {
      throw new Error('No snodes available');
    }

    // Keeps the real reason the last node failed, so exhausting the pool
    // reports "Empty swarm"/"non-JSON body" rather than masking it.
    let lastError: Error | undefined;

    return retry(
      async () => {
        const target = pool.pop();
        if (!target) {
          // Stop retrying: no amount of backoff will refill the pool.
          throw new AbortError(lastError ?? new Error('No snodes available'));
        }
        const res = await this.rpc.call({
          method: 'get_mnodes_for_pubkey',
          params: { pubKey },
          targetNode: target,
        });
        const json = parseJson(res.body, 'get_mnodes_for_pubkey');
        if (!Array.isArray(json.mnodes)) {
          throw new Error('Invalid snode response');
        }
        // Anything that is not a literal, publicly routable IP is dropped
        // here: a hostile node can otherwise smuggle URL syntax through `ip`.
        const nodes = json.mnodes.filter((n: any) => isUsableSnode(n, this.policy));
        const rejected = json.mnodes.length - nodes.length;
        if (rejected > 0) {
          this.logger.warn(
            `discarded ${rejected} swarm entr${rejected === 1 ? 'y' : 'ies'} with an ` +
              `invalid or non-routable address`
          );
        }
        if (!nodes.length) {
          throw new Error('Empty swarm');
        }
        return nodes.map((n: any) => ({
          ip: n.ip,
          port: n.port,
          pubkey_x25519: n.pubkey_x25519,
          pubkey_ed25519: n.pubkey_ed25519,
        }));
      },
      {
        retries: 3,
        minTimeout: 250,
        maxTimeout: 2_000,
        onFailedAttempt: e => {
          lastError = e;
          this.logger.warn('swarm fetch retry', e.message);
        },
      }
    );
  }

  /** Generic storage_rpc call against a random snode in pool */
  async call(method: string, params: any) {
    const pool = shuffle(await this.pool());
    const target = pool[0];
    if (!target) throw new Error('No snodes available');
    const res = await this.rpc.call({ method, params, targetNode: target });
    return res.body;
  }

  /** Store an envelope on the swarm; returns message hash (string) when provided by snode */
  async storeMessage(params: SendMessageParams): Promise<string | boolean> {
    const {
      recipientPubKey,
      payload,
      ttlMs = DEFAULT_TTL_MS,
      namespace = 0,
      isSyncMessage,
      messageId,
      timestampMs,
    } = params;

    if (!recipientPubKey) throw new Error('recipientPubKey is required');

    const bytes = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : Buffer.from(payload);
    const timestamp = timestampMs ?? Date.now();

    const swarm = await this.getSnodesForPubkey(recipientPubKey);
    const selected = swarm.slice(0, DEFAULT_CONNECTIONS);
    if (!selected.length) throw new Error('No snodes available to store message');

    // Fan out to every selected member *concurrently*. Writing to all of them
    // is what makes swarm replication real (one bad node cannot silently drop
    // the message), but doing it in a sequential await loop made every send
    // cost the sum of three round trips instead of the slowest one.
    const attempts = await Promise.allSettled(
      selected.map(async node => {
        const res = await this.transport.store(
          {
            recipientPubKey,
            payload: bytes,
            ttlMs,
            namespace,
            isSyncMessage,
            messageId,
            timestampMs: timestamp,
          },
          node
        );

        let parsed: any;
        try {
          parsed = JSON.parse(res.body);
        } catch {
          parsed = undefined;
        }

        // A bare HTTP 200 is NOT proof of storage: a node that answers 200 with
        // an empty body would otherwise blackhole the message while the caller
        // reported success. Require an explicit acknowledgement.
        const ack: string | true | undefined = parsed?.hash
          ? String(parsed.hash)
          : parsed?.status === 'OK'
            ? true
            : undefined;

        if (ack === undefined) {
          throw new Error(`snode ${node.ip}:${node.port} did not acknowledge the store`);
        }
        return ack;
      })
    );

    const successes: Array<string | true> = [];
    let lastError: any;
    attempts.forEach((outcome, i) => {
      const node = selected[i]!;
      if (outcome.status === 'fulfilled') {
        successes.push(outcome.value);
      } else {
        lastError = outcome.reason;
        this.logger.warn(
          'store failed on',
          `${node.ip}:${node.port}`,
          outcome.reason?.message || outcome.reason
        );
      }
    });

    if (!successes.length) throw lastError || new Error('store failed on all snodes');
    return successes.find(v => typeof v === 'string') ?? successes[0]!;
  }

  /** Retrieve next batch of messages for pubKey starting after lastHash */
  async retrieveMessages(params: GetMessagesParams): Promise<any[]> {
    const { pubKey, namespace = 0, ed25519PrivHex, ed25519PubHex, decryptWith } = params;
    if (!pubKey) throw new Error('pubKey is required');

    // Fall back to the persisted cursor so callers that configured a store
    // don't silently re-download the whole mailbox.
    const lastHash =
      params.lastHash ?? (this.persistence ? await this.persistence.getLastHash(pubKey) : '') ?? '';

    const swarm = await this.getSnodesForPubkey(pubKey);
    if (!swarm.length) throw new Error('No snodes available to retrieve messages');

    // `lastHash` is *snode-relative*: a storage node that has never seen the
    // hash you cite answers with the whole mailbox from the beginning. The
    // previous implementation shuffled the swarm and popped a random member on
    // every poll, so consecutive polls asked different nodes about a cursor
    // they did not share and the same messages came back over and over.
    // Retrieval now stays pinned to one member and only rotates on failure.
    const pin = this.pinned.get(pubKey);
    const primary = pin && swarm.some(n => sameNode(n, pin)) ? pin : swarm[0]!;
    const candidates = [primary, ...swarm.filter(n => !sameNode(n, primary))];

    let lastError: Error | undefined;

    return retry(
      async () => {
        const target = candidates.shift();
        if (!target) {
          // Every member refused: drop the cache so the next call re-resolves.
          this.forgetSwarm(pubKey);
          throw new AbortError(lastError ?? new Error('Ran out of snodes while retrieving'));
        }

        // Built per attempt: the signed payload includes a timestamp and
        // storage nodes reject signatures outside a short window, so a
        // signature computed once before the retry loop goes stale.
        const signatureParams = await this.buildRetrieveSignature({
          namespace,
          ed25519PrivHex,
          ed25519PubHex,
        });

        const rpcParams = {
          pubKey,
          lastHash,
          ...(namespace ? { namespace } : {}),
          ...signatureParams,
        };

        const res = await this.transport.retrieve(rpcParams, target);
        if (res.status !== 200) throw new Error(`retrieve status ${res.status}`);
        const json = parseJson(res.body, 'retrieve');
        this.pinned.set(pubKey, target);

        const all: any[] = Array.isArray(json.messages) ? json.messages : [];

        // Replay guard, keyed on a digest of the *payload* rather than the
        // snode-assigned hash. Keying on the hash let a hostile node re-serve
        // a captured message under a fresh hash, or omit the hash entirely, and
        // have it accepted as new. Digests are persisted so the guard survives
        // a restart.
        const seen = this.seenFor(pubKey);
        const msgs: any[] = [];
        for (const m of all) {
          const digest = await this.messageDigest(m);
          if (seen.has(digest)) continue;
          if (await this.persistedSeen(pubKey, digest)) {
            seen.add(digest);
            continue;
          }
          seen.add(digest);
          await this.markPersistedSeen(pubKey, digest);
          msgs.push(m);
        }
        this.trimSeen(seen);

        const account = decryptWith || this.accountX25519;
        const results = account
          ? await Promise.all(msgs.map((m: any) => this.decryptMessage(m, account)))
          : msgs;

        // Persistence used to be nested inside the `if (account)` branch, so
        // configuring a store without account keys silently persisted nothing.
        if (this.persistence) {
          if (results.length) {
            await this.persistence.appendMessages(
              pubKey,
              // `body` is message text only. It used to fall back to `m.data`,
              // so an undecryptable blob from any third party was stored -- and
              // served -- as though it were the message.
              results.map((m: any) => ({
                hash: m?.hash,
                body: m?.plaintext,
                raw: m?.data,
                decrypted: m?.plaintext !== undefined,
                sender: m?.sender,
                receivedAt: Date.now(),
              }))
            );
          }
          // `?? ` alone was wrong: a snode answering `last_hash: ""` produced an
          // empty cursor that was then never saved, so the mailbox replayed.
          const reported = typeof json.last_hash === 'string' ? json.last_hash : '';
          const newLastHash =
            reported || [...all].reverse().find((m: any) => m?.hash)?.hash;
          if (newLastHash) {
            await this.persistence.saveLastHash(pubKey, newLastHash);
          }
        }

        return results;
      },
      {
        retries: 3,
        minTimeout: 400,
        maxTimeout: 2_000,
        onFailedAttempt: e => {
          lastError = e;
          this.logger.warn('retrieve retry', e.message);
        },
      }
    );
  }

  /**
   * Providers that expose `decryptEnvelope` (e.g. the real BChat protocol) also
   * return the authenticated sender, so surface that alongside the body.
   */
  private async decryptMessage(message: any, account: { pub: string; priv: string }) {
    if (!message?.data) return message;
    const bytes = Buffer.from(message.data, 'base64');

    try {
      if (this.encryption.decryptEnvelope) {
        const decoded = await this.encryption.decryptEnvelope(bytes, account.priv, account.pub);
        if (!decoded) return message;
        return {
          ...message,
          kind: decoded.kind,
          plaintext: decoded.body,
          quote: decoded.quote,
          reaction: decoded.reaction,
          // A reaction/typing/receipt has no body but decrypted fine.
          decrypted: true,
          sender: decoded.senderBchatId,
          // Deliberately keeps the `unverified` prefix: this address is a
          // sender-controlled claim, not authenticated data.
          unverifiedSenderWalletAddress: decoded.unverifiedSenderWalletAddress,
          displayName: decoded.displayName,
          sentAt: decoded.sentAt ?? decoded.envelopeTimestamp,
        };
      }

      const plain = await this.encryption.decryptForAccount(bytes, account.priv, account.pub);
      return plain ? { ...message, plaintext: Buffer.from(plain).toString('utf8') } : message;
    } catch (e: any) {
      // A forged signature must not abort the whole batch.
      this.logger.warn('decrypt failed for', message?.hash, e?.message || e);
      return message;
    }
  }

  /**
   * Bound the per-pubkey bookkeeping. A service polling many mailboxes would
   * otherwise leak a swarm/pin/replay entry per pubkey for the process
   * lifetime. Maps iterate in insertion order, so this drops the oldest.
   */
  private evictStaleTracking() {
    while (this.swarms.size > MAX_TRACKED_PUBKEYS) {
      const oldest = this.swarms.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.swarms.delete(oldest);
      this.pinned.delete(oldest);
      this.seen.delete(oldest);
    }
    while (this.seen.size > MAX_TRACKED_PUBKEYS) {
      const oldest = this.seen.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.seen.delete(oldest);
    }
  }

  /** Digest of the stored payload; falls back to the hash when there is no data. */
  private async messageDigest(message: any): Promise<string> {
    await sodium.ready;
    const data = typeof message?.data === 'string' ? message.data : '';
    if (!data) {
      const hash = typeof message?.hash === 'string' ? message.hash : '';
      return `h:${hash || Math.random().toString(36)}`;
    }
    return Buffer.from(
      sodium.crypto_generichash(32, Buffer.from(data, 'base64'))
    ).toString('base64');
  }

  private async persistedSeen(pubKey: string, digest: string): Promise<boolean> {
    try {
      return (await this.persistence?.hasSeen?.(pubKey, digest)) ?? false;
    } catch {
      return false;
    }
  }

  private async markPersistedSeen(pubKey: string, digest: string): Promise<void> {
    try {
      await this.persistence?.markSeen?.(pubKey, digest);
    } catch {
      /* a full replay-guard store must not break message delivery */
    }
  }

  private seenFor(pubKey: string): Set<string> {
    let set = this.seen.get(pubKey);
    if (!set) {
      set = new Set<string>();
      this.seen.set(pubKey, set);
    }
    return set;
  }

  private trimSeen(seen: Set<string>) {
    if (seen.size <= SEEN_HASH_LIMIT) return;
    // Sets iterate in insertion order, so this drops the oldest hashes.
    const excess = seen.size - SEEN_HASH_LIMIT;
    let dropped = 0;
    for (const hash of seen) {
      seen.delete(hash);
      if (++dropped >= excess) break;
    }
  }

  private async buildRetrieveSignature({
    namespace,
    ed25519PrivHex,
    ed25519PubHex,
  }: {
    namespace?: number;
    ed25519PrivHex?: string;
    ed25519PubHex?: string;
  }): Promise<Record<string, any>> {
    if (!ed25519PrivHex) return {};
    await sodium.ready;

    const priv = Buffer.from(ed25519PrivHex, 'hex');
    if (priv.length !== 64) {
      throw new Error(`ed25519 private key must be 64 bytes, got ${priv.length}`);
    }
    const pub = ed25519PubHex ? Buffer.from(ed25519PubHex, 'hex') : undefined;
    if (pub && pub.length !== 32) {
      throw new Error(`ed25519 public key must be 32 bytes, got ${pub.length}`);
    }

    const timestamp = Date.now();
    const namespacePart = namespace ? `${namespace}` : '';
    const toSign = `retrieve${namespacePart}${timestamp}`;
    const signature = sodium.crypto_sign_detached(Buffer.from(toSign, 'utf8'), priv);

    return {
      timestamp,
      signature: Buffer.from(signature).toString('base64'),
      ...(pub ? { pubkey_ed25519: pub.toString('hex') } : {}),
    };
  }
}
