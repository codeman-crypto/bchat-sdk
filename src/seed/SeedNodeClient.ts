import shuffle from 'lodash.shuffle';
import https from 'https';
import { FetchFn, Logger, SDKOptions, Snode } from '../types.js';
import { retry } from '../util/retry.js';
import { defaultFetch } from '../http/fetchImpl.js';
import { isUsableSnode, type AddressPolicy } from '../snode/validate.js';
import { MAX_RESPONSE_BYTES } from '../snode/bchatRpc.js';

type GetSnodesResponse = {
  result?: {
    master_node_states: Array<{
      public_ip: string;
      storage_port: number;
      pubkey_x25519: string;
      pubkey_ed25519: string;
    }>;
  };
};

const DEFAULT_TIMEOUT = 5_000;
/** extra attempts against a *single* seed before moving to the next one */
const ATTEMPTS_PER_SEED = 1;

export class SeedNodeClient {
  private seedNodes: string[];
  private fetch: FetchFn;
  private logger: Logger;
  private timeoutMs: number;
  private insecureTls: boolean;
  private agent: https.Agent;
  private policy: AddressPolicy;

  constructor(opts: SDKOptions) {
    if (!opts.seedNodes || !opts.seedNodes.length) {
      throw new Error('seedNodes is required');
    }
    // BCHAT-14: an http:// seed sends discovery in cleartext and lets any
    // observer replace the entire snode pool.
    this.seedNodes = opts.seedNodes.map(raw => {
      let parsed: URL;
      try {
        parsed = new URL(raw);
      } catch {
        throw new Error(`seed node "${raw}" is not a valid URL`);
      }
      if (parsed.protocol !== 'https:' && !opts.insecureTls) {
        throw new Error(
          `seed node ${raw} must use https (or set insecureTls: true to allow ${parsed.protocol})`
        );
      }
      return parsed.toString();
    });
    this.policy = { allowPrivateNodes: opts.allowPrivateNodes };
    // The global `fetch` (undici) silently ignores the `agent` option, which
    // would quietly discard the TLS configuration below, so fall back to
    // node-fetch instead of globalThis.fetch.
    this.fetch = opts.fetch ?? defaultFetch;
    this.logger = opts.logger ?? console;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT;
    this.insecureTls = Boolean(opts.insecureTls);

    // BCHAT-13: the bundle previously "pinned" here was three copies of the
    // cross-signed ISRG Root X1, which expired 2024-09-30, appended to the
    // system trust store -- so it accepted anything the system did and pinned
    // nothing. Dead code removed rather than left looking like a control.
    // Real pinning would need `checkServerIdentity` against a current SPKI
    // hash plus a rotation plan.
    this.agent = this.insecureTls
      ? new https.Agent({ rejectUnauthorized: false, keepAlive: false })
      : new https.Agent({ rejectUnauthorized: true, keepAlive: false });
  }

  /**
   * Try every configured seed node (in random order) until one returns a usable
   * pool.
   *
   * The previous implementation retried a closure that `shift()`ed a shared
   * array: once the seeds ran out it kept retrying a function that could only
   * ever throw "No seed nodes responded", and it did so with a backoff derived
   * from `timeoutMs` (2.5s, 5s, 10s), so a dead seed list took ~17s to fail.
   */
  async fetchSnodePool(): Promise<Snode[]> {
    const seeds = shuffle(this.seedNodes);
    const failures: string[] = [];

    for (const seedUrl of seeds) {
      try {
        return await retry(() => this.tryOne(seedUrl), {
          retries: ATTEMPTS_PER_SEED,
          minTimeout: 250,
          maxTimeout: 1_000,
          onFailedAttempt: err =>
            this.logger.warn(`Seed ${seedUrl} failed, retrying:`, err.message),
        });
      } catch (e: any) {
        failures.push(`${seedUrl}: ${e?.message || e}`);
      }
    }

    throw new Error(`No seed nodes responded (${failures.join('; ')})`);
  }

  private async tryOne(seedUrl: string): Promise<Snode[]> {
    const url = new URL('json_rpc', seedUrl).toString();
    const body = {
      jsonrpc: '2.0',
      id: '0',
      method: 'get_n_master_nodes',
      params: {
        active_only: true,
        ours_only: true,
        fields: {
          public_ip: true,
          storage_port: true,
          pubkey_x25519: true,
          pubkey_ed25519: true,
        },
      },
    };

    // `timeoutMs` was previously only used to size the retry backoff; a hung
    // seed node would hang the whole call forever.
    const fetchOnce = async (agentOverride?: https.Agent) => {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      try {
        return await this.fetch(url, {
          method: 'POST',
          body: JSON.stringify(body),
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'bchat-sdk',
          },
          agent: agentOverride ?? this.agent,
          redirect: 'error',
          size: MAX_RESPONSE_BYTES,
          signal: controller.signal as any,
        });
      } finally {
        clearTimeout(timer);
      }
    };

    let res;
    try {
      res = await fetchOnce();
    } catch (e: any) {
      // Only downgrade to an unverified connection when the caller explicitly
      // opted in. The old code retried insecurely on *any* transport error
      // (DNS, timeout, connection refused), silently turning off certificate
      // verification for a public HTTPS endpoint.
      if (this.insecureTls && this.agent.options.rejectUnauthorized !== false) {
        this.logger.warn(`Seed fetch strict TLS failed, retrying insecure: ${e?.message || e}`);
        res = await fetchOnce(new https.Agent({ rejectUnauthorized: false, keepAlive: false }));
      } else {
        throw e;
      }
    }

    if (res.status !== 200) {
      throw new Error(`Seed node ${seedUrl} responded ${res.status}`);
    }
    const contentType = res.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
      throw new Error(`Seed node ${seedUrl} returned non-JSON`);
    }
    const json = (await res.json()) as GetSnodesResponse;
    const nodes = json.result?.master_node_states || [];
    const valid = nodes
      .map(n => ({
        ip: n.public_ip,
        port: n.storage_port,
        pubkey_x25519: n.pubkey_x25519,
        pubkey_ed25519: n.pubkey_ed25519,
      }))
      // BCHAT-02: reject anything that is not a literal, routable IP before it
      // can reach URL construction.
      .filter(n => isUsableSnode(n, this.policy));

    const rejected = nodes.length - valid.length;
    if (rejected > 0) {
      this.logger.warn(`seed ${seedUrl}: discarded ${rejected} node(s) with invalid addresses`);
    }

    if (!valid.length) {
      throw new Error(`Seed node ${seedUrl} returned 0 valid nodes`);
    }

    this.logger.info('Fetched snode pool', valid.length, 'nodes from', seedUrl);
    return shuffle(valid);
  }
}
