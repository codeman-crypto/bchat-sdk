import shuffle from 'lodash.shuffle';
import https from 'https';
import tls from 'tls';
import { FetchFn, Logger, SDKOptions, Snode } from '../types.js';
import { retry } from '../util/retry.js';
import { defaultFetch } from '../http/fetchImpl.js';

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

// Copied from bchat-desktop seed_node_api (pinned self-signed certs)
const storageSeed1Crt = `-----BEGIN CERTIFICATE-----
MIIFYDCCBEigAwIBAgIQQAF3ITfU6UK47naqPGQKtzANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTIxMDEyMDE5MTQwM1oXDTI0MDkzMDE4MTQwM1ow
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQCt6CRz9BQ385ueK1coHIe+3LffOJCMbjzmV6B493XC
ov71am72AE8o295ohmxEk7axY/0UEmu/H9LqMZshftEzPLpI9d1537O4/xLxIZpL
wYqGcWlKZmZsj348cL+tKSIG8+TA5oCu4kuPt5l+lAOf00eXfJlII1PoOK5PCm+D
LtFJV4yAdLbaL9A4jXsDcCEbdfIwPPqPrt3aY6vrFk/CjhFLfs8L6P+1dy70sntK
4EwSJQxwjQMpoOFTJOwT2e4ZvxCzSow/iaNhUd6shweU9GNx7C7ib1uYgeGJXDR5
bHbvO5BieebbpJovJsXQEOEO3tkQjhb7t/eo98flAgeYjzYIlefiN5YNNnWe+w5y
sR2bvAP5SQXYgd0FtCrWQemsAXaVCg/Y39W9Eh81LygXbNKYwagJZHduRze6zqxZ
Xmidf3LWicUGQSk+WT7dJvUkyRGnWqNMQB9GoZm1pzpRboY7nn1ypxIFeFntPlF4
FQsDj43QLwWyPntKHEtzBRL8xurgUBN8Q5N0s8p0544fAQjQMNRbcTa0B7rBMDBc
SLeCO5imfWCKoqMpgsy6vYMEG6KDA0Gh1gXxG8K28Kh8hjtGqEgqiNx2mna/H2ql
PRmP6zjzZN7IKw0KKP/32+IVQtQi0Cdd4Xn+GOdwiK1O5tmLOsbdJ1Fu/7xk9TND
TwIDAQABo4IBRjCCAUIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw
SwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vYXBwcy5pZGVudHJ1
c3QuY29tL3Jvb3RzL2RzdHJvb3RjYXgzLnA3YzAfBgNVHSMEGDAWgBTEp7Gkeyxx
+tvhS5B1/8QVYIWJEDBUBgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEB
ATAwMC4GCCsGAQUFBwIBFiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQu
b3JnMDwGA1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly9jcmwuaWRlbnRydXN0LmNvbS9E
U1RST09UQ0FYM0NSTC5jcmwwHQYDVR0OBBYEFHm0WeZ7tuXkAXOACIjIGlj26Ztu
MA0GCSqGSIb3DQEBCwUAA4IBAQAKcwBslm7/DlLQrt2M51oGrS+o44+/yQoDFVDC
5WxCu2+b9LRPwkSICHXM6webFGJueN7sJ7o5XPWioW5WlHAQU7G75K/QosMrAdSW
9MUgNTP52GE24HGNtLi1qoJFlcDyqSMo59ahy2cI2qBDLKobkx/J3vWraV0T9VuG
WCLKTVXkcGdtwlfFRjlBz4pYg1htmf5X6DYO8A4jqv2Il9DjXA6USbW1FzXSLr9O
he8Y4IWS6wY7bCkjCWDcRQJMEhg76fsO3txE+FiYruq9RUWhiF1myv4Q6W+CyBFC
Dfvp7OOGAN6dEOM4+qR9sdjoSYKEBpsr6GtPAQw4dy753ec5
-----END CERTIFICATE-----
`;

const storageSeed3Crt = storageSeed1Crt; // same as desktop source
const publicBeldexFoundationCtr = storageSeed1Crt; // same bundle used for other hosts

export class SeedNodeClient {
  private seedNodes: string[];
  private fetch: FetchFn;
  private logger: Logger;
  private timeoutMs: number;
  private insecureTls: boolean;
  private agent: https.Agent;

  constructor(opts: SDKOptions) {
    if (!opts.seedNodes || !opts.seedNodes.length) {
      throw new Error('seedNodes is required');
    }
    this.seedNodes = opts.seedNodes;
    // The global `fetch` (undici) silently ignores the `agent` option, which
    // would quietly discard the TLS configuration below, so fall back to
    // node-fetch instead of globalThis.fetch.
    this.fetch = opts.fetch ?? defaultFetch;
    this.logger = opts.logger ?? console;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT;
    this.insecureTls = Boolean(opts.insecureTls);

    // The pinned bundle below is the cross-signed ISRG Root X1, which expired
    // on 2024-09-30. Supplying `ca` *replaces* Node's trust store, so pinning
    // it alone makes every strict-TLS seed request fail. Append the system
    // roots so verification still succeeds against the current chain.
    const pinnedCa = [storageSeed1Crt, storageSeed3Crt, publicBeldexFoundationCtr];
    this.agent = this.insecureTls
      ? new https.Agent({ rejectUnauthorized: false, keepAlive: false })
      : new https.Agent({
          ca: [...pinnedCa, ...tls.rootCertificates],
          rejectUnauthorized: true,
          keepAlive: false,
        });
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
      .filter(n => n.public_ip && n.public_ip !== '0.0.0.0' && n.storage_port)
      .map(n => ({
        ip: n.public_ip,
        port: n.storage_port,
        pubkey_x25519: n.pubkey_x25519,
        pubkey_ed25519: n.pubkey_ed25519,
      }));

    if (!valid.length) {
      throw new Error(`Seed node ${seedUrl} returned 0 valid nodes`);
    }

    this.logger.info('Fetched snode pool', valid.length, 'nodes from', seedUrl);
    return shuffle(valid);
  }
}
