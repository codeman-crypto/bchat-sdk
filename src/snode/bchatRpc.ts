import { FetchFn, Logger, Snode } from '../types.js';
import { AbortError, retry } from '../util/retry.js';
import https from 'https';

export type SnodeResponse = { status: number; body: string };

type CallParams = {
  method: string;
  params: any;
  targetNode: Snode;
  associatedWith?: string;
  timeout?: number;
};

const CERT_ERROR_PATTERN =
  /self[- ]signed certificate|unable to verify the first certificate|unable to get local issuer certificate|DEPTH_ZERO_SELF_SIGNED_CERT|CERT_/i;

export class BchatRpc {
  private agent?: https.Agent;
  /**
   * Created once and reused. The old code built a new keepAlive https.Agent on
   * *every* call() -- including the calls that never needed it -- leaking a
   * socket pool per request.
   */
  private insecureAgent?: https.Agent;
  /**
   * Nodes already known to serve a self-signed certificate.
   *
   * Storage nodes serve self-signed certs by design, so the strict-TLS attempt
   * below fails for essentially all of them. Without this set every single RPC
   * paid for a doomed TLS handshake before falling back -- two handshakes per
   * poll, forever, plus a warning line each time.
   */
  private selfSigned = new Set<string>();

  constructor(
    private fetch: FetchFn,
    private logger: Logger,
    private timeoutMs: number,
    private insecureTls?: boolean
  ) {
    this.agent = insecureTls
      ? new https.Agent({ rejectUnauthorized: false, keepAlive: true })
      : undefined;
  }

  private getInsecureAgent(): https.Agent {
    if (!this.insecureAgent) {
      this.insecureAgent = new https.Agent({ rejectUnauthorized: false, keepAlive: true });
    }
    return this.insecureAgent;
  }

  async call({ method, params, targetNode, timeout }: CallParams): Promise<SnodeResponse> {
    if (!targetNode?.ip || !targetNode?.port) {
      throw new Error('BchatRpc.call requires a target node with ip and port');
    }

    const url = `https://${targetNode.ip}:${targetNode.port}/storage_rpc/v1`;
    const body = {
      jsonrpc: '2.0',
      id: '0',
      method,
      params,
    };
    const timeoutMs = timeout ?? this.timeoutMs;

    const doFetch = async (agentOverride?: https.Agent): Promise<SnodeResponse> => {
      const controller = new AbortController();
      const to = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const r = await this.fetch(url, {
          method: 'POST',
          body: JSON.stringify(body),
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'bchat-sdk',
            'Accept-Language': 'en-us',
          },
          agent: agentOverride ?? this.agent,
          signal: controller.signal as any,
        });
        if (r.status < 200 || r.status >= 300) {
          const error = new Error(
            `snode ${targetNode.ip}:${targetNode.port} status ${r.status}`
          );
          // 4xx means this request is malformed or rejected; hammering the same
          // node three more times only adds latency to a guaranteed failure.
          if (r.status >= 400 && r.status < 500) {
            throw new AbortError(error);
          }
          throw error;
        }
        const text = await r.text();
        return { status: r.status, body: text };
      } finally {
        clearTimeout(to);
      }
    };

    const nodeKey = `${targetNode.ip}:${targetNode.port}`;

    return retry(
      async () => {
        // Already known to be self-signed: skip straight to the unverified
        // agent, whose keep-alive pool then gets reused across polls.
        if (this.selfSigned.has(nodeKey)) {
          return await doFetch(this.getInsecureAgent());
        }

        try {
          return await doFetch();
        } catch (e: any) {
          if (e instanceof AbortError) throw e;
          if (
            this.agent?.options.rejectUnauthorized !== false &&
            CERT_ERROR_PATTERN.test(e?.message || '')
          ) {
            this.selfSigned.add(nodeKey);
            // Once per node, not once per request.
            this.logger.warn(
              `snode ${nodeKey} serves a self-signed certificate; using an unverified ` +
                `connection to it (payloads are sealed-box encrypted, but request ` +
                `metadata is exposed to a network attacker)`
            );
            return await doFetch(this.getInsecureAgent());
          }
          throw e;
        }
      },
      {
        retries: 2,
        // Was `timeoutMs / 2`, i.e. 5s then 10s between attempts on the default
        // 10s timeout, so one flaky node could stall a call for ~25s.
        minTimeout: 300,
        maxTimeout: 2_000,
        onFailedAttempt: e =>
          this.logger.warn(
            `snode rpc retry ${method} on ${targetNode.ip}:${targetNode.port}: ${e?.message || e}`
          ),
      }
    );
  }
}
