import { FetchFn, Logger, Snode } from '../types.js';
import { AbortError, retry } from '../util/retry.js';
import { assertSnodeAddress, buildSnodeUrl, type AddressPolicy } from './validate.js';
import https from 'https';

export type SnodeResponse = { status: number; body: string };

type CallParams = {
  method: string;
  params: any;
  targetNode: Snode;
  associatedWith?: string;
  timeout?: number;
};

/**
 * Cap on any single storage-node response. node-fetch v3 is unlimited by
 * default, so without this a hostile node can stream until the heap dies.
 */
export const MAX_RESPONSE_BYTES = 5 * 1024 * 1024;

export type BchatRpcOptions = AddressPolicy & {
  /** disables verification for every request this SDK makes */
  insecureTls?: boolean;
  /** accepts self-signed certificates from storage nodes only */
  allowSelfSignedStorageNodes?: boolean;
};

export class BchatRpc {
  private agent?: https.Agent;
  private policy: AddressPolicy;
  private acceptSelfSigned: boolean;

  constructor(
    private fetch: FetchFn,
    private logger: Logger,
    private timeoutMs: number,
    opts?: boolean | BchatRpcOptions
  ) {
    // Back-compat: this parameter used to be a bare `insecureTls` boolean.
    const options: BchatRpcOptions = typeof opts === 'boolean' ? { insecureTls: opts } : opts ?? {};
    this.policy = { allowPrivateNodes: options.allowPrivateNodes };

    // Storage nodes have no PKI and always serve self-signed certificates, so
    // this is opt-in per-node-class rather than a blanket downgrade. Crucially
    // it does NOT affect SeedNodeClient, whose certificates are real.
    this.acceptSelfSigned = Boolean(options.insecureTls || options.allowSelfSignedStorageNodes);
    this.agent = new https.Agent({
      rejectUnauthorized: !this.acceptSelfSigned,
      keepAlive: true,
    });
  }

  async call({ method, params, targetNode, timeout }: CallParams): Promise<SnodeResponse> {
    // Validated again here even though node lists are filtered on ingest: this
    // is the last point before a URL is constructed.
    const port = assertSnodeAddress(targetNode?.ip, targetNode?.port, this.policy);
    const url = buildSnodeUrl(targetNode.ip, port, '/storage_rpc/v1');

    const body = { jsonrpc: '2.0', id: '0', method, params };
    const timeoutMs = timeout ?? this.timeoutMs;

    const doFetch = async (): Promise<SnodeResponse> => {
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
          agent: this.agent,
          // A storage node has no legitimate reason to redirect a JSON-RPC POST,
          // and following one would re-send the signed request elsewhere.
          redirect: 'error',
          size: MAX_RESPONSE_BYTES,
          signal: controller.signal as any,
        });

        if (r.status < 200 || r.status >= 300) {
          const error = new Error(`snode ${targetNode.ip}:${port} status ${r.status}`);
          // 4xx means this request is malformed or rejected; hammering the same
          // node only adds latency to a guaranteed failure.
          if (r.status >= 400 && r.status < 500) throw new AbortError(error);
          throw error;
        }

        const text = await r.text();
        return { status: r.status, body: text };
      } finally {
        clearTimeout(to);
      }
    };

    return retry(
      async () => {
        try {
          return await doFetch();
        } catch (e: any) {
          if (e instanceof AbortError) throw e;
          // BCHAT-01: there is deliberately NO per-node TLS downgrade here.
          // Retrying a failed certificate check with rejectUnauthorized:false
          // hands any on-path attacker the full request, including the account
          // pubkey and the signed retrieve material. `insecureTls` is the only
          // way to disable verification, and it is a caller decision.
          if (isCertificateError(e)) {
            throw new AbortError(
              new Error(
                `snode ${targetNode.ip}:${port} TLS certificate could not be verified ` +
                  `(${e?.code || e?.message}). BChat storage nodes serve self-signed ` +
                  `certificates by design, so this is expected on the live network: set ` +
                  `allowSelfSignedStorageNodes: true (in the examples, just don't pass ` +
                  `--strict-tls). Seed node certificates stay verified either way.`
              )
            );
          }
          throw e;
        }
      },
      {
        retries: 2,
        minTimeout: 300,
        maxTimeout: 2_000,
        onFailedAttempt: e =>
          this.logger.warn(
            `snode rpc retry ${method} on ${targetNode.ip}:${port}: ${e?.message || e}`
          ),
      }
    );
  }
}

const CERT_ERROR_PATTERN =
  /self[- ]signed certificate|unable to verify the first certificate|unable to get local issuer certificate|DEPTH_ZERO_SELF_SIGNED_CERT|CERT_|ERR_TLS/i;

/** Recognises a certificate failure so it can be reported clearly, not retried. */
export function isCertificateError(e: any): boolean {
  const code = typeof e?.code === 'string' ? e.code : '';
  const message = typeof e?.message === 'string' ? e.message : '';
  return CERT_ERROR_PATTERN.test(code) || CERT_ERROR_PATTERN.test(message);
}
