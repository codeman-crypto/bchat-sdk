/**
 * Attachment download from the BChat file server v2, ported from bchat-desktop
 * `ts/receiver/attachments.ts` (`downloadAttachment`) and
 * `ts/bchat/apis/file_server_api/FileServerApiV2.ts` (`downloadFileFromFSv2`).
 *
 * Desktop sends this GET through an onion path. This module makes a DIRECT
 * plain-HTTP GET instead (verified to reach the server), which reveals the
 * downloader's IP address to the file server. See "Attachments" in the README.
 */
import { Buffer } from 'buffer';
import type { AttachmentPointer } from '../protocol/wire.js';
import { AttachmentError, decryptAttachment } from './crypto.js';

/** Desktop's `fileServerV2URL`. */
export const DEFAULT_FILE_SERVER_URL = 'http://fs1.rpcnode.stream';
const FILES_ENDPOINT = 'files';
const DEFAULT_TIMEOUT_MS = 60_000;
/** Desktop caps uploads at 6 MB; padding adds ~5% and base64 another 33%. */
const DEFAULT_MAX_BYTES = 32 * 1024 * 1024;

/** The slice of a fetch implementation attachment downloads need. */
export type AttachmentFetchFn = (
  input: string,
  init?: { method?: string; signal?: AbortSignal; headers?: Record<string, string> }
) => Promise<{
  status: number;
  headers: { get(name: string): string | null };
  arrayBuffer(): Promise<ArrayBuffer>;
}>;

export type DownloadAttachmentOptions = {
  /**
   * File server base URL; defaults to `http://fs1.rpcnode.stream`. The request
   * always goes here. Pointer URLs are accepted when they name either this
   * server or the default one, so overriding it (a mirror, a test server, an
   * IP literal) still works for pointers minted against the default host.
   */
  fileServerUrl?: string;
  /** fetch implementation; defaults to the global `fetch` (Node >= 18) */
  fetch?: AttachmentFetchFn;
  /** per-request timeout in ms (default 60000) */
  timeoutMs?: number;
  /** abort the download early */
  signal?: AbortSignal;
  /** refuse responses larger than this many bytes (default 32 MiB) */
  maxBytes?: number;
};

/**
 * Work out which file to request, mirroring desktop:
 *
 * - a `url` naming another host is refused. The pointer is sender-controlled,
 *   and fetching arbitrary URLs would let any sender make this process issue
 *   requests to hosts of their choosing (desktop refuses them too);
 * - the pointer `id` is preferred, as desktop does, then the id at the end of
 *   a `<server>/files/<id>` url, then a bare-id `url`.
 *
 * Exported for tests and for callers that want to check a pointer up front.
 */
export function resolveAttachmentFileId(
  pointer: Pick<AttachmentPointer, 'id' | 'url'>,
  fileServerUrl: string = DEFAULT_FILE_SERVER_URL
): string {
  const allowedOrigins = new Set([originOf(DEFAULT_FILE_SERVER_URL), originOf(fileServerUrl)]);
  let fromUrl: string | undefined;
  const raw = pointer.url?.trim();

  if (raw) {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
      let parsed: URL;
      try {
        parsed = new URL(raw);
      } catch {
        throw new AttachmentError('BAD_POINTER', 'attachment url is not a valid URL');
      }
      if (!allowedOrigins.has(parsed.origin)) {
        throw new AttachmentError(
          'BAD_POINTER',
          `attachment is hosted on ${parsed.origin}, which is not the configured file server; ` +
            'open-group and third-party hosts are not supported'
        );
      }
      const match = parsed.pathname.match(/^\/files\/([^/]+)\/?$/);
      fromUrl = match?.[1];
    } else {
      fromUrl = raw;
    }
  }

  // An absent fixed64 decodes to undefined here, but other encoders write 0.
  const id = pointer.id && pointer.id !== '0' ? pointer.id : fromUrl;
  if (!id || !/^[A-Za-z0-9_-]{1,128}$/.test(id)) {
    throw new AttachmentError(
      'BAD_POINTER',
      'attachment pointer has no usable file id (expected a numeric id or a <server>/files/<id> url)'
    );
  }
  return id;
}

/**
 * Download an attachment and return its decrypted plaintext.
 *
 * GETs `<fileServerUrl>/files/<id>` directly, unwraps the JSON envelope
 * (`{"status_code":200,"result":"<base64>"}`, or desktop's onion-shaped
 * `{"result":{"status_code":200,"result":"<base64>"}}`), tolerates a raw binary
 * body, then verifies and decrypts with `decryptAttachment`, trimming sender
 * padding to `pointer.size`.
 *
 * Like desktop, it requires the pointer's `key`, `digest` and a non-zero
 * `size`. A 404 means the file is gone — the server expires files after
 * about 60 days — and throws `DOWNLOAD_FAILED` with `status` 404.
 */
export async function downloadAttachment(
  pointer: AttachmentPointer,
  options: DownloadAttachmentOptions = {}
): Promise<Uint8Array> {
  if (!pointer.key?.length) {
    throw new AttachmentError('MISSING_KEY', 'attachment pointer has no decryption key');
  }
  if (!pointer.size) {
    throw new AttachmentError(
      'MISSING_SIZE',
      'attachment pointer has no size; refusing it as BChat desktop does'
    );
  }
  const blob = await fetchAttachmentBlob(pointer, options);
  return decryptAttachment(blob, pointer.key, pointer.digest, pointer.size);
}

/**
 * Fetch the still-encrypted blob for a pointer. Exposed separately so a caller
 * can cache ciphertext, or decrypt later with `decryptAttachment`.
 */
export async function fetchAttachmentBlob(
  pointer: Pick<AttachmentPointer, 'id' | 'url'>,
  options: DownloadAttachmentOptions = {}
): Promise<Uint8Array> {
  const base = (options.fileServerUrl ?? DEFAULT_FILE_SERVER_URL).replace(/\/+$/, '');
  const fileId = resolveAttachmentFileId(pointer, base);
  const url = `${base}/${FILES_ENDPOINT}/${encodeURIComponent(fileId)}`;
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;

  const fetchImpl: AttachmentFetchFn | undefined =
    options.fetch ?? ((globalThis as any).fetch as AttachmentFetchFn | undefined);
  if (!fetchImpl) {
    throw new AttachmentError(
      'DOWNLOAD_FAILED',
      'no fetch implementation: pass options.fetch (global fetch needs Node >= 18)'
    );
  }

  const timeout = AbortSignal.timeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const signal = options.signal ? anySignal([options.signal, timeout]) : timeout;

  let status: number;
  let body: Uint8Array;
  try {
    const res = await fetchImpl(url, { method: 'GET', signal });
    status = res.status;
    const declared = Number(res.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > maxBytes) {
      throw new AttachmentError(
        'TOO_LARGE',
        `file server response is ${declared} bytes, over the ${maxBytes}-byte limit`
      );
    }
    body = new Uint8Array(await res.arrayBuffer());
  } catch (e: any) {
    if (e instanceof AttachmentError) throw e;
    const why = timeout.aborted
      ? `timed out after ${options.timeoutMs ?? DEFAULT_TIMEOUT_MS} ms`
      : e?.message ?? String(e);
    throw new AttachmentError('DOWNLOAD_FAILED', `attachment ${fileId}: GET ${url} failed: ${why}`);
  }
  if (body.length > maxBytes) {
    throw new AttachmentError(
      'TOO_LARGE',
      `file server response is ${body.length} bytes, over the ${maxBytes}-byte limit`
    );
  }

  const envelope = parseJsonEnvelope(body);
  if (envelope) {
    const code = envelope.status_code ?? status;
    if (code !== 200 || typeof envelope.result !== 'string' || !envelope.result) {
      throw new AttachmentError(
        'DOWNLOAD_FAILED',
        `attachment ${fileId}: file server returned status_code ${code}` +
          (code === 404 ? ' (not found: expired, never uploaded, or wrong id)' : ''),
        code
      );
    }
    const blob = Buffer.from(envelope.result, 'base64');
    if (!blob.length) {
      throw new AttachmentError('DOWNLOAD_FAILED', `attachment ${fileId}: empty file`, code);
    }
    return new Uint8Array(blob.buffer, blob.byteOffset, blob.byteLength);
  }

  // Not a JSON envelope: accept a raw body only from a successful response.
  if (status < 200 || status >= 300) {
    throw new AttachmentError(
      'DOWNLOAD_FAILED',
      `attachment ${fileId}: file server returned HTTP ${status}` +
        (status === 404 ? ' (not found: expired, never uploaded, or wrong id)' : ''),
      status
    );
  }
  if (!body.length) {
    throw new AttachmentError('DOWNLOAD_FAILED', `attachment ${fileId}: empty file`, status);
  }
  return body;
}

type Envelope = { status_code?: number; result?: unknown };

/**
 * Returns the `{status_code, result}` envelope if the body is one, either at
 * the top level or nested under `result` (desktop's onion response shape).
 * Anything else — including binary that happens to start with `{` — is null.
 */
function parseJsonEnvelope(body: Uint8Array): Envelope | null {
  let i = 0;
  while (i < body.length && (body[i] === 0x20 || body[i] === 0x0a || body[i] === 0x0d || body[i] === 0x09)) i++;
  if (body[i] !== 0x7b /* { */) return null;
  let json: any;
  try {
    json = JSON.parse(Buffer.from(body).toString('utf8'));
  } catch {
    return null;
  }
  if (!json || typeof json !== 'object') return null;
  if (json.result && typeof json.result === 'object' && 'status_code' in json.result) {
    return json.result as Envelope;
  }
  if (!('status_code' in json) && !('result' in json)) return null;
  return json as Envelope;
}

function originOf(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    throw new AttachmentError('BAD_POINTER', `fileServerUrl is not a valid URL: ${url}`);
  }
}

/** AbortSignal.any is Node >= 20.3; this package supports Node 18. */
function anySignal(signals: AbortSignal[]): AbortSignal {
  const controller = new AbortController();
  for (const s of signals) {
    if (s.aborted) {
      controller.abort(s.reason);
      break;
    }
    s.addEventListener('abort', () => controller.abort(s.reason), { once: true });
  }
  return controller.signal;
}
