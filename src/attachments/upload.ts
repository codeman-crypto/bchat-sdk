/**
 * Attachment upload: encrypt a file and store it on the BChat file server,
 * the counterpart of `download.ts`.
 *
 * The apps POST `{"file": "<base64 blob>"}` to `<fileServer>/files` and read
 * the new file id from `{"result": <id>}` (bchat-ios `FileServerAPIV2.upload`).
 * They do so through onion requests; this is a direct HTTP POST, so the file
 * server sees this host's IP. It only ever sees the encrypted blob.
 */
import { Buffer } from 'buffer';
import type { AttachmentPointer } from '../protocol/wire.js';
import { AttachmentError, encryptAttachment } from './crypto.js';
import { DEFAULT_FILE_SERVER_URL } from './download.js';

const FILES_ENDPOINT = 'files';
const DEFAULT_TIMEOUT_MS = 120_000;
/** The apps refuse files over 10 MB (`FileServerAPIV2.maxFileSize`). */
export const MAX_ATTACHMENT_UPLOAD_BYTES = 10_000_000;

/** The slice of a fetch implementation attachment uploads need. */
export type AttachmentUploadFetchFn = (
  input: string,
  init: { method: string; signal?: AbortSignal; headers: Record<string, string>; body: string }
) => Promise<{ status: number; text(): Promise<string> }>;

export type UploadAttachmentOptions = {
  /** File server base URL; defaults to `http://fs1.rpcnode.stream`. */
  fileServerUrl?: string;
  /** fetch implementation; defaults to the global `fetch` (Node >= 18) */
  fetch?: AttachmentUploadFetchFn;
  /** per-request timeout in ms (default 120000) */
  timeoutMs?: number;
  /** abort the upload early */
  signal?: AbortSignal;
  /** refuse files larger than this many bytes (default and ceiling: 10 MB) */
  maxBytes?: number;
  /**
   * Extra attempts after a failed request or a 5xx answer (default 2). The
   * file server fails a share of uploads at random; a repeated upload only
   * leaves an unreferenced encrypted blob behind.
   */
  retries?: number;
};

export type AttachmentUpload = {
  /** the file itself, unencrypted */
  data: Uint8Array;
  /** MIME type shown to the recipient, e.g. `audio/aac`, `image/jpeg` */
  contentType: string;
  fileName?: string;
  /** mark the file as a voice message, which the apps show with a player */
  isVoiceMessage?: boolean;
  caption?: string;
  width?: number;
  height?: number;
};

const anySignal = (signals: AbortSignal[]): AbortSignal => {
  const controller = new AbortController();
  for (const s of signals) {
    if (s.aborted) {
      controller.abort(s.reason);
      break;
    }
    s.addEventListener('abort', () => controller.abort(s.reason), { once: true });
  }
  return controller.signal;
};

/**
 * Store an already-encrypted blob and return its file id as a decimal string.
 * The id is a u64, so it is read from the response text, never as a JS number.
 */
export async function uploadAttachmentBlob(
  blob: Uint8Array,
  options: UploadAttachmentOptions = {}
): Promise<string> {
  const retries = Math.max(0, options.retries ?? 2);
  for (let attempt = 0; ; attempt++) {
    try {
      return await uploadAttachmentBlobOnce(blob, options);
    } catch (e) {
      const status = e instanceof AttachmentError ? e.status : undefined;
      const retryable = status === undefined || status >= 500;
      if (!retryable || attempt >= retries || options.signal?.aborted) throw e;
      await new Promise(resolve => setTimeout(resolve, 1000 * 3 ** attempt));
    }
  }
}

async function uploadAttachmentBlobOnce(
  blob: Uint8Array,
  options: UploadAttachmentOptions
): Promise<string> {
  const base = (options.fileServerUrl ?? DEFAULT_FILE_SERVER_URL).replace(/\/+$/, '');
  const url = `${base}/${FILES_ENDPOINT}`;
  const fetchImpl: AttachmentUploadFetchFn | undefined =
    options.fetch ?? ((globalThis as any).fetch as AttachmentUploadFetchFn | undefined);
  if (!fetchImpl) {
    throw new AttachmentError(
      'UPLOAD_FAILED',
      'no fetch implementation: pass options.fetch (global fetch needs Node >= 18)'
    );
  }

  const timeout = AbortSignal.timeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const signal = options.signal ? anySignal([options.signal, timeout]) : timeout;

  let status: number;
  let text: string;
  try {
    const res = await fetchImpl(url, {
      method: 'POST',
      signal,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ file: Buffer.from(blob).toString('base64') }),
    });
    status = res.status;
    text = await res.text();
  } catch (e: any) {
    const why = timeout.aborted
      ? `timed out after ${options.timeoutMs ?? DEFAULT_TIMEOUT_MS} ms`
      : e?.message ?? String(e);
    throw new AttachmentError('UPLOAD_FAILED', `POST ${url} failed: ${why}`);
  }

  // {"result": 678783661637972, "status_code": 200}
  const id = /"result"\s*:\s*"?(\d+)"?/.exec(text)?.[1];
  const code = Number(/"status_code"\s*:\s*(\d+)/.exec(text)?.[1] ?? status);
  if (status < 200 || status >= 300 || code !== 200 || !id || id === '0') {
    throw new AttachmentError(
      'UPLOAD_FAILED',
      `file server refused the upload (HTTP ${status}, status_code ${code})`,
      code !== 200 ? code : status
    );
  }
  return id;
}

/**
 * Encrypt `upload.data`, store it on the file server and return the pointer
 * to put in a message's `attachments`. The pointer carries the key, which is
 * secret: anyone holding it can read the file until it expires on the server.
 */
export async function uploadAttachment(
  upload: AttachmentUpload,
  options: UploadAttachmentOptions = {}
): Promise<AttachmentPointer> {
  const maxBytes = Math.min(options.maxBytes ?? MAX_ATTACHMENT_UPLOAD_BYTES, MAX_ATTACHMENT_UPLOAD_BYTES);
  if (!upload?.data?.length) {
    throw new AttachmentError('MISSING_SIZE', 'cannot upload an empty attachment');
  }
  if (upload.data.length > maxBytes) {
    throw new AttachmentError(
      'TOO_LARGE',
      `attachment is ${upload.data.length} bytes, over the ${maxBytes}-byte limit`
    );
  }
  if (!upload.contentType) {
    throw new AttachmentError('BAD_POINTER', 'an attachment needs a contentType');
  }

  const encrypted = encryptAttachment(upload.data);
  const id = await uploadAttachmentBlob(encrypted.blob, options);
  const base = (options.fileServerUrl ?? DEFAULT_FILE_SERVER_URL).replace(/\/+$/, '');
  return {
    id,
    contentType: upload.contentType,
    key: encrypted.key,
    size: encrypted.size,
    digest: encrypted.digest,
    fileName: upload.fileName,
    caption: upload.caption,
    width: upload.width,
    height: upload.height,
    isVoiceMessage: upload.isVoiceMessage || undefined,
    url: `${base}/${FILES_ENDPOINT}/${id}`,
  };
}
