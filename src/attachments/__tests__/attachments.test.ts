import { describe, it, expect, vi } from 'vitest';
import { Buffer } from 'buffer';
import { createHash, createHmac, randomBytes, webcrypto } from 'crypto';
import {
  AttachmentError,
  decryptAttachment,
  downloadAttachment,
  resolveAttachmentFileId,
  type AttachmentFetchFn,
} from '../index';
import type { AttachmentPointer } from '../../protocol/wire';
import { BchatSDK } from '../../BchatSDK';

// ---------------------------------------------------------------------------
// Faithful ports of bchat-desktop's sender side, so the tests exercise the
// decrypter against what the real client produces rather than against itself.

/** desktop ts/util/crypto/attachmentsEncrypter.ts `encryptAttachment` (WebCrypto, as desktop) */
async function desktopEncryptAttachment(plaintext: Uint8Array, keys: Uint8Array, iv: Uint8Array) {
  const subtle = webcrypto.subtle;
  if (keys.byteLength !== 64) throw new Error('Got invalid length attachment keys');
  if (iv.byteLength !== 16) throw new Error('Got invalid length attachment iv');
  const aesKey = keys.slice(0, 32);
  const macKey = keys.slice(32, 64);

  const aes = await subtle.importKey('raw', aesKey, { name: 'AES-CBC' }, false, ['encrypt']);
  const ciphertext = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv }, aes, plaintext));

  const ivAndCiphertext = new Uint8Array(16 + ciphertext.byteLength);
  ivAndCiphertext.set(iv);
  ivAndCiphertext.set(ciphertext, 16);

  const hmac = await subtle.importKey('raw', macKey, { name: 'HMAC', hash: { name: 'SHA-256' } }, false, ['sign']);
  const mac = new Uint8Array(await subtle.sign({ name: 'HMAC', hash: 'SHA-256' }, hmac, ivAndCiphertext));

  const encryptedBin = new Uint8Array(16 + ciphertext.byteLength + 32);
  encryptedBin.set(ivAndCiphertext);
  encryptedBin.set(mac, 16 + ciphertext.byteLength);
  const digest = new Uint8Array(await subtle.digest({ name: 'SHA-256' }, encryptedBin));
  return { ciphertext: encryptedBin, digest };
}

/** desktop ts/bchat/crypto/BufferPadding.ts `addAttachmentPadding` */
function desktopAddAttachmentPadding(data: Uint8Array): Uint8Array {
  const paddedSize = Math.max(
    541,
    Math.floor(Math.pow(1.05, Math.ceil(Math.log(data.length) / Math.log(1.05))))
  );
  const padded = new Uint8Array(paddedSize);
  padded.set(data);
  return padded;
}

/** desktop AttachmentFsV2Utils.uploadToFsV2 with shouldPad: true (message attachments) */
async function desktopUpload(plaintext: Uint8Array, opts: { pad?: boolean } = {}) {
  const key = new Uint8Array(randomBytes(64));
  const iv = new Uint8Array(randomBytes(16));
  const toEncrypt = opts.pad === false ? plaintext : desktopAddAttachmentPadding(plaintext);
  const { ciphertext, digest } = await desktopEncryptAttachment(toEncrypt, key, iv);
  return { key, digest, blob: ciphertext, size: plaintext.length };
}

const expectCode = (fn: () => unknown, code: string) => {
  try {
    fn();
  } catch (e: any) {
    expect(e).toBeInstanceOf(AttachmentError);
    expect(e.code).toBe(code);
    return e as AttachmentError;
  }
  throw new Error(`expected AttachmentError ${code}, nothing was thrown`);
};

const expectRejectCode = async (p: Promise<unknown>, code: string) => {
  try {
    await p;
  } catch (e: any) {
    expect(e).toBeInstanceOf(AttachmentError);
    expect(e.code).toBe(code);
    return e as AttachmentError;
  }
  throw new Error(`expected AttachmentError ${code}, promise resolved`);
};

// A plausible start of an Android AAC voice note (MP4 'ftyp' box, M4A brand).
const fakeVoiceNote = () =>
  Buffer.concat([
    Buffer.from('000000206674797049534f6d0000020069736f6d69736f326d703431', 'hex'),
    randomBytes(5_000),
  ]);

// ---------------------------------------------------------------- decryption

describe('decryptAttachment', () => {
  it('round-trips an unpadded attachment', async () => {
    const plaintext = new Uint8Array(randomBytes(1000));
    const { key, digest, blob } = await desktopUpload(plaintext, { pad: false });
    expect(Buffer.from(decryptAttachment(blob, key, digest))).toEqual(Buffer.from(plaintext));
    expect(Buffer.from(decryptAttachment(blob, key, digest, 1000))).toEqual(Buffer.from(plaintext));
  });

  it('trims desktop padding to the pointer size, whatever the audio format', async () => {
    const voice = fakeVoiceNote();
    const { key, digest, blob, size } = await desktopUpload(voice);

    const raw = decryptAttachment(blob, key, digest);
    expect(raw.length).toBeGreaterThan(voice.length); // padding really was added
    expect(Buffer.from(raw.subarray(voice.length)).every(b => b === 0)).toBe(true);

    expect(Buffer.from(decryptAttachment(blob, key, digest, size))).toEqual(voice);
  });

  it('pads tiny attachments to 541 bytes and still trims back', async () => {
    const plaintext = Buffer.from('hi');
    const { key, digest, blob, size } = await desktopUpload(plaintext);
    expect(decryptAttachment(blob, key, digest).length).toBe(541);
    expect(Buffer.from(decryptAttachment(blob, key, digest, size)).toString()).toBe('hi');
  });

  it('rejects a flipped MAC byte', async () => {
    const { key, digest, blob } = await desktopUpload(Buffer.from('payload'));
    const bad = Uint8Array.from(blob);
    bad[bad.length - 1]! ^= 0x01;
    expectCode(() => decryptAttachment(bad, key, digest), 'MAC_MISMATCH');
  });

  it('rejects a flipped ciphertext byte at the MAC, before the digest', async () => {
    const { key, digest, blob } = await desktopUpload(Buffer.from('payload'));
    const bad = Uint8Array.from(blob);
    bad[20]! ^= 0x80;
    expectCode(() => decryptAttachment(bad, key, digest), 'MAC_MISMATCH');
  });

  it('rejects the wrong key', async () => {
    const { digest, blob } = await desktopUpload(Buffer.from('payload'));
    expectCode(() => decryptAttachment(blob, new Uint8Array(randomBytes(64)), digest), 'MAC_MISMATCH');
  });

  it('rejects a wrong digest', async () => {
    const { key, digest, blob } = await desktopUpload(Buffer.from('payload'));
    const bad = Uint8Array.from(digest);
    bad[0]! ^= 0xff;
    expectCode(() => decryptAttachment(blob, key, bad), 'DIGEST_MISMATCH');
  });

  it('rejects a digest prefix (desktop would accept one; we require all 32 bytes)', async () => {
    const { key, digest, blob } = await desktopUpload(Buffer.from('payload'));
    expectCode(() => decryptAttachment(blob, key, digest.subarray(0, 16)), 'DIGEST_MISMATCH');
  });

  it('refuses a missing or empty digest, as desktop does', async () => {
    const { key, blob } = await desktopUpload(Buffer.from('payload'));
    expectCode(() => decryptAttachment(blob, key), 'DIGEST_MISSING');
    expectCode(() => decryptAttachment(blob, key, new Uint8Array(0)), 'DIGEST_MISSING');
  });

  it('rejects a truncated blob', async () => {
    const { key, digest, blob } = await desktopUpload(Buffer.from('payload'));
    expectCode(() => decryptAttachment(blob.subarray(0, 47), key, digest), 'SHORT_BLOB');
    // still long enough to parse, but the MAC is now over the wrong bytes
    expectCode(() => decryptAttachment(blob.subarray(0, blob.length - 16), key, digest), 'MAC_MISMATCH');
  });

  it('rejects a key that is not 64 bytes', async () => {
    const { key, digest, blob } = await desktopUpload(Buffer.from('payload'));
    expectCode(() => decryptAttachment(blob, key.subarray(0, 32), digest), 'BAD_KEY_LENGTH');
  });

  it('reports a plaintext shorter than the declared size', async () => {
    const { key, digest, blob } = await desktopUpload(Buffer.from('payload'), { pad: false });
    expectCode(() => decryptAttachment(blob, key, digest, 8), 'SIZE_MISMATCH');
  });

  it('reports AES failure separately when the MAC and digest are valid', () => {
    // A correctly MACed blob whose ciphertext is not a whole number of blocks.
    const key = randomBytes(64);
    const ivAndCt = randomBytes(16 + 20);
    const mac = createHmac('sha256', key.subarray(32)).update(ivAndCt).digest();
    const blob = Buffer.concat([ivAndCt, mac]);
    const digest = createHash('sha256').update(blob).digest();
    expectCode(() => decryptAttachment(blob, key, digest), 'DECRYPT_FAILED');
  });
});

// ------------------------------------------------------------------ download

type FakeResponse = { status: number; body: Uint8Array | string; contentType?: string };

function fakeFetch(response: FakeResponse | ((url: string, init?: any) => Promise<FakeResponse>)) {
  return vi.fn(async (url: string, init?: any) => {
    const r = typeof response === 'function' ? await response(url, init) : response;
    const bytes = typeof r.body === 'string' ? Buffer.from(r.body, 'utf8') : Buffer.from(r.body);
    return {
      status: r.status,
      headers: {
        get: (name: string) =>
          name.toLowerCase() === 'content-type'
            ? (r.contentType ?? 'application/json')
            : name.toLowerCase() === 'content-length'
              ? String(bytes.length)
              : null,
      },
      arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.length),
    };
  });
}

async function uploadedPointer(plaintext: Uint8Array, extra: Partial<AttachmentPointer> = {}) {
  const up = await desktopUpload(plaintext);
  const pointer: AttachmentPointer = {
    id: '12345',
    contentType: 'audio/aac',
    key: up.key,
    digest: up.digest,
    size: up.size,
    url: 'http://fs1.rpcnode.stream/files/12345',
    isVoiceMessage: true,
    ...extra,
  };
  return { pointer, blob: up.blob };
}

describe('downloadAttachment', () => {
  it('GETs the file server directly and decrypts the base64 JSON envelope', async () => {
    const voice = fakeVoiceNote();
    const { pointer, blob } = await uploadedPointer(voice);
    const fetch = fakeFetch({
      status: 200,
      body: JSON.stringify({ status_code: 200, result: Buffer.from(blob).toString('base64') }),
    });

    const out = await downloadAttachment(pointer, { fetch: fetch as AttachmentFetchFn });
    expect(Buffer.from(out)).toEqual(voice);
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch.mock.calls[0]![0]).toBe('http://fs1.rpcnode.stream/files/12345');
    expect(fetch.mock.calls[0]![1]?.method).toBe('GET');
  });

  it("accepts desktop's onion-shaped nested envelope", async () => {
    const { pointer, blob } = await uploadedPointer(Buffer.from('nested'));
    const fetch = fakeFetch({
      status: 200,
      body: JSON.stringify({
        result: { status_code: 200, result: Buffer.from(blob).toString('base64') },
      }),
    });
    const out = await downloadAttachment(pointer, { fetch: fetch as AttachmentFetchFn });
    expect(Buffer.from(out).toString()).toBe('nested');
  });

  it('tolerates a raw binary body', async () => {
    const { pointer, blob } = await uploadedPointer(Buffer.from('raw body'));
    const fetch = fakeFetch({ status: 200, body: blob, contentType: 'application/octet-stream' });
    const out = await downloadAttachment(pointer, { fetch: fetch as AttachmentFetchFn });
    expect(Buffer.from(out).toString()).toBe('raw body');
  });

  it('turns the 404 envelope into a clear error carrying the status', async () => {
    const { pointer } = await uploadedPointer(Buffer.from('gone'));
    // exactly what the live server returned for GET /files/1 on 2026-10-15
    const fetch = fakeFetch({ status: 404, body: '{"status_code": 404}' });
    const err = await expectRejectCode(
      downloadAttachment(pointer, { fetch: fetch as AttachmentFetchFn }),
      'DOWNLOAD_FAILED'
    );
    expect(err.status).toBe(404);
    expect(err.message).toMatch(/404.*expired/);
  });

  it('reports a non-JSON HTTP error', async () => {
    const { pointer } = await uploadedPointer(Buffer.from('x'));
    const fetch = fakeFetch({ status: 502, body: '<html>bad gateway</html>', contentType: 'text/html' });
    const err = await expectRejectCode(
      downloadAttachment(pointer, { fetch: fetch as AttachmentFetchFn }),
      'DOWNLOAD_FAILED'
    );
    expect(err.status).toBe(502);
  });

  it('surfaces a tampered download as a MAC failure', async () => {
    const { pointer, blob } = await uploadedPointer(Buffer.from('x'));
    const bad = Uint8Array.from(blob);
    bad[17]! ^= 1;
    const fetch = fakeFetch({
      status: 200,
      body: JSON.stringify({ status_code: 200, result: Buffer.from(bad).toString('base64') }),
    });
    await expectRejectCode(downloadAttachment(pointer, { fetch: fetch as AttachmentFetchFn }), 'MAC_MISMATCH');
  });

  it('refuses a pointer that names another host, without fetching', async () => {
    const { pointer } = await uploadedPointer(Buffer.from('x'), {
      id: undefined,
      url: 'http://169.254.169.254/files/1',
    });
    const fetch = fakeFetch({ status: 200, body: '' });
    await expectRejectCode(downloadAttachment(pointer, { fetch: fetch as AttachmentFetchFn }), 'BAD_POINTER');
    expect(fetch).not.toHaveBeenCalled();
  });

  it('requires key and size, as desktop does', async () => {
    const { pointer } = await uploadedPointer(Buffer.from('x'));
    const fetch = fakeFetch({ status: 200, body: '' });
    await expectRejectCode(
      downloadAttachment({ ...pointer, key: undefined }, { fetch: fetch as AttachmentFetchFn }),
      'MISSING_KEY'
    );
    await expectRejectCode(
      downloadAttachment({ ...pointer, size: 0 }, { fetch: fetch as AttachmentFetchFn }),
      'MISSING_SIZE'
    );
    expect(fetch).not.toHaveBeenCalled();
  });

  it('times out', async () => {
    const { pointer } = await uploadedPointer(Buffer.from('x'));
    const fetch = vi.fn(
      (_url: string, init?: any) =>
        new Promise<never>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(new Error('aborted')));
        })
    );
    const err = await expectRejectCode(
      downloadAttachment(pointer, { fetch: fetch as unknown as AttachmentFetchFn, timeoutMs: 20 }),
      'DOWNLOAD_FAILED'
    );
    expect(err.message).toMatch(/timed out/);
  });

  it('enforces maxBytes', async () => {
    const { pointer, blob } = await uploadedPointer(Buffer.from('x'));
    const fetch = fakeFetch({ status: 200, body: blob, contentType: 'application/octet-stream' });
    await expectRejectCode(
      downloadAttachment(pointer, { fetch: fetch as AttachmentFetchFn, maxBytes: 100 }),
      'TOO_LARGE'
    );
  });

  it('sends requests to an overridden server even for default-host pointers', async () => {
    const { pointer, blob } = await uploadedPointer(Buffer.from('mirror'));
    const fetch = fakeFetch({
      status: 200,
      body: JSON.stringify({ status_code: 200, result: Buffer.from(blob).toString('base64') }),
    });
    await downloadAttachment(pointer, {
      fetch: fetch as AttachmentFetchFn,
      fileServerUrl: 'http://files.example.test/',
    });
    expect(fetch.mock.calls[0]![0]).toBe('http://files.example.test/files/12345');
  });
});

describe('resolveAttachmentFileId', () => {
  it('prefers the pointer id, as desktop does', () => {
    expect(resolveAttachmentFileId({ id: '777', url: 'http://fs1.rpcnode.stream/files/12345' })).toBe('777');
  });
  it('falls back to the id in a full file-server url', () => {
    expect(resolveAttachmentFileId({ url: 'http://fs1.rpcnode.stream/files/12345' })).toBe('12345');
    expect(resolveAttachmentFileId({ id: '0', url: 'http://fs1.rpcnode.stream/files/9' })).toBe('9');
  });
  it('accepts a bare id as the url', () => {
    expect(resolveAttachmentFileId({ url: '4242' })).toBe('4242');
  });
  it('rejects path tricks and empty pointers', () => {
    expectCode(() => resolveAttachmentFileId({ url: '../../etc/passwd' }), 'BAD_POINTER');
    expectCode(() => resolveAttachmentFileId({ url: 'http://fs1.rpcnode.stream/other/1' }), 'BAD_POINTER');
    expectCode(() => resolveAttachmentFileId({}), 'BAD_POINTER');
  });
});

// ----------------------------------------------------------------------- SDK

describe('BchatSDK.downloadAttachment', () => {
  it('uses the SDK-level file server and attachment fetch', async () => {
    const { pointer, blob } = await uploadedPointer(Buffer.from('via sdk'));
    const attachmentFetch = fakeFetch({
      status: 200,
      body: JSON.stringify({ status_code: 200, result: Buffer.from(blob).toString('base64') }),
    });
    const sdk = new BchatSDK({
      seedNodes: ['https://seed.invalid/'],
      fileServerUrl: 'http://files.test',
      attachmentFetch: attachmentFetch as AttachmentFetchFn,
    });
    const out = await sdk.downloadAttachment(pointer);
    expect(Buffer.from(out).toString()).toBe('via sdk');
    expect(attachmentFetch.mock.calls[0]![0]).toBe('http://files.test/files/12345');
  });
});
