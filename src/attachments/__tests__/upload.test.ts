import { describe, expect, it } from 'vitest';
import { Buffer } from 'buffer';
import {
  AttachmentError,
  decryptAttachment,
  encryptAttachment,
  paddedAttachmentSize,
  uploadAttachment,
  type AttachmentUploadFetchFn,
} from '../index.js';
import {
  decodeDataMessage,
  encodeAttachmentPointer,
  encodeDataMessage,
  decodeAttachmentPointer,
} from '../../protocol/wire.js';

/** A file server that stores what it is sent and answers from a script. */
function fakeServer(script: Array<{ status: number; body: string } | Error>) {
  const calls: Array<{ url: string; blob: Uint8Array }> = [];
  const fetch: AttachmentUploadFetchFn = async (url, init) => {
    calls.push({ url, blob: new Uint8Array(Buffer.from(JSON.parse(init.body).file, 'base64')) });
    const step = script.shift() ?? { status: 200, body: '{"result":7,"status_code":200}' };
    if (step instanceof Error) throw step;
    return { status: step.status, text: async () => step.body };
  };
  return { fetch, calls };
}

describe('encryptAttachment', () => {
  it('round-trips through decryptAttachment', () => {
    const plain = new Uint8Array(1234).map((_, i) => i % 251);
    const enc = encryptAttachment(plain);
    const out = decryptAttachment(enc.blob, enc.key, enc.digest, enc.size);
    expect(Buffer.from(out).equals(Buffer.from(plain))).toBe(true);
    expect(enc.size).toBe(plain.length);
    expect(enc.key.length).toBe(64);
  });

  it('pads to the size buckets the apps use and uses a fresh key each time', () => {
    expect(paddedAttachmentSize(1)).toBe(541);
    expect(paddedAttachmentSize(100_000)).toBeGreaterThanOrEqual(100_000);
    const a = encryptAttachment(new Uint8Array(10));
    const b = encryptAttachment(new Uint8Array(10));
    // IV(16) + padded plaintext rounded up to an AES block + HMAC(32)
    expect(a.blob.length).toBe(16 + (Math.floor(541 / 16) + 1) * 16 + 32);
    expect(Buffer.from(a.key).equals(Buffer.from(b.key))).toBe(false);
  });
});

describe('uploadAttachment', () => {
  it('uploads the encrypted blob and returns a pointer that opens it', async () => {
    const server = fakeServer([{ status: 200, body: '{"result": 6067465816148571, "status_code": 200}' }]);
    const data = new Uint8Array(Buffer.from('hello voice'));
    const pointer = await uploadAttachment(
      { data, contentType: 'audio/aac', isVoiceMessage: true },
      { fetch: server.fetch, fileServerUrl: 'http://fs.test/' }
    );
    expect(server.calls[0]!.url).toBe('http://fs.test/files');
    expect(pointer.id).toBe('6067465816148571');
    expect(pointer.url).toBe('http://fs.test/files/6067465816148571');
    expect(pointer.isVoiceMessage).toBe(true);
    const out = decryptAttachment(server.calls[0]!.blob, pointer.key!, pointer.digest, pointer.size);
    expect(Buffer.from(out).toString()).toBe('hello voice');
  });

  it('keeps a file id above 2^53 exact', async () => {
    const server = fakeServer([{ status: 200, body: '{"result":18446744073709551615,"status_code":200}' }]);
    const pointer = await uploadAttachment(
      { data: new Uint8Array(3), contentType: 'image/png' },
      { fetch: server.fetch }
    );
    expect(pointer.id).toBe('18446744073709551615');
  });

  it('tries again after a server error and after a failed request', async () => {
    const server = fakeServer([{ status: 500, body: 'oops' }, new Error('reset')]);
    const pointer = await uploadAttachment(
      { data: new Uint8Array(3), contentType: 'image/png' },
      { fetch: server.fetch, retries: 2 }
    );
    expect(pointer.id).toBe('7');
    expect(server.calls.length).toBe(3);
  }, 15_000);

  it('does not retry a refusal', async () => {
    const server = fakeServer([{ status: 413, body: '{"status_code":413}' }]);
    await expect(
      uploadAttachment({ data: new Uint8Array(3), contentType: 'image/png' }, { fetch: server.fetch })
    ).rejects.toMatchObject({ code: 'UPLOAD_FAILED', status: 413 });
    expect(server.calls.length).toBe(1);
  });

  it('refuses empty, oversized and untyped files before any request', async () => {
    const server = fakeServer([]);
    const opts = { fetch: server.fetch };
    await expect(uploadAttachment({ data: new Uint8Array(0), contentType: 'a/b' }, opts)).rejects.toBeInstanceOf(AttachmentError);
    await expect(uploadAttachment({ data: new Uint8Array(11), contentType: 'a/b' }, { ...opts, maxBytes: 10 })).rejects.toMatchObject({ code: 'TOO_LARGE' });
    await expect(uploadAttachment({ data: new Uint8Array(3), contentType: '' }, opts)).rejects.toBeInstanceOf(AttachmentError);
    expect(server.calls.length).toBe(0);
  });
});

describe('attachment pointers on the wire', () => {
  const pointer = {
    id: '18446744073709551615',
    contentType: 'audio/aac',
    key: new Uint8Array(64).fill(1),
    size: 4321,
    digest: new Uint8Array(32).fill(2),
    isVoiceMessage: true,
    url: 'http://fs1.rpcnode.stream/files/18446744073709551615',
  };

  it('encodes a pointer that decodes to the same fields', () => {
    const back = decodeAttachmentPointer(encodeAttachmentPointer(pointer).finish());
    expect(back).toMatchObject({ id: pointer.id, contentType: 'audio/aac', size: 4321, isVoiceMessage: true, url: pointer.url });
    expect(Buffer.from(back.key!).equals(Buffer.from(pointer.key))).toBe(true);
    expect(Buffer.from(back.digest!).equals(Buffer.from(pointer.digest))).toBe(true);
  });

  it('carries attachments in a data message with no body', () => {
    const back = decodeDataMessage(encodeDataMessage({ attachments: [pointer], timestamp: 1 } as any).finish());
    expect(back.body ?? '').toBe('');
    expect(back.attachments?.length).toBe(1);
    expect(back.attachments![0]!.id).toBe(pointer.id);
  });
});
