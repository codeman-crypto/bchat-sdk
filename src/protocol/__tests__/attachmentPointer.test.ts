import { describe, it, expect } from 'vitest';
import { Buffer } from 'buffer';
import { decodeAttachmentPointer, decodeContent } from '../wire';
import { redactAttachment } from '../../attachments/index';

/**
 * A Content{dataMessage{attachments[0]}} encoded by `protoc --encode=signalservice.Content`
 * against bchat-desktop's protos/SignalService.proto, from this text proto:
 *
 *   dataMessage { attachments { id: 12345 contentType: "audio/aac" key: <bytes 0x00..0x3f>
 *     size: 1234 digest: <bytes 0xa0..0xbf> fileName: "voice.m4a" flags: 1
 *     url: "http://fs1.rpcnode.stream/files/12345" } timestamp: 1767000000000 }
 */
const PROTOC_CONTENT_FIXTURE =
  '0aba0112b0010939300000000000001209617564696f2f6161631a40000102030405060708090a0b0c0d0e0f' +
  '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b' +
  '3c3d3e3f20d2093220a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf3a0976' +
  '6f6963652e6d34614001aa0625687474703a2f2f6673312e7270636e6f64652e73747265616d2f66696c6573' +
  '2f313233343538808ca1cbb633';

const range = (from: number, to: number) => Array.from({ length: to - from }, (_, i) => from + i);

describe('decodeAttachmentPointer keeps key and digest', () => {
  it('from a protoc-encoded Content', () => {
    const fixture = new Uint8Array(Buffer.from(PROTOC_CONTENT_FIXTURE, 'hex'));
    const content = decodeContent(fixture);
    expect(content.kind).toBe('message');
    const [a] = content.dataMessage!.attachments!;
    expect(a).toMatchObject({
      id: '12345',
      contentType: 'audio/aac',
      size: 1234,
      fileName: 'voice.m4a',
      url: 'http://fs1.rpcnode.stream/files/12345',
      isVoiceMessage: true,
    });
    expect(Array.from(a!.key!)).toEqual(range(0, 64));
    expect(Array.from(a!.digest!)).toEqual(range(0xa0, 0xc0));

    // the key is a copy, not a view into the (reusable) input buffer
    fixture.fill(0);
    expect(Array.from(a!.key!)).toEqual(range(0, 64));
  });

  it('leaves key and digest undefined when absent', () => {
    // AttachmentPointer { contentType: "a/b" }
    const a = decodeAttachmentPointer(Uint8Array.from([0x12, 0x03, 0x61, 0x2f, 0x62]));
    expect(a.key).toBeUndefined();
    expect(a.digest).toBeUndefined();
  });

  it('redactAttachment hides the key from logs', () => {
    const a = decodeContent(Buffer.from(PROTOC_CONTENT_FIXTURE, 'hex')).dataMessage!.attachments![0]!;
    const redacted = redactAttachment(a);
    expect(redacted.key).toBe('[redacted]');
    expect(redacted.digest).toBe(Buffer.from(range(0xa0, 0xc0)).toString('hex'));
    const json = JSON.stringify(redacted);
    expect(json).not.toContain(Buffer.from(range(0, 64)).toString('hex'));
    expect(json).not.toContain('"0":0');
    expect(a.key).toBeInstanceOf(Uint8Array); // the original is untouched
  });
});

