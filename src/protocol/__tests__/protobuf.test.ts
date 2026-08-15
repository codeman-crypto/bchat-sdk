import { describe, it, expect } from 'vitest';
import { ProtoWriter, decodeFields, firstString, firstNumber, firstBytes } from '../protobuf';
import { encodeContent, decodeContent, encodeEnvelope, decodeEnvelope, wrapEnvelope, unwrapEnvelope, EnvelopeType } from '../wire';

describe('protobuf codec', () => {
  it('encodes varints and strings the way protobuf specifies', () => {
    // field 1, wire 2, len 5, "hello"  ->  0x0a 0x05 h e l l o
    const bytes = new ProtoWriter().string(1, 'hello').finish();
    expect(Array.from(bytes)).toEqual([0x0a, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f]);
  });

  it('encodes multi-byte varints correctly', () => {
    // field 5, wire 0, value 300 -> 0x28 0xac 0x02
    expect(Array.from(new ProtoWriter().uint(5, 300).finish())).toEqual([0x28, 0xac, 0x02]);
  });

  it('handles millisecond timestamps beyond 32 bits', () => {
    const ts = 1_767_000_000_000;
    expect(firstNumber(decodeFields(new ProtoWriter().uint(5, ts).finish()), 5)).toBe(ts);
  });

  it('omits undefined optional fields', () => {
    expect(new ProtoWriter().string(1, undefined).uint(2, undefined).finish()).toHaveLength(0);
  });

  it('rejects truncated input rather than returning junk', () => {
    expect(() => decodeFields(Uint8Array.from([0x0a, 0x05, 0x68]))).toThrow(/truncated/);
  });

  it('round-trips a Content with a DataMessage', () => {
    const encoded = encodeContent({ body: 'hi there', timestamp: 1_767_000_000_001 });
    const decoded = decodeContent(encoded);
    expect(decoded.dataMessage?.body).toBe('hi there');
    expect(decoded.dataMessage?.timestamp).toBe(1_767_000_000_001);
  });

  it('round-trips an Envelope through the WebSocketMessage wrapper', () => {
    const content = Uint8Array.from([1, 2, 3, 4]);
    const envelope = encodeEnvelope({
      type: EnvelopeType.BCHAT_MESSAGE,
      timestamp: 1_767_000_000_002,
      content,
    });

    const wrapped = wrapEnvelope(envelope);
    // the wrapper must actually wrap
    expect(wrapped).not.toEqual(envelope);

    const decoded = decodeEnvelope(unwrapEnvelope(wrapped));
    expect(decoded.type).toBe(EnvelopeType.BCHAT_MESSAGE);
    expect(decoded.timestamp).toBe(1_767_000_000_002);
    expect(Array.from(decoded.content!)).toEqual([1, 2, 3, 4]);
  });

  it('accepts a bare Envelope that was never wrapped', () => {
    const envelope = encodeEnvelope({ type: EnvelopeType.BCHAT_MESSAGE, timestamp: 1, content: Uint8Array.from([7]) });
    expect(Array.from(decodeEnvelope(unwrapEnvelope(envelope)).content!)).toEqual([7]);
  });

  it('puts the wrapper request at verb PUT /api/v1/message', () => {
    const wrapped = wrapEnvelope(Uint8Array.from([1]));
    const request = firstBytes(decodeFields(wrapped), 2)!;
    const fields = decodeFields(request);
    expect(firstString(fields, 1)).toBe('PUT');
    expect(firstString(fields, 2)).toBe('/api/v1/message');
  });
});
