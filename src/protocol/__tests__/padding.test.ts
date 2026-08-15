import { describe, it, expect } from 'vitest';
import { addMessagePadding, removeMessagePadding } from '../padding';

describe('message padding', () => {
  // Desktop allocates `getPaddedMessageLength(len + 1) - 1`, so a padded buffer
  // is one byte *short* of a 160 multiple. It looks like an off-by-one and it
  // is, but it is the format on the wire, so the port keeps it.
  it('pads to one byte below a multiple of 160', () => {
    for (const size of [0, 1, 100, 158, 159, 160, 161, 400]) {
      const padded = addMessagePadding(new Uint8Array(size).fill(0x41));
      expect((padded.length + 1) % 160).toBe(0);
      expect(padded.length).toBeGreaterThan(size);
    }
    expect(addMessagePadding(new Uint8Array(0)).length).toBe(159);
    expect(addMessagePadding(new Uint8Array(158)).length).toBe(159);
    expect(addMessagePadding(new Uint8Array(159)).length).toBe(319);
  });

  it('writes the 0x80 terminator immediately after the payload', () => {
    const body = new Uint8Array([1, 2, 3]);
    const padded = addMessagePadding(body);
    expect(padded[3]).toBe(0x80);
    expect(padded.slice(4).every(b => b === 0)).toBe(true);
  });

  it('round-trips arbitrary payloads', () => {
    for (const size of [0, 1, 159, 160, 161, 1000]) {
      const body = Uint8Array.from({ length: size }, (_, i) => (i % 255) + 1);
      expect(Array.from(removeMessagePadding(addMessagePadding(body)))).toEqual(Array.from(body));
    }
  });

  it('passes through payloads that were never padded', () => {
    const raw = new Uint8Array([9, 9, 9]);
    expect(Array.from(removeMessagePadding(raw))).toEqual([9, 9, 9]);
  });

  it('throws on an all-zero buffer, which carries no terminator', () => {
    expect(() => removeMessagePadding(new Uint8Array(16))).toThrow('Invalid padding');
  });
});
