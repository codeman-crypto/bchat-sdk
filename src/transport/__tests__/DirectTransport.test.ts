import { describe, it, expect, vi } from 'vitest';
import { DirectTransport } from '../DirectTransport';

const target = { ip: '1.1.1.1', port: 80, pubkey_x25519: 'x', pubkey_ed25519: 'e' };

describe('DirectTransport', () => {
  it('base64-encodes a string payload', async () => {
    // vitest 4 takes the full function signature as a single type argument.
    const call = vi.fn<(args: any) => Promise<{ status: number; body: string }>>(async () => ({
      status: 200,
      body: '{}',
    }));
    const transport = new DirectTransport({ call } as any);

    await transport.store({ recipientPubKey: 'pk', payload: 'hello' }, target);

    expect(call.mock.calls[0]![0].params.data).toBe(Buffer.from('hello').toString('base64'));
  });

  it('base64-encodes a byte payload identically', async () => {
    // vitest 4 takes the full function signature as a single type argument.
    const call = vi.fn<(args: any) => Promise<{ status: number; body: string }>>(async () => ({
      status: 200,
      body: '{}',
    }));
    const transport = new DirectTransport({ call } as any);

    await transport.store(
      { recipientPubKey: 'pk', payload: new Uint8Array([104, 105]) },
      target
    );

    expect(call.mock.calls[0]![0].params.data).toBe(Buffer.from('hi').toString('base64'));
  });
});
