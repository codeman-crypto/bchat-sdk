import { describe, it, expect, vi } from 'vitest';
import { SeedNodeClient } from '../SeedNodeClient';

const dummySeed = 'https://seed.example/';

const makeFetch = (payload: any, status = 200) =>
  vi.fn(async () => ({
    status,
    headers: { get: () => 'application/json' },
    json: async () => payload,
    text: async () => JSON.stringify(payload),
  }));

describe('SeedNodeClient', () => {
  it('returns shuffled, filtered snodes', async () => {
    const fetch = makeFetch({
      result: {
        master_node_states: [
          { public_ip: '0.0.0.0', storage_port: 1, pubkey_x25519: 'x', pubkey_ed25519: 'e' },
          { public_ip: '1.2.3.4', storage_port: 2, pubkey_x25519: 'x2', pubkey_ed25519: 'e2' },
        ],
      },
    });

    const client = new SeedNodeClient({ seedNodes: [dummySeed], fetch });
    const result = await client.fetchSnodePool();

    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({ ip: '1.2.3.4', port: 2 });
  });

  it('throws on non-200', async () => {
    const fetch = makeFetch({}, 500);
    const client = new SeedNodeClient({ seedNodes: [dummySeed], fetch });
    await expect(client.fetchSnodePool()).rejects.toThrow();
  });
});

describe('seed TLS is independent of the storage-node opt-in', () => {
  it('keeps verifying seed certificates when only storage nodes are exempted', () => {
    const client = new SeedNodeClient({
      seedNodes: [dummySeed],
      fetch: makeFetch({}),
      allowSelfSignedStorageNodes: true,
    } as any);

    // the seed agent must still verify
    expect((client as any).agent.options.rejectUnauthorized).toBe(true);
  });

  it('only insecureTls disables seed verification', () => {
    const client = new SeedNodeClient({
      seedNodes: [dummySeed],
      fetch: makeFetch({}),
      insecureTls: true,
    } as any);
    expect((client as any).agent.options.rejectUnauthorized).toBe(false);
  });
});
