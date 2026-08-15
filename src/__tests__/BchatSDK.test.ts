import { describe, it, expect, vi } from 'vitest';
import { BchatSDK } from '../BchatSDK';

const seedPayload = {
  result: {
    master_node_states: [
      { public_ip: '1.2.3.4', storage_port: 443, pubkey_x25519: 'x', pubkey_ed25519: 'e' },
    ],
  },
};

const swarmPayload = {
  mnodes: [
    { ip: '1.2.3.4', port: 443, pubkey_x25519: 'x', pubkey_ed25519: 'e' },
  ],
};

describe('BchatSDK', () => {
  it('refreshes pool then queries swarm', async () => {
    const fetch = vi
      .fn()
      // seed fetch
      .mockResolvedValueOnce({
        status: 200,
        headers: { get: () => 'application/json' },
        json: async () => seedPayload,
        text: async () => JSON.stringify(seedPayload),
      })
      // snode fetch
      .mockResolvedValueOnce({
        status: 200,
        headers: { get: () => 'application/json' },
        text: async () => JSON.stringify(swarmPayload),
      });

    const sdk = new BchatSDK({ seedNodes: ['https://seed/'], fetch });
    const pool = await sdk.refreshSnodePool();
    expect(pool).toHaveLength(1);
    const swarm = await sdk.getSwarm('abcd');
    expect(swarm[0].ip).toBe('1.2.3.4');
  });
});
