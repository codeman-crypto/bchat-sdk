import { describe, it, expect, vi } from 'vitest';
import sodium from 'libsodium-wrappers-sumo';
import { Buffer } from 'buffer';
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

  it('sendMessage resolves a BNS name to the tagged BChat ID and caches it', async () => {
    await sodium.ready;
    const bchatId = 'bd' + 'ab'.repeat(32);

    // Encrypt the ID exactly as the BNS contract does (modern scheme). The
    // registered string includes the .bdx suffix, as bchat-desktop hashes it.
    const nameAsData = Buffer.from('codeman.bdx', 'utf8');
    const nameHash = sodium.crypto_generichash(32, nameAsData);
    const key = sodium.crypto_generichash(32, nameAsData, nameHash);
    const nonce = sodium.randombytes_buf(24);
    const record = {
      encrypted_value: Buffer.from(
        sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
          Buffer.from(bchatId, 'hex'),
          null,
          null,
          nonce,
          key
        )
      ).toString('hex'),
      nonce: Buffer.from(nonce).toString('hex'),
    };

    const response = (body: unknown) => ({
      status: 200,
      headers: { get: () => 'application/json' },
      json: async () => body,
      text: async () => JSON.stringify(body),
    });

    const fetch = vi
      .fn()
      .mockResolvedValueOnce(response(seedPayload)) // seed pool
      .mockResolvedValueOnce(response({ result: record })) // bns_resolve
      .mockResolvedValueOnce(response(swarmPayload)) // recipient swarm
      .mockResolvedValueOnce(response({ hash: 'stored123' })); // store

    const sdk = new BchatSDK({ seedNodes: ['https://seed/'], fetch });
    const hash = await sdk.sendMessage({ recipientPubKey: 'Codeman.bdx', payload: 'hi' });
    expect(hash).toBe('stored123');

    // the swarm lookup and store must target the *resolved* ID, not the name
    const swarmBody = JSON.parse((fetch.mock.calls[2] as any)[1].body);
    expect(swarmBody.params.pubKey).toBe(bchatId);

    // second resolution comes from the cache: no extra bns_resolve round trip
    await expect(sdk.resolveBnsName('codeman')).resolves.toBe(bchatId);
    expect(fetch).toHaveBeenCalledTimes(4);
  });
});
