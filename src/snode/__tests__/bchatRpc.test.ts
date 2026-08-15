import { describe, it, expect, vi } from 'vitest';
import { BchatRpc } from '../bchatRpc';

const target = { ip: '1.1.1.1', port: 80, pubkey_x25519: 'x', pubkey_ed25519: 'e' };
const silent = { info: () => {}, warn: () => {}, error: () => {} };

describe('BchatRpc', () => {
  it('does not retry 4xx responses', async () => {
    const fetch = vi.fn(async () => ({
      status: 400,
      headers: { get: () => 'application/json' },
      json: async () => ({}),
      text: async () => '',
    }));

    const rpc = new BchatRpc(fetch as any, silent, 1_000);
    await expect(rpc.call({ method: 'store', params: {}, targetNode: target })).rejects.toThrow(
      /status 400/
    );
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('retries 5xx responses', async () => {
    const fetch = vi.fn(async () => ({
      status: 503,
      headers: { get: () => 'application/json' },
      json: async () => ({}),
      text: async () => '',
    }));

    const rpc = new BchatRpc(fetch as any, silent, 50);
    await expect(rpc.call({ method: 'store', params: {}, targetNode: target })).rejects.toThrow(
      /status 503/
    );
    expect(fetch).toHaveBeenCalledTimes(3);
  });
});

describe('BchatRpc self-signed handling', () => {
  const certError = () => {
    throw new Error('self-signed certificate in certificate chain');
  };

  const ok = {
    status: 200,
    headers: { get: () => 'application/json' },
    json: async () => ({}),
    text: async () => '{}',
  };

  it('probes strict TLS once per node, then goes straight to the insecure agent', async () => {
    let strictAttempts = 0;
    const fetch = vi.fn(async (_url: string, init: any) => {
      // node-fetch is handed `agent: undefined` for the strict attempt
      if (!init.agent) {
        strictAttempts++;
        certError();
      }
      return ok;
    });

    const warnings: string[] = [];
    const rpc = new BchatRpc(fetch as any, { ...silent, warn: m => warnings.push(String(m)) }, 1_000);

    for (let i = 0; i < 5; i++) {
      await rpc.call({ method: 'retrieve', params: {}, targetNode: target });
    }

    expect(strictAttempts).toBe(1);
    expect(warnings.filter(w => w.includes('self-signed'))).toHaveLength(1);
  });

  it('keeps probing a different node independently', async () => {
    const strictHosts: string[] = [];
    const fetch = vi.fn(async (url: string, init: any) => {
      if (!init.agent) {
        strictHosts.push(url);
        certError();
      }
      return ok;
    });

    const rpc = new BchatRpc(fetch as any, silent, 1_000);
    await rpc.call({ method: 'retrieve', params: {}, targetNode: target });
    await rpc.call({
      method: 'retrieve',
      params: {},
      targetNode: { ...target, ip: '9.9.9.9' },
    });
    await rpc.call({ method: 'retrieve', params: {}, targetNode: target });

    expect(strictHosts).toHaveLength(2);
  });
});
