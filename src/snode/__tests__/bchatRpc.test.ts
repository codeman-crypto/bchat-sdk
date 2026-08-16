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

describe('BchatRpc TLS policy (BCHAT-01)', () => {
  const certError = () => {
    const e: any = new Error('self-signed certificate in certificate chain');
    e.code = 'DEPTH_ZERO_SELF_SIGNED_CERT';
    throw e;
  };

  const ok = {
    status: 200,
    headers: { get: () => 'application/json' },
    json: async () => ({}),
    text: async () => '{}',
  };

  it('rejects a self-signed certificate when insecureTls is unset', async () => {
    const fetch = vi.fn(async () => certError());
    const rpc = new BchatRpc(fetch as any, silent, 1_000);

    await expect(
      rpc.call({ method: 'retrieve', params: {}, targetNode: target })
    ).rejects.toThrow(/certificate could not be verified/);

    // no silent second attempt with verification disabled
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('never issues a request with rejectUnauthorized disabled by default', async () => {
    const agents: any[] = [];
    const fetch = vi.fn(async (_url: string, init: any) => {
      agents.push(init.agent);
      return certError();
    });

    const rpc = new BchatRpc(fetch as any, silent, 1_000);
    await rpc.call({ method: 'retrieve', params: {}, targetNode: target }).catch(() => undefined);

    expect(agents).toHaveLength(1);
    expect(agents[0]?.options?.rejectUnauthorized).toBe(true);
  });

  it('uses an unverified agent only when the caller opts in', async () => {
    const agents: any[] = [];
    const fetch = vi.fn(async (_url: string, init: any) => {
      agents.push(init.agent);
      return ok;
    });

    const rpc = new BchatRpc(fetch as any, silent, 1_000, { insecureTls: true });
    await rpc.call({ method: 'retrieve', params: {}, targetNode: target });

    expect(agents[0]?.options?.rejectUnauthorized).toBe(false);
  });

  it('sets redirect:error and a response size cap on every request', async () => {
    let init: any;
    const fetch = vi.fn(async (_url: string, i: any) => {
      init = i;
      return ok;
    });

    const rpc = new BchatRpc(fetch as any, silent, 1_000);
    await rpc.call({ method: 'retrieve', params: {}, targetNode: target });

    expect(init.redirect).toBe('error');
    expect(init.size).toBeGreaterThan(0);
  });
});
