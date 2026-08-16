import { describe, it, expect, vi } from 'vitest';
import { SnodeClient } from '../SnodeClient';

const samplePool = [
  { ip: '1.1.1.1', port: 80, pubkey_x25519: 'x', pubkey_ed25519: 'e' },
  { ip: '2.2.2.2', port: 80, pubkey_x25519: 'x2', pubkey_ed25519: 'e2' },
];

describe('SnodeClient', () => {
  it('returns swarm nodes', async () => {
    const fetch = vi.fn(async () => ({
      status: 200,
      headers: { get: () => 'application/json' },
      json: async () => ({}),
      text: async () =>
        JSON.stringify({
          mnodes: [{ ip: '9.9.9.9', port: 220, pubkey_x25519: 'a', pubkey_ed25519: 'b' }],
        }),
    }));

    const client = new SnodeClient(async () => samplePool, fetch, console);
    const nodes = await client.getSnodesForPubkey('abc');
    expect(nodes[0].ip).toBe('9.9.9.9');
  });

  it('throws if empty pool', async () => {
    const fetch = vi.fn();
    const client = new SnodeClient(async () => [], fetch, console);
    await expect(client.getSnodesForPubkey('abc')).rejects.toThrow('No snodes available');
  });

  it('stores message on a snode and returns hash', async () => {
    const fetch = vi
      .fn()
      // swarm
      .mockResolvedValueOnce({
        status: 200,
        headers: { get: () => 'application/json' },
        json: async () => ({}),
        text: async () =>
          JSON.stringify({
            mnodes: [{ ip: '1.1.1.1', port: 80, pubkey_x25519: 'x', pubkey_ed25519: 'e' }],
          }),
      })
      // store
      .mockResolvedValueOnce({
        status: 200,
        headers: { get: () => 'application/json' },
        json: async () => ({ hash: 'abc123' }),
        text: async () => JSON.stringify({ hash: 'abc123' }),
      });

    const client = new SnodeClient(async () => samplePool, fetch, console);
    const hash = await client.storeMessage({
      recipientPubKey: '0500',
      payload: 'hi',
    });
    expect(hash).toBe('abc123');
  });

  it('retrieves messages from a snode', async () => {
    const fetch = vi
      .fn()
      // swarm
      .mockResolvedValueOnce({
        status: 200,
        headers: { get: () => 'application/json' },
        json: async () => ({}),
        text: async () =>
          JSON.stringify({
            mnodes: [{ ip: '1.1.1.1', port: 80, pubkey_x25519: 'x', pubkey_ed25519: 'e' }],
          }),
      })
      // retrieve
      .mockResolvedValueOnce({
        status: 200,
        headers: { get: () => 'application/json' },
        json: async () => ({ messages: [{ body: 'hello' }] }),
        text: async () => JSON.stringify({ messages: [{ body: 'hello' }] }),
      });

    const client = new SnodeClient(async () => samplePool, fetch, console);
    const msgs = await client.retrieveMessages({ pubKey: '0500' });
    expect(msgs[0].body).toBe('hello');
  });
});

describe('SnodeClient regressions', () => {
  it('stops retrying once the snode pool is exhausted', async () => {
    const fetch = vi.fn(async () => ({
      status: 200,
      headers: { get: () => 'application/json' },
      json: async () => ({}),
      text: async () => JSON.stringify({ mnodes: [] }), // always an empty swarm
    }));

    const silent = { info: () => {}, warn: () => {}, error: () => {} };
    const client = new SnodeClient(async () => samplePool, fetch, silent);

    // one attempt per pool member, then abort -- not a full backoff cycle
    await expect(client.getSnodesForPubkey('abc')).rejects.toThrow('Empty swarm');
    expect(fetch).toHaveBeenCalledTimes(samplePool.length);
  });

  it('surfaces a non-JSON snode body as a clear error', async () => {
    const fetch = vi.fn(async () => ({
      status: 200,
      headers: { get: () => 'text/html' },
      json: async () => ({}),
      text: async () => '<html>502 Bad Gateway</html>',
    }));

    const silent = { info: () => {}, warn: () => {}, error: () => {} };
    const client = new SnodeClient(async () => samplePool, fetch, silent);
    await expect(client.getSnodesForPubkey('abc')).rejects.toThrow(/non-JSON/);
  });

  it('persists messages and the cursor even without account keys', async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce({
        status: 200,
        headers: { get: () => 'application/json' },
        json: async () => ({}),
        text: async () =>
          JSON.stringify({
            mnodes: [{ ip: '1.1.1.1', port: 80, pubkey_x25519: 'x', pubkey_ed25519: 'e' }],
          }),
      })
      .mockResolvedValueOnce({
        status: 200,
        headers: { get: () => 'application/json' },
        json: async () => ({}),
        text: async () => JSON.stringify({ messages: [{ hash: 'h1', data: 'aGk=' }] }),
      });

    const saved: Record<string, any> = { messages: [] };
    const persistence = {
      saveLastHash: async (_k: string, h: string) => {
        saved.lastHash = h;
      },
      getLastHash: async () => undefined,
      appendMessages: async (_k: string, m: any[]) => {
        saved.messages.push(...m);
      },
      listMessages: async () => saved.messages,
    };

    const client = new SnodeClient(async () => samplePool, fetch, console, 10_000, {
      persistence,
    });
    await client.retrieveMessages({ pubKey: '0500' });

    expect(saved.messages).toHaveLength(1);
    expect(saved.lastHash).toBe('h1');
  });
});

describe('SnodeClient retrieval pinning', () => {
  const silent = { info: () => {}, warn: () => {}, error: () => {} };
  const swarmNodes = [
    { ip: '1.1.1.1', port: 80, pubkey_x25519: 'x', pubkey_ed25519: 'e' },
    { ip: '2.2.2.2', port: 80, pubkey_x25519: 'x2', pubkey_ed25519: 'e2' },
    { ip: '3.3.3.3', port: 80, pubkey_x25519: 'x3', pubkey_ed25519: 'e3' },
  ];

  const ok = (body: string) => ({
    status: 200,
    headers: { get: () => 'application/json' },
    json: async () => JSON.parse(body),
    text: async () => body,
  });

  const makeFetch = (calls: Array<{ url: string; method: string }>, messages: any[]) =>
    vi.fn(async (url: string, init: any) => {
      const method = JSON.parse(init.body).method;
      calls.push({ url, method });
      if (method === 'get_mnodes_for_pubkey') return ok(JSON.stringify({ mnodes: swarmNodes }));
      return ok(JSON.stringify({ messages }));
    });

  it('talks to the same swarm member across polls', async () => {
    const calls: Array<{ url: string; method: string }> = [];
    const fetch = makeFetch(calls, [{ hash: 'h1', data: 'aGk=' }]);
    const client = new SnodeClient(async () => samplePool, fetch as any, silent);

    await client.retrieveMessages({ pubKey: 'bd00' });
    await client.retrieveMessages({ pubKey: 'bd00' });
    await client.retrieveMessages({ pubKey: 'bd00' });

    const retrieveHosts = calls.filter(c => c.method === 'retrieve').map(c => c.url);
    expect(retrieveHosts).toHaveLength(3);
    expect(new Set(retrieveHosts).size).toBe(1);
  });

  it('resolves the swarm once and serves later polls from cache', async () => {
    const calls: Array<{ url: string; method: string }> = [];
    const fetch = makeFetch(calls, []);
    const client = new SnodeClient(async () => samplePool, fetch as any, silent);

    await client.retrieveMessages({ pubKey: 'bd00' });
    await client.retrieveMessages({ pubKey: 'bd00' });

    expect(calls.filter(c => c.method === 'get_mnodes_for_pubkey')).toHaveLength(1);
  });

  it('never hands the same message to the caller twice', async () => {
    const calls: Array<{ url: string; method: string }> = [];
    // A node that ignores lastHash and always replays the whole mailbox.
    // Distinct payloads: real sealed boxes never repeat, because each carries a
    // fresh ephemeral key and timestamp.
    const fetch = makeFetch(calls, [
      { hash: 'h1', data: 'aGkx' },
      { hash: 'h2', data: 'aGky' },
    ]);
    const client = new SnodeClient(async () => samplePool, fetch as any, silent);

    const first = await client.retrieveMessages({ pubKey: 'bd00' });
    const second = await client.retrieveMessages({ pubKey: 'bd00' });

    expect(first.map((m: any) => m.hash)).toEqual(['h1', 'h2']);
    expect(second).toEqual([]);
  });

  it('drops a replayed payload even when the node relabels its hash (BCHAT-05/12)', async () => {
    const calls: Array<{ url: string; method: string }> = [];
    let round = 0;
    const fetch = vi.fn(async (url: string, init: any) => {
      const method = JSON.parse(init.body).method;
      calls.push({ url, method });
      if (method === 'get_mnodes_for_pubkey') return ok(JSON.stringify({ mnodes: swarmNodes }));
      // same payload, brand new hash each time
      return ok(JSON.stringify({ messages: [{ hash: `fresh-${++round}`, data: 'c2FtZQ==' }] }));
    });

    const client = new SnodeClient(async () => samplePool, fetch as any, silent);
    expect(await client.retrieveMessages({ pubKey: 'bd00' })).toHaveLength(1);
    expect(await client.retrieveMessages({ pubKey: 'bd00' })).toHaveLength(0);
    expect(await client.retrieveMessages({ pubKey: 'bd00' })).toHaveLength(0);
  });

  it('rotates to another member only when the pinned one is persistently down', async () => {
    const calls: Array<{ url: string; method: string }> = [];
    // BchatRpc retries a node a couple of times before giving up, so the pin is
    // only abandoned when that member is down for good -- not on a blip.
    const fetch = vi.fn(async (url: string, init: any) => {
      const method = JSON.parse(init.body).method;
      calls.push({ url, method });
      if (method === 'get_mnodes_for_pubkey') return ok(JSON.stringify({ mnodes: swarmNodes }));
      if (url.includes('1.1.1.1')) throw new Error('connection reset');
      return ok(JSON.stringify({ messages: [{ hash: 'h9', data: 'aGk=' }] }));
    });

    const client = new SnodeClient(async () => samplePool, fetch as any, silent);
    const messages = await client.retrieveMessages({ pubKey: 'bd00' });

    expect(messages.map((m: any) => m.hash)).toEqual(['h9']);

    const retrieveHosts = calls.filter(c => c.method === 'retrieve').map(c => c.url);
    expect(retrieveHosts.some(u => u.includes('1.1.1.1'))).toBe(true);
    expect(retrieveHosts.at(-1)).toContain('2.2.2.2');

    // the healthy node is now the pin
    calls.length = 0;
    await client.retrieveMessages({ pubKey: 'bd00' });
    expect(calls.filter(c => c.method === 'retrieve').map(c => c.url)).toEqual([
      expect.stringContaining('2.2.2.2'),
    ]);
  });
});
