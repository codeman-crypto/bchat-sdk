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

describe('SnodeClient swarm validation', () => {
  const json = (body: unknown) => ({
    status: 200,
    headers: { get: () => 'application/json' },
    json: async () => body,
    text: async () => JSON.stringify(body),
  });
  const node = (n: number, swarm?: string) => ({
    ip: `8.8.${n}.${n}`,
    port: 443,
    pubkey_x25519: `x${n}`,
    pubkey_ed25519: `e${n}`,
    ...(swarm ? { swarm_id: swarm } : {}),
  });
  const quiet = { info: () => {}, warn: () => {}, error: () => {} };

  it('rejects an answer whose members sit in different swarms and asks another node', async () => {
    const pool = [node(1, 'A'), node(2, 'A'), node(3, 'B'), node(4, 'C')];
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(json({ mnodes: [node(1), node(3)] }))
      .mockResolvedValueOnce(json({ mnodes: [node(1), node(2)] }));

    const client = new SnodeClient(async () => pool, fetch, quiet);
    const swarm = await client.getSnodesForPubkey('abc');

    expect(fetch).toHaveBeenCalledTimes(2);
    expect(swarm.map(n => n.pubkey_ed25519)).toEqual(['e1', 'e2']);
  });

  it('accepts an answer naming a node the seed list does not know yet', async () => {
    // The pool is fetched once and can be older than the swarm it describes.
    const pool = [node(1, 'A'), node(2, 'A')];
    const fetch = vi.fn().mockResolvedValueOnce(json({ mnodes: [node(1), node(9)] }));

    const client = new SnodeClient(async () => pool, fetch, quiet);
    const swarm = await client.getSnodesForPubkey('abc');

    expect(fetch).toHaveBeenCalledTimes(1);
    expect(swarm.map(n => n.pubkey_ed25519)).toEqual(['e1', 'e9']);
  });

  it('uses the most common answer when a stale pool makes every answer fail the check', async () => {
    // After a rebalance every honest node names the same new swarm, which the
    // stale pool still places in two swarms. Resolution must not fail.
    const pool = [1, 2, 3, 4, 5, 6].map(n => node(n, n <= 3 ? 'A' : 'B'));
    const honest = json({ mnodes: [node(1), node(2), node(4)] });
    const odd = json({ mnodes: [node(3), node(5)] });
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(honest)
      .mockResolvedValueOnce(odd)
      .mockResolvedValueOnce(honest)
      .mockResolvedValueOnce(honest);
    const warn = vi.fn();

    const client = new SnodeClient(async () => pool, fetch, { ...quiet, warn });
    const started = Date.now();
    const swarm = await client.getSnodesForPubkey('abc');

    expect(swarm.map(n => n.pubkey_ed25519)).toEqual(['e1', 'e2', 'e4']);
    expect(fetch).toHaveBeenCalledTimes(4);
    // Set-aside answers are not retried with backoff.
    expect(Date.now() - started).toBeLessThan(200);
    expect(warn.mock.calls.flat().join(' ')).toMatch(/node list may be stale/);
  });

  it('falls back to a set-aside answer when the pool runs out before the limit', async () => {
    const pool = [node(1, 'A'), node(2, 'B')];
    const fetch = vi.fn().mockResolvedValue(json({ mnodes: [node(1), node(2)] }));

    const client = new SnodeClient(async () => pool, fetch, quiet);
    const swarm = await client.getSnodesForPubkey('abc');

    expect(fetch).toHaveBeenCalledTimes(2);
    expect(swarm).toHaveLength(2);
  });

  it('accepts any answer when the pool carries no swarm ids', async () => {
    const pool = [node(1), node(2)];
    const fetch = vi.fn().mockResolvedValueOnce(json({ mnodes: [node(1), node(9)] }));

    const client = new SnodeClient(async () => pool, fetch, quiet);
    const swarm = await client.getSnodesForPubkey('abc');

    expect(fetch).toHaveBeenCalledTimes(1);
    expect(swarm).toHaveLength(2);
  });

  it('tries the rest of the swarm when the first three do not acknowledge a store', async () => {
    const members = [1, 2, 3, 4, 5].map(n => node(n));
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(json({ mnodes: members }))
      .mockResolvedValueOnce(json({}))
      .mockResolvedValueOnce(json({}))
      .mockResolvedValueOnce(json({}))
      .mockResolvedValueOnce(json({ hash: 'stored-on-fourth' }))
      .mockResolvedValueOnce(json({}));

    const client = new SnodeClient(async () => members, fetch, quiet);
    const hash = await client.storeMessage({ recipientPubKey: '0500', payload: 'hi' });

    expect(hash).toBe('stored-on-fourth');
    // Swarm lookup, the first three, then both remaining members together.
    expect(fetch).toHaveBeenCalledTimes(6);
  });

  it('does not use the fallback when one of the first three stores', async () => {
    const members = [1, 2, 3, 4, 5].map(n => node(n));
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(json({ mnodes: members }))
      .mockResolvedValueOnce(json({}))
      .mockResolvedValueOnce(json({ hash: 'ok' }))
      .mockResolvedValueOnce(json({}));

    const client = new SnodeClient(async () => members, fetch, quiet);
    expect(await client.storeMessage({ recipientPubKey: '0500', payload: 'hi' })).toBe('ok');
    expect(fetch).toHaveBeenCalledTimes(4);
  });

  it('forgets the swarm when every member refuses, so the next send looks it up again', async () => {
    const members = [1, 2, 3, 4, 5].map(n => node(n));
    const fetch = vi.fn().mockImplementation(async (_url: string, init: any) =>
      String(init?.body ?? '').includes('get_mnodes_for_pubkey') ? json({ mnodes: members }) : json({})
    );

    const client = new SnodeClient(async () => members, fetch, quiet);
    await expect(client.storeMessage({ recipientPubKey: '0500', payload: 'hi' })).rejects.toThrow();
    await expect(client.storeMessage({ recipientPubKey: '0500', payload: 'hi' })).rejects.toThrow();

    const lookups = fetch.mock.calls.filter(c => String(c[1]?.body ?? '').includes('get_mnodes_for_pubkey'));
    expect(lookups).toHaveLength(2);
  });
});
