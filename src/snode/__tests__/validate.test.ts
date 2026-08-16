import { describe, it, expect, vi } from 'vitest';
import { assertSnodeAddress, buildSnodeUrl, isUsableSnode } from '../validate';
import { SnodeClient } from '../SnodeClient';

describe('assertSnodeAddress (BCHAT-02)', () => {
  it('accepts a public IPv4 address', () => {
    expect(assertSnodeAddress('1.2.3.4', 443)).toBe(443);
    expect(assertSnodeAddress('8.8.8.8', '19099')).toBe(19099);
  });

  it('rejects anything that is not a literal IP', () => {
    for (const ip of [
      'evil.tld',
      '1.2.3.4/collect?x=',
      'user:pass@evil.tld',
      '1.2.3.4:9443/exfil?ignored=',
      'localhost',
      '1.2.3.4 ',
      '../../etc',
    ]) {
      expect(() => assertSnodeAddress(ip, 443), ip).toThrow(/not a literal IP address/);
    }
  });

  it('rejects a missing or non-string ip', () => {
    for (const ip of ['', undefined, null, 42, {}]) {
      expect(() => assertSnodeAddress(ip, 443), String(ip)).toThrow(/missing or not a string/);
    }
  });

  it('rejects loopback, RFC1918, link-local, CGNAT and multicast', () => {
    for (const ip of [
      '127.0.0.1',
      '0.0.0.0',
      '10.1.2.3',
      '172.16.0.1',
      '192.168.1.1',
      '169.254.169.254', // cloud metadata
      '100.64.0.1',
      '239.1.1.1',
    ]) {
      expect(() => assertSnodeAddress(ip, 443), ip).toThrow(/not publicly routable/);
    }
  });

  it('rejects private IPv6 too', () => {
    for (const ip of ['::1', '::', 'fe80::1', 'fd00::1', '::ffff:127.0.0.1']) {
      expect(() => assertSnodeAddress(ip, 443), ip).toThrow(/not publicly routable/);
    }
    expect(assertSnodeAddress('2606:4700::1111', 443)).toBe(443);
  });

  it('allows private targets only when explicitly opted in', () => {
    expect(() => assertSnodeAddress('127.0.0.1', 8443)).toThrow();
    expect(assertSnodeAddress('127.0.0.1', 8443, { allowPrivateNodes: true })).toBe(8443);
  });

  it('rejects invalid ports', () => {
    for (const port of [0, -1, 65536, 1.5, 'abc', null, undefined]) {
      expect(() => assertSnodeAddress('1.2.3.4', port), String(port)).toThrow(/port is invalid/);
    }
  });
});

describe('buildSnodeUrl (BCHAT-02)', () => {
  it('builds a normal URL', () => {
    expect(buildSnodeUrl('1.2.3.4', 443, '/storage_rpc/v1')).toBe(
      'https://1.2.3.4/storage_rpc/v1'
    );
    expect(buildSnodeUrl('1.2.3.4', 19099, '/storage_rpc/v1')).toBe(
      'https://1.2.3.4:19099/storage_rpc/v1'
    );
  });

  it('brackets IPv6 literals', () => {
    expect(buildSnodeUrl('2606:4700::1111', 443, '/storage_rpc/v1')).toContain(
      '[2606:4700::1111]'
    );
  });

  it('never lets the address escape into path or query', () => {
    const url = buildSnodeUrl('1.2.3.4', 443, '/storage_rpc/v1');
    expect(new URL(url).hostname).toBe('1.2.3.4');
    expect(new URL(url).pathname).toBe('/storage_rpc/v1');
    expect(new URL(url).search).toBe('');
  });
});

describe('SnodeClient swarm filtering (BCHAT-02)', () => {
  const silent = { info: () => {}, warn: () => {}, error: () => {} };
  const pool = [{ ip: '1.1.1.1', port: 80, pubkey_x25519: 'x', pubkey_ed25519: 'e' }];

  const ok = (body: string) => ({
    status: 200,
    headers: { get: () => 'application/json' },
    json: async () => JSON.parse(body),
    text: async () => body,
  });

  it('discards a malicious swarm entry rather than requesting it', async () => {
    const requested: string[] = [];
    const fetch = vi.fn(async (url: string, init: any) => {
      requested.push(url);
      const method = JSON.parse(init.body).method;
      if (method === 'get_mnodes_for_pubkey') {
        return ok(
          JSON.stringify({
            mnodes: [
              { ip: '127.0.0.1:9443/exfil?ignored=', port: 1, pubkey_x25519: 'a' },
              { ip: 'attacker.tld/collect?x=', port: 443, pubkey_x25519: 'b' },
              { ip: '169.254.169.254', port: 80, pubkey_x25519: 'c' },
              { ip: '5.6.7.8', port: 443, pubkey_x25519: 'd', pubkey_ed25519: 'e' },
            ],
          })
        );
      }
      return ok(JSON.stringify({ messages: [] }));
    });

    const client = new SnodeClient(async () => pool, fetch as any, silent);
    const swarm = await client.getSnodesForPubkey('bd00');

    // only the one legitimate entry survives
    expect(swarm.map(n => n.ip)).toEqual(['5.6.7.8']);
    expect(requested.some(u => u.includes('exfil') || u.includes('attacker'))).toBe(false);
  });

  it('treats a swarm of only-bad entries as empty', async () => {
    const fetch = vi.fn(async (_url: string, init: any) => {
      const method = JSON.parse(init.body).method;
      if (method === 'get_mnodes_for_pubkey') {
        return ok(JSON.stringify({ mnodes: [{ ip: 'evil.tld', port: 443 }] }));
      }
      return ok('{}');
    });

    const client = new SnodeClient(async () => pool, fetch as any, silent);
    await expect(client.getSnodesForPubkey('bd00')).rejects.toThrow(/Empty swarm/);
  });
});

describe('isUsableSnode', () => {
  it('is a non-throwing predicate', () => {
    expect(isUsableSnode({ ip: '1.2.3.4', port: 443 })).toBe(true);
    expect(isUsableSnode({ ip: 'evil.tld', port: 443 })).toBe(false);
    expect(isUsableSnode({})).toBe(false);
  });
});
