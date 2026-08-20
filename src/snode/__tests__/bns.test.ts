import { describe, it, expect, vi } from 'vitest';
import sodium from 'libsodium-wrappers-sumo';
import { Buffer } from 'buffer';
import {
  bnsCandidateNames,
  bnsNameHashBase64,
  decryptBnsRecord,
  isBnsName,
  looksLikeBchatId,
  normalizeBnsName,
} from '../bns';
import { SnodeClient } from '../SnodeClient';

const BCHAT_ID = 'bd' + 'ab'.repeat(32); // 33 bytes as hex

/** Encrypt a BChat ID the way the BNS contract does (modern scheme). */
async function makeModernRecord(name: string, idHex: string) {
  await sodium.ready;
  const nameAsData = Buffer.from(name, 'utf8');
  const nameHash = sodium.crypto_generichash(sodium.crypto_generichash_BYTES, nameAsData);
  const key = sodium.crypto_generichash(sodium.crypto_generichash_BYTES, nameAsData, nameHash);
  const nonce = sodium.randombytes_buf(24);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    Buffer.from(idHex, 'hex'),
    null,
    null,
    nonce,
    key
  );
  return {
    encrypted_value: Buffer.from(ciphertext).toString('hex'),
    nonce: Buffer.from(nonce).toString('hex'),
  };
}

describe('normalizeBnsName', () => {
  it('lowercases and KEEPS a trailing .bdx (the hash covers the suffix)', () => {
    expect(normalizeBnsName('Codeman.BDX')).toBe('codeman.bdx');
    expect(normalizeBnsName('codeman')).toBe('codeman');
    expect(normalizeBnsName('my-name_1')).toBe('my-name_1');
  });

  it('rejects names BNS cannot contain', () => {
    expect(() => normalizeBnsName('-dash-start')).toThrow(/not a valid BNS name/);
    expect(() => normalizeBnsName('dash-end-')).toThrow(/not a valid BNS name/);
    expect(() => normalizeBnsName('has.dot')).toThrow(/not a valid BNS name/);
    expect(() => normalizeBnsName('')).toThrow(/required/);
    expect(() => normalizeBnsName('x'.repeat(65))).toThrow(/not a valid BNS name/);
  });
});

describe('bnsCandidateNames', () => {
  it('tries the name as given first, then the alternate form', () => {
    expect(bnsCandidateNames('Codeman.bdx')).toEqual(['codeman.bdx', 'codeman']);
    expect(bnsCandidateNames('codeman')).toEqual(['codeman', 'codeman.bdx']);
  });
});

describe('isBnsName / looksLikeBchatId', () => {
  it('classifies BChat IDs as IDs, not names', () => {
    expect(looksLikeBchatId(BCHAT_ID)).toBe(true);
    expect(looksLikeBchatId('ab'.repeat(32))).toBe(true); // bare x25519
    expect(isBnsName(BCHAT_ID)).toBe(false);
  });

  it('classifies names as names', () => {
    expect(isBnsName('codeman')).toBe(true);
    expect(isBnsName('codeman.bdx')).toBe(true);
    expect(looksLikeBchatId('codeman')).toBe(false);
    expect(isBnsName('not a name!')).toBe(false);
  });
});

describe('bnsNameHashBase64', () => {
  it('is base64 of blake2b-32 of the name', async () => {
    await sodium.ready;
    const expected = Buffer.from(
      sodium.crypto_generichash(32, Buffer.from('codeman', 'utf8'))
    ).toString('base64');
    expect(await bnsNameHashBase64('codeman')).toBe(expected);
  });
});

describe('decryptBnsRecord', () => {
  it('decrypts a modern (xchacha20) record to the BChat ID', async () => {
    const record = await makeModernRecord('codeman', BCHAT_ID);
    const id = await decryptBnsRecord('codeman', record.encrypted_value, record.nonce);
    expect(id).toBe(BCHAT_ID);
  });

  it('fails for the wrong name', async () => {
    const record = await makeModernRecord('codeman', BCHAT_ID);
    await expect(
      decryptBnsRecord('other', record.encrypted_value, record.nonce)
    ).rejects.toThrow(/decryption failed/);
  });

  it('rejects records that are not a 33-byte ID', async () => {
    const record = await makeModernRecord('codeman', 'ab'.repeat(10)); // 10 bytes
    await expect(
      decryptBnsRecord('codeman', record.encrypted_value, record.nonce)
    ).rejects.toThrow(/expected 33/);
  });

  it('decrypts a legacy (argon2) record to the BChat ID', async () => {
    await sodium.ready;
    const salt = new Uint8Array(sodium.crypto_pwhash_SALTBYTES);
    const nonce = new Uint8Array(sodium.crypto_secretbox_NONCEBYTES);
    const key = sodium.crypto_pwhash(
      sodium.crypto_secretbox_KEYBYTES,
      'codeman',
      salt,
      sodium.crypto_pwhash_OPSLIMIT_MODERATE,
      sodium.crypto_pwhash_MEMLIMIT_MODERATE,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );
    const ciphertext = sodium.crypto_secretbox_easy(Buffer.from(BCHAT_ID, 'hex'), nonce, key);
    const id = await decryptBnsRecord('codeman', Buffer.from(ciphertext).toString('hex'));
    expect(id).toBe(BCHAT_ID);
  }, 30_000);
});

describe('SnodeClient.resolveBns', () => {
  const pool = [
    { ip: '1.1.1.1', port: 443, pubkey_x25519: 'x1', pubkey_ed25519: 'e1' },
    { ip: '2.2.2.2', port: 443, pubkey_x25519: 'x2', pubkey_ed25519: 'e2' },
    { ip: '3.3.3.3', port: 443, pubkey_x25519: 'x3', pubkey_ed25519: 'e3' },
  ];

  const response = (body: unknown) => ({
    status: 200,
    headers: { get: () => 'application/json' },
    json: async () => body,
    text: async () => JSON.stringify(body),
  });

  it('resolves when every queried snode agrees', async () => {
    // Registered as "codeman.bdx", exactly as bchat-desktop hashes user input.
    const record = await makeModernRecord('codeman.bdx', BCHAT_ID);
    const fetch = vi.fn(async () => response({ result: record }));

    const client = new SnodeClient(async () => pool, fetch as any, console);
    const id = await client.resolveBns('Codeman.bdx');
    expect(id).toBe(BCHAT_ID);
    expect(fetch).toHaveBeenCalledTimes(3);
    // request shape matches the desktop client: full string, suffix included
    const body = JSON.parse((fetch.mock.calls[0] as any)[1].body);
    expect(body.method).toBe('beldexd_request');
    expect(body.params.endpoint).toBe('bns_resolve');
    expect(body.params.params.type).toBe(0);
    expect(body.params.params.name_hash).toBe(await bnsNameHashBase64('codeman.bdx'));
  });

  it('falls back to the alternate name form when the first misses', async () => {
    // Registered WITHOUT the suffix; user typed it WITH the suffix.
    const record = await makeModernRecord('codeman', BCHAT_ID);
    const bareHash = await bnsNameHashBase64('codeman');
    const fetch = vi.fn(async (_url: string, init: any) => {
      const requested = JSON.parse(init.body).params.params.name_hash;
      return response({ result: requested === bareHash ? { ...record } : {} });
    });

    const client = new SnodeClient(async () => pool, fetch as any, console);
    const id = await client.resolveBns('codeman.bdx');
    expect(id).toBe(BCHAT_ID);
    // 3 misses for "codeman.bdx", then 3 hits for "codeman"
    expect(fetch).toHaveBeenCalledTimes(6);
  });

  it('throws when snodes disagree', async () => {
    const record = await makeModernRecord('codeman', BCHAT_ID);
    const other = await makeModernRecord('codeman', 'bd' + 'cd'.repeat(32));
    let call = 0;
    const fetch = vi.fn(async () => response({ result: call++ === 0 ? record : other }));

    const client = new SnodeClient(async () => pool, fetch as any, console);
    await expect(client.resolveBns('codeman')).rejects.toThrow(/conflicting/);
  });

  it('throws when the name is not registered', async () => {
    const fetch = vi.fn(async () => response({ result: {} }));
    const client = new SnodeClient(async () => pool, fetch as any, console);
    await expect(client.resolveBns('codeman')).rejects.toThrow(/not registered/);
  });

  it('rejects invalid names before touching the network', async () => {
    const fetch = vi.fn();
    const client = new SnodeClient(async () => pool, fetch as any, console);
    await expect(client.resolveBns('bad.name.here')).rejects.toThrow(/not a valid BNS name/);
    expect(fetch).not.toHaveBeenCalled();
  });
});
