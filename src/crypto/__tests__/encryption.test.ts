import { describe, it, expect } from 'vitest';
import { SealedBoxEncryption, normalizeX25519Hex } from '../encryption';
import { createAccount, BCHAT_ID_PREFIX } from '../../account';

const enc = new SealedBoxEncryption();

describe('normalizeX25519Hex', () => {
  it('strips bd/05 account-id prefixes', () => {
    const bare = 'a'.repeat(64);
    expect(normalizeX25519Hex(bare).toString('hex')).toBe(bare);
    expect(normalizeX25519Hex(`bd${bare}`).toString('hex')).toBe(bare);
    expect(normalizeX25519Hex(`05${bare}`).toString('hex')).toBe(bare);
  });

  it('rejects non-hex and wrong-length keys instead of truncating', () => {
    expect(() => normalizeX25519Hex('zz'.repeat(32))).toThrow(/valid hex/);
    expect(() => normalizeX25519Hex('ab')).toThrow(/32 bytes/);
    expect(() => normalizeX25519Hex('')).toThrow(/required/);
  });
});

describe('SealedBoxEncryption', () => {
  it('round-trips through a prefixed BChat ID', async () => {
    const acct = await createAccount();
    expect(acct.bchatId.startsWith(BCHAT_ID_PREFIX)).toBe(true);

    const sealed = await enc.encryptForRecipient(Buffer.from('hello there', 'utf8'), acct.bchatId);
    const opened = await enc.decryptForAccount(
      sealed,
      acct.x25519.privateKey,
      acct.x25519.publicKey
    );

    expect(opened).not.toBeNull();
    expect(Buffer.from(opened!).toString('utf8')).toBe('hello there');
  });

  it('returns null rather than throwing for foreign or truncated ciphertext', async () => {
    const mine = await createAccount();
    const theirs = await createAccount();

    const sealed = await enc.encryptForRecipient(Buffer.from('secret', 'utf8'), theirs.bchatId);
    expect(
      await enc.decryptForAccount(sealed, mine.x25519.privateKey, mine.x25519.publicKey)
    ).toBeNull();
    expect(
      await enc.decryptForAccount(
        Buffer.from('too short'),
        mine.x25519.privateKey,
        mine.x25519.publicKey
      )
    ).toBeNull();
  });
});
