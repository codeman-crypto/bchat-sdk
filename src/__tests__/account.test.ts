import { describe, it, expect } from 'vitest';
import sodium from 'libsodium-wrappers-sumo';
import { createAccount, accountFromEd25519, BCHAT_ID_PREFIX } from '../account';

describe('createAccount', () => {
  it('derives the x25519 pair from the ed25519 pair', async () => {
    const acct = await createAccount();
    await sodium.ready;

    const derivedPub = Buffer.from(
      sodium.crypto_sign_ed25519_pk_to_curve25519(
        Buffer.from(acct.ed25519.publicKey, 'hex')
      )
    ).toString('hex');
    const derivedPriv = Buffer.from(
      sodium.crypto_sign_ed25519_sk_to_curve25519(
        Buffer.from(acct.ed25519.privateKey, 'hex')
      )
    ).toString('hex');

    expect(acct.x25519.publicKey).toBe(derivedPub);
    expect(acct.x25519.privateKey).toBe(derivedPriv);
  });

  it('returns a prefixed bchatId', async () => {
    const acct = await createAccount();
    expect(acct.bchatId).toBe(`${BCHAT_ID_PREFIX}${acct.x25519.publicKey}`);
    expect(acct.bchatId).toHaveLength(66);
  });

  it('rebuilds the same account from the ed25519 keys', async () => {
    const acct = await createAccount();
    const again = await accountFromEd25519(acct.ed25519);
    expect(again).toEqual(acct);
  });

  it('rejects malformed ed25519 keys', async () => {
    await expect(accountFromEd25519({ publicKey: 'aa', privateKey: 'bb' })).rejects.toThrow(
      /32 bytes/
    );
  });
});
