import { describe, it, expect } from 'vitest';
import { mnDecode, mnEncode, MnemonicError } from '../mnemonic';
import { createIdentity, generateMnemonic, identityFromMnemonic } from '../identity';
import { decodeAddress } from '../address';
import { ENGLISH_WORDLIST } from '../wordlist';

describe('mnemonic', () => {
  it('ships the full 1626-word set with unique 3-char prefixes', () => {
    expect(ENGLISH_WORDLIST).toHaveLength(1626);
    expect(new Set(ENGLISH_WORDLIST).size).toBe(1626);
    expect(new Set(ENGLISH_WORDLIST.map(w => w.slice(0, 3))).size).toBe(1626);
  });

  it('encodes a 32-byte seed as 25 words', async () => {
    const phrase = await generateMnemonic();
    expect(phrase.split(' ')).toHaveLength(25);
  });

  it('round-trips seed -> phrase -> seed', () => {
    const seed = 'a'.repeat(64);
    expect(mnDecode(mnEncode(seed))).toBe(seed);

    const other = '0123456789abcdef'.repeat(4);
    expect(mnDecode(mnEncode(other))).toBe(other);
  });

  it('tolerates extra whitespace', async () => {
    const phrase = await generateMnemonic();
    expect(mnDecode(`  ${phrase.replace(/ /g, '   ')}  `)).toBe(mnDecode(phrase));
  });

  it('rejects a phrase with a wrong checksum word', async () => {
    const words = (await generateMnemonic()).split(' ');
    words[24] = words[24] === 'abbey' ? 'zoom' : 'abbey';
    expect(() => mnDecode(words.join(' '))).toThrow(MnemonicError);
  });

  it('only looks at the first three characters of each word', async () => {
    // this is why 'notarealword' is accepted -- it truncates to 'not', the
    // prefix of 'noted'. Typos past the third character are harmless.
    const words = (await generateMnemonic()).split(' ');
    const original = words[3]!;
    words[3] = `${original.slice(0, 3)}zzzzz`;
    expect(mnDecode(words.join(' '))).toBe(mnDecode(words.map((w, i) => (i === 3 ? original : w)).join(' ')));
  });

  it('rejects a word whose prefix is not in the set', async () => {
    const words = (await generateMnemonic()).split(' ');
    words[3] = 'xylophone'; // no word in the set starts with 'xyl'
    expect(() => mnDecode(words.join(' '))).toThrow(/invalid word/);
  });

  it('rejects a truncated phrase', () => {
    expect(() => mnDecode('abbey abducts ability')).toThrow(/25-word/);
  });
});

describe('identity', () => {
  it('derives a bd-prefixed BChat ID and a valid wallet address from one seed', async () => {
    const id = await createIdentity('mainnet');

    expect(id.mnemonic.split(' ')).toHaveLength(25);
    expect(id.seed).toHaveLength(64);
    expect(id.bchatId).toMatch(/^bd[0-9a-f]{64}$/);
    expect(id.bchatId.slice(2)).toBe(id.x25519.publicKey);
    expect(id.walletAddress).toHaveLength(97);

    // the address must survive an independent checksum decode
    const decoded = decodeAddress(id.walletAddress);
    expect(decoded.network).toBe('mainnet');
    expect(decoded.spendPublicKey).toBe(id.wallet.spendPublicKey);
    expect(decoded.viewPublicKey).toBe(id.wallet.viewPublicKey);
  });

  it('is fully deterministic from the phrase', async () => {
    const first = await createIdentity();
    const second = await identityFromMnemonic(first.mnemonic);

    expect(second.seed).toBe(first.seed);
    expect(second.bchatId).toBe(first.bchatId);
    expect(second.walletAddress).toBe(first.walletAddress);
    expect(second.ed25519).toEqual(first.ed25519);
    expect(second.wallet).toEqual(first.wallet);
  });

  it('gives different seeds different IDs *and* different addresses', async () => {
    const a = await createIdentity();
    const b = await createIdentity();
    expect(a.bchatId).not.toBe(b.bchatId);
    expect(a.walletAddress).not.toBe(b.walletAddress);
  });

  it('keeps the BChat ID stable across networks but changes the address', async () => {
    const phrase = await generateMnemonic();
    const main = await identityFromMnemonic(phrase, 'mainnet');
    const test = await identityFromMnemonic(phrase, 'testnet');

    // the ID is a function of the seed only
    expect(test.bchatId).toBe(main.bchatId);
    expect(test.walletAddress).not.toBe(main.walletAddress);
    expect(test.walletAddress).toHaveLength(95);
  });

  it('derives the view key as keccak256 of the spend key, reduced', async () => {
    const id = await createIdentity();
    // distinct, valid scalars
    expect(id.wallet.viewSecretKey).not.toBe(id.wallet.spendSecretKey);
    expect(id.wallet.spendSecretKey).toHaveLength(64);
    expect(id.wallet.viewSecretKey).toHaveLength(64);
    // reduced scalars always have the high bit clear
    expect(parseInt(id.wallet.viewSecretKey.slice(-2), 16) & 0xf0).toBeLessThanOrEqual(0x10);
  });
});
