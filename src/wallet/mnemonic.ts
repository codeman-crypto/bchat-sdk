/**
 * Electrum-style mnemonic used by Monero, Beldex and BChat.
 *
 * Ported from bchat-desktop (ts/bchat/crypto/mnemonic.ts). Four bytes of seed
 * become three words; a 32-byte seed therefore produces 24 words plus one
 * checksum word, for the familiar 25-word recovery phrase.
 */
import { crc32 } from './crc32.js';
import { ENGLISH_PREFIX_LENGTH, ENGLISH_WORDLIST } from './wordlist.js';

export class MnemonicError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MnemonicError';
  }
}

const TRUNCATED = ENGLISH_WORDLIST.map(w => w.slice(0, ENGLISH_PREFIX_LENGTH));

function swapEndian4Byte(hex: string): string {
  if (hex.length !== 8) throw new MnemonicError(`Invalid input length: ${hex.length}`);
  return hex.slice(6, 8) + hex.slice(4, 6) + hex.slice(2, 4) + hex.slice(0, 2);
}

function checksumIndex(words: string[]): number {
  const trimmed = words.map(w => w.slice(0, ENGLISH_PREFIX_LENGTH)).join('');
  return crc32(trimmed) % words.length;
}

/** Encode a hex seed (length a multiple of 8) as a mnemonic phrase. */
export function mnEncode(seedHex: string): string {
  if (seedHex.length % 8 !== 0) {
    throw new MnemonicError(`seed hex length must be a multiple of 8, got ${seedHex.length}`);
  }
  if (!/^[0-9a-fA-F]*$/.test(seedHex)) {
    throw new MnemonicError('seed must be a hex string');
  }

  const n = ENGLISH_WORDLIST.length;
  const out: string[] = [];

  for (let i = 0; i < seedHex.length; i += 8) {
    const x = parseInt(swapEndian4Byte(seedHex.slice(i, i + 8)), 16);
    const w1 = x % n;
    const w2 = (Math.floor(x / n) + w1) % n;
    const w3 = (Math.floor(Math.floor(x / n) / n) + w2) % n;
    out.push(ENGLISH_WORDLIST[w1]!, ENGLISH_WORDLIST[w2]!, ENGLISH_WORDLIST[w3]!);
  }

  out.push(out[checksumIndex(out)]!);
  return out.join(' ');
}

/** Decode a mnemonic phrase back to its hex seed, verifying the checksum word. */
export function mnDecode(phrase: string): string {
  const n = ENGLISH_WORDLIST.length;
  const words = phrase.trim().replace(/\s+/g, ' ').split(' ').filter(Boolean);

  if (words.length < 25) {
    throw new MnemonicError(
      `expected a 25-word recovery phrase, got ${words.length} word(s)`
    );
  }
  if (words.length % 3 === 2) {
    throw new MnemonicError("You've entered too few words, please try again");
  }
  if (words.length % 3 === 0) {
    throw new MnemonicError('You seem to be missing the last word in your private key');
  }

  const checksumWord = words.pop()!;
  let out = '';

  for (let i = 0; i < words.length; i += 3) {
    const w1 = TRUNCATED.indexOf(words[i]!.slice(0, ENGLISH_PREFIX_LENGTH));
    const w2 = TRUNCATED.indexOf(words[i + 1]!.slice(0, ENGLISH_PREFIX_LENGTH));
    const w3 = TRUNCATED.indexOf(words[i + 2]!.slice(0, ENGLISH_PREFIX_LENGTH));
    if (w1 === -1 || w2 === -1 || w3 === -1) {
      throw new MnemonicError('invalid word in mnemonic');
    }

    const x = w1 + n * ((n - w1 + w2) % n) + n * n * ((n - w2 + w3) % n);
    if (x % n !== w1) {
      throw new MnemonicError('Something went wrong when decoding your private key');
    }
    out += swapEndian4Byte(`0000000${x.toString(16)}`.slice(-8));
  }

  const expected = words[checksumIndex(words)]!;
  if (
    expected.slice(0, ENGLISH_PREFIX_LENGTH) !== checksumWord.slice(0, ENGLISH_PREFIX_LENGTH)
  ) {
    throw new MnemonicError('Your private key could not be verified, please check the last word');
  }

  return out;
}
