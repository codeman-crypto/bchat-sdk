import { describe, it, expect } from 'vitest';
import { crc32 } from '../crc32';
import { base58Decode, base58Encode } from '../base58';
import { decodeAddress, encodeAddress, NETWORK_ADDRESS_PREFIX } from '../address';

/**
 * Known-good addresses lifted from beldex/src/cryptonote_config.h. These are the
 * governance wallets baked into consensus, so they are the strongest available
 * fixture for the base58 + keccak + varint stack.
 */
const GOVERNANCE = {
  mainnet:
    'bxcguQiBhYaDW5wAdPLSwRHA6saX1nCEYUF89SPKZfBY1BENdLQWjti59aEtAEgrVZjnCJEVFoCDrG1DCoz2HeeN2pxhxL9xa',
  mainnetV17:
    'bxdwQ4ruRpW9QTfBpStRAMNKgdt7Rr39UcThNZ7mwsfxH7StmykPe9ah1KgJL2LwEAgqRXHLvZYBm1aaUVR8mLtB1u3WauV6P',
  testnet:
    'A1cuNRow8sMLmKCwTWvBM2EsNUNLdkrVLLqjdagqA7XQbRcrVKNo1Cbedk1iK2b1rPFj36Jv6RKhV7J72Rs7SSL7HKFMwva',
};

describe('crc32', () => {
  it('matches the standard IEEE check value', () => {
    expect(crc32('123456789')).toBe(0xcbf43926);
  });
});

describe('monero base58', () => {
  it('round-trips arbitrary byte lengths', () => {
    for (const size of [1, 4, 8, 9, 16, 69, 70]) {
      const data = Uint8Array.from({ length: size }, (_, i) => (i * 37 + 11) % 256);
      expect(Array.from(base58Decode(base58Encode(data)))).toEqual(Array.from(data));
    }
  });

  it('encodes 8-byte blocks to 11 characters', () => {
    expect(base58Encode(new Uint8Array(8)).length).toBe(11);
    expect(base58Encode(new Uint8Array(16)).length).toBe(22);
  });

  it('rejects characters outside the alphabet', () => {
    expect(() => base58Decode('0OIl00000000')).toThrow(/invalid base58/);
  });
});

describe('beldex addresses', () => {
  it('decodes the real mainnet governance address', () => {
    const decoded = decodeAddress(GOVERNANCE.mainnet);
    expect(GOVERNANCE.mainnet).toHaveLength(97);
    expect(decoded.network).toBe('mainnet');
    expect(decoded.prefix).toBe(NETWORK_ADDRESS_PREFIX.mainnet);
    expect(decoded.spendPublicKey).toHaveLength(64);
    expect(decoded.viewPublicKey).toHaveLength(64);
  });

  it('decodes the real testnet governance address', () => {
    const decoded = decodeAddress(GOVERNANCE.testnet);
    expect(GOVERNANCE.testnet).toHaveLength(95);
    expect(decoded.network).toBe('testnet');
    expect(decoded.prefix).toBe(NETWORK_ADDRESS_PREFIX.testnet);
  });

  it('re-encodes every known address byte-identically', () => {
    for (const address of Object.values(GOVERNANCE)) {
      const decoded = decodeAddress(address);
      expect(
        encodeAddress(decoded.spendPublicKey, decoded.viewPublicKey, decoded.network as 'mainnet')
      ).toBe(address);
    }
  });

  it('rejects an address with a corrupted character', () => {
    const broken = `${GOVERNANCE.mainnet.slice(0, -1)}${GOVERNANCE.mainnet.endsWith('a') ? 'b' : 'a'}`;
    expect(() => decodeAddress(broken)).toThrow(/bad checksum/);
  });

  it('produces the documented lengths per network', () => {
    const spend = 'a'.repeat(64);
    const view = 'b'.repeat(64);
    // BChat slices exactly these lengths off incoming messages
    expect(encodeAddress(spend, view, 'mainnet')).toHaveLength(97);
    expect(encodeAddress(spend, view, 'testnet')).toHaveLength(95);
  });
});
