/**
 * Beldex wallet key derivation and address encoding (CryptoNote/Monero scheme).
 *
 * Address bytes = varint(networkPrefix) ‖ publicSpendKey ‖ publicViewKey
 *                 ‖ first 4 bytes of keccak256(those bytes)
 * then Monero base58.
 *
 * Prefixes come from beldex/src/cryptonote_config.h. Mainnet's 0xd1 needs a
 * two-byte varint, which is why mainnet addresses are 97 characters and testnet
 * (prefix 53, one byte) are 95 — exactly the lengths bchat-desktop hardcodes
 * when slicing the address off a received message.
 */
import sodium from 'libsodium-wrappers-sumo';
// js-sha3 is CommonJS. A named import (`import { keccak256 } from 'js-sha3'`)
// type-checks and works under bundlers, but Node's native ESM loader cannot
// statically detect the export and throws at runtime in the dist/esm build.
// Importing the default and destructuring works in both outputs.
import sha3 from 'js-sha3';
import { Buffer } from 'buffer';
import { base58Decode, base58Encode } from './base58.js';

export const NETWORK_ADDRESS_PREFIX = {
  mainnet: 0xd1, // 209
  testnet: 53,
  devnet: 24,
} as const;

export type BeldexNetworkName = keyof typeof NETWORK_ADDRESS_PREFIX;

export type WalletKeys = {
  spendSecretKey: string;
  spendPublicKey: string;
  viewSecretKey: string;
  viewPublicKey: string;
};

const toHex = (u8: Uint8Array) => Buffer.from(u8).toString('hex');

const keccak = (data: Uint8Array): Uint8Array => Uint8Array.from(sha3.keccak256.array(data));

function writeVarint(value: number): Uint8Array {
  const out: number[] = [];
  let v = value;
  while (v >= 0x80) {
    out.push((v & 0x7f) | 0x80);
    v >>>= 7;
  }
  out.push(v);
  return Uint8Array.from(out);
}

function readVarint(data: Uint8Array): { value: number; length: number } {
  let value = 0;
  let shift = 0;
  for (let i = 0; i < data.length; i++) {
    const byte = data[i]!;
    value |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return { value: value >>> 0, length: i + 1 };
    shift += 7;
    if (shift > 28) break;
  }
  throw new Error('address: malformed network prefix varint');
}

const concat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
};

/** Monero's sc_reduce32: interpret 32 little-endian bytes as a scalar mod l. */
function scReduce32(bytes: Uint8Array): Uint8Array {
  const wide = new Uint8Array(64);
  wide.set(bytes.subarray(0, 32));
  return sodium.crypto_core_ed25519_scalar_reduce(wide);
}

/**
 * Derive the wallet keypairs from a 32-byte seed.
 *
 * This is the standard CryptoNote deterministic wallet: the seed reduces to the
 * spend secret key, and the view secret key is keccak256 of it, also reduced.
 */
export async function deriveWalletKeys(seed: Uint8Array): Promise<WalletKeys> {
  await sodium.ready;
  if (seed.length !== 32) throw new Error(`seed must be 32 bytes, got ${seed.length}`);

  const spendSecret = scReduce32(seed);
  const viewSecret = scReduce32(keccak(spendSecret));

  return {
    spendSecretKey: toHex(spendSecret),
    spendPublicKey: toHex(sodium.crypto_scalarmult_ed25519_base_noclamp(spendSecret)),
    viewSecretKey: toHex(viewSecret),
    viewPublicKey: toHex(sodium.crypto_scalarmult_ed25519_base_noclamp(viewSecret)),
  };
}

export function encodeAddress(
  spendPublicKeyHex: string,
  viewPublicKeyHex: string,
  network: BeldexNetworkName = 'mainnet'
): string {
  const prefix = NETWORK_ADDRESS_PREFIX[network];
  if (prefix === undefined) throw new Error(`unknown network "${network}"`);

  const body = concat(
    writeVarint(prefix),
    Buffer.from(spendPublicKeyHex, 'hex'),
    Buffer.from(viewPublicKeyHex, 'hex')
  );
  const checksum = keccak(body).subarray(0, 4);
  return base58Encode(concat(body, checksum));
}

export type DecodedAddress = {
  network: BeldexNetworkName | 'unknown';
  prefix: number;
  spendPublicKey: string;
  viewPublicKey: string;
};

/** Decode and checksum-verify a Beldex address. Throws if it is malformed. */
export function decodeAddress(address: string): DecodedAddress {
  const raw = base58Decode(address);
  if (raw.length < 4 + 64 + 1) throw new Error('address: too short');

  const body = raw.subarray(0, raw.length - 4);
  const checksum = raw.subarray(raw.length - 4);
  const expected = keccak(body).subarray(0, 4);
  if (!checksum.every((b, i) => b === expected[i])) {
    throw new Error('address: bad checksum');
  }

  const { value: prefix, length } = readVarint(body);
  if (body.length !== length + 64) {
    throw new Error(`address: unexpected payload length ${body.length - length}, expected 64`);
  }

  const entry = (Object.keys(NETWORK_ADDRESS_PREFIX) as BeldexNetworkName[]).find(
    name => NETWORK_ADDRESS_PREFIX[name] === prefix
  );

  return {
    network: entry ?? 'unknown',
    prefix,
    spendPublicKey: toHex(body.subarray(length, length + 32)),
    viewPublicKey: toHex(body.subarray(length + 32, length + 64)),
  };
}
