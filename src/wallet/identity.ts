/**
 * A BChat identity: one mnemonic seed produces BOTH the BChat ID and the Beldex
 * wallet, exactly as bchat-desktop does on registration.
 *
 * The BChat ID comes from `crypto_sign_seed_keypair(seed)` — it is NOT derived
 * from the wallet address, which is why two identities sharing a wallet address
 * string would still have different IDs. Both are functions of the same seed.
 */
import sodium from 'libsodium-wrappers-sumo';
import { Buffer } from 'buffer';
import { BCHAT_ID_PREFIX } from '../account.js';
import { mnDecode, mnEncode } from './mnemonic.js';
import {
  deriveWalletKeys,
  encodeAddress,
  type BeldexNetworkName,
  type WalletKeys,
} from './address.js';

const SEED_BYTES = 32;

const toHex = (u8: Uint8Array) => Buffer.from(u8).toString('hex');

export type BchatIdentity = {
  /** 25-word recovery phrase; the only thing the user needs to back up */
  mnemonic: string;
  /** 32-byte seed, hex */
  seed: string;
  network: BeldexNetworkName;
  /** signs retrieve/delete requests and message payloads */
  ed25519: { publicKey: string; privateKey: string };
  /** storage routing + sealed-box recipient keys */
  x25519: { publicKey: string; privateKey: string };
  /** 'bd' + 64 hex chars */
  bchatId: string;
  /** base58 Beldex address (97 chars mainnet, 95 testnet) */
  walletAddress: string;
  wallet: WalletKeys;
};

/** Generate a fresh 25-word recovery phrase from 32 random bytes. */
export async function generateMnemonic(): Promise<string> {
  await sodium.ready;
  return mnEncode(toHex(sodium.randombytes_buf(SEED_BYTES)));
}

/**
 * Rebuild a full identity from a recovery phrase.
 *
 * bchat-desktop zero-pads seeds shorter than 32 bytes for legacy 13-word
 * phrases. That branch is deliberately not reproduced: `mnDecode` requires 25
 * words, so it was unreachable, and padding a 16-byte seed to 32 bytes yields
 * an identity with only 128 bits of entropy. Enabling short phrases would mean
 * lowering the word-count floor on purpose and documenting the weaker keys.
 */
export async function identityFromMnemonic(
  mnemonic: string,
  network: BeldexNetworkName = 'mainnet'
): Promise<BchatIdentity> {
  await sodium.ready;

  const seedHex = mnDecode(mnemonic);
  if (seedHex.length !== SEED_BYTES * 2) {
    throw new Error(
      `recovery phrase decoded to ${seedHex.length / 2} bytes, expected ${SEED_BYTES}`
    );
  }
  const seed = Buffer.from(seedHex, 'hex');

  const ed = sodium.crypto_sign_seed_keypair(seed);
  const xPublic = sodium.crypto_sign_ed25519_pk_to_curve25519(ed.publicKey);
  const xPrivate = sodium.crypto_sign_ed25519_sk_to_curve25519(ed.privateKey);

  const wallet = await deriveWalletKeys(seed);

  return {
    mnemonic: mnemonic.trim().replace(/\s+/g, ' '),
    seed: seedHex,
    network,
    ed25519: { publicKey: toHex(ed.publicKey), privateKey: toHex(ed.privateKey) },
    x25519: { publicKey: toHex(xPublic), privateKey: toHex(xPrivate) },
    bchatId: `${BCHAT_ID_PREFIX}${toHex(xPublic)}`,
    walletAddress: encodeAddress(wallet.spendPublicKey, wallet.viewPublicKey, network),
    wallet,
  };
}

/** Generate a brand new identity: mnemonic, BChat ID and wallet address. */
export async function createIdentity(
  network: BeldexNetworkName = 'mainnet'
): Promise<BchatIdentity> {
  return identityFromMnemonic(await generateMnemonic(), network);
}
