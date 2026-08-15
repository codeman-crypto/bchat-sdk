import sodium from 'libsodium-wrappers-sumo';
import { Buffer } from 'buffer';

/** Prefix byte used by BChat account IDs (Session uses '05'). */
export const BCHAT_ID_PREFIX = 'bd';

export type AccountKeys = {
  /** X25519 keypair used for storage routing, derived from the Ed25519 keypair */
  x25519: { publicKey: string; privateKey: string };
  /** Ed25519 keypair used to sign retrieve/delete requests */
  ed25519: { publicKey: string; privateKey: string };
  /** Convenience BChat ID: prefix byte + 64 hex chars of the X25519 pubkey */
  bchatId: string;
};

const toHex = (u8: Uint8Array) => Buffer.from(u8).toString('hex');

/**
 * Generate an Ed25519 identity plus the X25519 pair derived from it.
 *
 * The X25519 keys MUST be derived from the Ed25519 keys. Storage nodes verify
 * that the `pubkey_ed25519` attached to a signed `retrieve`/`delete` converts
 * (via crypto_sign_ed25519_pk_to_curve25519) to the account pubkey the swarm
 * was looked up with. The previous implementation called
 * `sodium.crypto_box_keypair()` to make a completely independent X25519 pair,
 * so every authenticated request from a generated account was rejected and
 * messages encrypted to the ID could never be read back by the Ed25519 owner.
 */
export async function createAccount(): Promise<AccountKeys> {
  await sodium.ready;

  const ed = sodium.crypto_sign_keypair();
  return accountFromEd25519({ publicKey: ed.publicKey, privateKey: ed.privateKey });
}

/** Rebuild an AccountKeys bundle from an existing Ed25519 keypair. */
export async function accountFromEd25519(ed: {
  publicKey: Uint8Array | string;
  privateKey: Uint8Array | string;
}): Promise<AccountKeys> {
  await sodium.ready;

  const edPub = typeof ed.publicKey === 'string' ? Buffer.from(ed.publicKey, 'hex') : ed.publicKey;
  const edPriv =
    typeof ed.privateKey === 'string' ? Buffer.from(ed.privateKey, 'hex') : ed.privateKey;

  if (edPub.length !== 32) {
    throw new Error(`ed25519 public key must be 32 bytes, got ${edPub.length}`);
  }
  if (edPriv.length !== 64) {
    throw new Error(`ed25519 private key must be 64 bytes, got ${edPriv.length}`);
  }

  const xPub = sodium.crypto_sign_ed25519_pk_to_curve25519(edPub);
  const xPriv = sodium.crypto_sign_ed25519_sk_to_curve25519(edPriv);

  const xPubHex = toHex(xPub);

  return {
    x25519: { publicKey: xPubHex, privateKey: toHex(xPriv) },
    ed25519: { publicKey: toHex(edPub), privateKey: toHex(edPriv) },
    bchatId: `${BCHAT_ID_PREFIX}${xPubHex}`,
  };
}
