import sodium from 'libsodium-wrappers-sumo';
import { Buffer } from 'buffer';
import { EncryptionProvider } from '../types.js';

export type SealedBoxCiphertext = Uint8Array;

const X25519_KEY_BYTES = 32;
/** ephemeral X25519 public key (32) + Poly1305 MAC (16) */
const SEALED_BOX_OVERHEAD = 48;
/** account-ID prefix bytes seen in the wild: 'bd' (BChat) and '05' (Session) */
const ID_PREFIXES = ['bd', '05'];

/**
 * Accepts a bare 64-char X25519 hex key or a 66-char prefixed account ID and
 * returns the raw 32 bytes.
 *
 * Previously the hex string was fed straight to `Buffer.from(hex, 'hex')`,
 * which silently produces a 33-byte buffer for a prefixed ID (libsodium then
 * throws an opaque "invalid publicKey length") and silently truncates or
 * returns an empty buffer for malformed hex.
 */
export function normalizeX25519Hex(value: string, label = 'x25519 key'): Buffer {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`${label} is required`);
  }

  let hex = value.trim().toLowerCase();
  if (hex.length === (X25519_KEY_BYTES + 1) * 2 && ID_PREFIXES.includes(hex.slice(0, 2))) {
    hex = hex.slice(2);
  }

  if (!/^[0-9a-f]+$/.test(hex) || hex.length % 2 !== 0) {
    throw new Error(`${label} is not a valid hex string`);
  }

  const buf = Buffer.from(hex, 'hex');
  if (buf.length !== X25519_KEY_BYTES) {
    throw new Error(`${label} must be ${X25519_KEY_BYTES} bytes, got ${buf.length}`);
  }
  return buf;
}

/** Default implementation using libsodium sealed boxes (anonymous sender, X25519 recipient) */
export class SealedBoxEncryption implements EncryptionProvider {
  async encryptForRecipient(plaintext: Uint8Array, recipientX25519Hex: string): Promise<Uint8Array> {
    await sodium.ready;
    const pk = normalizeX25519Hex(recipientX25519Hex, 'recipient x25519 pubkey');
    return sodium.crypto_box_seal(plaintext, pk);
  }

  async decryptForAccount(
    ciphertext: Uint8Array,
    accountX25519PrivHex: string,
    accountX25519PubHex: string
  ): Promise<Uint8Array | null> {
    await sodium.ready;
    const pk = normalizeX25519Hex(accountX25519PubHex, 'account x25519 pubkey');
    const sk = normalizeX25519Hex(accountX25519PrivHex, 'account x25519 privkey');

    // Short buffers make libsodium abort the process in some builds rather than
    // throw, so reject them before handing them over.
    if (!ciphertext || ciphertext.length <= SEALED_BOX_OVERHEAD) {
      return null;
    }

    try {
      return sodium.crypto_box_seal_open(ciphertext, pk, sk);
    } catch {
      return null;
    }
  }
}
