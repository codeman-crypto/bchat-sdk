/**
 * Attachment body decryption, ported from bchat-desktop
 * `ts/util/crypto/attachmentsEncrypter.ts` (`decryptAttachment`) and
 * `ts/bchat/crypto/BufferPadding.ts` (`getUnpaddedAttachment`).
 *
 * Format of the blob stored on the file server:
 *
 *     IV (16) || AES-256-CBC ciphertext (PKCS#7) || HMAC-SHA256(IV || ciphertext) (32)
 *
 * The 64-byte pointer key is AES key (32) || MAC key (32). The pointer digest is
 * SHA-256 over the whole blob. Senders pad the plaintext with zero bytes up to
 * a size bucket before encrypting; the pointer's `size` is the unpadded length.
 *
 * Uses Node's built-in `crypto` only.
 */
import { Buffer } from 'buffer';
import { createDecipheriv, createHash, createHmac, timingSafeEqual } from 'crypto';

export type AttachmentErrorCode =
  /** key is not 64 bytes */
  | 'BAD_KEY_LENGTH'
  /** blob is shorter than IV + MAC (48 bytes) */
  | 'SHORT_BLOB'
  /** HMAC over IV || ciphertext does not match: wrong key, or tampered blob */
  | 'MAC_MISMATCH'
  /** pointer carried no digest; desktop refuses these, and so do we */
  | 'DIGEST_MISSING'
  /** SHA-256 of the blob does not match the pointer's digest */
  | 'DIGEST_MISMATCH'
  /** MAC verified but AES-CBC decryption failed (bad block length / PKCS#7) */
  | 'DECRYPT_FAILED'
  /** plaintext is shorter than the pointer's declared size */
  | 'SIZE_MISMATCH'
  /** pointer has no key: nothing to decrypt with */
  | 'MISSING_KEY'
  /** pointer has no usable size; desktop refuses these */
  | 'MISSING_SIZE'
  /** neither url nor id resolves to a file on an allowed file server */
  | 'BAD_POINTER'
  /** the file server request failed (network, timeout, non-200 status) */
  | 'DOWNLOAD_FAILED'
  /** the response exceeded `maxBytes` */
  | 'TOO_LARGE';

/** All attachment failures throw this, with a machine-readable `code`. */
export class AttachmentError extends Error {
  constructor(
    readonly code: AttachmentErrorCode,
    message: string,
    /** HTTP / envelope status for DOWNLOAD_FAILED, when there was one */
    readonly status?: number
  ) {
    super(message);
    this.name = 'AttachmentError';
  }
}

export const ATTACHMENT_KEY_LENGTH = 64;
const IV_LENGTH = 16;
const MAC_LENGTH = 32;
const DIGEST_LENGTH = 32;

const toBuffer = (b: Uint8Array) => Buffer.from(b.buffer, b.byteOffset, b.byteLength);

/**
 * Verify and decrypt an attachment blob downloaded from the file server.
 *
 * Checks run in desktop's order: key length, blob length, MAC (constant time),
 * digest presence, digest (constant time), then AES-CBC. When `size` is given
 * and the plaintext is longer, the excess is sender padding and is trimmed —
 * desktop trims without inspecting it, and so does this. A plaintext *shorter*
 * than `size` is an error.
 *
 * @param blob   IV || ciphertext || MAC, exactly as the file server stores it
 * @param key    the pointer's 64-byte `key`
 * @param digest the pointer's 32-byte `digest`. Typed optional so a pointer's
 *               field can be passed straight through, but an absent or empty
 *               digest throws `DIGEST_MISSING`, matching desktop.
 * @param size   the pointer's plaintext `size`; omit to skip unpadding
 */
export function decryptAttachment(
  blob: Uint8Array,
  key: Uint8Array,
  digest?: Uint8Array,
  size?: number
): Uint8Array {
  if (!key || key.length !== ATTACHMENT_KEY_LENGTH) {
    throw new AttachmentError(
      'BAD_KEY_LENGTH',
      `attachment key must be ${ATTACHMENT_KEY_LENGTH} bytes, got ${key?.length ?? 0}`
    );
  }
  if (!blob || blob.length < IV_LENGTH + MAC_LENGTH) {
    throw new AttachmentError(
      'SHORT_BLOB',
      `attachment blob is ${blob?.length ?? 0} bytes; at least ${IV_LENGTH + MAC_LENGTH} (IV + MAC) are required`
    );
  }

  const keyBuf = toBuffer(key);
  const data = toBuffer(blob);
  const aesKey = keyBuf.subarray(0, 32);
  const macKey = keyBuf.subarray(32, 64);

  const ivAndCiphertext = data.subarray(0, data.length - MAC_LENGTH);
  const theirMac = data.subarray(data.length - MAC_LENGTH);
  const ourMac = createHmac('sha256', macKey).update(ivAndCiphertext).digest();
  if (!timingSafeEqual(ourMac, theirMac)) {
    throw new AttachmentError(
      'MAC_MISMATCH',
      'attachment MAC mismatch: wrong key, or the blob was corrupted or tampered with'
    );
  }

  // Desktop treats an empty digest as absent and refuses ("Ask sender to update
  // and resend"). It compares only theirDigest.byteLength bytes, so a short
  // digest would pass on a prefix; we require the full 32 bytes instead.
  if (!digest || digest.length === 0) {
    throw new AttachmentError(
      'DIGEST_MISSING',
      'attachment pointer has no digest; refusing it as BChat desktop does'
    );
  }
  const ourDigest = createHash('sha256').update(data).digest();
  if (digest.length !== DIGEST_LENGTH || !timingSafeEqual(ourDigest, toBuffer(digest))) {
    throw new AttachmentError(
      'DIGEST_MISMATCH',
      'attachment digest mismatch: the downloaded blob is not the one the sender referenced'
    );
  }

  let plaintext: Buffer;
  try {
    const decipher = createDecipheriv('aes-256-cbc', aesKey, data.subarray(0, IV_LENGTH));
    plaintext = Buffer.concat([
      decipher.update(data.subarray(IV_LENGTH, data.length - MAC_LENGTH)),
      decipher.final(),
    ]);
  } catch (e: any) {
    throw new AttachmentError(
      'DECRYPT_FAILED',
      `attachment AES-CBC decryption failed after a valid MAC: ${e?.message ?? e}`
    );
  }

  const out = new Uint8Array(plaintext.buffer, plaintext.byteOffset, plaintext.byteLength);
  return size === undefined ? out : unpadAttachment(out, size);
}

/**
 * Trim sender padding: desktop's `getUnpaddedAttachment`. Everything after
 * `size` is padding regardless of its contents; fewer than `size` bytes is an
 * error.
 */
export function unpadAttachment(data: Uint8Array, size: number): Uint8Array {
  if (data.length === size) return data;
  if (data.length < size) {
    throw new AttachmentError(
      'SIZE_MISMATCH',
      `attachment decrypted to ${data.length} bytes but the pointer says ${size}`
    );
  }
  return data.slice(0, size);
}
