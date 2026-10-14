import { Buffer } from 'buffer';
import type { AttachmentPointer } from '../protocol/wire.js';

export type RedactedAttachmentPointer = Omit<AttachmentPointer, 'key' | 'digest'> & {
  /** '[redacted]' when the pointer carried a key */
  key?: string;
  /** hex SHA-256 of the encrypted blob; not secret */
  digest?: string;
};

/**
 * A copy of the pointer that is safe to log or serialise: the decryption key
 * is replaced by '[redacted]' and the digest (a public hash) becomes hex.
 *
 * `JSON.stringify` on a raw pointer would print the key as a byte array.
 */
export function redactAttachment(pointer: AttachmentPointer): RedactedAttachmentPointer {
  const { key, digest, ...rest } = pointer;
  return {
    ...rest,
    key: key?.length ? '[redacted]' : undefined,
    digest: digest?.length ? Buffer.from(digest).toString('hex') : undefined,
  };
}
