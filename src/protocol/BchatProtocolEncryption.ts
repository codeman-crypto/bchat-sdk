import sodium from 'libsodium-wrappers-sumo';
import { Buffer } from 'buffer';
import type { DecryptedEnvelope, EncryptionProvider } from '../types.js';
import { normalizeX25519Hex } from '../crypto/encryption.js';
import { BCHAT_ID_PREFIX } from '../account.js';
import { addMessagePadding, removeMessagePadding } from './padding.js';
import {
  EnvelopeType,
  decodeContent,
  decodeEnvelope,
  encodeContent,
  encodeEnvelope,
  unwrapEnvelope,
  wrapEnvelope,
} from './wire.js';

const ED25519_PUBLIC_KEY_BYTES = 32;
const ED25519_SIGNATURE_BYTES = 64;

/** Tolerance for a sender's clock running ahead of ours. */
export const MAX_CLOCK_SKEW_MS = 15 * 60 * 1000;
/** Oldest message we will accept; matches the default store TTL. */
export const MAX_MESSAGE_AGE_MS = 14 * 24 * 60 * 60 * 1000;

/**
 * Beldex address lengths, as hardcoded on bchat-desktop's decrypt path. These
 * follow from the network prefix varint width -- see src/wallet/address.ts.
 */
export const BELDEX_ADDRESS_LENGTH = { mainnet: 97, testnet: 95 } as const;
export type BeldexNetwork = keyof typeof BELDEX_ADDRESS_LENGTH;

const concat = (...parts: Uint8Array[]): Uint8Array => {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};

export type BchatProtocolOptions = {
  /** hex ed25519 identity keypair; the private key must be 64 bytes */
  ed25519: { publicKey: string; privateKey: string };
  /**
   * Your Beldex wallet address.
   *
   * bchat-desktop prepends this to every message before signing, and slices it
   * back off on receipt using a *hardcoded* length (97 mainnet / 95 testnet).
   * A message without it — or with one of the wrong length — is silently
   * mis-sliced by the real client, so it is required rather than optional.
   */
  beldexAddress: string;
  network?: BeldexNetwork;
  /** optional display name attached to outgoing messages */
  displayName?: string;
};

/**
 * The real BChat wire protocol, interoperable with the official clients.
 *
 * Outgoing:
 *   Content protobuf → pad to a multiple of 160
 *   → walletAddress ‖ padded ‖ senderEdPub ‖ sign(walletAddress ‖ padded ‖ senderEdPub ‖ recipientX25519)
 *   → crypto_box_seal to the recipient
 *   → Envelope protobuf → WebSocketMessage protobuf → base64
 *
 * Incoming is the exact inverse, and the signature is verified before the
 * sender ID is trusted.
 */
export class BchatProtocolEncryption implements EncryptionProvider {
  private readonly edPublicKey: Buffer;
  private readonly edPrivateKey: Buffer;
  private readonly beldexAddress: Buffer;
  private readonly addressLength: number;
  private readonly displayName?: string;

  constructor(opts: BchatProtocolOptions) {
    this.edPublicKey = Buffer.from(opts.ed25519.publicKey, 'hex');
    this.edPrivateKey = Buffer.from(opts.ed25519.privateKey, 'hex');
    if (this.edPublicKey.length !== ED25519_PUBLIC_KEY_BYTES) {
      throw new Error(`ed25519 public key must be 32 bytes, got ${this.edPublicKey.length}`);
    }
    if (this.edPrivateKey.length !== 64) {
      throw new Error(`ed25519 private key must be 64 bytes, got ${this.edPrivateKey.length}`);
    }

    const network: BeldexNetwork = opts.network ?? 'mainnet';
    this.addressLength = BELDEX_ADDRESS_LENGTH[network];
    if (!BELDEX_ADDRESS_LENGTH[network]) {
      throw new Error(`unknown network "${network}"`);
    }

    this.beldexAddress = Buffer.from(opts.beldexAddress ?? '', 'utf8');
    if (this.beldexAddress.length !== this.addressLength) {
      throw new Error(
        `beldexAddress must be exactly ${this.addressLength} characters on ${network}, ` +
          `got ${this.beldexAddress.length}. The receiving client slices this length off ` +
          `every message, so a wrong length corrupts the payload.`
      );
    }

    this.displayName = opts.displayName;
  }

  /** Wraps `plaintext` (a utf8 message body) into a full BChat payload. */
  async encryptForRecipient(plaintext: Uint8Array, recipientX25519Hex: string): Promise<Uint8Array> {
    await sodium.ready;
    const recipient = normalizeX25519Hex(recipientX25519Hex, 'recipient BChat ID');
    const timestamp = Date.now();

    const content = encodeContent({
      body: Buffer.from(plaintext).toString('utf8'),
      timestamp,
      profile: this.displayName ? { displayName: this.displayName } : undefined,
    });

    const padded = addMessagePadding(content);
    const withAddress = concat(this.beldexAddress, padded);

    const verificationData = concat(withAddress, this.edPublicKey, recipient);
    const signature = sodium.crypto_sign_detached(verificationData, this.edPrivateKey);

    const plaintextWithMetadata = concat(withAddress, this.edPublicKey, signature);
    const ciphertext = sodium.crypto_box_seal(plaintextWithMetadata, recipient);

    return wrapEnvelope(
      encodeEnvelope({ type: EnvelopeType.BCHAT_MESSAGE, timestamp, content: ciphertext })
    );
  }

  /** EncryptionProvider contract: returns just the message body bytes. */
  async decryptForAccount(
    payload: Uint8Array,
    accountX25519PrivHex: string,
    accountX25519PubHex: string
  ): Promise<Uint8Array | null> {
    const decoded = await this.decryptEnvelope(payload, accountX25519PrivHex, accountX25519PubHex);
    if (!decoded || decoded.body === undefined) return null;
    return Buffer.from(decoded.body, 'utf8');
  }

  /** Full decode, including the cryptographically verified sender ID. */
  async decryptEnvelope(
    payload: Uint8Array,
    accountX25519PrivHex: string,
    accountX25519PubHex: string
  ): Promise<DecryptedEnvelope | null> {
    await sodium.ready;

    let envelope;
    try {
      envelope = decodeEnvelope(unwrapEnvelope(payload));
    } catch {
      return null; // not a BChat payload at all
    }

    if (envelope.type !== EnvelopeType.BCHAT_MESSAGE) return null;
    if (!envelope.content?.length) return null;

    const ourPub = normalizeX25519Hex(accountX25519PubHex, 'account x25519 pubkey');
    const ourPriv = normalizeX25519Hex(accountX25519PrivHex, 'account x25519 privkey');

    let blob: Uint8Array;
    try {
      blob = sodium.crypto_box_seal_open(envelope.content, ourPub, ourPriv);
    } catch {
      return null; // not addressed to us
    }

    if (blob.length <= ED25519_SIGNATURE_BYTES + ED25519_PUBLIC_KEY_BYTES) return null;

    const signatureStart = blob.length - ED25519_SIGNATURE_BYTES;
    const pubkeyStart = signatureStart - ED25519_PUBLIC_KEY_BYTES;
    const signature = blob.subarray(signatureStart);
    const senderEdPublicKey = blob.subarray(pubkeyStart, signatureStart);
    const signed = blob.subarray(0, pubkeyStart); // walletAddress ‖ padded content

    const valid = sodium.crypto_sign_verify_detached(
      signature,
      concat(signed, senderEdPublicKey, ourPub),
      senderEdPublicKey
    );
    // The signature is what binds the payload to a sender; without this check
    // the sender ID below would be attacker-chosen.
    if (!valid) throw new Error('Invalid message signature');

    // BCHAT-05: a byte-identical payload verifies forever, so bound freshness
    // here. Without this a captured "yes, go ahead" can be re-served later by a
    // hostile node and will be accepted as new.
    const timestamp = envelope.timestamp;
    const age = Date.now() - timestamp;
    if (!Number.isFinite(timestamp) || age > MAX_MESSAGE_AGE_MS || age < -MAX_CLOCK_SKEW_MS) {
      return null;
    }

    const senderX25519 = sodium.crypto_sign_ed25519_pk_to_curve25519(senderEdPublicKey);
    const senderBchatId = `${BCHAT_ID_PREFIX}${Buffer.from(senderX25519).toString('hex')}`;

    if (signed.length < this.addressLength) return null;
    const senderWalletAddress = Buffer.from(signed.subarray(0, this.addressLength)).toString('utf8');

    let content: ReturnType<typeof decodeContent> | undefined;
    try {
      content = decodeContent(removeMessagePadding(signed.subarray(this.addressLength)));
    } catch {
      content = undefined;
    }
    const dataMessage = content?.dataMessage;

    return {
      kind: content?.kind ?? 'unknown',
      body: dataMessage?.body,
      quote: dataMessage?.quote,
      reaction: dataMessage?.reaction,
      senderBchatId,
      // Named to make the trust level impossible to miss at the call site.
      unverifiedSenderWalletAddress: senderWalletAddress,
      displayName: dataMessage?.profile?.displayName,
      sentAt: dataMessage?.timestamp,
      envelopeTimestamp: envelope.timestamp,
      isBnsHolder: envelope.isBnsHolder,
    };
  }
}
