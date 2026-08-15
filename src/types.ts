import type { Persistence } from './persistence/Store.js';

export type Snode = {
  ip: string;
  port: number;
  pubkey_x25519: string;
  pubkey_ed25519: string;
};

export type SeedNode = string; // URL string ending with '/'

export type FetchFn = (input: string, init?: any) => Promise<{
  status: number;
  headers: { get(name: string): string | null };
  json(): Promise<any>;
  text(): Promise<string>;
}>;

export type Logger = {
  info: (...args: any[]) => void;
  warn: (...args: any[]) => void;
  error: (...args: any[]) => void;
};

export type DecryptedEnvelope = {
  /** utf8 message body, when the payload carried a DataMessage */
  body?: string;
  /** sender ID ('bd' + 64 hex), authenticated by the payload signature */
  senderBchatId: string;
  /** the sender's Beldex wallet address, carried in the payload */
  senderWalletAddress?: string;
  /** the sender's display name, if they attached a profile */
  displayName?: string;
  /** DataMessage.timestamp in ms */
  sentAt?: number;
  /** Envelope.timestamp in ms */
  envelopeTimestamp?: number;
  isBnsHolder?: boolean;
};

export interface EncryptionProvider {
  encryptForRecipient(plaintext: Uint8Array, recipientX25519Hex: string): Promise<Uint8Array>;
  decryptForAccount(
    ciphertext: Uint8Array,
    accountX25519PrivHex: string,
    accountX25519PubHex: string
  ): Promise<Uint8Array | null>;
  /**
   * Optional richer decode. Providers that carry sender metadata (like the real
   * BChat protocol) implement this so callers get an authenticated sender ID
   * instead of just the body bytes.
   */
  decryptEnvelope?(
    ciphertext: Uint8Array,
    accountX25519PrivHex: string,
    accountX25519PubHex: string
  ): Promise<DecryptedEnvelope | null>;
}

export type SDKOptions = {
  /** list of seed node base URLs (e.g. https://publicnode1.rpcnode.stream/) */
  seedNodes: SeedNode[];
  /** optional custom fetch (defaults to node-fetch, loaded lazily) */
  fetch?: FetchFn;
  /** timeout in ms for HTTP calls */
  timeoutMs?: number;
  /** logger interface; defaults to console */
  logger?: Logger;
  /**
   * Disable TLS certificate verification for seed and storage node requests.
   * Scoped to this SDK's https.Agent -- it no longer mutates the
   * process-global NODE_TLS_REJECT_UNAUTHORIZED.
   */
  insecureTls?: boolean;
  /** if true, will attempt to use onion transport (currently falls back to direct) */
  useOnion?: boolean;
  /** optional message persistence implementation */
  persistence?: Persistence;
  /** account keys for encryption/decryption */
  account?: {
    x25519: { publicKey: string; privateKey: string };
    ed25519?: { publicKey: string; privateKey: string };
  };
  /** override encryption implementation */
  encryption?: EncryptionProvider;
};

export type SendMessageParams = {
  recipientPubKey: string;
  payload: Uint8Array | string; // raw bytes; string is utf8 encoded before send
  /** message TTL in milliseconds; defaults to 14 days */
  ttlMs?: number;
  /** optional namespace (0 for user, -10 for closed groups etc) */
  namespace?: number;
  /** marks sync messages; forwarded to storage_rpc */
  isSyncMessage?: boolean;
  /** optional client-side identifier passed through */
  messageId?: string;
  /** optional timestamp override (ms); defaults to Date.now() */
  timestampMs?: number;
  /** set to false to send the payload unencrypted; defaults to true */
  encrypt?: boolean;
};

export type GetMessagesParams = {
  pubKey: string;
  /**
   * Last seen message hash. When omitted, a persisted value is used if the SDK
   * was configured with a Persistence implementation.
   */
  lastHash?: string;
  namespace?: number;
  /** ed25519 private key (hex) to sign retrieve; required for authenticated pulls */
  ed25519PrivHex?: string;
  /** ed25519 public key (hex); if provided alongside priv key, included in signature params */
  ed25519PubHex?: string;
  /** decrypt with this x25519 private/public pair; defaults to SDK account */
  decryptWith?: { priv: string; pub: string };
};

// NOTE: `Persistence` is intentionally NOT re-exported here; index.ts already
// re-exports it from ./persistence/Store, and exporting it twice makes the
// star-export in index.ts ambiguous.
