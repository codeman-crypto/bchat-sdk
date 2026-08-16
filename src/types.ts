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
  /**
   * What the payload actually was. Only `'message'` carries text — a
   * `'reaction'`, `'typing'` or `'receipt'` decrypts perfectly well but has no
   * body, so an absent `body` is not a decryption failure.
   */
  kind?:
    | 'message'
    | 'reaction'
    | 'call'
    | 'receipt'
    | 'typing'
    | 'configuration'
    | 'dataExtraction'
    | 'unsend'
    | 'messageRequestResponse'
    | 'unknown';
  /** utf8 message body, when the payload carried a DataMessage with text */
  body?: string;
  /**
   * Present when the message is a reply.
   *
   * `kind` stays `'message'` for a reply: it is an ordinary text message that
   * happens to quote another one. Giving it its own kind would mean any
   * consumer switching on `kind` silently dropped replies.
   */
  quote?: {
    /** sent-timestamp of the message being replied to */
    messageTimestamp?: number;
    author?: string;
    text?: string;
  };
  /** present when `kind` is 'reaction' */
  reaction?: {
    /** sent-timestamp of the message being reacted to */
    messageTimestamp?: number;
    author?: string;
    emoji?: string;
    /** 0 = react, 1 = remove */
    action?: number;
  };
  /** sender ID ('bd' + 64 hex), authenticated by the payload signature */
  senderBchatId: string;
  /**
   * UNVERIFIED. The Beldex wallet address the sender *claims*.
   *
   * It sits inside the signed region, but the sender signs their own claim and
   * nothing binds this string to `senderBchatId` — the two derive from one seed
   * by a one-way function, so a recipient cannot recompute the expected value.
   * Any sender can embed any address.
   *
   * Never use it as a payment destination without out-of-band confirmation.
   */
  unverifiedSenderWalletAddress?: string;
  /** UNVERIFIED. Display name chosen by the sender; treat as untrusted text. */
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
  /**
   * Accept self-signed certificates **from storage nodes only**. Seed node
   * certificates are still fully verified.
   *
   * Storage nodes on the BChat network serve self-signed certificates by
   * design — there is no PKI for them — so this is required for the SDK to
   * talk to the live network at all. It is a separate option from
   * `insecureTls` precisely so that enabling it does not also stop verifying
   * the seed nodes, which do have real certificates.
   *
   * This does not weaken message confidentiality (bodies are sealed boxes),
   * but it does mean an on-path attacker can observe and tamper with storage
   * node traffic metadata. The durable fix is authenticating nodes by their
   * `pubkey_ed25519` — see "Security model" in the README.
   */
  allowSelfSignedStorageNodes?: boolean;
  /**
   * Permit storage nodes on loopback / RFC1918 addresses. Off by default so a
   * hostile node cannot point the SDK at localhost services or cloud metadata
   * endpoints. Enable only when running against a node on your own machine.
   */
  allowPrivateNodes?: boolean;
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
