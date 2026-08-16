export interface MessageRecord {
  hash?: string;
  /**
   * Decrypted message text. Undefined when the payload could not be opened --
   * it is deliberately NOT backfilled with the raw ciphertext, so a consumer
   * can never mistake attacker-supplied bytes for message content.
   */
  body?: string;
  /** the raw base64 payload exactly as the storage node served it */
  raw?: string;
  /** whether `body` is present and trustworthy */
  decrypted?: boolean;
  /** authenticated sender ID, when the encryption provider reports one */
  sender?: string;
  receivedAt: number;
}

export interface Persistence {
  saveLastHash(pubKey: string, hash: string): Promise<void>;
  getLastHash(pubKey: string): Promise<string | undefined>;
  appendMessages(pubKey: string, messages: MessageRecord[]): Promise<void>;
  listMessages(pubKey: string): Promise<MessageRecord[]>;

  /**
   * Optional durable replay guard. When implemented, `SnodeClient` records a
   * digest of every payload it accepts so a message cannot be re-served as new
   * after a restart. Implementations may bound the set however they like.
   */
  hasSeen?(pubKey: string, digest: string): Promise<boolean>;
  markSeen?(pubKey: string, digest: string): Promise<void>;
}
