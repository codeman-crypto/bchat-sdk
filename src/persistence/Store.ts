export interface MessageRecord {
  hash?: string;
  body?: any;
  raw?: string;
  receivedAt: number;
}

export interface Persistence {
  saveLastHash(pubKey: string, hash: string): Promise<void>;
  getLastHash(pubKey: string): Promise<string | undefined>;
  appendMessages(pubKey: string, messages: MessageRecord[]): Promise<void>;
  listMessages(pubKey: string): Promise<MessageRecord[]>;
}
