import { promises as fs } from 'fs';
import { join, resolve } from 'path';
import { Persistence, MessageRecord } from './Store.js';

export class FileStore implements Persistence {
  /**
   * Serialises read-modify-write cycles per key. Without this, two concurrent
   * appendMessages()/saveLastHash() calls both read the same snapshot and the
   * second write silently discards the first.
   */
  private queues = new Map<string, Promise<unknown>>();

  constructor(private baseDir: string) {}

  /**
   * Keys come from the network (a pubkey a peer supplied), so they cannot be
   * dropped straight into a path -- `../../foo` would escape baseDir.
   */
  private pathFor(pubKey: string) {
    const safe = pubKey.replace(/[^a-zA-Z0-9_-]/g, '_');
    if (!safe) throw new Error('pubKey is required');
    const file = resolve(join(this.baseDir, `${safe}.json`));
    const root = resolve(this.baseDir);
    if (file !== join(root, `${safe}.json`)) {
      throw new Error(`refusing to write outside ${root}`);
    }
    return file;
  }

  private enqueue<T>(pubKey: string, task: () => Promise<T>): Promise<T> {
    const previous = this.queues.get(pubKey) ?? Promise.resolve();
    const next = previous.then(task, task);
    this.queues.set(
      pubKey,
      next.catch(() => undefined)
    );
    return next;
  }

  async saveLastHash(pubKey: string, hash: string): Promise<void> {
    return this.enqueue(pubKey, async () => {
      const data = await this.read(pubKey);
      data.lastHash = hash;
      await this.write(pubKey, data);
    });
  }

  async getLastHash(pubKey: string): Promise<string | undefined> {
    const data = await this.read(pubKey);
    return data.lastHash;
  }

  async appendMessages(pubKey: string, messages: MessageRecord[]): Promise<void> {
    if (!messages.length) return;
    return this.enqueue(pubKey, async () => {
      const data = await this.read(pubKey);
      data.messages = [...(data.messages || []), ...messages];
      await this.write(pubKey, data);
    });
  }

  async listMessages(pubKey: string): Promise<MessageRecord[]> {
    const data = await this.read(pubKey);
    return data.messages || [];
  }

  private async read(pubKey: string): Promise<any> {
    const file = this.pathFor(pubKey);
    try {
      const content = await fs.readFile(file, 'utf8');
      return JSON.parse(content);
    } catch (e: any) {
      if (e?.code === 'ENOENT') return {};
      // A truncated/corrupt cache file should not make every later call throw.
      if (e instanceof SyntaxError) return {};
      throw e;
    }
  }

  private async write(pubKey: string, data: any): Promise<void> {
    const file = this.pathFor(pubKey);
    await fs.mkdir(resolve(this.baseDir), { recursive: true });
    // Write-then-rename so a crash mid-write cannot leave a half-written file.
    const tmp = `${file}.${process.pid}.tmp`;
    await fs.writeFile(tmp, JSON.stringify(data, null, 2), 'utf8');
    await fs.rename(tmp, file);
  }
}
