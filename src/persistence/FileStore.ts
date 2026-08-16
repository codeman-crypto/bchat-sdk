import { promises as fs } from 'fs';
import { createHash, randomBytes } from 'crypto';
import { join, resolve } from 'path';
import { Persistence, MessageRecord } from './Store.js';

/** Cap on retained history per pubkey; the file is rewritten on every append. */
export const MAX_RETAINED_MESSAGES = 5_000;
/** Cap on retained replay-guard digests per pubkey. */
export const MAX_RETAINED_DIGESTS = 5_000;

const DIR_MODE = 0o700;
const FILE_MODE = 0o600;

export class FileStore implements Persistence {
  /**
   * Serialises read-modify-write cycles per key. Without this, two concurrent
   * appendMessages()/saveLastHash() calls both read the same snapshot and the
   * second write silently discards the first.
   */
  private queues = new Map<string, Promise<unknown>>();
  private ensuredDir = false;

  constructor(private baseDir: string) {}

  /**
   * Keys come from the network, so they cannot be dropped straight into a path.
   * Hashing rather than character-replacing avoids both traversal *and* the
   * collision where `bd<hex>` and `bd:<hex>` mapped onto the same file.
   */
  private pathFor(pubKey: string) {
    if (!pubKey) throw new Error('pubKey is required');
    const name = createHash('sha256').update(pubKey, 'utf8').digest('hex');
    return resolve(join(this.baseDir, `${name}.json`));
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
      const merged = [...(data.messages || []), ...messages];
      // Anyone who knows a BChat ID can write to the mailbox, so history has to
      // be bounded or a bot's cache grows without limit (and rewriting it every
      // poll turns into O(n^2) I/O).
      data.messages = merged.slice(-MAX_RETAINED_MESSAGES);
      await this.write(pubKey, data);
    });
  }

  async listMessages(pubKey: string): Promise<MessageRecord[]> {
    const data = await this.read(pubKey);
    return data.messages || [];
  }

  async hasSeen(pubKey: string, digest: string): Promise<boolean> {
    const data = await this.read(pubKey);
    return Array.isArray(data.seen) ? data.seen.includes(digest) : false;
  }

  async markSeen(pubKey: string, digest: string): Promise<void> {
    return this.enqueue(pubKey, async () => {
      const data = await this.read(pubKey);
      const seen: string[] = Array.isArray(data.seen) ? data.seen : [];
      if (seen.includes(digest)) return;
      seen.push(digest);
      data.seen = seen.slice(-MAX_RETAINED_DIGESTS);
      await this.write(pubKey, data);
    });
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

  /**
   * These files hold decrypted message plaintext and the retrieval cursor, so
   * they must not be left at the umask default (0644 in a 0755 directory would
   * expose the entire message history to every local user).
   */
  private async ensureDir(): Promise<string> {
    const dir = resolve(this.baseDir);
    await fs.mkdir(dir, { recursive: true, mode: DIR_MODE });
    if (!this.ensuredDir) {
      // `mkdir`'s mode only applies to directories it creates, so tighten an
      // existing one too.
      await fs.chmod(dir, DIR_MODE).catch(() => undefined);
      this.ensuredDir = true;
    }
    return dir;
  }

  private async write(pubKey: string, data: any): Promise<void> {
    const file = this.pathFor(pubKey);
    await this.ensureDir();

    // Random suffix as well as the pid: two processes can share a pid across
    // namespaces, and a predictable temp name is a symlink-swap target.
    const tmp = `${file}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
    await fs.writeFile(tmp, JSON.stringify(data, null, 2), {
      encoding: 'utf8',
      mode: FILE_MODE,
    });
    // `mode` is only honoured on create; chmod unconditionally.
    await fs.chmod(tmp, FILE_MODE);
    await fs.rename(tmp, file);
  }
}
