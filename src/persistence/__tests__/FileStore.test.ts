import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, readdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { FileStore } from '../FileStore';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'bchat-store-'));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('FileStore', () => {
  it('stores and reads back a cursor', async () => {
    const store = new FileStore(dir);
    expect(await store.getLastHash('abc')).toBeUndefined();
    await store.saveLastHash('abc', 'hash-1');
    expect(await store.getLastHash('abc')).toBe('hash-1');
  });

  it('does not let a hostile pubKey escape the base directory', async () => {
    const store = new FileStore(dir);
    await store.saveLastHash('../../evil', 'x');
    const files = readdirSync(dir);
    expect(files).toHaveLength(1);
    expect(files[0]).not.toContain('..');
  });

  it('does not lose writes when appends run concurrently', async () => {
    const store = new FileStore(dir);
    await Promise.all(
      Array.from({ length: 20 }, (_, i) =>
        store.appendMessages('abc', [{ hash: `h${i}`, receivedAt: i }])
      )
    );
    expect(await store.listMessages('abc')).toHaveLength(20);
  });
});
