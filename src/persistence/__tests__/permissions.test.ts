import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { FileStore, MAX_RETAINED_MESSAGES } from '../FileStore';
import { writeSecretFile } from '../../util/secretFile';

let dir: string;
const mode = (p: string) => statSync(p).mode & 0o777;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'bchat-perm-'));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('FileStore permissions (BCHAT-06)', () => {
  it('writes cache files 0600 inside a 0700 directory', async () => {
    const base = join(dir, 'cache');
    const store = new FileStore(base);
    await store.saveLastHash('bd00', 'h1');

    expect(mode(base)).toBe(0o700);
    const file = readdirSync(base)[0]!;
    expect(mode(join(base, file))).toBe(0o600);
  });

  it('tightens a pre-existing world-readable directory', async () => {
    const base = join(dir, 'preexisting');
    mkdirSync(base, { mode: 0o755 });
    chmodSync(base, 0o755);

    const store = new FileStore(base);
    await store.saveLastHash('bd00', 'h1');
    expect(mode(base)).toBe(0o700);
  });

  it('hashes the key so distinct pubkeys never collide (BCHAT-17)', async () => {
    const store = new FileStore(dir);
    await store.saveLastHash('bd00', 'first');
    await store.saveLastHash('bd:00', 'second');

    expect(await store.getLastHash('bd00')).toBe('first');
    expect(await store.getLastHash('bd:00')).toBe('second');
    expect(readdirSync(dir)).toHaveLength(2);
  });

  it('still refuses to escape the base directory', async () => {
    const store = new FileStore(dir);
    await store.saveLastHash('../../evil', 'x');
    const files = readdirSync(dir);
    expect(files).toHaveLength(1);
    expect(files[0]).toMatch(/^[0-9a-f]{64}\.json$/);
  });
});

describe('FileStore growth bounds (BCHAT-09)', () => {
  it('caps retained history', async () => {
    const store = new FileStore(dir);
    const batch = Array.from({ length: 1_000 }, (_, i) => ({ hash: `h${i}`, receivedAt: i }));
    for (let i = 0; i < 6; i++) await store.appendMessages('bd00', batch);

    const kept = await store.listMessages('bd00');
    expect(kept.length).toBe(MAX_RETAINED_MESSAGES);
    // keeps the newest
    expect(kept[kept.length - 1]!.hash).toBe('h999');
  });

  it('caps the persisted replay-guard set', async () => {
    const store = new FileStore(dir);
    await store.markSeen('bd00', 'digest-a');
    expect(await store.hasSeen('bd00', 'digest-a')).toBe(true);
    expect(await store.hasSeen('bd00', 'digest-b')).toBe(false);
  });
});

describe('writeSecretFile (BCHAT-08)', () => {
  it('creates the file 0600', () => {
    const file = join(dir, 'id.json');
    writeSecretFile(file, '{"mnemonic":"x"}');
    expect(mode(file)).toBe(0o600);
    expect(readFileSync(file, 'utf8')).toBe('{"mnemonic":"x"}');
  });

  it('refuses to overwrite an existing file', () => {
    const file = join(dir, 'id.json');
    writeFileSync(file, 'old', { mode: 0o644 });
    expect(() => writeSecretFile(file, 'new')).toThrow(/refusing to overwrite/);
    // and leaves the original untouched
    expect(readFileSync(file, 'utf8')).toBe('old');
  });

  it('is not fooled by a pre-created 0644 path, unlike writeFileSync', () => {
    const loose = join(dir, 'loose.json');
    writeFileSync(loose, '');
    chmodSync(loose, 0o644);
    // demonstrates the original bug: mode is ignored on an existing file
    writeFileSync(loose, 'secret', { mode: 0o600 });
    expect(mode(loose)).toBe(0o644);

    // writeSecretFile refuses instead of silently leaving it exposed
    expect(() => writeSecretFile(loose, 'secret')).toThrow(/refusing to overwrite/);
  });
});
