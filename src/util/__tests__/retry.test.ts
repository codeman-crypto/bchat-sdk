import { describe, it, expect, vi } from 'vitest';
import { retry, AbortError } from '../retry';

describe('retry', () => {
  it('retries until success and reports attempts', async () => {
    const onFailedAttempt = vi.fn();
    let calls = 0;
    const result = await retry(
      async () => {
        calls++;
        if (calls < 3) throw new Error('nope');
        return 'ok';
      },
      { retries: 3, minTimeout: 1, onFailedAttempt }
    );

    expect(result).toBe('ok');
    expect(calls).toBe(3);
    expect(onFailedAttempt).toHaveBeenCalledTimes(2);
  });

  it('makes exactly retries + 1 attempts before giving up', async () => {
    let calls = 0;
    await expect(
      retry(
        async () => {
          calls++;
          throw new Error('always');
        },
        { retries: 2, minTimeout: 1 }
      )
    ).rejects.toThrow('always');
    expect(calls).toBe(3);
  });

  it('stops immediately on AbortError and unwraps it', async () => {
    let calls = 0;
    await expect(
      retry(
        async () => {
          calls++;
          throw new AbortError('exhausted');
        },
        { retries: 5, minTimeout: 1 }
      )
    ).rejects.toThrow('exhausted');
    expect(calls).toBe(1);
  });
});
