/**
 * Minimal exponential-backoff retry helper.
 *
 * This replaces `p-retry`, which ships as ESM-only from v6. Because this package
 * also emits a CommonJS build (and `bin` points at `dist/cjs/cli.js`), a plain
 * `require('p-retry')` throws ERR_REQUIRE_ESM on every Node version below 22.12
 * even though `engines` claims `>=18`.
 */

/** Throw this from a retried function to stop retrying immediately. */
export class AbortError extends Error {
  readonly originalError: Error;

  constructor(error: Error | string) {
    const original = typeof error === 'string' ? new Error(error) : error;
    super(original.message);
    this.name = 'AbortError';
    this.originalError = original;
  }
}

export type RetryOptions = {
  /** number of *additional* attempts after the first one */
  retries?: number;
  /** delay before the first retry, in ms */
  minTimeout?: number;
  /** upper bound on the backoff delay, in ms */
  maxTimeout?: number;
  factor?: number;
  onFailedAttempt?: (error: Error, attempt: number) => void;
};

const sleep = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms));

const toError = (value: unknown): Error =>
  value instanceof Error ? value : new Error(String(value));

export async function retry<T>(
  fn: (attempt: number) => Promise<T>,
  options: RetryOptions = {}
): Promise<T> {
  const {
    retries = 3,
    minTimeout = 250,
    maxTimeout = 5_000,
    factor = 2,
    onFailedAttempt,
  } = options;

  let lastError = new Error('retry() was called but no attempt ran');

  for (let attempt = 1; attempt <= retries + 1; attempt++) {
    try {
      return await fn(attempt);
    } catch (error) {
      if (error instanceof AbortError) {
        throw error.originalError;
      }
      lastError = toError(error);
      onFailedAttempt?.(lastError, attempt);
      if (attempt > retries) break;
      await sleep(Math.min(minTimeout * factor ** (attempt - 1), maxTimeout));
    }
  }

  throw lastError;
}
