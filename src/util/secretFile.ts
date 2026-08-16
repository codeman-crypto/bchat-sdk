import { chmodSync, closeSync, openSync, writeFileSync } from 'fs';

const SECRET_MODE = 0o600;

/**
 * Write a file containing key material.
 *
 * `writeFileSync(path, data, { mode })` only applies `mode` when open(2)
 * *creates* the file — writing over an existing path silently keeps whatever
 * permissions were already there. So an identity file written twice, or written
 * to a path the user pre-created with `touch`, ended up world-readable despite
 * the code asking for 0600.
 *
 * Opening with 'wx' refuses to clobber, and the explicit chmod covers the case
 * where the mode was not honoured.
 */
export function writeSecretFile(path: string, contents: string): void {
  let fd: number;
  try {
    fd = openSync(path, 'wx', SECRET_MODE);
  } catch (e: any) {
    if (e?.code === 'EEXIST') {
      throw new Error(
        `${path} already exists — refusing to overwrite a file containing key material. ` +
          `Move or delete it first if you really mean to replace it.`
      );
    }
    throw e;
  }

  try {
    writeFileSync(fd, contents, 'utf8');
  } finally {
    closeSync(fd);
  }
  chmodSync(path, SECRET_MODE);
}
