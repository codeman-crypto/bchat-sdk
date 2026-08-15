/**
 * CRC32 (IEEE 802.3), used to pick the mnemonic checksum word.
 *
 * bchat-desktop uses the `buffer-crc32` package for this; a table-driven
 * implementation is ~20 lines and keeps the dependency out of the tree.
 */
const TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
})();

/** Unsigned CRC32 of a utf8 string, matching `crc32.unsigned(...)`. */
export function crc32(input: string): number {
  const bytes = Buffer.from(input, 'utf8');
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    crc = TABLE[(crc ^ bytes[i]!) & 0xff]! ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}
