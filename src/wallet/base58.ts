/**
 * Monero-flavoured base58: the data is chunked into 8-byte blocks, each encoded
 * to a fixed number of characters. This is NOT the same as Bitcoin base58.
 */
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const FULL_BLOCK_SIZE = 8;
/** encoded length for a block of 0..8 bytes */
const ENCODED_BLOCK_SIZES = [0, 2, 3, 5, 6, 7, 9, 10, 11];
const FULL_ENCODED_BLOCK_SIZE = ENCODED_BLOCK_SIZES[FULL_BLOCK_SIZE]!;

function encodeBlock(data: Uint8Array): string {
  const size = ENCODED_BLOCK_SIZES[data.length];
  if (size === undefined) throw new Error(`invalid block size ${data.length}`);

  let num = 0n;
  for (const byte of data) num = (num << 8n) | BigInt(byte);

  const chars = new Array<string>(size).fill(ALPHABET[0]!);
  let i = size - 1;
  while (num > 0n) {
    chars[i--] = ALPHABET[Number(num % 58n)]!;
    num /= 58n;
  }
  return chars.join('');
}

function decodeBlock(str: string): Uint8Array {
  const size = ENCODED_BLOCK_SIZES.indexOf(str.length);
  if (size <= 0) throw new Error(`invalid encoded block length ${str.length}`);

  let num = 0n;
  for (const ch of str) {
    const index = ALPHABET.indexOf(ch);
    if (index < 0) throw new Error(`invalid base58 character "${ch}"`);
    num = num * 58n + BigInt(index);
  }
  if (num >= 1n << BigInt(size * 8)) throw new Error('base58 block overflow');

  const out = new Uint8Array(size);
  for (let i = size - 1; i >= 0; i--) {
    out[i] = Number(num & 0xffn);
    num >>= 8n;
  }
  return out;
}

export function base58Encode(data: Uint8Array): string {
  const fullBlocks = Math.floor(data.length / FULL_BLOCK_SIZE);
  const remainder = data.length % FULL_BLOCK_SIZE;

  let out = '';
  for (let i = 0; i < fullBlocks; i++) {
    out += encodeBlock(data.subarray(i * FULL_BLOCK_SIZE, (i + 1) * FULL_BLOCK_SIZE));
  }
  if (remainder > 0) out += encodeBlock(data.subarray(fullBlocks * FULL_BLOCK_SIZE));
  return out;
}

export function base58Decode(str: string): Uint8Array {
  const fullBlocks = Math.floor(str.length / FULL_ENCODED_BLOCK_SIZE);
  const remainder = str.length % FULL_ENCODED_BLOCK_SIZE;

  const parts: Uint8Array[] = [];
  for (let i = 0; i < fullBlocks; i++) {
    parts.push(
      decodeBlock(str.slice(i * FULL_ENCODED_BLOCK_SIZE, (i + 1) * FULL_ENCODED_BLOCK_SIZE))
    );
  }
  if (remainder > 0) parts.push(decodeBlock(str.slice(fullBlocks * FULL_ENCODED_BLOCK_SIZE)));

  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
