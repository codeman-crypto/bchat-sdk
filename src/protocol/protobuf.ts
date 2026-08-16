/**
 * Minimal protobuf wire-format codec.
 *
 * The BChat/Session payloads this SDK needs are a handful of simple messages,
 * so hand-encoding the wire format avoids pulling protobufjs (and its codegen
 * step) into the dependency tree.
 *
 * Wire types used here: 0 = varint, 1 = fixed64, 2 = length-delimited,
 * 5 = fixed32. Groups (3/4) are not supported and are rejected.
 */
import { Buffer } from 'buffer';

export const WIRE_VARINT = 0;
export const WIRE_FIXED64 = 1;
export const WIRE_BYTES = 2;
export const WIRE_FIXED32 = 5;

export class ProtoWriter {
  private parts: number[] = [];

  private varint(value: number | bigint): void {
    let v = typeof value === 'bigint' ? value : BigInt(Math.trunc(value));
    if (v < 0n) v += 1n << 64n; // two's complement, matching protobuf int32/int64
    while (v >= 0x80n) {
      this.parts.push(Number((v & 0x7fn) | 0x80n));
      v >>= 7n;
    }
    this.parts.push(Number(v));
  }

  private tag(field: number, wire: number): void {
    this.varint((field << 3) | wire);
  }

  /** proto2 optional scalars are omitted when undefined (not when 0/false). */
  uint(field: number, value?: number | bigint): this {
    if (value === undefined || value === null) return this;
    this.tag(field, WIRE_VARINT);
    this.varint(value);
    return this;
  }

  bool(field: number, value?: boolean): this {
    if (value === undefined || value === null) return this;
    return this.uint(field, value ? 1 : 0);
  }

  bytes(field: number, value?: Uint8Array): this {
    if (value === undefined || value === null) return this;
    this.tag(field, WIRE_BYTES);
    this.varint(value.length);
    for (let i = 0; i < value.length; i++) this.parts.push(value[i]!);
    return this;
  }

  string(field: number, value?: string): this {
    if (value === undefined || value === null) return this;
    return this.bytes(field, Buffer.from(value, 'utf8'));
  }

  message(field: number, sub?: ProtoWriter): this {
    if (!sub) return this;
    return this.bytes(field, sub.finish());
  }

  finish(): Uint8Array {
    return Uint8Array.from(this.parts);
  }
}

export type ProtoValue = bigint | Uint8Array;

/** Decodes a message into field number -> values (repeated fields keep order). */
export function decodeFields(buf: Uint8Array): Map<number, ProtoValue[]> {
  const out = new Map<number, ProtoValue[]>();
  let i = 0;

  const push = (field: number, value: ProtoValue) => {
    const existing = out.get(field);
    if (existing) existing.push(value);
    else out.set(field, [value]);
  };

  const varint = (): bigint => {
    let shift = 0n;
    let result = 0n;
    for (;;) {
      if (i >= buf.length) throw new Error('protobuf: truncated varint');
      const byte = buf[i++]!;
      result |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) return result;
      shift += 7n;
      if (shift > 63n) throw new Error('protobuf: varint overflow');
    }
  };

  const take = (n: number): Uint8Array => {
    if (i + n > buf.length) throw new Error('protobuf: truncated field');
    const slice = buf.subarray(i, i + n);
    i += n;
    return slice;
  };

  while (i < buf.length) {
    const key = varint();
    const field = Number(key >> 3n);
    const wire = Number(key & 7n);
    if (field === 0) throw new Error('protobuf: invalid field number 0');

    switch (wire) {
      case WIRE_VARINT:
        push(field, varint());
        break;
      case WIRE_FIXED64:
        push(field, take(8));
        break;
      case WIRE_BYTES:
        push(field, take(Number(varint())));
        break;
      case WIRE_FIXED32:
        push(field, take(4));
        break;
      default:
        throw new Error(`protobuf: unsupported wire type ${wire}`);
    }
  }

  return out;
}

export const firstBytes = (
  fields: Map<number, ProtoValue[]>,
  field: number
): Uint8Array | undefined => {
  const value = fields.get(field)?.[0];
  return value instanceof Uint8Array ? value : undefined;
};

export const firstNumber = (
  fields: Map<number, ProtoValue[]>,
  field: number
): number | undefined => {
  const value = fields.get(field)?.[0];
  return typeof value === 'bigint' ? Number(value) : undefined;
};

/** All values for a repeated length-delimited field, in wire order. */
export const allBytes = (
  fields: Map<number, ProtoValue[]>,
  field: number
): Uint8Array[] =>
  (fields.get(field) ?? []).filter((v): v is Uint8Array => v instanceof Uint8Array);

/** All values for a repeated varint field, in wire order. */
export const allNumbers = (fields: Map<number, ProtoValue[]>, field: number): number[] =>
  (fields.get(field) ?? [])
    .filter((v): v is bigint => typeof v === 'bigint')
    .map(v => Number(v));

/** Little-endian fixed64, returned as a decimal string to avoid precision loss. */
export const firstFixed64 = (
  fields: Map<number, ProtoValue[]>,
  field: number
): string | undefined => {
  const value = fields.get(field)?.[0];
  if (!(value instanceof Uint8Array) || value.length !== 8) return undefined;
  let n = 0n;
  for (let i = 7; i >= 0; i--) n = (n << 8n) | BigInt(value[i]!);
  return n.toString();
};

export const firstString = (
  fields: Map<number, ProtoValue[]>,
  field: number
): string | undefined => {
  const value = firstBytes(fields, field);
  return value === undefined ? undefined : Buffer.from(value).toString('utf8');
};
