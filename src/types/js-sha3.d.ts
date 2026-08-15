declare module 'js-sha3' {
  type Hasher = {
    (message: Uint8Array | string): string;
    array(message: Uint8Array | string): number[];
    arrayBuffer(message: Uint8Array | string): ArrayBuffer;
    digest(message: Uint8Array | string): number[];
    hex(message: Uint8Array | string): string;
  };
  export const keccak256: Hasher;
  export const sha3_256: Hasher;
}
