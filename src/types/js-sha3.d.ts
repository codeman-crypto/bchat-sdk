declare module 'js-sha3' {
  type Hasher = {
    (message: Uint8Array | string): string;
    array(message: Uint8Array | string): number[];
    arrayBuffer(message: Uint8Array | string): ArrayBuffer;
    digest(message: Uint8Array | string): number[];
    hex(message: Uint8Array | string): string;
  };

  const sha3: {
    keccak256: Hasher;
    sha3_256: Hasher;
  };

  export default sha3;
}
