declare module 'libsodium-wrappers-sumo' {
  export type KeyPair = {
    keyType: string;
    privateKey: Uint8Array;
    publicKey: Uint8Array;
  };

  const sodium: {
    ready: Promise<void>;
    crypto_sign_keypair(): KeyPair;
    crypto_sign_seed_keypair(seed: Uint8Array): KeyPair;
    randombytes_buf(length: number): Uint8Array;
    /** reduces a 64-byte little-endian value mod the ed25519 group order */
    crypto_core_ed25519_scalar_reduce(wide: Uint8Array): Uint8Array;
    /** ge_scalarmult_base: scalar * B, without clamping the scalar */
    crypto_scalarmult_ed25519_base_noclamp(scalar: Uint8Array): Uint8Array;
    crypto_box_keypair(): KeyPair;
    crypto_sign_detached(message: Uint8Array, privateKey: Uint8Array): Uint8Array;
    crypto_sign_verify_detached(
      signature: Uint8Array,
      message: Uint8Array,
      publicKey: Uint8Array
    ): boolean;
    crypto_sign_ed25519_pk_to_curve25519(edPublicKey: Uint8Array): Uint8Array;
    crypto_sign_ed25519_sk_to_curve25519(edPrivateKey: Uint8Array): Uint8Array;
    crypto_box_seal(message: Uint8Array, publicKey: Uint8Array): Uint8Array;
    crypto_box_seal_open(
      ciphertext: Uint8Array,
      publicKey: Uint8Array,
      privateKey: Uint8Array
    ): Uint8Array;
  };

  export default sodium;
}
