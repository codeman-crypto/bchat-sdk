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
    crypto_generichash(hashLength: number, message: Uint8Array, key?: Uint8Array): Uint8Array;
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
    // --- BNS record decryption (see src/snode/bns.ts) ---
    crypto_generichash_BYTES: number;
    crypto_secretbox_KEYBYTES: number;
    crypto_secretbox_NONCEBYTES: number;
    crypto_pwhash_SALTBYTES: number;
    crypto_pwhash_OPSLIMIT_MODERATE: number;
    crypto_pwhash_MEMLIMIT_MODERATE: number;
    crypto_pwhash_ALG_ARGON2ID13: number;
    crypto_pwhash(
      keyLength: number,
      password: string | Uint8Array,
      salt: Uint8Array,
      opsLimit: number,
      memLimit: number,
      algorithm: number
    ): Uint8Array;
    crypto_secretbox_easy(message: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array;
    crypto_secretbox_open_easy(
      ciphertext: Uint8Array,
      nonce: Uint8Array,
      key: Uint8Array
    ): Uint8Array;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
      message: Uint8Array,
      additionalData: Uint8Array | null,
      secretNonce: Uint8Array | null,
      publicNonce: Uint8Array,
      key: Uint8Array
    ): Uint8Array;
    crypto_aead_xchacha20poly1305_ietf_decrypt(
      secretNonce: Uint8Array | null,
      ciphertext: Uint8Array,
      additionalData: Uint8Array | null,
      publicNonce: Uint8Array,
      key: Uint8Array
    ): Uint8Array;
  };

  export default sodium;
}
