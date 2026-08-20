/**
 * BNS (Beldex Name Service) resolution: maps a human-readable name
 * ("codeman" / "codeman.bdx") to the BChat ID it is tagged to.
 *
 * Wire-compatible with bchat-desktop's `getBchatIDForOnsName`:
 *   - the lowercased name is hashed with blake2b-32 and sent to a storage
 *     node as `beldexd_request` -> endpoint `bns_resolve`,
 *     params `{ type: 0, name_hash: base64(hash) }`
 *   - the node returns `{ encrypted_value, nonce? }`. The record is encrypted
 *     with a key derived from the name itself, so only someone who already
 *     knows the name can learn the mapping:
 *       - modern records (nonce present): XChaCha20-Poly1305 with
 *         key = blake2b-32(name, key = blake2b-32(name))
 *       - legacy records (pre-hardfork, no nonce): XSalsa20-Poly1305
 *         secretbox with key = Argon2id(name, zero salt) and a zero nonce
 *   - the plaintext is the 33-byte BChat ID (0xbd prefix + x25519 key).
 */
import sodium from 'libsodium-wrappers-sumo';
import { Buffer } from 'buffer';

/** BNS mapping type for BChat IDs (wallet and BelNet use other types) */
export const BNS_MAPPING_TYPE_BCHAT = 0;

/**
 * Shape of the name *label* (the part before an optional `.bdx`): word chars
 * and dashes, no leading or trailing dash — same as bchat-desktop's
 * onsNameRegex.
 */
const BNS_NAME_REGEX = /^\w([\w-]*\w)?$/;
const MAX_BNS_NAME_LENGTH = 64;

/** 64-hex bare x25519 key, or 66-hex with a bd/05 account prefix */
const BCHAT_ID_REGEX = /^(?:(?:bd|05)[0-9a-fA-F]{64}|[0-9a-fA-F]{64})$/;

/** true when the value already is a (possibly prefixed) BChat ID / pubkey */
export function looksLikeBchatId(value: string): boolean {
  return BCHAT_ID_REGEX.test(value);
}

/**
 * Lowercases and validates. The `.bdx` suffix is deliberately KEPT: the
 * desktop client hashes the user's input verbatim, so a record registered as
 * "codeman.bdx" lives under blake2b("codeman.bdx") — stripping the suffix
 * would hash a different string and miss the record entirely.
 *
 * Throws on names BNS cannot contain, so callers fail fast instead of
 * querying the network for a name that can never resolve.
 */
export function normalizeBnsName(name: string): string {
  if (!name || typeof name !== 'string') throw new Error('BNS name is required');
  const lower = name.trim().toLowerCase();
  const label = lower.endsWith('.bdx') ? lower.slice(0, -4) : lower;
  if (!label || label.length > MAX_BNS_NAME_LENGTH || !BNS_NAME_REGEX.test(label)) {
    throw new Error(`"${name}" is not a valid BNS name`);
  }
  return lower;
}

/**
 * The name strings actually worth querying, in order. The on-chain record is
 * keyed by the hash of whatever string was registered, and registrations
 * exist both with and without the `.bdx` suffix — so resolution tries the
 * name exactly as given first, then the alternate form.
 */
export function bnsCandidateNames(name: string): string[] {
  const normalized = normalizeBnsName(name);
  const alternate = normalized.endsWith('.bdx')
    ? normalized.slice(0, -4)
    : `${normalized}.bdx`;
  return [normalized, alternate];
}

/** true when the value could be a BNS name (and is not already a BChat ID) */
export function isBnsName(value: string): boolean {
  if (typeof value !== 'string' || looksLikeBchatId(value)) return false;
  try {
    normalizeBnsName(value);
    return true;
  } catch {
    return false;
  }
}

/** base64(blake2b-32(lowercased name)) — the `name_hash` request parameter */
export async function bnsNameHashBase64(normalizedName: string): Promise<string> {
  await sodium.ready;
  const nameAsData = Buffer.from(normalizedName, 'utf8');
  const nameHash = sodium.crypto_generichash(sodium.crypto_generichash_BYTES, nameAsData);
  return Buffer.from(nameHash).toString('base64');
}

/**
 * Decrypts a `bns_resolve` record. Returns the BChat ID as lowercase hex
 * (66 chars, `bd`-prefixed on mainnet records).
 *
 * A missing `nonce` selects the legacy Argon2id scheme, exactly as the
 * desktop client does.
 */
export async function decryptBnsRecord(
  normalizedName: string,
  encryptedValueHex: string,
  nonceHex?: string
): Promise<string> {
  await sodium.ready;
  if (!encryptedValueHex) throw new Error('BNS record has no encrypted_value');

  const nameAsData = Buffer.from(normalizedName, 'utf8');
  const ciphertext = Buffer.from(encryptedValueHex, 'hex');
  if (!ciphertext.length) throw new Error('BNS record encrypted_value is not valid hex');

  let idBytes: Uint8Array;

  if (!nonceHex) {
    // Legacy scheme: Argon2id over the name with an all-zero salt, opened as
    // a secretbox with an all-zero nonce. Deterministic zero salt/nonce are
    // safe here because the key is only ever used for this single record.
    const salt = new Uint8Array(sodium.crypto_pwhash_SALTBYTES);
    const nonce = new Uint8Array(sodium.crypto_secretbox_NONCEBYTES);
    const key = sodium.crypto_pwhash(
      sodium.crypto_secretbox_KEYBYTES,
      normalizedName,
      salt,
      sodium.crypto_pwhash_OPSLIMIT_MODERATE,
      sodium.crypto_pwhash_MEMLIMIT_MODERATE,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );
    try {
      idBytes = sodium.crypto_secretbox_open_easy(ciphertext, nonce, key);
    } catch {
      throw new Error('BNS record decryption failed (legacy scheme)');
    }
  } else {
    const nonce = Buffer.from(nonceHex, 'hex');
    const nameHash = sodium.crypto_generichash(sodium.crypto_generichash_BYTES, nameAsData);
    const key = sodium.crypto_generichash(
      sodium.crypto_generichash_BYTES,
      nameAsData,
      nameHash
    );
    try {
      idBytes = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        ciphertext,
        null,
        nonce,
        key
      );
    } catch {
      throw new Error('BNS record decryption failed');
    }
  }

  // A BChat ID is one prefix byte + a 32-byte x25519 key. Anything else means
  // the record is not a BChat mapping (or the node served garbage).
  if (idBytes.length !== 33) {
    throw new Error(`BNS record decrypted to ${idBytes.length} bytes, expected 33`);
  }
  return Buffer.from(idBytes).toString('hex');
}
