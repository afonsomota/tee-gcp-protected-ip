/**
 * Passphrase-derived encryption, independent of React and of the DOM.
 *
 * Login *is* key derivation: Argon2id (hash-wasm) stretches the passphrase
 * with a per-journal random salt into 32 bytes, which become a non-extractable
 * AES-256-GCM WebCrypto key. There are no accounts and no server.
 *
 * A "check value" (a known constant encrypted under the key) is stored next to
 * the salt so a wrong passphrase can be detected cleanly instead of surfacing
 * as garbled entries.
 */
import { argon2id } from "hash-wasm";

export interface Argon2Params {
  /** Memory cost in KiB. */
  memorySizeKib: number;
  /** Time cost (passes over memory). */
  iterations: number;
  /** Lanes; keep 1 for portability across browsers. */
  parallelism: number;
}

/** OWASP-recommended interactive-login class parameters: 64 MiB, t=3, p=1. */
export const DEFAULT_ARGON2_PARAMS: Argon2Params = {
  memorySizeKib: 64 * 1024,
  iterations: 3,
  parallelism: 1,
};

export const SALT_LENGTH = 16;
const IV_LENGTH = 12;

/** Thrown when ciphertext cannot be authenticated/decrypted with the given key. */
export class DecryptionError extends Error {
  constructor(message = "Decryption failed: wrong key or corrupted data") {
    super(message);
    this.name = "DecryptionError";
  }
}

export function generateSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
}

/** Argon2id(passphrase, salt) -> non-extractable AES-256-GCM key. */
export async function deriveKey(
  passphrase: string,
  salt: Uint8Array,
  params: Argon2Params = DEFAULT_ARGON2_PARAMS,
): Promise<CryptoKey> {
  const keyBytes = await argon2id({
    password: passphrase,
    salt,
    memorySize: params.memorySizeKib,
    iterations: params.iterations,
    parallelism: params.parallelism,
    hashLength: 32,
    outputType: "binary",
  });
  return crypto.subtle.importKey("raw", keyBytes as BufferSource, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

/** AES-256-GCM with a fresh random IV; output is `iv || ciphertext+tag`. */
export async function encryptBytes(key: CryptoKey, plaintext: Uint8Array): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plaintext as BufferSource,
  );
  const out = new Uint8Array(IV_LENGTH + ciphertext.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ciphertext), IV_LENGTH);
  return out;
}

export async function decryptBytes(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  if (data.length <= IV_LENGTH) throw new DecryptionError();
  const iv = data.subarray(0, IV_LENGTH);
  const ciphertext = data.subarray(IV_LENGTH);
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      ciphertext as BufferSource,
    );
    return new Uint8Array(plaintext);
  } catch {
    // WebCrypto throws an opaque OperationError on GCM tag mismatch.
    throw new DecryptionError();
  }
}

export async function encryptJson(key: CryptoKey, value: unknown): Promise<Uint8Array> {
  return encryptBytes(key, new TextEncoder().encode(JSON.stringify(value)));
}

export async function decryptJson<T>(key: CryptoKey, data: Uint8Array): Promise<T> {
  return JSON.parse(new TextDecoder().decode(await decryptBytes(key, data))) as T;
}

/** Known plaintext for passphrase verification; its ciphertext reveals nothing secret. */
const CHECK_MAGIC = new TextEncoder().encode("tee-journal-check-v1");

export async function createCheckValue(key: CryptoKey): Promise<Uint8Array> {
  return encryptBytes(key, CHECK_MAGIC);
}

/** True iff `key` decrypts the stored check value (i.e. the passphrase is right). */
export async function verifyCheckValue(key: CryptoKey, check: Uint8Array): Promise<boolean> {
  try {
    const plaintext = await decryptBytes(key, check);
    return (
      plaintext.length === CHECK_MAGIC.length &&
      plaintext.every((byte, i) => byte === CHECK_MAGIC[i])
    );
  } catch (err) {
    if (err instanceof DecryptionError) return false;
    throw err;
  }
}
