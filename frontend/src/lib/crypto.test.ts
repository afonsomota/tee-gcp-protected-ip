import { describe, expect, it } from "vitest";
import {
  DecryptionError,
  createCheckValue,
  decryptJson,
  deriveKey,
  encryptJson,
  generateSalt,
  verifyCheckValue,
} from "./crypto";

// Small Argon2id parameters so the suite runs fast; production defaults are
// exercised implicitly (same code path, different numbers).
const testParams = { memorySizeKib: 1024, iterations: 2, parallelism: 1 };

describe("key derivation", () => {
  it("derives the same key for the same passphrase and salt (stable ciphertext roundtrip)", async () => {
    const salt = generateSalt();
    const key1 = await deriveKey("correct horse battery staple", salt, testParams);
    const key2 = await deriveKey("correct horse battery staple", salt, testParams);
    const box = await encryptJson(key1, { hello: "world" });
    await expect(decryptJson(key2, box)).resolves.toEqual({ hello: "world" });
  });

  it("derives different keys for different salts", async () => {
    const pass = "same passphrase";
    const keyA = await deriveKey(pass, generateSalt(), testParams);
    const keyB = await deriveKey(pass, generateSalt(), testParams);
    const box = await encryptJson(keyA, { secret: 42 });
    await expect(decryptJson(keyB, box)).rejects.toBeInstanceOf(DecryptionError);
  });

  it("generates 16-byte random salts", () => {
    const a = generateSalt();
    const b = generateSalt();
    expect(a).toHaveLength(16);
    expect(a).not.toEqual(b);
  });
});

describe("encrypt / decrypt", () => {
  it("roundtrips a JSON value", async () => {
    const key = await deriveKey("pw", generateSalt(), testParams);
    const value = { title: "Dear diary", body: "今日は良い日だった ✨", n: [1, 2, 3] };
    const box = await encryptJson(key, value);
    expect(await decryptJson(key, box)).toEqual(value);
  });

  it("produces different ciphertext for the same plaintext (fresh IV)", async () => {
    const key = await deriveKey("pw", generateSalt(), testParams);
    const a = await encryptJson(key, { x: 1 });
    const b = await encryptJson(key, { x: 1 });
    expect(a).not.toEqual(b);
  });

  it("does not leak plaintext in the ciphertext bytes", async () => {
    const key = await deriveKey("pw", generateSalt(), testParams);
    const box = await encryptJson(key, { body: "VERYSECRETSTRING" });
    const asText = new TextDecoder().decode(box);
    expect(asText).not.toContain("VERYSECRETSTRING");
  });

  it("rejects tampered ciphertext", async () => {
    const key = await deriveKey("pw", generateSalt(), testParams);
    const box = await encryptJson(key, { x: 1 });
    box[box.length - 1] ^= 0xff;
    await expect(decryptJson(key, box)).rejects.toBeInstanceOf(DecryptionError);
  });

  it("rejects decryption with a key derived from the wrong passphrase", async () => {
    const salt = generateSalt();
    const right = await deriveKey("right passphrase", salt, testParams);
    const wrong = await deriveKey("wrong passphrase", salt, testParams);
    const box = await encryptJson(right, { x: 1 });
    await expect(decryptJson(wrong, box)).rejects.toBeInstanceOf(DecryptionError);
  });
});

describe("passphrase check value", () => {
  it("verifies the correct passphrase", async () => {
    const salt = generateSalt();
    const key = await deriveKey("my passphrase", salt, testParams);
    const check = await createCheckValue(key);
    expect(await verifyCheckValue(key, check)).toBe(true);
  });

  it("cleanly rejects a wrong passphrase (no throw, returns false)", async () => {
    const salt = generateSalt();
    const right = await deriveKey("my passphrase", salt, testParams);
    const wrong = await deriveKey("my passphrase but wrong", salt, testParams);
    const check = await createCheckValue(right);
    expect(await verifyCheckValue(wrong, check)).toBe(false);
  });
});
