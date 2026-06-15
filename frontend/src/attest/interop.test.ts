/**
 * Rust ↔ TypeScript HPKE interop (DESIGN.md open spike #5) plus the
 * attestation claim checks' distinct failure modes.
 *
 * Shared fixture shape (all byte fields standard base64) lives in
 * launcher/tests/fixtures/: `hpke-interop.json` is sealed by the Rust `hpke`
 * crate and opened here; `hpke-interop-ts.json` is sealed here (generated
 * once, then committed) and opened by `cargo test` on the launcher side.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { b64decode, b64encode, makeSuite, open, seal } from "./hpke";
import { CHAT_REQUEST_INFO, CHAT_RESPONSE_INFO } from "./chat";
import { AttestationError, checkClaims, sha256Hex, type AttestationClaims } from "./verify";

const FIXTURES = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  "launcher",
  "tests",
  "fixtures",
);

interface Fixture {
  recipient_private_key: string;
  recipient_public_key: string;
  info: string;
  plaintext: string;
  enc: string;
  ct: string;
}

async function openFixture(fixture: Fixture): Promise<void> {
  const suite = makeSuite();
  const privateKey = await suite.kem.deserializePrivateKey(
    b64decode(fixture.recipient_private_key),
  );
  const plaintext = await open(
    privateKey,
    { enc: fixture.enc, ct: fixture.ct },
    b64decode(fixture.info),
  );
  expect(b64encode(plaintext)).toBe(fixture.plaintext);
}

describe("hpke interop with the rust `hpke` crate", () => {
  it("opens the rust-generated fixture with hpke-js", async () => {
    const fixture = JSON.parse(
      readFileSync(join(FIXTURES, "hpke-interop.json"), "utf8"),
    ) as Fixture;
    await openFixture(fixture);
    expect(new TextDecoder().decode(b64decode(fixture.plaintext))).toBe(
      "hpke interop test vector, sealed by the rust `hpke` crate",
    );
  });

  it("generates (once) and opens the ts fixture; cargo test opens it too", async () => {
    const path = join(FIXTURES, "hpke-interop-ts.json");
    if (!existsSync(path)) {
      const suite = makeSuite();
      const keyPair = await suite.kem.generateKeyPair();
      const info = new TextEncoder().encode("tee-example/hpke-interop/v1");
      const plaintext = new TextEncoder().encode(
        "hpke interop test vector, sealed by hpke-js (@hpke/core)",
      );
      const publicKeyRaw = new Uint8Array(await suite.kem.serializePublicKey(keyPair.publicKey));
      const envelope = await seal(publicKeyRaw, info, plaintext);
      const fixture = {
        suite: {
          kem: "DHKEM(X25519, HKDF-SHA256)",
          kdf: "HKDF-SHA256",
          aead: "ChaCha20Poly1305",
        },
        generator: "hpke-js @hpke/core v1.9",
        recipient_private_key: b64encode(
          new Uint8Array(await suite.kem.serializePrivateKey(keyPair.privateKey)),
        ),
        recipient_public_key: b64encode(publicKeyRaw),
        info: b64encode(info),
        aad: "",
        plaintext: b64encode(plaintext),
        enc: envelope.enc,
        ct: envelope.ct,
      };
      writeFileSync(path, JSON.stringify(fixture, null, 2) + "\n");
    }
    await openFixture(JSON.parse(readFileSync(path, "utf8")) as Fixture);
  });
});

async function generateChatFixture(infoStr: string, label: string): Promise<Fixture & { suite: object; generator: string; aad: string }> {
  const suite = makeSuite();
  const keyPair = await suite.kem.generateKeyPair();
  const info = new TextEncoder().encode(infoStr);
  const plaintext = new TextEncoder().encode(label);
  const publicKeyRaw = new Uint8Array(await suite.kem.serializePublicKey(keyPair.publicKey));
  const envelope = await seal(publicKeyRaw, info, plaintext);
  return {
    suite: { kem: "DHKEM(X25519, HKDF-SHA256)", kdf: "HKDF-SHA256", aead: "ChaCha20Poly1305" },
    generator: "hpke-js @hpke/core v1.9",
    recipient_private_key: b64encode(
      new Uint8Array(await suite.kem.serializePrivateKey(keyPair.privateKey)),
    ),
    recipient_public_key: b64encode(publicKeyRaw),
    info: b64encode(info),
    aad: "",
    plaintext: b64encode(plaintext),
    enc: envelope.enc,
    ct: envelope.ct,
  };
}

describe("hpke chat channel interop with the rust `hpke` crate", () => {
  it("generates (once) and opens the ts chat/request fixture; cargo test opens it too", async () => {
    const path = join(FIXTURES, "hpke-chat-request-ts.json");
    if (!existsSync(path)) {
      const fixture = await generateChatFixture(
        CHAT_REQUEST_INFO,
        "hpke chat/request interop vector, sealed by hpke-js (@hpke/core)",
      );
      writeFileSync(path, JSON.stringify(fixture, null, 2) + "\n");
    }
    await openFixture(JSON.parse(readFileSync(path, "utf8")) as Fixture);
  });

  it("generates (once) and opens the ts chat/response fixture; cargo test opens it too", async () => {
    const path = join(FIXTURES, "hpke-chat-response-ts.json");
    if (!existsSync(path)) {
      const fixture = await generateChatFixture(
        CHAT_RESPONSE_INFO,
        "hpke chat/response interop vector, sealed by hpke-js (@hpke/core)",
      );
      writeFileSync(path, JSON.stringify(fixture, null, 2) + "\n");
    }
    await openFixture(JSON.parse(readFileSync(path, "utf8")) as Fixture);
  });

  it("opens the rust-generated chat/request fixture", async () => {
    const path = join(FIXTURES, "hpke-chat-request.json");
    expect(existsSync(path), `missing ${path}: run \`cargo test\` in launcher/ to generate it`).toBe(true);
    await openFixture(JSON.parse(readFileSync(path, "utf8")) as Fixture);
  });

  it("opens the rust-generated chat/response fixture", async () => {
    const path = join(FIXTURES, "hpke-chat-response.json");
    expect(existsSync(path), `missing ${path}: run \`cargo test\` in launcher/ to generate it`).toBe(true);
    await openFixture(JSON.parse(readFileSync(path, "utf8")) as Fixture);
  });
});

describe("attestation claim checks fail distinctly", () => {
  const hpkePublicKey = new Uint8Array(32).fill(7);
  const challenge = "0123456789abcdef";

  async function claims(): Promise<AttestationClaims> {
    return {
      eat_nonce: [challenge, `hpke:${await sha256Hex(hpkePublicKey)}`, "tls:" + "0".repeat(64)],
      submods: { container: { image_digest: "sha256:expected" } },
    };
  }

  const checks = { challenge, expectedImageDigest: "sha256:expected", hpkePublicKey };

  async function failureCode(overrides: Partial<typeof checks>): Promise<string> {
    try {
      await checkClaims(await claims(), { ...checks, ...overrides });
      return "NO_ERROR";
    } catch (err) {
      if (err instanceof AttestationError) return err.code;
      throw err;
    }
  }

  it("passes when everything matches", async () => {
    await expect(checkClaims(await claims(), checks)).resolves.toBeUndefined();
  });

  it("distinguishes stale challenge, wrong digest, and swapped key", async () => {
    expect(await failureCode({ challenge: "fedcba9876543210" })).toBe("CHALLENGE_MISMATCH");
    expect(await failureCode({ expectedImageDigest: "sha256:other" })).toBe(
      "IMAGE_DIGEST_MISMATCH",
    );
    expect(await failureCode({ hpkePublicKey: new Uint8Array(32).fill(8) })).toBe(
      "KEY_HASH_MISMATCH",
    );
  });

  it("reports DIGEST_UNCONFIGURED when expectedImageDigest is empty", async () => {
    expect(await failureCode({ expectedImageDigest: "" })).toBe("DIGEST_UNCONFIGURED");
  });
});
