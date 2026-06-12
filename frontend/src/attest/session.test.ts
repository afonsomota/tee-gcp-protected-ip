/**
 * runAttestation failure paths and the build-time dev-mode gate.
 *
 * fetch is stubbed per test — no real network. We cannot mint genuinely
 * Google-signed tokens in tests, so the production-build (`allowDevUnsigned:
 * false`) cases assert the flow FAILS closed; the only path asserted to
 * succeed is the dev build accepting the local launcher's unsigned token,
 * and even that is flagged `signatureVerified: false`.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { b64encode } from "./hpke";
import { runAttestation } from "./session";
import { AttestationError, DEV_ISSUER, sha256Hex } from "./verify";

const API = "http://enclave.test";
const EXPECTED_DIGEST = "sha256:" + "a".repeat(64);
const HPKE_KEY = new Uint8Array(32).fill(7);

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const b64url = (value: unknown): string =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

/** Unsigned attestation-shaped token, like the launcher's `--dev` mode serves. */
function devToken(nonce: string, keyBinding: string): string {
  const payload = {
    iss: DEV_ISSUER,
    aud: "https://tee-example/attestation",
    eat_nonce: [nonce, keyBinding],
    submods: { container: { image_digest: EXPECTED_DIGEST } },
  };
  return `${b64url({ alg: "none", typ: "JWT" })}.${b64url(payload)}.`;
}

interface Routes {
  attestation: (nonce: string) => Response;
  hpkeKey: () => Response;
}

function stubFetch(routes: Routes): void {
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL): Promise<Response> => {
      const url = new URL(String(input));
      if (url.pathname === "/attestation") {
        return Promise.resolve(routes.attestation(url.searchParams.get("nonce") ?? ""));
      }
      if (url.pathname === "/hpke-key") {
        return Promise.resolve(routes.hpkeKey());
      }
      // Anything else (e.g. Google JWKS discovery) is unreachable in tests.
      return Promise.reject(new Error(`no network in tests: ${String(input)}`));
    }),
  );
}

/** Routes for a well-behaved local dev launcher. */
async function devRoutes(): Promise<Routes> {
  const keyBinding = `hpke:${await sha256Hex(HPKE_KEY)}`;
  return {
    attestation: (nonce) => json({ token: devToken(nonce, keyBinding), dev: true }),
    hpkeKey: () => json({ public_key: b64encode(HPKE_KEY) }),
  };
}

async function failureOf(promise: Promise<unknown>): Promise<AttestationError> {
  try {
    await promise;
  } catch (err) {
    expect(err).toBeInstanceOf(AttestationError);
    return err as AttestationError;
  }
  throw new Error("expected runAttestation to reject, but it resolved");
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("runAttestation failure paths", () => {
  it("fails with ATTESTATION_FETCH_FAILED on a non-ok /attestation response", async () => {
    const routes = await devRoutes();
    stubFetch({ ...routes, attestation: () => json({ error: "boom" }, 500) });
    const err = await failureOf(runAttestation(API, EXPECTED_DIGEST, true));
    expect(err.code).toBe("ATTESTATION_FETCH_FAILED");
    expect(err.message).toContain("500");
  });

  it("fails with ATTESTATION_FETCH_FAILED when the response carries no token", async () => {
    const routes = await devRoutes();
    stubFetch({ ...routes, attestation: () => json({ dev: true }) });
    const err = await failureOf(runAttestation(API, EXPECTED_DIGEST, true));
    expect(err.code).toBe("ATTESTATION_FETCH_FAILED");
  });

  it("fails with KEY_FETCH_FAILED on a non-ok /hpke-key response", async () => {
    const routes = await devRoutes();
    stubFetch({ ...routes, hpkeKey: () => json({ error: "unavailable" }, 503) });
    const err = await failureOf(runAttestation(API, EXPECTED_DIGEST, true));
    expect(err.code).toBe("KEY_FETCH_FAILED");
    expect(err.message).toContain("503");
  });

  it("fails with KEY_FETCH_FAILED when /hpke-key omits public_key", async () => {
    const routes = await devRoutes();
    stubFetch({ ...routes, hpkeKey: () => json({}) });
    const err = await failureOf(runAttestation(API, EXPECTED_DIGEST, true));
    expect(err.code).toBe("KEY_FETCH_FAILED");
  });

  it("runs the claim checks on the dev path: wrong digest fails distinctly", async () => {
    stubFetch(await devRoutes());
    const err = await failureOf(runAttestation(API, "sha256:" + "b".repeat(64), true));
    expect(err.code).toBe("IMAGE_DIGEST_MISMATCH");
  });
});

describe("dev-mode gate is build-time, never server-controlled", () => {
  it("production build: server claiming dev:true with an unsigned token is rejected", async () => {
    // A hostile production endpoint replays the challenge, claims the public
    // expected digest, and binds its own HPKE key — exactly the forged-token
    // attack. It must never yield a chat-enabling "verified" result.
    stubFetch(await devRoutes());
    const err = await failureOf(runAttestation(API, EXPECTED_DIGEST, false));
    expect(err.code).toBe("DEV_TOKEN_REJECTED");
  });

  it("production build: unsigned dev-issuer token with dev:false still fails signature", async () => {
    const keyBinding = `hpke:${await sha256Hex(HPKE_KEY)}`;
    const routes = await devRoutes();
    stubFetch({
      ...routes,
      attestation: (nonce) => json({ token: devToken(nonce, keyBinding), dev: false }),
    });
    const err = await failureOf(runAttestation(API, EXPECTED_DIGEST, false));
    expect(err.code).toBe("TOKEN_SIGNATURE_INVALID");
  });

  it("dev build: accepts the local launcher's unsigned token, flagged unverified", async () => {
    stubFetch(await devRoutes());
    const result = await runAttestation(API, EXPECTED_DIGEST, true);
    expect(result.signatureVerified).toBe(false);
    expect(result.hpkePublicKey).toEqual(HPKE_KEY);
  });
});
