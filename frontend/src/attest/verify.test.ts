/**
 * verifyTokenSignature must NOT touch Google's OIDC discovery endpoint.
 *
 * That endpoint (`.../.well-known/openid-configuration`) sends no
 * `Access-Control-Allow-Origin` header, so any in-browser fetch of it is
 * blocked by CORS — which silently broke signature verification on every web
 * origin (issue #41). Verification must reach only the CORS-enabled JWKS URL.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  AttestationError,
  DEV_ISSUER,
  GOOGLE_JWKS_URL,
  GOOGLE_TOKEN_ISSUER,
  verifyTokenSignature,
} from "./verify";

const AUD = "https://tee-example/attestation";

const b64url = (value: unknown): string =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

/** A Google-issuer (non-dev) token, so verification takes the JWKS path. */
function googleIssuerToken(): string {
  const payload = { iss: GOOGLE_TOKEN_ISSUER, aud: AUD };
  return `${b64url({ alg: "RS256", typ: "JWT", kid: "test" })}.${b64url(payload)}.sig`;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("verifyTokenSignature JWKS fetch (issue #41 regression)", () => {
  it("fetches the CORS-enabled JWKS URL, never the OIDC discovery endpoint", async () => {
    const fetched: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL): Promise<Response> => {
        fetched.push(String(input));
        // Return an empty (signer-less) JWKS so signature verification fails
        // cleanly without us having to mint a genuinely Google-signed token.
        return Promise.resolve(
          new Response(JSON.stringify({ keys: [] }), {
            status: 200,
            headers: { "content-type": "application/json" },
          }),
        );
      }),
    );

    // It must reject (we cannot produce a real signature), but the point of
    // this test is *which URL it tried to reach*, not the rejection itself.
    await expect(verifyTokenSignature(googleIssuerToken(), AUD, false)).rejects.toBeInstanceOf(
      AttestationError,
    );

    expect(fetched.length).toBeGreaterThan(0);
    expect(fetched).toContain(GOOGLE_JWKS_URL);
    for (const url of fetched) {
      expect(url).not.toContain(".well-known/openid-configuration");
    }
  });

  it("maps a signature failure to TOKEN_SIGNATURE_INVALID", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        Promise.resolve(
          new Response(JSON.stringify({ keys: [] }), {
            status: 200,
            headers: { "content-type": "application/json" },
          }),
        ),
      ),
    );
    try {
      await verifyTokenSignature(googleIssuerToken(), AUD, false);
      throw new Error("expected rejection");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestationError);
      expect((err as AttestationError).code).toBe("TOKEN_SIGNATURE_INVALID");
    }
  });

  it("accepts a dev-issuer unsigned token without any network fetch", async () => {
    const fetchSpy = vi.fn(() => Promise.reject(new Error("no network expected")));
    vi.stubGlobal("fetch", fetchSpy);
    const token = `${b64url({ alg: "none", typ: "JWT" })}.${b64url({ iss: DEV_ISSUER, aud: AUD })}.`;
    const result = await verifyTokenSignature(token, AUD, true);
    expect(result.signatureVerified).toBe(false);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
