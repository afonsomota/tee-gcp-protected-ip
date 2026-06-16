/**
 * In-browser attestation verification, with no server assistance:
 *
 *   1. token signature against Google's Confidential Space JWKS (jose);
 *   2. our freshly generated challenge nonce is echoed in `eat_nonce`;
 *   3. the workload image digest claim equals the expected (audited) digest;
 *   4. the served HPKE public key hashes to the `hpke:<sha256>` entry that
 *      the *enclave bound into the token at issuance* — this is what makes
 *      the key trustworthy.
 *
 * Each failure mode carries a distinct `FailureCode` so tampered tokens,
 * wrong images, and swapped keys are visibly different errors.
 *
 * Dev mode: the local launcher (no TEE hardware) serves an *unsigned* token
 * with issuer `urn:tee-example:dev-unverified`. It is accepted only when
 * `allowDevUnsigned` is set and is always flagged `signatureVerified: false`.
 * Checks 2–4 run unchanged either way, so the same code path verifies a real
 * Google-signed token against a real enclave.
 */
import { createRemoteJWKSet, decodeJwt, jwtVerify, type JWTPayload } from "jose";

/**
 * Confidential Space token issuer, and its JWKS endpoint.
 *
 * We point `createRemoteJWKSet` straight at the JWKS URL rather than fetching
 * the OIDC discovery document to learn it. The discovery endpoint
 * (`.../.well-known/openid-configuration`) returns NO `Access-Control-Allow-Origin`
 * header, so any in-browser fetch of it is blocked by CORS — which silently
 * broke signature verification on every web origin (issue #41). The JWKS URL is
 * a stable, CORS-enabled endpoint, so the discovery round-trip is both
 * unnecessary and harmful here.
 */
export const GOOGLE_TOKEN_ISSUER = "https://confidentialcomputing.googleapis.com";
export const GOOGLE_JWKS_URL =
  "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com";
export const DEV_ISSUER = "urn:tee-example:dev-unverified";

export type FailureCode =
  | "TOKEN_SIGNATURE_INVALID"
  | "CHALLENGE_MISMATCH"
  | "IMAGE_DIGEST_MISMATCH"
  | "DIGEST_UNCONFIGURED"
  | "KEY_HASH_MISMATCH"
  // Thrown by session.ts (runAttestation), not by this module:
  | "ATTESTATION_FETCH_FAILED"
  | "KEY_FETCH_FAILED"
  | "DEV_TOKEN_REJECTED";

export class AttestationError extends Error {
  readonly code: FailureCode;

  constructor(code: FailureCode, detail: string) {
    super(`${code}: ${detail}`);
    this.name = "AttestationError";
    this.code = code;
  }
}

/** The Confidential Space claims this page inspects. */
export interface AttestationClaims extends JWTPayload {
  eat_nonce?: string | string[];
  submods?: { container?: { image_digest?: string } };
}

export interface VerifiedToken {
  claims: AttestationClaims;
  /** False only for dev-mode unsigned tokens — shown as a loud warning. */
  signatureVerified: boolean;
}

/** `eat_nonce` is a string for one nonce, an array for several. */
export function eatNonces(claims: AttestationClaims): string[] {
  if (claims.eat_nonce === undefined) return [];
  return Array.isArray(claims.eat_nonce) ? claims.eat_nonce : [claims.eat_nonce];
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Step 1: decode and verify the token signature. Any signature, decoding, or
 * audience problem maps to TOKEN_SIGNATURE_INVALID (the detail differs).
 */
export async function verifyTokenSignature(
  token: string,
  audience: string,
  allowDevUnsigned: boolean,
): Promise<VerifiedToken> {
  let claims: AttestationClaims;
  try {
    claims = decodeJwt<AttestationClaims>(token);
  } catch (err) {
    throw new AttestationError("TOKEN_SIGNATURE_INVALID", `token does not decode: ${String(err)}`);
  }
  if (allowDevUnsigned && claims.iss === DEV_ISSUER) {
    return { claims, signatureVerified: false };
  }
  try {
    const jwks = createRemoteJWKSet(new URL(GOOGLE_JWKS_URL));
    const { payload } = await jwtVerify<AttestationClaims>(token, jwks, {
      audience,
      issuer: GOOGLE_TOKEN_ISSUER,
      // Confidential Space tokens are RS256, and so are the JWKS keys; pin it
      // so algorithm selection is explicit on this audited path.
      algorithms: ["RS256"],
    });
    return { claims: payload, signatureVerified: true };
  } catch (err) {
    throw new AttestationError(
      "TOKEN_SIGNATURE_INVALID",
      `signature verification against Google JWKS failed: ${String(err)}`,
    );
  }
}

export interface ClaimChecks {
  /** The nonce this page generated for this request (anti-replay). */
  challenge: string;
  /** The audited image digest the user expects to be running. */
  expectedImageDigest: string;
  /** Raw 32-byte X25519 public key served by GET /hpke-key. */
  hpkePublicKey: Uint8Array;
}

/**
 * Steps 2–4: challenge freshness, image digest, HPKE key binding.
 * Throws AttestationError with a distinct code per failure mode.
 */
export async function checkClaims(claims: AttestationClaims, checks: ClaimChecks): Promise<void> {
  if (!checks.expectedImageDigest) {
    throw new AttestationError(
      "DIGEST_UNCONFIGURED",
      "VITE_EXPECTED_IMAGE_DIGEST is not set — deploy with a pinned digest to enable full verification",
    );
  }
  const nonces = eatNonces(claims);
  if (!nonces.includes(checks.challenge)) {
    throw new AttestationError(
      "CHALLENGE_MISMATCH",
      `eat_nonce ${JSON.stringify(nonces)} does not echo our challenge "${checks.challenge}" — possible replay of an old token`,
    );
  }
  const digest = claims.submods?.container?.image_digest;
  if (digest !== checks.expectedImageDigest) {
    throw new AttestationError(
      "IMAGE_DIGEST_MISMATCH",
      `token attests image "${digest ?? "<absent>"}" but expected "${checks.expectedImageDigest}" — this is NOT the audited workload`,
    );
  }
  const binding = `hpke:${await sha256Hex(checks.hpkePublicKey)}`;
  if (!nonces.includes(binding)) {
    throw new AttestationError(
      "KEY_HASH_MISMATCH",
      `eat_nonce has no entry "${binding}" — the served HPKE key is NOT the key the enclave bound at attestation time`,
    );
  }
}
