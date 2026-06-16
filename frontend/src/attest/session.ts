/**
 * Attestation session: fetch and verify the enclave token in one shot,
 * returning the pinned HPKE public key on success.
 *
 * Called at chat pane mount and again on reconnect (enclave restart yields
 * new keys and a fresh token — the old pinned key becomes invalid).
 *
 * Dev-mode gating is BUILD-TIME only (`import.meta.env.DEV`): the server's
 * own `dev: true` flag is never trusted to relax verification. A production
 * build that is served an unsigned dev token fails attestation outright
 * (DEV_TOKEN_REJECTED) — a hostile endpoint cannot talk a deployed page into
 * chatting against a key that was never bound by a Google-signed token.
 */
import { b64decode } from "./hpke";
import { AttestationError, checkClaims, verifyTokenSignature } from "./verify";

export const ATTESTATION_AUDIENCE = "https://tee-example/attestation";

/**
 * Status code for failures that are not AttestationErrors (network down,
 * malformed JSON, …). Lives here so the badge can type its label table
 * against `FailureCode | typeof NETWORK_ERROR_CODE`.
 */
export const NETWORK_ERROR_CODE = "NETWORK_ERROR";

export type AttestationStatus =
  | { kind: "idle" }
  | { kind: "verifying" }
  | { kind: "verified"; hpkePublicKey: Uint8Array; signatureVerified: boolean }
  | { kind: "failed"; code: string; detail: string };

export interface AttestationResult {
  hpkePublicKey: Uint8Array;
  signatureVerified: boolean;
}

/**
 * Run the full attestation flow against the enclave.
 * Throws AttestationError (distinct code per failure) or Error on network issues.
 *
 * `allowDevUnsigned` is a parameter only so tests can pin it; it defaults to
 * the build-time Vite flag. `pnpm dev` against `cargo run -- --dev` accepts
 * the local launcher's unsigned token (flagged `signatureVerified: false`);
 * a production build never does.
 */
export async function runAttestation(
  apiEndpoint: string,
  expectedImageDigest: string,
  allowDevUnsigned: boolean = import.meta.env.DEV,
): Promise<AttestationResult> {
  const challenge = Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");

  const [attResponse, keyResponse] = await Promise.all([
    fetch(`${apiEndpoint}/attestation?nonce=${challenge}`),
    fetch(`${apiEndpoint}/hpke-key`),
  ]);

  if (!attResponse.ok) {
    throw new AttestationError(
      "ATTESTATION_FETCH_FAILED",
      `GET /attestation failed: HTTP ${attResponse.status}`,
    );
  }
  let attBody: { token?: string; dev?: boolean; error?: string };
  try {
    attBody = (await attResponse.json()) as { token?: string; dev?: boolean; error?: string };
  } catch {
    throw new AttestationError("ATTESTATION_FETCH_FAILED", "attestation response is not valid JSON");
  }
  if (!attBody.token) {
    throw new AttestationError(
      "ATTESTATION_FETCH_FAILED",
      attBody.error ?? "attestation response carries no token",
    );
  }

  if (!keyResponse.ok) {
    throw new AttestationError(
      "KEY_FETCH_FAILED",
      `GET /hpke-key failed: HTTP ${keyResponse.status}`,
    );
  }
  let keyBody: { public_key?: string };
  try {
    keyBody = (await keyResponse.json()) as { public_key?: string };
  } catch {
    throw new AttestationError("KEY_FETCH_FAILED", "hpke-key response is not valid JSON");
  }
  if (typeof keyBody.public_key !== "string") {
    throw new AttestationError("KEY_FETCH_FAILED", "hpke-key response carries no public_key");
  }
  let hpkePublicKey: Uint8Array;
  try {
    hpkePublicKey = b64decode(keyBody.public_key);
  } catch (err) {
    throw new AttestationError("KEY_FETCH_FAILED", `public_key is not valid base64: ${String(err)}`);
  }

  // The server's dev flag is informational only — it can fail us early with a
  // clear reason, but it can never relax verification (that would hand a
  // hostile endpoint a signature bypass).
  if (!allowDevUnsigned && attBody.dev === true) {
    throw new AttestationError(
      "DEV_TOKEN_REJECTED",
      "the server claims dev mode (unsigned token) but this is a production build — only Google-signed attestation tokens are accepted",
    );
  }

  const { claims, signatureVerified } = await verifyTokenSignature(
    attBody.token,
    ATTESTATION_AUDIENCE,
    allowDevUnsigned,
  );
  if (!allowDevUnsigned && !signatureVerified) {
    // Defence in depth: a production build must never proceed on a token whose
    // signature was not verified against Google JWKS.
    throw new AttestationError(
      "DEV_TOKEN_REJECTED",
      "token signature was not verified and this is a production build",
    );
  }

  await checkClaims(claims, { challenge, expectedImageDigest, hpkePublicKey });

  return { hpkePublicKey, signatureVerified };
}
