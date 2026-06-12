/**
 * Attestation session: fetch and verify the enclave token in one shot,
 * returning the pinned HPKE public key on success.
 *
 * Called at chat pane mount and again on reconnect (enclave restart yields
 * new keys and a fresh token — the old pinned key becomes invalid).
 */
import { b64decode } from "./hpke";
import { checkClaims, verifyTokenSignature } from "./verify";

export const ATTESTATION_AUDIENCE = "https://tee-example/attestation";

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
 */
export async function runAttestation(
  apiEndpoint: string,
  expectedImageDigest: string,
): Promise<AttestationResult> {
  const challenge = Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");

  const [attResponse, keyResponse] = await Promise.all([
    fetch(`${apiEndpoint}/attestation?nonce=${challenge}`),
    fetch(`${apiEndpoint}/hpke-key`),
  ]);

  const attBody = (await attResponse.json()) as { token?: string; dev?: boolean; error?: string };
  if (!attResponse.ok || !attBody.token) {
    throw new Error(attBody.error ?? `attestation fetch failed: HTTP ${attResponse.status}`);
  }

  const keyBody = (await keyResponse.json()) as { public_key: string };
  const hpkePublicKey = b64decode(keyBody.public_key);

  const dev = attBody.dev === true;
  const { claims, signatureVerified } = await verifyTokenSignature(
    attBody.token,
    ATTESTATION_AUDIENCE,
    dev,
  );

  await checkClaims(claims, { challenge, expectedImageDigest, hpkePublicKey });

  return { hpkePublicKey, signatureVerified };
}
