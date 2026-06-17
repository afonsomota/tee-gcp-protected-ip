import type { AttestationStatus } from "../attest/session";
import { NETWORK_ERROR_CODE } from "../attest/session";
import type { FailureCode } from "../attest/verify";

interface Props {
  status: AttestationStatus;
  onRetry: () => void;
}

// Typed against the FailureCode union so a new failure mode without a
// human-readable label is a compile error.
const FAILURE_LABELS: Record<FailureCode | typeof NETWORK_ERROR_CODE, string> = {
  TOKEN_SIGNATURE_INVALID: "Token signature invalid",
  CHALLENGE_MISMATCH: "Challenge mismatch (possible replay)",
  IMAGE_DIGEST_MISMATCH: "Image digest mismatch — wrong workload",
  DIGEST_UNCONFIGURED: "Expected digest not configured — set VITE_EXPECTED_IMAGE_DIGEST",
  KEY_HASH_MISMATCH: "Key not bound in attestation token",
  ATTESTATION_FETCH_FAILED: "Could not fetch attestation token",
  KEY_FETCH_FAILED: "Could not fetch enclave key",
  DEV_TOKEN_REJECTED: "Unsigned dev token rejected (production build)",
  NETWORK_ERROR: "Could not reach the enclave",
};

function failureLabel(code: string): string {
  return code in FAILURE_LABELS ? FAILURE_LABELS[code as keyof typeof FAILURE_LABELS] : code;
}

export function AttestationBadge({ status, onRetry }: Props) {
  if (status.kind === "idle" || status.kind === "verifying" || status.kind === "warming") {
    const label =
      status.kind === "warming"
        ? "Enclave starting…"
        : status.kind === "verifying"
          ? "Verifying enclave…"
          : "Connecting…";
    return (
      <div className="attest-badge attest-badge--pending">
        <span className="attest-badge__dot" />
        {label}
      </div>
    );
  }

  if (status.kind === "failed") {
    return (
      <div className="attest-badge attest-badge--failed">
        <span className="attest-badge__dot" />
        <span>
          <strong>Enclave not verified</strong>
          {" — "}
          {failureLabel(status.code)}
          {status.detail !== "" && (
            <span className="attest-badge__detail">{status.detail}</span>
          )}
        </span>
        <button className="attest-badge__retry secondary" onClick={onRetry}>
          Retry
        </button>
        <a href="#know-more" className="attest-badge__link">
          Know more
        </a>
      </div>
    );
  }

  // verified
  const devMode = !status.signatureVerified;
  return (
    <div className={`attest-badge ${devMode ? "attest-badge--dev" : "attest-badge--ok"}`}>
      <span className="attest-badge__dot" />
      {devMode ? "Dev mode — unsigned token" : "Enclave verified"}
      <a href="#know-more" className="attest-badge__link">
        Know more
      </a>
    </div>
  );
}
