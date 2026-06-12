import type { AttestationStatus } from "../attest/session";

interface Props {
  status: AttestationStatus;
  onRetry: () => void;
}

const FAILURE_LABELS: Record<string, string> = {
  TOKEN_SIGNATURE_INVALID: "Token signature invalid",
  CHALLENGE_MISMATCH: "Challenge mismatch (possible replay)",
  IMAGE_DIGEST_MISMATCH: "Image digest mismatch — wrong workload",
  KEY_HASH_MISMATCH: "Key not bound in attestation token",
};

export function AttestationBadge({ status, onRetry }: Props) {
  if (status.kind === "idle" || status.kind === "verifying") {
    return (
      <div className="attest-badge attest-badge--pending">
        <span className="attest-badge__dot" />
        {status.kind === "verifying" ? "Verifying enclave…" : "Connecting…"}
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
          {FAILURE_LABELS[status.code] ?? status.code}
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
