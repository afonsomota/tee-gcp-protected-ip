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

function pendingLabel(kind: "idle" | "verifying" | "warming"): string {
  return kind === "warming"
    ? "Enclave starting…"
    : kind === "verifying"
      ? "Verifying enclave…"
      : "Connecting…";
}

export function AttestationBadge({ status, onRetry }: Props) {
  if (status.kind === "idle" || status.kind === "verifying" || status.kind === "warming") {
    return (
      <div className="attest-badge attest-badge--pending">
        <span className="attest-badge__dot" />
        {pendingLabel(status.kind)}
      </div>
    );
  }

  if (status.kind === "failed") {
    return (
      <div className="attest-badge attest-badge--failed">
        <span className="attest-badge__dot" />
        <span className="attest-badge__text" title={status.detail}>
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

function pillState(status: AttestationStatus): { variant: string; label: string } {
  if (status.kind === "failed") return { variant: "failed", label: "Not verified" };
  if (status.kind !== "verified") return { variant: "pending", label: pendingLabel(status.kind) };
  if (!status.signatureVerified) return { variant: "dev", label: "Dev mode" };
  return { variant: "ok", label: "Verified" };
}

/**
 * Compact, single-line badge for the top bar on small screens: a dot and a
 * short label only. The failure detail, Retry and "Know more" don't fit in a
 * phone header, so tapping the pill opens the full badge (the inspector's
 * Details tab) instead.
 */
export function AttestationPill({
  status,
  onOpen,
}: {
  status: AttestationStatus;
  onOpen: () => void;
}) {
  const { variant, label } = pillState(status);
  return (
    <button
      type="button"
      className={`attest-badge attest-badge--compact attest-badge--${variant}`}
      aria-label={`Enclave status: ${label}. Show details`}
      onClick={onOpen}
    >
      <span className="attest-badge__dot" />
      <span className="attest-badge__label">{label}</span>
    </button>
  );
}
