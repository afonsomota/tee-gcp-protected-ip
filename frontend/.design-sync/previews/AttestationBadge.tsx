// Authored preview — sweeps the attestation status union, the prop that drives
// the badge's colour and label. Imports the shipped component from the package
// (redirected to window.TeeJournalUI by the converter).
import { AttestationBadge } from "tee-journal-frontend";

const noop = () => {};

/** The happy path: the enclave's signed token verified against the pinned digest. */
export const Verified = () => (
  <AttestationBadge status={{ kind: "verified", signatureVerified: true }} onRetry={noop} />
);

/** Local dev: an unsigned, attestation-shaped token (amber, not green). */
export const DevMode = () => (
  <AttestationBadge status={{ kind: "verified", signatureVerified: false }} onRetry={noop} />
);

/** In-flight: verifying the freshly-fetched attestation token. */
export const Verifying = () => (
  <AttestationBadge status={{ kind: "verifying" }} onRetry={noop} />
);

/** Cold start: waiting for a scaled-to-zero enclave to boot. */
export const Warming = () => (
  <AttestationBadge status={{ kind: "warming" }} onRetry={noop} />
);

/** Failure: the running image's digest didn't match the one this app pins. */
export const Failed = () => (
  <AttestationBadge
    status={{
      kind: "failed",
      code: "IMAGE_DIGEST_MISMATCH",
      detail: "expected sha256:9f2c… but the enclave reported sha256:41ab…",
    }}
    onRetry={noop}
  />
);
