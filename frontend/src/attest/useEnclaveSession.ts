/**
 * One verified enclave session, shared across the app (issue #11).
 *
 * Attestation runs once and is reused by everything that talks to the enclave —
 * the chat pane and entry-save enrichment alike — so the page holds a single
 * pinned HPKE key, not one per feature. Re-verifies when the tab becomes
 * visible again (an enclave restart yields new keys and a fresh token, so the
 * old pinned key becomes invalid).
 */
import { useCallback, useEffect, useState } from "react";
import { config } from "../lib/config";
import { type AttestationStatus, NETWORK_ERROR_CODE, runAttestation } from "./session";
import { AttestationError } from "./verify";

export interface EnclaveSession {
  status: AttestationStatus;
  /** Re-run attestation (e.g. after a chat error suggests the enclave restarted). */
  verify: () => Promise<void>;
}

export function useEnclaveSession(): EnclaveSession {
  const [status, setStatus] = useState<AttestationStatus>({ kind: "idle" });

  const verify = useCallback(async () => {
    setStatus({ kind: "verifying" });
    try {
      const result = await runAttestation(config.apiEndpoint, config.expectedImageDigest);
      setStatus({ kind: "verified", ...result });
    } catch (err) {
      const code = err instanceof AttestationError ? err.code : NETWORK_ERROR_CODE;
      const detail = err instanceof Error ? err.message : String(err);
      setStatus({ kind: "failed", code, detail });
    }
  }, []);

  useEffect(() => {
    void verify();
  }, [verify]);

  useEffect(() => {
    const onVisible = () => {
      if (document.visibilityState === "visible") void verify();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => document.removeEventListener("visibilitychange", onVisible);
  }, [verify]);

  return { status, verify };
}
