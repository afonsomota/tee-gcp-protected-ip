/**
 * One verified enclave session, shared across the app (issue #11).
 *
 * Attestation runs once and is reused by everything that talks to the enclave —
 * the chat pane and entry-save enrichment alike — so the page holds a single
 * pinned HPKE key, not one per feature. Re-verifies when the tab becomes
 * visible again (an enclave restart yields new keys and a fresh token, so the
 * old pinned key becomes invalid).
 *
 * Cold-start (issue #45): if attestation fails because the API is unreachable
 * and a controller is configured, the session pokes the controller to start the
 * stopped CVM and polls attestation until the woken enclave verifies. The
 * controller is untrusted — trust is re-established from scratch by the poll.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { config } from "../lib/config";
import { type AttestationStatus, NETWORK_ERROR_CODE, runAttestation } from "./session";
import { AttestationError } from "./verify";
import { delay, requestWake, WARMING_POLL_MS, WARMING_TIMEOUT_MS } from "./wake";

export interface EnclaveSession {
  status: AttestationStatus;
  /** Re-run attestation (e.g. after a chat error suggests the enclave restarted). */
  verify: () => Promise<void>;
}

export function useEnclaveSession(): EnclaveSession {
  const [status, setStatus] = useState<AttestationStatus>({ kind: "idle" });

  // A live token for the warming poll loop; flipping `cancelled` stops it (on
  // re-verify or unmount) so we never race two loops or set state after teardown.
  const warmingRef = useRef<{ cancelled: boolean } | null>(null);
  const cancelWarming = useCallback(() => {
    if (warmingRef.current) warmingRef.current.cancelled = true;
    warmingRef.current = null;
  }, []);

  // Cold-start path (issue #45): the API was unreachable and a controller is
  // configured. Poke it to start the stopped enclave, then poll attestation
  // until it boots — trust is re-established from scratch by the poll, so the
  // untrusted controller is only ever asked to flip the power switch.
  const startWarming = useCallback(async () => {
    cancelWarming();
    const token = { cancelled: false };
    warmingRef.current = token;
    setStatus({ kind: "warming" });
    try {
      await requestWake(config.controllerEndpoint);
    } catch {
      // A failed poke doesn't mean the VM won't come up — keep polling anyway.
    }
    const deadline = Date.now() + WARMING_TIMEOUT_MS;
    while (!token.cancelled && Date.now() < deadline) {
      await delay(WARMING_POLL_MS);
      if (token.cancelled) return;
      try {
        const result = await runAttestation(config.apiEndpoint, config.expectedImageDigest);
        if (token.cancelled) return;
        setStatus({ kind: "verified", ...result });
        return;
      } catch {
        // Still warming; keep polling until the deadline.
      }
    }
    if (!token.cancelled) {
      setStatus({
        kind: "failed",
        code: NETWORK_ERROR_CODE,
        detail: "the enclave did not come up in time — try again",
      });
    }
  }, [cancelWarming]);

  const verify = useCallback(async () => {
    cancelWarming();
    setStatus({ kind: "verifying" });
    try {
      const result = await runAttestation(config.apiEndpoint, config.expectedImageDigest);
      setStatus({ kind: "verified", ...result });
    } catch (err) {
      const code = err instanceof AttestationError ? err.code : NETWORK_ERROR_CODE;
      const detail = err instanceof Error ? err.message : String(err);
      // Unreachable enclave + a configured controller → try to wake it.
      if (code === NETWORK_ERROR_CODE && config.controllerEndpoint !== "") {
        void startWarming();
        return;
      }
      setStatus({ kind: "failed", code, detail });
    }
  }, [cancelWarming, startWarming]);

  useEffect(() => {
    void verify();
  }, [verify]);

  // Stop any in-flight warming loop when the session unmounts.
  useEffect(() => cancelWarming, [cancelWarming]);

  useEffect(() => {
    const onVisible = () => {
      if (document.visibilityState === "visible") void verify();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => document.removeEventListener("visibilitychange", onVisible);
  }, [verify]);

  return { status, verify };
}
