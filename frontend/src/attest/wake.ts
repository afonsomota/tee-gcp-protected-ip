/**
 * Scale-from-zero wake (issue #45).
 *
 * When the enclave API is unreachable, the app pokes the always-on controller
 * to start the stopped CVM, then polls attestation (`runAttestation`) until it
 * boots. The controller is *untrusted*: it only starts the VM. Trust is
 * re-established from scratch by the attestation poll — a freshly booted
 * enclave has new keys and a new Google-signed token. See docs/DESIGN.md.
 */

/** How long to keep polling attestation after a wake before giving up. A cold
 * Confidential Space boot (pull image, decrypt weights, order a cert) is a
 * couple of minutes; we allow generous headroom. */
export const WARMING_TIMEOUT_MS = 5 * 60 * 1000;
/** Delay between attestation polls while warming. */
export const WARMING_POLL_MS = 4000;

/**
 * Ask the controller to start the enclave. Resolves once the request is
 * accepted (202 "warming" or 200 "already running"); rejects otherwise. The
 * caller polls attestation regardless — a rejected poke (e.g. a transient
 * controller error) does not mean the VM won't come up, so the warming loop
 * keeps polling even when this throws.
 */
export async function requestWake(controllerEndpoint: string): Promise<void> {
  const res = await fetch(`${controllerEndpoint}/wake`, { method: "POST" });
  if (!res.ok && res.status !== 202) {
    throw new Error(`wake request failed: HTTP ${res.status}`);
  }
}

export const delay = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));
