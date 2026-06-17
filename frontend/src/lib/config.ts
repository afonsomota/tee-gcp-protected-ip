/**
 * Build-time configuration, injected by Vite from `VITE_*` env vars.
 *
 * These are *explicit, documented* values (see frontend/README.md):
 *
 * - `VITE_API_ENDPOINT` — base URL of the enclave API the app talks to.
 *   Default: `http://localhost:8080` (the launcher's local dev port).
 * - `VITE_EXPECTED_IMAGE_DIGEST` — the enclave container image digest
 *   (`sha256:<64 hex chars>`) the attestation badge must match (issue 009).
 *   Default: empty string, meaning "no pinned digest" — the badge cannot
 *   verify and must show an unverified state.
 * - `VITE_CONTROLLER_ENDPOINT` — base URL of the scale-from-zero controller
 *   (issue #45) the app pokes when the API is unreachable, to wake a stopped
 *   enclave. Default: empty string, meaning "no controller" — the app shows
 *   "unreachable" without trying to wake anything.
 *
 * In CI (.github/workflows/deploy-frontend.yml) both come from the repo
 * variables of the same name, so the deployed values are auditable.
 */

export interface AppConfig {
  /** Base URL of the enclave API (no trailing slash). */
  readonly apiEndpoint: string;
  /** Expected enclave image digest (`sha256:...`), or "" if not pinned. */
  readonly expectedImageDigest: string;
  /** Base URL of the scale-from-zero controller (no trailing slash), or "" if
   * no controller is configured (then the app never tries to wake the enclave). */
  readonly controllerEndpoint: string;
}

export const DEFAULT_API_ENDPOINT = "http://localhost:8080";

/** Raw env shape we read — a subset of import.meta.env. */
type RawEnv = Record<string, string | undefined>;

function normalizeEndpoint(value: string | undefined): string {
  const trimmed = value?.trim();
  if (!trimmed) return DEFAULT_API_ENDPOINT;
  return trimmed.replace(/\/+$/, "");
}

function normalizeDigest(value: string | undefined): string {
  return value?.trim() ?? "";
}

/** Like normalizeEndpoint but defaults to "" (no controller) rather than the
 * local API endpoint — an absent controller must be a clear "disabled", never
 * a stray localhost POST. */
function normalizeOptionalEndpoint(value: string | undefined): string {
  const trimmed = value?.trim();
  if (!trimmed) return "";
  return trimmed.replace(/\/+$/, "");
}

/** Build an AppConfig from an env object (exported for testing). */
export function loadConfig(env: RawEnv): AppConfig {
  return {
    apiEndpoint: normalizeEndpoint(env.VITE_API_ENDPOINT),
    expectedImageDigest: normalizeDigest(env.VITE_EXPECTED_IMAGE_DIGEST),
    controllerEndpoint: normalizeOptionalEndpoint(env.VITE_CONTROLLER_ENDPOINT),
  };
}

/** The app-wide config, resolved at build time. */
export const config: AppConfig = loadConfig(import.meta.env as RawEnv);
