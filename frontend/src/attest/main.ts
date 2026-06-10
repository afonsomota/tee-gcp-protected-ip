/**
 * Bare-bones attestation test page (NOT part of the journal UI).
 *
 * Flow: fresh challenge → fetch token → verify signature (Google JWKS) →
 * check challenge / image digest / HPKE key binding → pin the key →
 * round-trip an HPKE-encrypted echo and show the decrypted reply.
 *
 * The three red buttons deliberately break one input each, demonstrating
 * that every failure mode yields a distinct error code.
 */
import { b64decode, hpkeEcho } from "./hpke";
import { AttestationError, checkClaims, sha256Hex, verifyTokenSignature } from "./verify";

const DEFAULT_AUDIENCE = "https://tee-example/attestation";

const el = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;
const logEl = el<HTMLDivElement>("log");

function logLine(kind: "step" | "ok" | "warn" | "fail", text: string): void {
  const line = document.createElement("div");
  line.className = `line ${kind}`;
  line.textContent = `${{ step: "→", ok: "✓", warn: "⚠", fail: "✗" }[kind]} ${text}`;
  logEl.appendChild(line);
  logEl.scrollTop = logEl.scrollHeight;
}

interface Sabotage {
  tamperToken?: boolean;
  wrongDigest?: boolean;
  wrongKeyHash?: boolean;
}

/** Flip one character of the payload segment: any real signature check must fail. */
function tamper(token: string): string {
  const [header, payload, signature] = token.split(".");
  const flipped = (payload.at(-1) === "A" ? "B" : "A") + payload.slice(1);
  return [header, flipped, signature].join(".");
}

async function run(sabotage: Sabotage): Promise<void> {
  logEl.replaceChildren();
  const badge = el<HTMLDivElement>("badge");
  badge.className = "badge";
  badge.textContent = "verifying…";

  const baseUrl = el<HTMLInputElement>("launcher-url").value.trim();
  const audience = el<HTMLInputElement>("audience").value.trim() || DEFAULT_AUDIENCE;
  const expectedDigest = sabotage.wrongDigest
    ? "sha256:" + "0".repeat(64)
    : el<HTMLInputElement>("expected-digest").value.trim();

  try {
    // 1. Fresh challenge (anti-replay), 16 random bytes hex-encoded.
    const challenge = Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) =>
      b.toString(16).padStart(2, "0"),
    ).join("");
    logLine("step", `challenge nonce: ${challenge}`);

    // 2. Fetch attestation token and the served HPKE key.
    const attResponse = await fetch(new URL(`/attestation?nonce=${challenge}`, baseUrl));
    const attBody = (await attResponse.json()) as {
      token?: string;
      dev?: boolean;
      error?: string;
    };
    if (!attResponse.ok || !attBody.token) {
      throw new Error(`attestation fetch failed: ${attBody.error ?? attResponse.status}`);
    }
    let token = attBody.token;
    const dev = attBody.dev === true;
    logLine(dev ? "warn" : "step", `token fetched${dev ? " (DEV MODE: unsigned, unverified)" : ""}`);

    const keyResponse = await fetch(new URL("/hpke-key", baseUrl));
    const keyBody = (await keyResponse.json()) as { public_key: string };
    let hpkePublicKey = b64decode(keyBody.public_key);
    logLine("step", `HPKE key served, sha256 ${await sha256Hex(hpkePublicKey)}`);

    // Sabotage hooks for the failure-mode buttons.
    if (sabotage.tamperToken) {
      token = tamper(token);
      logLine("warn", "sabotage: token payload tampered; enforcing strict signature check");
    }
    if (sabotage.wrongDigest) logLine("warn", `sabotage: expecting digest ${expectedDigest}`);
    if (sabotage.wrongKeyHash) {
      hpkePublicKey = crypto.getRandomValues(new Uint8Array(32));
      logLine("warn", "sabotage: pinning a random key instead of the served one");
    }

    // 3. Signature. A tampered token is never given the dev-mode pass, so
    //    locally it fails strict verification just as it would against Google.
    const { claims, signatureVerified } = await verifyTokenSignature(
      token,
      audience,
      dev && !sabotage.tamperToken,
    );
    logLine(
      signatureVerified ? "ok" : "warn",
      signatureVerified
        ? "signature verified against Google JWKS"
        : "signature NOT verified (dev token) — trust nothing this page shows",
    );

    // 4–6. Challenge, digest, key binding (distinct error per failure).
    await checkClaims(claims, { challenge, expectedImageDigest: expectedDigest, hpkePublicKey });
    logLine("ok", "challenge echoed in eat_nonce");
    logLine("ok", `image digest matches expected (${expectedDigest})`);
    logLine("ok", "HPKE key binding matches eat_nonce — key pinned");

    // 7. Encrypted echo round-trip with the pinned key.
    const msg = el<HTMLInputElement>("message").value;
    const echoed = await hpkeEcho(baseUrl, hpkePublicKey, msg);
    logLine("ok", `HPKE echo round-trip OK, decrypted reply: "${echoed}"`);

    badge.className = `badge ${signatureVerified ? "good" : "dev"}`;
    badge.textContent = signatureVerified ? "VERIFIED" : "DEV MODE — UNVERIFIED";
  } catch (err) {
    const code = err instanceof AttestationError ? err.code : "ERROR";
    logLine("fail", err instanceof Error ? err.message : String(err));
    badge.className = "badge bad";
    badge.textContent = code;
  }
}

el<HTMLButtonElement>("run").addEventListener("click", () => void run({}));
el<HTMLButtonElement>("run-tampered").addEventListener("click", () =>
  void run({ tamperToken: true }),
);
el<HTMLButtonElement>("run-wrong-digest").addEventListener("click", () =>
  void run({ wrongDigest: true }),
);
el<HTMLButtonElement>("run-wrong-key").addEventListener("click", () =>
  void run({ wrongKeyHash: true }),
);
