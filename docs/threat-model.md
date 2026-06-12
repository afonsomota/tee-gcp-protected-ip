# Threat model

This project makes two independent security claims, with two independent
trusted computing bases. Keeping them separate is the point of the design:
the user's privacy must not depend on anything the company controls, and the
company's IP protection must not require the user to behave.

| Claim | Who it protects | TCB |
|---|---|---|
| **Privacy:** journal entries are processed only by open, auditable code; nobody — company, cloud provider, network — can read them | the user | AMD silicon + Google Confidential Space stack + the open launcher and its dependency tree + the frontend code the user runs |
| **IP:** model weights and the harness blob are released only into an attested enclave running the published image | the company | Google Cloud KMS / IAM + the attestation-gated key-release policy |

Note the asymmetry: Google IAM appears only in the **IP** TCB. If KMS
mis-releases a key, the company loses weights — no user data is exposed,
because no user data is ever at rest in the cloud.

## The privacy TCB, bottom to top

1. **AMD SEV-SNP silicon.** Memory encryption and the hardware attestation
   report. Not verifiable by software above it; accepted.
2. **Google's Confidential Space stack** — firmware, the hardened OS image,
   the container launcher, and the attestation service that signs tokens.
   Google measures the workload container and mints OIDC tokens naming its
   digest. Google could in principle mint a false token; accepting this is
   what "the cloud provider is in the platform TCB" means. (What the design
   removes is Google or the company being able to read user data through any
   *software* path — the claim is "we cannot read your data by design",
   with hardware vendors as the explicitly named floor.)
3. **The launcher** (`launcher/`) — the open, audited workload. Small on
   purpose; skeptical auditors reading it is the product. It generates the
   channel keys, binds them into the attestation token, and is the only
   process that touches plaintext user data inside the enclave.
4. **Its load-bearing dependencies** — wasmtime (the harness sandbox),
   llama.cpp (model inference), rustls (TLS), the `hpke` crate, axum. Open
   source, version-locked in `Cargo.lock`, part of what an auditor reviews
   and what the reproducible build pins.
5. **The frontend code the user runs.** Entries are encrypted client-side;
   the master key never leaves the browser. A user who runs the frontend
   locally from audited source removes the hosting from their TCB entirely
   (see TOFU below).

The **reproducible build** (`docs/verifying.md`, step 6) is what connects 3
and 4 to the running enclave: the attested image digest is re-derivable from
the public source by anyone, so "the launcher" in this list means *exactly
the code in this repo at the released tag*, not "whatever the operator
deployed".

## The harness is untrusted — and that's the headline

The company's proprietary orchestration code (the harness) runs *inside* the
enclave but *outside* the privacy TCB:

- It is compiled to WebAssembly and executed under wasmtime, deny-by-default:
  no filesystem, no network, no clocks, no threads — its only capabilities
  are the host functions the open launcher explicitly exposes.
- The host-function manifest is part of the audited open code. Auditors
  verify the *cage*, not the animal: nothing the harness computes can leave
  the enclave except through the launcher, and the launcher routes every
  output back to the user who sent the session's data (the reply and
  tool-calls — there is no other sink).
- Therefore users need zero trust in the harness. A malicious harness could
  produce bad chat replies; it cannot exfiltrate, persist, or phone home.

This is the demo's central trick: **the company keeps its IP closed without
asking users to trust closed code.**

## What each party can and cannot do

**The company (operator):**
- Cannot read journal entries or chat plaintext: data is HPKE-encrypted to a
  key that exists only inside an attested enclave, and the enclave code
  (open, reproducible) never writes user data anywhere.
- Cannot quietly swap the enclave code: a different image yields a different
  attested digest; browsers and CLI verifiers reject it.
- Cannot forge attestation: tokens are signed by Google, keyed to a real
  SEV-SNP report.
- Can deny service, and can ship a malicious *frontend* to users who don't
  verify (TOFU, below).

**Google (cloud + TEE vendor):**
- Cannot read enclave memory through the normal hypervisor path (SEV-SNP
  encrypts guest memory; that is the product).
- Could mint a false attestation token or backdoor the Confidential Space
  stack — platform TCB, **accepted and documented**.
- Sees traffic metadata (IPs, timing, sizes) like any host.

**A network attacker:**
- Sees only TLS, and inside it HPKE envelopes to the attestation-bound
  enclave key. Stripping TLS still leaves HPKE (TLS is defense-in-depth; the
  HPKE key binding carries the trust — `eat_nonce` entries, see
  `docs/verifying.md` step 3).
- Cannot replay attestation tokens usefully: verifiers send fresh nonces.

**A malicious harness (or a compromised harness supply chain):**
- Cannot escape the wasm sandbox short of a wasmtime escape (in the audited
  dependency list for exactly this reason).
- Cannot reach the network, disk, or attestation socket; cannot read entries
  the user's client didn't send into the session.
- Can return wrong/manipulative chat output — out of scope (quality, not
  confidentiality).

**The user:**
- Cannot extract the model weights or harness blob: they are decrypted only
  inside the enclave (KMS releases the key only against a valid attestation
  of the published digest), and the open launcher exposes no endpoint that
  returns them.
- Can distill the model through its outputs over many queries — known,
  accepted IP leak (below).

## Trust-on-first-use (the hosted frontend)

The SPA served from GitHub Pages performs the attestation checks in your
browser — but you learned that from the same place that served you the
JavaScript. On first use you are trusting the host not to have served a
lying verifier. Mitigations, in increasing strength:

1. The frontend is open source and its checks are ~130 lines
   (`frontend/src/attest/verify.ts`).
2. Run the verifier CLI independently (`scripts/verify-chain.py`) — different
   codepath, your machine, no served JavaScript.
3. Clone the repo, audit, and run the frontend locally against the same
   enclave (`frontend/README.md`). After this, no hosting is in your TCB.

## Explicitly out of scope

- **Side-channel attacks** on SEV-SNP (power, timing, controlled-channel,
  speculative execution). Real research area; out of scope for this demo.
- **Compromised user device** — malware, malicious browser extensions, or a
  hostile browser see plaintext before encryption. Nothing server-side can
  help.
- **Google platform compromise / false attestation** — named as the platform
  TCB above, not defended against.
- **Model-output IP leakage (distillation)** — users can learn from what the
  model says; the KMS gate protects the weight *files*, not the function
  they compute.
- **Availability** — the operator (or anyone DoS-ing the enclave) can take
  the service down. Entries live client-side, so user data survives.
- **Traffic analysis** — message timing and sizes are visible to the host
  and network.

## Residual, documented limitations (not "out of scope" — being worked)

- **CI on GitHub infrastructure:** both the canonical and the cross-check
  release builds run on GitHub runners, so a GitHub compromise is
  *detectable* (any outside rebuild exposes it) but not *prevented*. Planned
  hardening: gate `make deploy` on an independent local re-derivation of the
  digest.
- **Alpine package pin:** one build input (`musl-dev`) is version-pinned but
  served from a repo that keeps only the latest version per branch — old
  tags eventually fail to rebuild *loudly*. Planned fix: a committed,
  digest-pinned builder image.
- **TOFU for the hosted frontend** — mitigated as above, never fully removed
  for users who won't run anything locally.
