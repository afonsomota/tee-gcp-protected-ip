# Verifying it yourself

This walks the full trust chain of a live deployment, one step at a time.
Each section explains **what the step proves** and **what is still assumed**
afterwards, so you always know exactly where you stand. By the end, the only
remaining assumptions are the platform itself (AMD silicon and Google's
Confidential Space stack) — everything else you will have checked with your
own tools on your own machine.

The whole chain is automated by one command:

```sh
./scripts/verify-chain.py --url https://HOST            # steps 1–5
./scripts/verify-chain.py --url https://HOST --rebuild  # + step 6 (needs docker)
```

(The script is ~250 lines of Python — read it; auditing your own verifier is
the point. `uv` runs it with its two dependencies pinned in the header.
`scripts/verify-attestation.py` is the smaller sibling used by `make verify`
when you already know the digest you expect.)

The hosted frontend performs steps 1–4 of this chain in your browser on every
page load, plus a key-binding check (see step 3), and shows the result as the
attestation badge. But the hosted frontend is trust-on-first-use: the
JavaScript could lie about its own checks. This page and the CLI exist so you
don't have to take its word — same enclave, your own verifier.

## Step 1 — Get a fresh attestation token

```sh
NONCE=$(openssl rand -hex 16)
curl "https://HOST/attestation?nonce=$NONCE"
```

The launcher forwards your nonce to the Confidential Space attestation
service (a Unix socket only present inside a real Confidential VM, backed by
an AMD SEV-SNP hardware report) and returns the OIDC token (a JWT) that
Google's service mints.

**Proven:** nothing yet. Anyone can return bytes shaped like a token.

**Still assumed:** everything. The next steps remove assumptions one by one.

## Step 2 — Verify Google's signature

The token is signed by Google's Confidential Space attestation service. Its
keys are published at a well-known URL:

```
https://confidentialcomputing.googleapis.com/.well-known/openid-configuration
  → jwks_uri → the RS256 keys
```

The CLI verifies the signature against that JWKS, with the algorithm pinned
to RS256 (never trusting the token's own header), and checks
`iss == https://confidentialcomputing.googleapis.com`.

**Proven:** this token was minted by Google's attestation service. The
operator of this project cannot forge one — they never see a signing key.
A server that is *not* a Confidential Space VM cannot obtain one at all.

**Still assumed:** Google's attestation service is honest, and you reached
the real `googleapis.com` (web PKI). This is the irreducible platform trust —
see [threat-model.md](threat-model.md). Also still unknown: whether the token
is fresh and *what* it attests.

## Step 3 — Check the claims

The CLI checks `aud` (the expected audience string) and that the random nonce
*you* generated in step 1 is echoed in the token's `eat_nonce` claim.

**Proven:** the token is fresh — it was minted after you issued your
challenge, not replayed from an earlier boot or a different machine.

`eat_nonce` also carries two extra entries the *enclave* bound at issuance:
`hpke:<sha256 of the enclave's HPKE public key>` and `tls:<sha256 of its TLS
key>`. These are how a client knows the keys it talks to live inside the
attested enclave and not in a middlebox. Each verifier checks the binding it
can see: the frontend checks the served HPKE key against the `hpke:` hash on
every session (`frontend/src/attest/verify.ts`) but *cannot* check `tls:` —
browsers expose no API to read the serving certificate. The CLI covers that
side: given an `https://` URL it hashes the served certificate's key and
compares it with the `tls:` entry; it doesn't establish an HPKE session, so
the `hpke:` entry stays the frontend's job.

**Still assumed:** what code is actually running.

## Step 4 — Read the attested image digest

The claim `submods.container.image_digest` names the exact OCI manifest
digest of the container the Confidential Space launcher booted. The launcher
cannot influence this value; it is measured by the platform before the
workload starts.

**Proven:** Google attests that *this exact image* — byte-for-byte, by
cryptographic digest — is what is running in the enclave, on SEV-SNP
hardware, with the launch policy in the image's labels enforced.

**Still assumed:** nothing yet links that digest to any source code you can
read. A digest of a malicious image is still a valid digest.

## Step 5 — Match the digest to a published release

Every release of this repo publishes the digest it built
(`image-digest.txt` on the GitHub release, plus the pinned build inputs in
`release-pins.txt`). The CLI scans the releases, finds the one whose
published digest equals the attested digest, and resolves its tag to a git
commit:

```
attested digest D == release vX.Y.Z digest → built from commit <sha>
```

This is the step that prints **the git commit the running code was built
from**.

**Proven:** the operator *claims* digest D corresponds to that tag and
commit, and the claim is on the public record (a GitHub release, with public
CI logs from `.github/workflows/release.yml` showing D built twice on
independent runners).

**Still assumed:** that the published claim is true — i.e. you are still
trusting the release pipeline and GitHub's infrastructure. If you stop here
you have the "detection, not prevention" tier described in the
[README](../README.md#what-you-trust-by-tier). Step 6 removes this
assumption entirely.

## Step 6 — Rebuild from source and re-derive the digest

The released image is produced by a fully pinned, deterministic recipe
(`scripts/build-image.sh`, ~200 lines — read it too). Run it yourself from
the tagged source:

```sh
git clone --depth 1 --branch vX.Y.Z https://github.com/afonsomota/tee-gcp-protected-ip
cd tee-gcp-protected-ip
make image     # → prints digest D; needs docker, python3, curl
```

or let the CLI do exactly that with `--rebuild` (or hand it a digest you
already derived with `--rebuilt-digest sha256:...`). Compare against the
attested digest from step 4.

The rebuild pulls one pinned base image — the official llama.cpp server
image, which provides the `llama-server` binary the launcher supervises —
from ghcr.io by digest. The operator also mirrors it by digest into
Artifact Registry (`make mirror-base`), so rebuilds of old releases never
depend on ghcr retention. Content-addressing makes the pull source
trust-neutral — both yield the same bytes or fail loudly:

```sh
LLAMA_BASE_SOURCE=REGION-docker.pkg.dev/PROJECT/tee-example/llama.cpp make image
```

(If you load the rebuilt image into Docker and run it locally to poke at
`/echo`, `docker ps` will report the container `unhealthy`: the llama.cpp
base image carries a `HEALTHCHECK` that probes `llama-server`, which never
starts in a weightless release build — `/chat` serves 503. The status is
expected and cosmetic; Confidential Space ignores Docker healthchecks.)

**Proven:** the digest is a pure function of the public source at that
commit plus one pinned public artifact. No build service, registry,
operator, or CI is trusted — if any of them had tampered with the image,
your locally derived digest would differ and step 6 would fail. Combined
with step 4, the claim splits per component (spike 002):

| Component | What your rebuild proves |
|---|---|
| launcher (the appended layer) | bytes re-derived on your machine from `launcher/src/` and its locked dependency tree (`Cargo.lock`) — zero trust in anyone |
| llama-server (the base image) | bytes are exactly the public artifact ggml-org published at the pinned digest — content-addressed, the same image everyone pulls; the bytes↔source link rests on upstream's release process |

A backdoor in `llama-server` would have to live in the public artifact used
by everyone, not in something targeted at this deployment. Building it
reproducibly from source too is recorded as future hardening
(`docs/spikes/002-llama-server-in-release-image.md`).

**Still assumed (the floor you cannot verify away):**

- AMD's silicon implements SEV-SNP correctly, and Google's Confidential
  Space stack (firmware, OS image, container launcher) does what it says.
  Google could in principle mint a false token. See
  [threat-model.md](threat-model.md) for why this is the accepted platform
  TCB.
- The pinned toolchain (the digest-pinned Rust image, `crane`) doesn't
  contain a reproducible-on-purpose backdoor — mitigated by the pins being
  public, auditable, and upstream artifacts used by many parties.
- The pinned llama.cpp base image faithfully corresponds to its public
  source: your rebuild fixes its bytes, but does not re-derive them (the
  table above).
- Known wrinkle: one build input (`musl-dev`, pinned by exact version) comes
  from Alpine's package repo, which keeps only the latest version per
  branch. When Alpine rolls it, rebuilds of *older* tags fail loudly rather
  than producing a different digest (the README documents this and the
  planned fix).

## Convenience tier — the artifact attestation

Each release also publishes a GitHub artifact attestation (sigstore) for D:

```sh
gh attestation verify oci://REGION-docker.pkg.dev/PROJECT/tee-example/launcher@D \
  --repo afonsomota/tee-gcp-protected-ip
```

This proves the image was built by this repo's release workflow, rooted in
GitHub's OIDC identity — useful as a quick check, but strictly weaker than
step 6: it tells you *who* built it, not *what it contains*. Rebuilding does
both.

## What the chain does NOT cover

Verification proves what code runs and that your channel terminates inside
it. It does not protect against a compromised device or browser on *your*
end, side-channel attacks against the enclave, or the hosted frontend lying
about its checks before you've verified independently (TOFU). The full list,
with reasoning, is in [threat-model.md](threat-model.md).
