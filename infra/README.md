# Infra — Confidential Space walking skeleton

Terraform for the attested-echo walking skeleton (issue 002): a GCP
Confidential Space CVM (AMD SEV-SNP) running the `launcher/` container, which
serves `/echo` and `/attestation`.

Two Terraform roots:

| Root | Purpose | Lifecycle |
|---|---|---|
| `infra/bootstrap/` | Required APIs + Artifact Registry repo + static external IP + Terraform state bucket + artifact delivery's long-lived halves (artifacts bucket, KMS key, workload identity pool) | Apply **once** per project, never destroy |
| `infra/` | Service account, firewall, the CVM itself, per-digest KMS decrypt grant | Apply/destroy per deployment |

The static IP lives in bootstrap so the CVM comes back on the **same address**
after every destroy/apply cycle — DNS pointed at it never goes stale. The main
root finds it by name (`data "google_compute_address"`), so neither root reads
the other's Terraform state. A reserved regional IP is free while attached to
a running instance and accrues a small idle charge while the CVM is destroyed.

## Remote state

Both roots keep their Terraform state in one GCS bucket,
`gs://YOUR_PROJECT_ID-tfstate`, under the prefixes `bootstrap` and `cvm`
(workspaces for [per-branch dev deployments](#per-branch-dev-deployments) land
at `cvm/<workspace>.tfstate`, prod in `cvm/default.tfstate`). The bucket is
itself Terraform-managed in the bootstrap root — versioned, public access
prevention enforced, uniform bucket-level access, `prevent_destroy` — which is
safe because bootstrap never runs destroy.

The repo is public and never commits the project ID, and backend blocks can't
read variables, so both roots use **partial backend configuration**: the
committed blocks are empty `backend "gcs" {}` and the bucket name arrives at
init time —

```sh
terraform -chdir=infra/bootstrap init \
  -backend-config="bucket=YOUR_PROJECT_ID-tfstate" -backend-config="prefix=bootstrap"
terraform -chdir=infra init \
  -backend-config="bucket=YOUR_PROJECT_ID-tfstate" -backend-config="prefix=cvm"
```

(`make deploy` / `make dev-deploy` pass these flags for you, derived from
`PROJECT_ID`.)

**Migrating an existing local state** (a checkout that applied either root
before the backend existed): run the init above with `-migrate-state` added;
Terraform copies the local state — including any `terraform.tfstate.d/`
workspaces in `infra/` — into the bucket. Confirm with
`terraform state list`, then delete the leftover local
`terraform.tfstate*` files.

**Closing the project down for good** is not a Terraform operation — the
state bucket refuses to destroy itself by design. Delete the GCP project:

```sh
gcloud projects delete YOUR_PROJECT_ID
```

## One-time GCP project setup

Authenticate and pick the project:

```sh
gcloud auth login                      # user credentials for gcloud
gcloud auth application-default login  # ADC, used by Terraform
gcloud config set project YOUR_PROJECT_ID
```

Then apply the bootstrap root. On a **fresh project** this is two-phase,
because the bucket that will hold bootstrap's own state is created by this
very apply — phase 1 runs against a local backend via a gitignored override
file, phase 2 moves the state into the bucket it just created:

```sh
# Phase 1: apply against local state (the GCS bucket doesn't exist yet)
printf 'terraform {\n  backend "local" {}\n}\n' > infra/bootstrap/backend_override.tf
terraform -chdir=infra/bootstrap init
terraform -chdir=infra/bootstrap apply -var project_id=YOUR_PROJECT_ID -var region=europe-west4

# Phase 2: migrate the state into the bucket phase 1 created
rm infra/bootstrap/backend_override.tf
terraform -chdir=infra/bootstrap init -migrate-state \
  -backend-config="bucket=YOUR_PROJECT_ID-tfstate" -backend-config="prefix=bootstrap"
rm infra/bootstrap/terraform.tfstate*    # local copies, now redundant
```

(The same two-phase flow migrates a checkout bootstrapped before remote state
existed: phase 1's apply adds the bucket to the existing local state, phase 2
moves that state in.)

Instead of Terraform you can run the equivalent gcloud one-liners — plus the
state bucket, which the `infra/` root still needs:

```sh
gcloud services enable compute.googleapis.com confidentialcomputing.googleapis.com artifactregistry.googleapis.com iam.googleapis.com iamcredentials.googleapis.com sts.googleapis.com
gcloud artifacts repositories create tee-example --repository-format=docker --location=europe-west4
gcloud compute addresses create tee-example-cvm --region=europe-west4
gcloud storage buckets create gs://YOUR_PROJECT_ID-tfstate --location=europe-west4 \
  --uniform-bucket-level-access --public-access-prevention
gcloud storage buckets update gs://YOUR_PROJECT_ID-tfstate --versioning
```

Already bootstrapped on an older revision? Re-run the bootstrap apply — it
only adds what's missing (the address, the bucket); existing resources are
untouched.

### DNS for the enclave API

Point a subdomain at the static IP with an **A record** (at your DNS
provider; nothing in Terraform manages this):

```
api.<domain>.  300  IN  A  <static IP>   # IP: terraform -chdir=infra/bootstrap output -raw cvm_ip
```

Keep the TTL low (~300 s) while iterating; raise it once the setup is stable.
The IP survives `terraform -chdir=infra destroy`/`apply`, so this record is
set once and stays valid across redeployments.

The frontend's custom domain is a separate concern: it's a CNAME to
`<user>.github.io` configured through GitHub Pages (issue #13), not anything
in `infra/`.

### Workload identity pool (attestation → IAM principal)

Retrieving a plain attestation token requires no workload identity pool: the
in-VM attestation service mints the OIDC token directly over
`/run/container_launcher/teeserver.sock`. The pool exists for **artifact
delivery** (issue #7): bootstrap creates pool `tee-example-pool` with
provider `attestation-verifier`, which accepts the Confidential Space
attestation JWT and maps `submods.container.image_digest` into
`attribute.image_digest`. The provider's attribute condition additionally
requires `'STABLE' in assertion.submods.confidential_space.support_attributes`,
so the SSH-able `confidential-space-debug` image — where an operator could
lift decrypted IP straight out of the guest — never gets an IAM principal at
all. Per deployment, the main root grants `roles/cloudkms.cryptoKeyDecrypter`
on the artifact-sealing key to the `principalSet` pinned to the deployed
image digest only (see "Encrypted weights" below).

## Build & push the workload image

> **Dev/bootstrap only.** This `docker buildx` path is for the walking
> skeleton and local iteration; its digests are not reproducible and will
> not match a release. Production images come from the deterministic
> release pipeline: `make image` (reproducible build, prints digest D),
> `make push PROJECT_ID=...` (push by digest), `make deploy PROJECT_ID=...`
> (pin D into the CVM and apply) — see the root `README.md` and
> `.github/workflows/release.yml`. Run `make mirror-base PROJECT_ID=...`
> once per base-image bump to mirror the pinned llama.cpp base into
> Artifact Registry under a per-digest tag, so every pin stays mirrored
> across bumps (verifier rebuilds must not depend on ghcr retention).

```sh
gcloud auth configure-docker europe-west4-docker.pkg.dev
# MODEL_URL (dev only) bakes plaintext chat-model weights (GGUF) into the
# image so /chat serves real inference (issue 006). Release images ship
# WITHOUT weights (spike 002): production /chat is activated by encrypted
# weights delivery instead — see "Encrypted weights" below. Without either,
# the image still works but /chat returns 503.
docker buildx build --platform linux/amd64 \
  --build-arg MODEL_URL="https://huggingface.co/google/gemma-4-E2B-it-qat-q4_0-gguf/resolve/main/gemma-4-E2B_q4_0-it.gguf" \
  -t europe-west4-docker.pkg.dev/YOUR_PROJECT_ID/tee-example/launcher:latest \
  --push launcher/
# Grab the digest the CVM will be measured against:
docker buildx imagetools inspect \
  europe-west4-docker.pkg.dev/YOUR_PROJECT_ID/tee-example/launcher:latest \
  --format '{{json .Manifest.Digest}}'
```

## Encrypted weights (attestation-gated artifact delivery)

The model weights are company IP, stored in GCS only as ciphertext
and decryptable **only inside an attested enclave running the expected image
digest**. Moving parts:

- **bootstrap** (long-lived; KMS key rings are undeletable and pool IDs stay
  reserved 30 days after delete): artifacts bucket
  `YOUR_PROJECT_ID-tee-example-artifacts`, KMS key ring `tee-example` with
  key `artifact-sealing`, workload identity pool + provider (above), and
  encrypt-only IAM for the provisioning operator via
  `-var 'artifact_encrypter_members=["user:you@example.com"]'`. Even the
  project owner needs that explicit grant — the basic role carries no KMS
  data-plane permissions, and nobody outside an enclave ever holds decrypt.
- **provisioning** (`scripts/provision-weights.py`): downloads the GGUF,
  envelope-encrypts it with a fresh DEK (ChaCha20-Poly1305 STREAM), wraps
  the DEK with the KMS key, uploads ciphertext + manifest, and prints the
  `weights_object` value for `infra/terraform.tfvars`. Idempotent —
  re-running with the same model is a no-op.
- **main root**: with `weights_object` set, the CVM gets metadata attributes
  the launcher reads at boot (bucket/object/key/pool-provider audience), a
  `tee-mount` tmpfs at `/models` (decrypted weights live only in SEV-SNP
  guest memory; the image label `tee.launch_policy.allow_mount_destinations`
  admits the mount), GCS read for the ciphertext, and the per-digest KMS
  decrypt grant.
- **launcher** (`launcher/src/artifacts.rs` + `gcp.rs`): exchanges its
  attestation JWT at STS for the pool principal, unwraps the DEK, streams
  the ciphertext through the envelope decryptor onto the tmpfs, verifies
  size + SHA-256, and starts llama-server.

```sh
# One-time per project: grant yourself encrypt (re-apply of bootstrap)
terraform -chdir=infra/bootstrap apply -var project_id=YOUR_PROJECT_ID \
  -var 'artifact_encrypter_members=["user:you@example.com"]'

# Encrypt + upload the weights; prints the weights_object to set
./scripts/provision-weights.py --project YOUR_PROJECT_ID

# Build + sign the harness, then encrypt + upload it the same way (issue #8);
# prints the harness_object to set. Rides the same KMS key — no extra grant.
./scripts/build-harness.sh
./scripts/provision-harness.py --project YOUR_PROJECT_ID

# Add both to infra/terraform.tfvars and (re)apply — make deploy only passes
# project_id and image_digest, the rest auto-loads from tfvars
echo 'weights_object = "weights/gemma-4-E2B_q4_0-it.gguf.manifest.json"' >> infra/terraform.tfvars
echo 'harness_object = "harness/harness.wasm.manifest.json"' >> infra/terraform.tfvars
terraform -chdir=infra apply
```

The CVM must run the **production** `confidential-space` family: the
provider's STABLE condition denies the debug image by design (don't "fix"
this by loosening the condition).

Two operational gotchas:

- The image must carry `tee.launch_policy.allow_mount_destinations=/models`
  (current `launcher/Dockerfile` and release recipe v3+). Setting
  `weights_object` against an image built before that label makes
  Confidential Space refuse the tmpfs mount and the VM self-terminates right
  after launch, with no log mentioning the mount.
- The launcher reads the weights metadata at boot and the tmpfs is created
  at workload launch, so enabling or changing `weights_object` on an
  **already-running** CVM does nothing — Terraform updates instance metadata
  in place. Replace the VM:
  `terraform -chdir=infra apply -replace=google_compute_instance.cvm`.

### Negative test: same service account, no attestation

`scripts/test-kms-denial.sh` proves the gate is the attestation, not the
service account: it boots a plain (non-confidential) e2-small VM with the
same workload SA and scopes, has it attempt to unwrap the real DEK, and
expects KMS to answer 403. The VM is deleted on exit.

```sh
./scripts/test-kms-denial.sh YOUR_PROJECT_ID weights/gemma-4-E2B_q4_0-it.gguf.manifest.json
```

### Rotation / revocation

The decrypt grant is pinned to one image digest, so rotating the digest in
Terraform revokes every previously released image: apply with the new
`image_digest` and the `principalSet` member is replaced — old images can
still pull the ciphertext but can no longer unwrap the DEK. Caveat for
[per-branch dev deployments](#per-branch-dev-deployments): two workspaces
deploying the *same* digest create the same IAM binding twice, and the first
destroy removes it for both — acceptable for dev churn.

## Deploy, verify, destroy

```sh
terraform -chdir=infra init \
  -backend-config="bucket=YOUR_PROJECT_ID-tfstate" -backend-config="prefix=cvm"
# Persist the deployment vars in a tfvars file (gitignored). Terraform
# auto-loads it, so the destroy at the end needs no vars re-supplied.
cat > infra/terraform.tfvars <<EOF
project_id   = "YOUR_PROJECT_ID"
image_digest = "sha256:DIGEST_FROM_ABOVE"
EOF
terraform -chdir=infra apply

IP=$(terraform -chdir=infra output -raw external_ip)
# Boot takes several minutes (image pull — ~3.4 GB with baked weights — then
# model load; the launcher logs "llama-server ready in Ns" when /chat works).
curl "http://$IP:8080/echo?msg=hello"
# …or, once the A record is in place:
curl "http://api.YOUR_DOMAIN:8080/echo?msg=hello"
./scripts/verify-attestation.py --url "http://$IP:8080" --image-digest sha256:DIGEST_FROM_ABOVE

terraform -chdir=infra destroy   # vars come from infra/terraform.tfvars

# If destroying a CI-deployed service locally (no tfvars file on disk),
# only project_id is needed — image_digest is not evaluated during destroy.
terraform -chdir=infra destroy -var="project_id=YOUR_PROJECT_ID"
```

The verifier generates a fresh random nonce, fetches the token from
`/attestation`, validates Google's signature against the Confidential Space
JWKS, and checks issuer, audience, `eat_nonce`, and
`submods.container.image_digest`, printing PASS/FAIL per check.

To exercise `/chat` on a deployed enclave without the browser, use
`scripts/chat-client.py` — it speaks the frontend's HPKE wire format
(fetch `/hpke-key`, seal the message, open the sealed reply):

```sh
./scripts/chat-client.py --url "http://$IP:8080" "how was my week?"  # one shot
./scripts/chat-client.py --url "http://$IP:8080"                     # interactive
```

In interactive mode the script keeps the conversation history locally and
resends it in full on every turn — the enclave holds no conversation state.

Unlike the frontend, the script does not verify the attestation token before
trusting the enclave key — pair it with `verify-attestation.py`.

Debugging tips: set `-var confidential_space_image_family=confidential-space-debug`
to get an SSH-able debug image, and check serial port 1 / Cloud Logging for
container logs (`tee-container-log-redirect=true` is set).

## TLS terminated inside the enclave (issue 004)

With `-var tls_domain=api.YOUR_DOMAIN` the launcher serves HTTPS directly:
rustls-acme obtains a Let's Encrypt certificate over TLS-ALPN-01 (port 443
only, no port 80, no LB). Nothing persists: every boot registers a fresh
ACME account and orders a fresh certificate, both living only in enclave
memory (`launcher/src/acme_cache.rs` has the rationale). Only the static IP
is long-lived (in `infra/bootstrap/`), so DNS stays valid across
destroy/apply cycles.

One-time DNS setup, after applying the bootstrap root:

```sh
terraform -chdir=infra/bootstrap output -raw cvm_ip
# Create an A record at your DNS provider:
#   api.YOUR_DOMAIN.  A  <cvm_ip>     (TTL ~300)
```

Deploy with TLS:

```sh
terraform -chdir=infra apply \
  -var project_id=YOUR_PROJECT_ID \
  -var image_digest=$DIGEST \
  -var tls_domain=api.YOUR_DOMAIN \
  -var acme_contact=you@example.com \
  -var acme_directory=letsencrypt-staging   # switch to letsencrypt once the flow is proven

curl -v "https://api.YOUR_DOMAIN/echo?msg=hello"   # staging cert: add --insecure
./scripts/verify-attestation.py --url "https://api.YOUR_DOMAIN" --image-digest "$DIGEST"
```

Notes:

- **Staging first.** The default ACME directory is Let's Encrypt staging:
  certs chain to untrusted test roots (`curl --insecure` to inspect), but
  issuance is effectively unlimited (30,000 certs/week per domain), so
  destroy/apply cycles cost nothing. Only set
  `-var acme_directory=letsencrypt` for a live demo with a browser-trusted
  cert. Production limits that matter here, since every boot is a fresh
  issuance: **5 certs per exact identifier set per 7 days** (refills 1 per
  ~34 h) and 50 per registered domain per 7 days — fine for occasional
  demos, not for tight redeploy loops. New-account registration (also fresh
  per boot) allows 10 per IP per 3 hours.
- **Cert/key binding.** The attestation token's `tls:` eat_nonce is the
  SHA-256 of the serving certificate key's SubjectPublicKeyInfo DER.
  `verify-attestation.py` checks this automatically when given an `https://`
  URL (it fetches the served certificate and compares the hashes, retrying
  once on mismatch to ride out a renewal rebind). Manual cross-check:
  `openssl s_client -connect api.YOUR_DOMAIN:443 | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | sha256sum`.

## Inference footprint & boot time

Measured for issue #6 with Gemma 4 E2B QAT Q4 (`gemma-4-E2B_q4_0-it.gguf`)
under the supervised launcher, per llama.cpp's own memory accounting:

| What | Size |
|---|---|
| Model weights | ~3.2 GiB |
| KV cache (default 128k context) | ~0.8 GiB |
| Compute buffer | ~0.5 GiB |
| Launcher | ~5 MiB |
| **Total** | **≈ 4.5 GiB** |

On the default `n2d-standard-4` (16 GB) that leaves >10 GiB headroom for the
EmbeddingGemma instance (issue #11). If memory ever gets tight,
`LLAMA_EXTRA_ARGS="--ctx-size 8192"` shaves ~0.7 GiB off the KV cache.

Cold boot to `/health` ok: **5.6 s locally** (M-series laptop; model load
dominates). On the CVM the launcher's own number is about the same —
**2.8–2.9 s** (`inference: llama-server ready in Ns`) — because the GGUF is
mmapped from local disk. What the user actually waits for is everything
before it.

On-VM numbers, measured 2026-06-12 against `tees-499001` (production
`confidential-space` image, `n2d-standard-4`, weights baked into a ~3.4 GB
image, two consecutive boots within a couple of seconds of each other):

| Phase (from Cloud Logging) | Duration |
|---|---|
| Instance create → guest `Boot completed` | ~42–45 s |
| Image pull from same-region Artifact Registry | ~87–90 s |
| Workload setup + launcher start | ~4 s |
| llama-server boot → `/health` ok | **2.8–2.9 s** |
| **Instance create → encrypted `/chat` ready** | **≈ 2 min 20 s – 2 min 40 s** |

Memory, per llama.cpp's on-VM fit (`common_params_fit_impl`): **3532 MiB
projected of 15024 MiB visible host memory** — ~11.2 GiB headroom for the
EmbeddingGemma instance (issue #11), with the full 128k context retained
(4 slots, unified KV). The image pull dominates cold boot, so shrinking the
image (or fetching weights at boot, issue #7) is the lever if redeploy
latency ever matters.

## Per-branch dev deployments

A feature branch can be deployed to its own CVM alongside prod (issue #28),
e.g. for on-VM measurements, without touching the production deployment:

```sh
make dev-deploy PROJECT_ID=YOUR_PROJECT_ID    # from the feature branch
make dev-destroy PROJECT_ID=YOUR_PROJECT_ID   # tear down this branch's CVM only
make dev-list                                 # what's (potentially) still up
```

`dev-deploy` derives a deployment suffix from the branch name
(`scripts/dev-slug.sh` → `dev-<slug>`, sanitized and truncated so the
service-account `account_id` stays within GCP's 30-char limit), buildx-pushes
the launcher image tagged `dev-<slug>` (non-reproducible digest — dev only;
releases still come from `make image`), and applies the main root with
`-var deployment_suffix=dev-<slug>` in a **Terraform workspace** of the same
name. Prod lives in the `default` workspace with an empty suffix, so its
state and resource names are untouched, and a dev `destroy` can only ever
see its own workspace's resources: `tee-example-cvm-dev-<slug>`, service
account `tee-ex-dev-<slug>`, firewall `tee-example-allow-http-dev-<slug>`.

Dev CVMs take an **ephemeral external IP** — `dev-deploy` prints it, along
with a ready-made `verify-attestation.py` line. The bootstrap static IP (and
the DNS pointing at it) belongs to prod alone. To point the frontend at a
dev enclave, drop the printed address into `frontend/.env.local`:

```sh
VITE_API_ENDPOINT=http://DEV_IP:8080
```

**Cost**: every dev deployment is a full SEV-SNP N2D instance billed while
it runs. Tear yours down when done; `make dev-list` shows leftover
workspaces, and dev instances carry labels for sweeping by hand:

```sh
gcloud compute instances list --filter=labels.created-by=dev-deploy
```

Running several deployments at once also eats into the regional N2D vCPU
quota (`europe-west4`) — check it before assuming many can coexist.

## Live run

Completed 2026-06-10 against project `tees-499001`: `/echo` responded and the
verifier printed `RESULT: PASS` on the production Confidential Space image.
Gotchas hit on the way, now fixed in-tree:

- The image families are `confidential-space` / `confidential-space-debug`
  (the previous `confidential-space-debian*` defaults don't exist).
- The workload image must carry `LABEL tee.launch_policy.log_redirect=always`
  (set in `launcher/Dockerfile`). Without it the production image gives the
  container no usable stdout, the launcher's first `println!` aborts it, and
  the VM self-terminates ~0.1 s after launch with no container logs.
- A fresh apply creates the workload service account, its IAM grants, and the
  CVM essentially at once, but GCP IAM grants on new principals are eventually
  consistent (can take a couple of minutes to propagate). If the CVM boots
  first it can neither pull the image (`artifactregistry.reader`) nor write to
  Cloud Logging (`logging.logWriter`), so it self-terminates after ~3 minutes
  with **zero guest-side logs**. `infra/main.tf` works around this with a
  `time_sleep.iam_propagation` (120 s) the CVM depends on. Distinguish the two
  silent-failure modes by timing: a missing `log_redirect` label kills the VM
  ~0.1 s after the container launches, the IAM race kills it ~3 minutes after
  boot — and a plain `gcloud compute instances start` of the same VM later
  comes up clean once IAM has settled.
- `eat_nonce` in real tokens also carries the issue-003 `hpke:`/`tls:`
  key-binding entries; the verifier checks membership of its fresh nonce.

Ordered commands (from the repo root; substitute your project ID):

```sh
# 1. Authenticate (interactive)
gcloud auth login
gcloud auth application-default login
gcloud config set project YOUR_PROJECT_ID

# 2. One-time project setup: enable APIs + create the Artifact Registry repo,
#    the state bucket, and the artifact-delivery resources (bucket, KMS key,
#    workload identity pool). Fresh project? Use the two-phase flow from
#    "One-time GCP project setup" above for the init.
terraform -chdir=infra/bootstrap init \
  -backend-config="bucket=YOUR_PROJECT_ID-tfstate" -backend-config="prefix=bootstrap"
terraform -chdir=infra/bootstrap apply -var project_id=YOUR_PROJECT_ID \
  -var 'artifact_encrypter_members=["user:YOU@example.com"]'

# 2b. Provision the encrypted weights (idempotent; prints the weights_object
#     value used in step 4)
./scripts/provision-weights.py --project YOUR_PROJECT_ID

# 2c. Build + sign + provision the encrypted harness (issue #8; idempotent;
#     prints the harness_object value used in step 4)
./scripts/build-harness.sh
./scripts/provision-harness.py --project YOUR_PROJECT_ID

# 3. Build & push the workload image, capture its digest
gcloud auth configure-docker europe-west4-docker.pkg.dev
docker buildx build --platform linux/amd64 \
  -t europe-west4-docker.pkg.dev/YOUR_PROJECT_ID/tee-example/launcher:latest \
  --push launcher/
DIGEST=$(docker buildx imagetools inspect \
  europe-west4-docker.pkg.dev/YOUR_PROJECT_ID/tee-example/launcher:latest \
  --format '{{json .Manifest.Digest}}' | tr -d '"')

# 4. Bring up the Confidential Space CVM. The vars are persisted in a
#    gitignored tfvars file so step 7's destroy needs none of them.
terraform -chdir=infra init \
  -backend-config="bucket=YOUR_PROJECT_ID-tfstate" -backend-config="prefix=cvm"
cat > infra/terraform.tfvars <<EOF
project_id     = "YOUR_PROJECT_ID"
image_digest   = "$DIGEST"
weights_object = "weights/gemma-4-E2B_q4_0-it.gguf.manifest.json"  # from step 2b
harness_object = "harness/harness.wasm.manifest.json"              # from step 2c
EOF
terraform -chdir=infra apply

# 5. Exercise the workload (allow a couple of minutes for boot + image pull,
#    plus weights download + decrypt before /chat answers)
IP=$(terraform -chdir=infra output -raw external_ip)
curl "http://$IP:8080/echo?msg=hello"
./scripts/chat-client.py --url "http://$IP:8080" "hello in five words"

# 6. Verify the attestation token end to end (expects RESULT: PASS), and that
#    a non-attested VM with the same service account cannot unwrap the DEK
./scripts/verify-attestation.py --url "http://$IP:8080" --image-digest "$DIGEST"
./scripts/test-kms-denial.sh YOUR_PROJECT_ID weights/gemma-4-E2B_q4_0-it.gguf.manifest.json

# 7. Tear everything down
# Same-env run (vars already in infra/terraform.tfvars):
terraform -chdir=infra destroy
# CI-deployed service, destroying locally (no tfvars on disk):
terraform -chdir=infra destroy -var="project_id=YOUR_PROJECT_ID"
```
