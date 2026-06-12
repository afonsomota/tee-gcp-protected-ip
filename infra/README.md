# Infra — Confidential Space walking skeleton

Terraform for the attested-echo walking skeleton (issue 002): a GCP
Confidential Space CVM (AMD SEV-SNP) running the `launcher/` container, which
serves `/echo` and `/attestation`.

Two Terraform roots:

| Root | Purpose | Lifecycle |
|---|---|---|
| `infra/bootstrap/` | Required APIs + Artifact Registry repo + static external IP | Apply **once** per project, never destroy |
| `infra/` | Service account, firewall, the CVM itself | Apply/destroy per deployment |

The static IP lives in bootstrap so the CVM comes back on the **same address**
after every destroy/apply cycle — DNS pointed at it never goes stale. The main
root finds it by name (`data "google_compute_address"`), so neither root reads
the other's Terraform state. A reserved regional IP is free while attached to
a running instance and accrues a small idle charge while the CVM is destroyed.

## One-time GCP project setup

Authenticate and pick the project:

```sh
gcloud auth login                      # user credentials for gcloud
gcloud auth application-default login  # ADC, used by Terraform
gcloud config set project YOUR_PROJECT_ID
```

Then either apply the bootstrap root:

```sh
terraform -chdir=infra/bootstrap init
terraform -chdir=infra/bootstrap apply -var project_id=YOUR_PROJECT_ID -var region=europe-west4
```

…or run the equivalent gcloud one-liners:

```sh
gcloud services enable compute.googleapis.com confidentialcomputing.googleapis.com artifactregistry.googleapis.com
gcloud artifacts repositories create tee-example --repository-format=docker --location=europe-west4
gcloud compute addresses create tee-example-cvm --region=europe-west4
```

Already bootstrapped before the static IP existed? Re-run the bootstrap apply
(it only adds the address; existing resources are untouched).

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

### Workload identity pool — not needed yet

Retrieving a plain attestation token (what this skeleton does) requires **no
workload identity pool**: the in-VM attestation service mints the OIDC token
directly over `/run/container_launcher/teeserver.sock`. A WIP + provider with
an attribute condition on `submods.container.image_digest` becomes necessary
in issue 007, when KMS decrypt access is gated on a valid attestation. Set it
up then, roughly:

```sh
gcloud iam workload-identity-pools create tee-pool --location=global
gcloud iam workload-identity-pools providers create-oidc attestation-verifier \
  --location=global --workload-identity-pool=tee-pool \
  --issuer-uri="https://confidentialcomputing.googleapis.com/" \
  --allowed-audiences="https://sts.googleapis.com" \
  --attribute-mapping="google.subject=assertion.sub" \
  --attribute-condition="assertion.submods.container.image_digest == 'sha256:EXPECTED'"
```

## Build & push the workload image

> **Dev/bootstrap only.** This `docker buildx` path is for the walking
> skeleton and local iteration; its digests are not reproducible and will
> not match a release. Production images come from the deterministic
> release pipeline: `make image` (reproducible build, prints digest D),
> `make push PROJECT_ID=...` (push by digest), `make deploy PROJECT_ID=...`
> (pin D into the CVM and apply) — see the root `README.md` and
> `.github/workflows/release.yml`.

```sh
gcloud auth configure-docker europe-west4-docker.pkg.dev
# MODEL_URL bakes chat-model weights (GGUF) into the image so /chat serves
# real inference (issue 006; encrypted delivery replaces this in issue 007).
# Without it the image still works, but /chat returns 503.
docker buildx build --platform linux/amd64 \
  --build-arg MODEL_URL="https://huggingface.co/google/gemma-4-E2B-it-qat-q4_0-gguf/resolve/main/gemma-4-E2B_q4_0-it.gguf" \
  -t europe-west4-docker.pkg.dev/YOUR_PROJECT_ID/tee-example/launcher:latest \
  --push launcher/
# Grab the digest the CVM will be measured against:
docker buildx imagetools inspect \
  europe-west4-docker.pkg.dev/YOUR_PROJECT_ID/tee-example/launcher:latest \
  --format '{{json .Manifest.Digest}}'
```

## Deploy, verify, destroy

```sh
terraform -chdir=infra init
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

# 2. One-time project setup: enable APIs + create the Artifact Registry repo
terraform -chdir=infra/bootstrap init
terraform -chdir=infra/bootstrap apply -var project_id=YOUR_PROJECT_ID

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
terraform -chdir=infra init
cat > infra/terraform.tfvars <<EOF
project_id   = "YOUR_PROJECT_ID"
image_digest = "$DIGEST"
EOF
terraform -chdir=infra apply

# 5. Exercise the workload (allow a couple of minutes for boot + image pull)
IP=$(terraform -chdir=infra output -raw external_ip)
curl "http://$IP:8080/echo?msg=hello"

# 6. Verify the attestation token end to end (expects RESULT: PASS)
./scripts/verify-attestation.py --url "http://$IP:8080" --image-digest "$DIGEST"

# 7. Tear everything down
# Same-env run (vars already in infra/terraform.tfvars):
terraform -chdir=infra destroy
# CI-deployed service, destroying locally (no tfvars on disk):
terraform -chdir=infra destroy -var="project_id=YOUR_PROJECT_ID"
```
