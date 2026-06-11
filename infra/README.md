# Infra — Confidential Space walking skeleton

Terraform for the attested-echo walking skeleton (issue 002): a GCP
Confidential Space CVM (AMD SEV-SNP) running the `launcher/` container, which
serves `/echo` and `/attestation`.

Two Terraform roots:

| Root | Purpose | Lifecycle |
|---|---|---|
| `infra/bootstrap/` | Required APIs + Artifact Registry repo + static external IP + TLS/ACME long-lived state (bucket, KMS key, workload identity pool) | Apply **once** per project, never destroy |
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

Already bootstrapped before the static IP (or the issue-004 TLS/ACME
resources) existed? Re-run the bootstrap apply — it only adds the new
resources; existing ones are untouched.

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

### Workload identity pool

The bootstrap root now creates a workload identity pool + provider
(`tee-example-pool` / `attestation-verifier`) that turns a Confidential Space
attestation token into an IAM principal, mapping the workload image digest to
`attribute.image_digest`. Issue 004 uses it to gate the ACME-state KMS key on
attestation; issue 007 (weights/harness key release) will reuse the same pool
with per-digest IAM bindings.

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
docker buildx build --platform linux/amd64 \
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
# Boot takes a couple of minutes (image pull + container start).
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

Debugging tips: set `-var confidential_space_image_family=confidential-space-debug`
to get an SSH-able debug image, and check serial port 1 / Cloud Logging for
container logs (`tee-container-log-redirect=true` is set).

## TLS terminated inside the enclave (issue 004)

With `-var tls_domain=api.YOUR_DOMAIN` the launcher serves HTTPS directly:
rustls-acme obtains a Let's Encrypt certificate over TLS-ALPN-01 (port 443
only, no port 80, no LB) and persists the ACME account + cert as KMS-wrapped
blobs in GCS, so `terraform destroy`/`apply` of this root reuses the same
certificate instead of re-issuing. The long-lived pieces (static IP, bucket,
KMS key, workload identity pool) live in `infra/bootstrap/`.

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

- **Staging first.** The default ACME directory is Let's Encrypt staging
  (untrusted test certs, generous rate limits). Only set
  `-var acme_directory=letsencrypt` once issuance works, because production
  issuance is rate-limited per domain (the sealed cache makes this a
  non-issue for restarts, but not for repeated state wipes).
- **KMS is gated on attestation.** Decrypt/encrypt on the sealing key is
  granted only to
  `principalSet://...workloadIdentityPools/tee-example-pool/attribute.image_digest/<digest>`;
  the VM service account has no KMS role. Demonstrate that a non-attested
  principal cannot unwrap the state:

  ```sh
  OBJ=$(gcloud storage ls gs://YOUR_PROJECT_ID-tee-example-acme-state | head -1)
  gcloud storage cp "$OBJ" sealed.bin
  gcloud kms decrypt --ciphertext-file=sealed.bin --plaintext-file=- \
    --key acme-state-sealing --keyring tee-example --location europe-west4
  # expected: PERMISSION_DENIED — even the project operator cannot unwrap
  ```

- **Cert/key binding.** The attestation token's `tls:` eat_nonce is the
  SHA-256 of the serving certificate key's SubjectPublicKeyInfo DER; compare
  with `openssl s_client -connect api.YOUR_DOMAIN:443 | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | sha256sum`.
- A new image digest changes the KMS principalSet member: the old enclave's
  state stays sealed and only the newly pinned digest can unwrap it (the IAM
  binding in this root tracks `var.image_digest`).

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
