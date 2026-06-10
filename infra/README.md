# Infra — Confidential Space walking skeleton

Terraform for the attested-echo walking skeleton (issue 002): a GCP
Confidential Space CVM (AMD SEV-SNP) running the `launcher/` container, which
serves `/echo` and `/attestation`.

Two Terraform roots:

| Root | Purpose | Lifecycle |
|---|---|---|
| `infra/bootstrap/` | Required APIs + Artifact Registry repo | Apply **once** per project, never destroy |
| `infra/` | Service account, firewall, the CVM itself | Apply/destroy per deployment |

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
```

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
terraform -chdir=infra apply \
  -var project_id=YOUR_PROJECT_ID \
  -var image_digest=sha256:DIGEST_FROM_ABOVE

IP=$(terraform -chdir=infra output -raw external_ip)
# Boot takes a couple of minutes (image pull + container start).
curl "http://$IP:8080/echo?msg=hello"
./scripts/verify-attestation.py --url "http://$IP:8080" --image-digest sha256:DIGEST_FROM_ABOVE

terraform -chdir=infra destroy \
  -var project_id=YOUR_PROJECT_ID \
  -var image_digest=sha256:DIGEST_FROM_ABOVE
```

The verifier generates a fresh random nonce, fetches the token from
`/attestation`, validates Google's signature against the Confidential Space
JWKS, and checks issuer, audience, `eat_nonce`, and
`submods.container.image_digest`, printing PASS/FAIL per check.

Debugging tips: set `-var confidential_space_image_family=confidential-space-debug`
to get an SSH-able debug image, and check serial port 1 / Cloud Logging for
container logs (`tee-container-log-redirect=true` is set).

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

# 4. Bring up the Confidential Space CVM
terraform -chdir=infra init
terraform -chdir=infra apply -var project_id=YOUR_PROJECT_ID -var image_digest=$DIGEST

# 5. Exercise the workload (allow a couple of minutes for boot + image pull)
IP=$(terraform -chdir=infra output -raw external_ip)
curl "http://$IP:8080/echo?msg=hello"

# 6. Verify the attestation token end to end (expects RESULT: PASS)
./scripts/verify-attestation.py --url "http://$IP:8080" --image-digest "$DIGEST"

# 7. Tear everything down
terraform -chdir=infra destroy -var project_id=YOUR_PROJECT_ID -var image_digest=$DIGEST
```
