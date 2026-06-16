# One-time project setup: required APIs + Artifact Registry repo + static IP
# + the GCS bucket holding Terraform state for both roots + the long-lived
# artifact-delivery resources (issue 007): the encrypted-artifacts bucket,
# the KMS key that wraps artifact DEKs, and the workload identity pool that
# turns a Confidential Space attestation into an IAM principal. Apply once
# per project, before the main infra root — see infra/README.md ("Remote
# state") for the init flags and the two-phase bootstrap on a fresh project
# (the state bucket is created by this root, so the very first apply must
# run against local state).

terraform {
  required_version = ">= 1.5"

  # Partial configuration: the bucket name embeds the project ID, which this
  # public repo never commits (and backend blocks can't read variables).
  # Supply it at init:
  #   terraform -chdir=infra/bootstrap init \
  #     -backend-config="bucket=${PROJECT_ID}-tfstate" \
  #     -backend-config="prefix=bootstrap"
  backend "gcs" {}

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "Region for the Artifact Registry repository and the static IP"
  type        = string
  default     = "europe-west4"
}

variable "artifact_encrypter_members" {
  description = <<-EOT
    IAM members (e.g. ["user:operator@example.com"]) allowed to wrap artifact
    DEKs with the artifact-sealing KMS key — what scripts/provision-weights.py
    needs. Encrypt-only by design: nobody outside an attested enclave ever
    holds decrypt, the operator included (decrypt is granted per image digest
    by the main root).
  EOT
  type        = list(string)
  default     = []
}

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_project_service" "apis" {
  for_each = toset([
    "compute.googleapis.com",
    "confidentialcomputing.googleapis.com",
    "artifactregistry.googleapis.com",
    # Service-account management: the main root creates the workload SA;
    # also needed to manage the workload identity pool + release SA that
    # the release workflow's registry push authenticates through.
    "iam.googleapis.com",
    # Mints workload-identity-federation access tokens; without it the
    # release workflow's registry push fails at the GCP auth step.
    "iamcredentials.googleapis.com",
    # Exchanges OIDC tokens for GCP credentials: the GitHub OIDC token for the
    # release workflow's WIF auth, and the enclave's attestation JWT for the
    # pool principal's access token in attestation-gated artifact delivery.
    "sts.googleapis.com",
    # Attestation-gated artifact delivery (issue 007): KMS wraps the artifact
    # DEKs, the workload identity pool (IAM, above) hosts the verifier, GCS
    # stores the ciphertext blobs.
    "cloudkms.googleapis.com",
    "storage.googleapis.com",
  ])
  service            = each.value
  disable_on_destroy = false
}

# Terraform state for both roots, prefixes "bootstrap" and "cvm". Lives in
# this never-destroyed root; the self-reference (the bucket holds its own
# root's state) is accepted because bootstrap never runs destroy — and
# prevent_destroy + force_destroy=false make that mechanical. State can
# contain secrets, hence public access prevention; versioning gives recovery
# from a corrupted or mistakenly-pushed state.
resource "google_storage_bucket" "tfstate" {
  name     = "${var.project_id}-tfstate"
  location = var.region

  force_destroy               = false
  public_access_prevention    = "enforced"
  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }

  # Prune noncurrent state versions after 30 days, but always keep the
  # newest 5 regardless of age (conditions AND together).
  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      days_since_noncurrent_time = 30
      num_newer_versions         = 5
    }
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_artifact_registry_repository" "tee_example" {
  repository_id = "tee-example"
  location      = var.region
  format        = "DOCKER"
  description   = "Container images for the TEE example workload"
  depends_on    = [google_project_service.apis]
}

# Static external IP for the CVM. Reserved here, in the never-destroyed root,
# so the address survives the main root's per-deployment apply/destroy cycle
# and DNS records stay valid. The main root looks it up by name via a data
# source, so neither root reads the other's state. Free while attached to a
# running instance; accrues a small idle charge while the CVM is destroyed —
# accepted cost for stable DNS.
resource "google_compute_address" "cvm" {
  name       = "tee-example-cvm"
  region     = var.region # must match the region the CVM is deployed in
  depends_on = [google_project_service.apis]

  lifecycle {
    prevent_destroy = true
  }
}

# ---- Attestation-gated artifact delivery (issue 007) -----------------------
# Long-lived halves of the "IP released only to the attested enclave"
# pipeline, shared by the model weights and (later) the harness blob. They
# live in this never-destroyed root because KMS key rings are undeletable in
# GCP and workload identity pool IDs stay reserved for 30 days after delete —
# per-deployment churn would brick the names. The per-deployment half (the
# decrypt grant pinned to one image digest) lives in the main root.

# Ciphertext artifacts (envelope-encrypted weights + manifests). The blobs
# are useless without KMS: confidentiality is enforced by the key below and
# its attestation-gated IAM, not by this bucket's ACLs.
resource "google_storage_bucket" "artifacts" {
  name     = "${var.project_id}-tee-example-artifacts"
  location = var.region

  force_destroy               = false
  public_access_prevention    = "enforced"
  uniform_bucket_level_access = true

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_project_service.apis]
}

resource "google_kms_key_ring" "tee_example" {
  name     = "tee-example"
  location = var.region

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_project_service.apis]
}

# Wraps the per-artifact DEKs. Decrypt is granted (in the main root) only to
# the attested workload-identity principalSet pinned to the deployed image
# digest; encrypt is granted here to the provisioning operator. No principal
# ever holds both halves outside the enclave.
resource "google_kms_crypto_key" "artifact_sealing" {
  name     = "artifact-sealing"
  key_ring = google_kms_key_ring.tee_example.id
  purpose  = "ENCRYPT_DECRYPT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "artifact_encrypters" {
  for_each      = toset(var.artifact_encrypter_members)
  crypto_key_id = google_kms_crypto_key.artifact_sealing.id
  role          = "roles/cloudkms.cryptoKeyEncrypter"
  member        = each.value
}

# Workload identity pool + provider that turns a Confidential Space
# attestation token into an IAM principal. The provider maps the workload
# image digest into an attribute; the main root grants KMS decrypt to the
# principalSet for the *expected* digest only.
resource "google_iam_workload_identity_pool" "tee_pool" {
  workload_identity_pool_id = "tee-example-pool"
  display_name              = "TEE example attested workloads"

  depends_on = [google_project_service.apis]
}

resource "google_iam_workload_identity_pool_provider" "attestation_verifier" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.tee_pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "attestation-verifier"
  display_name                       = "Confidential Space attestation"

  oidc {
    issuer_uri        = "https://confidentialcomputing.googleapis.com/"
    allowed_audiences = ["https://sts.googleapis.com"]
  }

  attribute_mapping = {
    "google.subject"         = "assertion.sub"
    "attribute.image_digest" = "assertion.submods.container.image_digest"
  }

  # STABLE restricts the principal to the production Confidential Space
  # image: the SSH-able confidential-space-debug family attests with the
  # same swname and image digest but without STABLE, and an operator with
  # SSH could lift decrypted IP straight out of the guest. Debug-image
  # deployments therefore get no KMS principal at all — by design.
  attribute_condition = "assertion.swname == 'CONFIDENTIAL_SPACE' && 'STABLE' in assertion.submods.confidential_space.support_attributes"
}

output "repository_url" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.tee_example.repository_id}"
}

output "cvm_ip" {
  description = "Static IP: point the API domain's A record here"
  value       = google_compute_address.cvm.address
}

output "artifacts_bucket" {
  value = google_storage_bucket.artifacts.name
}

output "artifact_kms_key" {
  value = google_kms_crypto_key.artifact_sealing.id
}

output "workload_identity_pool_provider" {
  description = "Full provider resource name (the STS exchange audience is //iam.googleapis.com/<this>)"
  value       = google_iam_workload_identity_pool_provider.attestation_verifier.name
}
