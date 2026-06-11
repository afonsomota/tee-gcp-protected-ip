# One-time project setup: required APIs, Artifact Registry repo, and the
# long-lived TLS/ACME resources (issue 004) that must survive per-deployment
# destroy/apply of the main root: static CVM IP, sealed-ACME-state bucket,
# KMS key, and the workload identity pool that gates KMS on attestation.
# Apply once per project, before the main infra root:
#   terraform -chdir=infra/bootstrap init && terraform -chdir=infra/bootstrap apply

terraform {
  required_version = ">= 1.5"
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

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_project_service" "apis" {
  for_each = toset([
    "compute.googleapis.com",
    "confidentialcomputing.googleapis.com",
    "artifactregistry.googleapis.com",
    "cloudkms.googleapis.com",
    "iam.googleapis.com",
    # Mints workload-identity-federation access tokens; without it the
    # release workflow's registry push fails at the GCP auth step.
    "iamcredentials.googleapis.com",
    "storage.googleapis.com",
    "sts.googleapis.com",
  ])
  service            = each.value
  disable_on_destroy = false
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

# ---- TLS / ACME long-lived state (issue 004) -------------------------------
# These live in the bootstrap root because they must survive destroy/apply of
# the per-deployment root: the static IP above is what DNS points at, and the
# sealed ACME state is what lets a recreated VM reuse its certificate instead
# of re-issuing (Let's Encrypt rate limits, stable serving key).

# Bucket holding the KMS-wrapped ACME account + certificate blobs. The blobs
# are ciphertext; confidentiality is enforced by the KMS key below, not here.
resource "google_storage_bucket" "acme_state" {
  name                        = "${var.project_id}-tee-example-acme-state"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

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

# Wraps the ACME state. Decrypt is granted (in the main root) only to the
# attested workload-identity principalSet pinned to the deployed image digest,
# so a non-attested principal cannot unwrap the state.
resource "google_kms_crypto_key" "acme_state" {
  name     = "acme-state-sealing"
  key_ring = google_kms_key_ring.tee_example.id
  purpose  = "ENCRYPT_DECRYPT"

  lifecycle {
    prevent_destroy = true
  }
}

# Workload identity pool + provider that turns a Confidential Space
# attestation token into an IAM principal. The provider maps the workload
# image digest into an attribute; the per-deployment root grants KMS access
# to the principalSet for the *expected* digest only.
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

  # Hardening for real releases: also require
  # 'STABLE' in assertion.submods.confidential_space.support_attributes
  # (excludes the SSH-able debug image family used during development).
  attribute_condition = "assertion.swname == 'CONFIDENTIAL_SPACE'"
}

output "repository_url" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.tee_example.repository_id}"
}

output "cvm_ip" {
  description = "Static IP: point the API domain's A record here"
  value       = google_compute_address.cvm.address
}

output "acme_state_bucket" {
  value = google_storage_bucket.acme_state.name
}

output "acme_kms_key" {
  value = google_kms_crypto_key.acme_state.id
}

output "workload_identity_pool_provider" {
  description = "Full provider resource name (audience for the STS exchange is //iam.googleapis.com/<this>)"
  value       = google_iam_workload_identity_pool_provider.attestation_verifier.name
}
