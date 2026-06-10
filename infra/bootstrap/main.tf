# One-time project setup: required APIs + Artifact Registry repo + static IP.
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
}

output "repository_url" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.tee_example.repository_id}"
}

output "cvm_ip" {
  value = google_compute_address.cvm.address
}
