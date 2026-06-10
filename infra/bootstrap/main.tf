# One-time project setup: required APIs + Artifact Registry repo.
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
  description = "Region for the Artifact Registry repository"
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

output "repository_url" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.tee_example.repository_id}"
}
