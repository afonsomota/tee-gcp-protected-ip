# Confidential Space CVM running the launcher container.
# Prerequisite: infra/bootstrap applied once (APIs + Artifact Registry repo).

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.13"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

locals {
  # Full image reference pinned by digest — this digest is what the
  # attestation token's submods.container.image_digest claim must equal.
  # image_digest is null on destroy-only runs; the placeholder is never
  # evaluated because the VM resource is being deleted, not created/updated.
  image_reference = var.image_digest != null ? "${var.region}-docker.pkg.dev/${var.project_id}/${var.repository_id}/launcher@${var.image_digest}" : "destroy-only-no-image"

  tls_enabled = var.tls_domain != ""

  # Long-lived TLS/ACME resources created by infra/bootstrap (issue 004).
  # Names must match the bootstrap root.
  acme_state_bucket = "${var.project_id}-tee-example-acme-state"
  acme_kms_key      = "projects/${var.project_id}/locations/${var.region}/keyRings/tee-example/cryptoKeys/acme-state-sealing"
  wip_provider      = "projects/${data.google_project.current.number}/locations/global/workloadIdentityPools/tee-example-pool/providers/attestation-verifier"

  # Confidential Space forwards tee-env-* metadata as container env vars
  # (admitted by the image's tee.launch_policy.allow_env_override label).
  tls_env = local.tls_enabled ? {
    tee-env-TLS_DOMAIN        = var.tls_domain
    tee-env-ACME_CONTACT      = var.acme_contact
    tee-env-ACME_DIRECTORY    = var.acme_directory
    tee-env-ACME_STATE_BUCKET = local.acme_state_bucket
    tee-env-ACME_KMS_KEY      = local.acme_kms_key
    tee-env-ACME_WIP_AUDIENCE = "//iam.googleapis.com/${local.wip_provider}"
  } : {}
}

data "google_project" "current" {}

# Static external IP reserved by infra/bootstrap. Looked up by name rather
# than via remote state so this root has no dependency on bootstrap's state —
# only on the address existing in the project.
data "google_compute_address" "cvm" {
  name   = var.static_ip_name
  region = var.region
}

# Identity the workload VM runs as. Confidential Space requires the
# workloadUser role; reader on Artifact Registry to pull the image.
resource "google_service_account" "workload" {
  account_id   = "tee-example-workload"
  display_name = "TEE example Confidential Space workload"
}

resource "google_project_iam_member" "workload_user" {
  project = var.project_id
  role    = "roles/confidentialcomputing.workloadUser"
  member  = "serviceAccount:${google_service_account.workload.email}"
}

resource "google_project_iam_member" "log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.workload.email}"
}

resource "google_project_iam_member" "ar_reader" {
  project = var.project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.workload.email}"
}

# IAM grants on a freshly created service account are eventually consistent
# (up to a couple of minutes). Without this wait the CVM boots before the
# grants propagate: it can't pull the image (artifactregistry.reader) or
# write logs (logging.logWriter), so it self-terminates after ~3 minutes
# with zero guest-side logs. depends_on alone is not enough — Terraform only
# waits for the IAM API call to return, not for propagation.
resource "time_sleep" "iam_propagation" {
  depends_on = [
    google_project_iam_member.workload_user,
    google_project_iam_member.log_writer,
    google_project_iam_member.ar_reader,
  ]
  create_duration = "120s"
}

# The launcher reads/writes the *sealed* ACME blobs as the VM service
# account; the plaintext is protected by the KMS binding below, not by GCS.
resource "google_storage_bucket_iam_member" "acme_state_rw" {
  count  = local.tls_enabled ? 1 : 0
  bucket = local.acme_state_bucket
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.workload.email}"
}

# The acceptance gate of issue 004: only the attested workload — a
# Confidential Space instance whose token carries *this* image digest —
# can wrap/unwrap the ACME state. The VM service account itself gets no
# KMS access, so a non-attested principal (operator included) cannot
# unwrap the sealed blobs.
resource "google_kms_crypto_key_iam_member" "acme_state_attested" {
  count         = local.tls_enabled ? 1 : 0
  crypto_key_id = local.acme_kms_key
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "principalSet://iam.googleapis.com/projects/${data.google_project.current.number}/locations/global/workloadIdentityPools/tee-example-pool/attribute.image_digest/${var.image_digest}"
}

resource "google_compute_firewall" "allow_http" {
  name    = "tee-example-allow-http"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = local.tls_enabled ? [tostring(var.http_port), tostring(var.https_port)] : [tostring(var.http_port)]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["tee-example"]
}

resource "google_compute_instance" "cvm" {
  name             = "tee-example-cvm"
  machine_type     = var.machine_type
  zone             = var.zone
  tags             = ["tee-example"]
  min_cpu_platform = "AMD Milan"

  confidential_instance_config {
    enable_confidential_compute = true
    confidential_instance_type  = "SEV_SNP"
  }

  scheduling {
    on_host_maintenance = "TERMINATE" # required for confidential VMs
  }

  shielded_instance_config {
    enable_secure_boot = true
  }

  boot_disk {
    initialize_params {
      image = "projects/confidential-space-images/global/images/family/${var.confidential_space_image_family}"
    }
  }

  network_interface {
    network = "default"
    access_config {
      # Static IP (bootstrap root) when TLS is on — DNS points at it;
      # ephemeral otherwise.
      nat_ip = local.tls_enabled ? data.google_compute_address.cvm.address : null
    }
  }

  metadata = merge(
    {
      tee-image-reference        = local.image_reference
      tee-container-log-redirect = "true"
    },
    local.tls_env,
  )

  service_account {
    email  = google_service_account.workload.email
    scopes = ["cloud-platform"]
  }

  # Wait out IAM propagation for the fresh service account; see
  # time_sleep.iam_propagation above.
  depends_on = [time_sleep.iam_propagation]
}

output "external_ip" {
  value = google_compute_instance.cvm.network_interface[0].access_config[0].nat_ip
}

output "image_reference" {
  value = local.image_reference
}
