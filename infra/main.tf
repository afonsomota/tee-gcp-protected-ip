# Confidential Space CVM running the launcher container.
# Prerequisite: infra/bootstrap applied once (APIs + Artifact Registry repo).

terraform {
  required_version = ">= 1.5"

  # Partial configuration — bucket name embeds the never-committed project
  # ID; supply it at init (or use make deploy / make dev-deploy):
  #   terraform -chdir=infra init \
  #     -backend-config="bucket=${PROJECT_ID}-tfstate" \
  #     -backend-config="prefix=cvm"
  # The bucket is created by infra/bootstrap. Workspaces (per-branch dev
  # deployments) map to objects under the prefix: cvm/<workspace>.tfstate,
  # with prod in cvm/default.tfstate.
  backend "gcs" {}

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

  # Per-branch dev deployments (issue #28): a non-empty deployment_suffix
  # suffixes every name so a dev CVM can run alongside prod in the same
  # project. With the default "" the rendered names below are byte-identical
  # to the pre-suffix configuration, so existing prod state plans zero-diff.
  is_prod     = var.deployment_suffix == ""
  name_suffix = local.is_prod ? "" : "-${var.deployment_suffix}"
  # The workspace a deployment's state must live in: prod in `default`,
  # dev deployments in the workspace named after their suffix.
  expected_workspace = local.is_prod ? "default" : var.deployment_suffix

  # ---- Attestation-gated weights delivery (issue #7) ------------------------
  weights_enabled = var.weights_object != null && var.weights_object != ""

  # Long-lived names created by infra/bootstrap, reconstructed here instead of
  # read from its outputs so this root has no dependency on bootstrap's state.
  artifacts_bucket = "${var.project_id}-tee-example-artifacts"
  artifact_kms_key = "projects/${var.project_id}/locations/${var.region}/keyRings/tee-example/cryptoKeys/artifact-sealing"
  wip_pool         = "projects/${data.google_project.current.number}/locations/global/workloadIdentityPools/tee-example-pool"
  wip_audience     = "//iam.googleapis.com/${local.wip_pool}/providers/attestation-verifier"

  # Launcher config travels as instance metadata attributes (read via the
  # metadata server), NOT as tee-env-* launch-policy overrides: the release
  # image deliberately omits tee.launch_policy.allow_env_override, so the
  # operator cannot inject environment into the audited workload.
  weights_metadata = local.weights_enabled ? {
    weights-bucket       = local.artifacts_bucket
    weights-object       = var.weights_object
    weights-kms-key      = local.artifact_kms_key
    weights-wip-audience = local.wip_audience
    # tmpfs at /models so decrypted weights only ever exist in guest memory
    # (encrypted by SEV-SNP), never on disk. Requires the image label
    # tee.launch_policy.allow_mount_destinations=/models.
    tee-mount = "type=tmpfs,source=tmpfs,destination=/models,size=${var.weights_tmpfs_bytes}"
  } : {}
}

# Project number is needed to name the workload identity pool principalSet.
data "google_project" "current" {
  project_id = var.project_id
}

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
  # account_id is capped at 30 chars, so dev deployments use the shorter
  # "tee-ex-" prefix: 7 + 23 (deployment_suffix max, enforced by its
  # validation) = 30.
  account_id   = local.is_prod ? "tee-example-workload" : "tee-ex-${var.deployment_suffix}"
  display_name = "TEE example Confidential Space workload${local.is_prod ? "" : " (${var.deployment_suffix})"}"
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

# Read access to the ciphertext artifacts. Deliberately weak on its own:
# the blobs are envelope-encrypted, so confidentiality rests on the KMS
# decrypt grant below, not on this bucket ACL.
resource "google_storage_bucket_iam_member" "artifacts_reader" {
  count  = local.weights_enabled ? 1 : 0
  bucket = local.artifacts_bucket
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.workload.email}"
}

# The per-deployment half of attestation-gated delivery: KMS decrypt for the
# attested principalSet pinned to *this* image digest. Applying with a new
# digest replaces the member, revoking every previously deployed image — the
# rotation/revocation story from issue #7. Note for dev deployments: two
# workspaces deploying the same digest create the same binding twice; the
# first `terraform destroy` removes it for both. Acceptable for dev churn.
resource "google_kms_crypto_key_iam_member" "weights_decrypter" {
  count         = local.weights_enabled && var.image_digest != null ? 1 : 0
  crypto_key_id = local.artifact_kms_key
  role          = "roles/cloudkms.cryptoKeyDecrypter"
  member        = "principalSet://iam.googleapis.com/${local.wip_pool}/attribute.image_digest/${var.image_digest}"
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
    google_storage_bucket_iam_member.artifacts_reader,
    google_kms_crypto_key_iam_member.weights_decrypter,
  ]

  # Re-run the wait when the per-digest decrypt grant changes: a digest
  # rotation replaces the KMS IAM member while this resource would otherwise
  # already exist, and KMS IAM propagation takes minutes too. (The launcher
  # also retries delivery for ~5 minutes, covering the slow tail.)
  triggers = {
    weights_decrypter_digest = local.weights_enabled && var.image_digest != null ? var.image_digest : ""
  }

  create_duration = "120s"
}

# Each deployment carries its own (identical) firewall rule rather than
# sharing prod's: the prod root is destroyed routinely to stop costs, so a
# dev deployment can't rely on prod's rule existing. All rules target the
# shared "tee-example" network tag; duplicates are harmless.
resource "google_compute_firewall" "allow_http" {
  name    = "tee-example-allow-http${local.name_suffix}"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = [tostring(var.http_port)]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["tee-example"]
}

resource "google_compute_instance" "cvm" {
  name             = "tee-example-cvm${local.name_suffix}"
  machine_type     = var.machine_type
  zone             = var.zone
  tags             = ["tee-example"]
  min_cpu_platform = "AMD Milan"

  # Label dev instances so stale deployments are easy to find and sweep:
  #   gcloud compute instances list --filter=labels.created-by=dev-deploy
  labels = local.is_prod ? null : {
    created-by = "dev-deploy"
    deployment = var.deployment_suffix
  }

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
      # Prod pins the bootstrap static IP so DNS never goes stale; dev
      # deployments must never steal it, so they take an ephemeral IP (null).
      nat_ip = local.is_prod ? data.google_compute_address.cvm.address : null
    }
  }

  metadata = merge(
    {
      tee-image-reference        = local.image_reference
      tee-container-log-redirect = "true"
    },
    local.weights_metadata,
  )

  service_account {
    email  = google_service_account.workload.email
    scopes = ["cloud-platform"]
  }

  # Wait out IAM propagation for the fresh service account; see
  # time_sleep.iam_propagation above.
  depends_on = [time_sleep.iam_propagation]

  lifecycle {
    # Each deployment's state lives in its own workspace; refuse to apply a
    # suffix against the wrong one. This catches e.g. running plain
    # `terraform apply` (no suffix, prod tfvars auto-loaded) while a dev
    # workspace from `make dev-deploy` is still selected.
    precondition {
      condition     = terraform.workspace == local.expected_workspace
      error_message = "deployment_suffix \"${var.deployment_suffix}\" belongs in workspace \"${local.expected_workspace}\", but \"${terraform.workspace}\" is selected. Run `terraform -chdir=infra workspace select ${local.expected_workspace}` (or use make deploy / make dev-deploy)."
    }
  }
}

output "external_ip" {
  value = google_compute_instance.cvm.network_interface[0].access_config[0].nat_ip
}

output "image_reference" {
  value = local.image_reference
}
