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
    # Zips the controller/ source for the Cloud Function (issue #45).
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
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
  # Instance name as a plain string so the controller can target it without
  # depending on the CVM resource — that breaks what would otherwise be a cycle
  # (the CVM's metadata references the controller's URL, issue #45).
  instance_name = "tee-example-cvm${local.name_suffix}"
  # The workspace a deployment's state must live in: prod in `default`,
  # dev deployments in the workspace named after their suffix.
  expected_workspace = local.is_prod ? "default" : var.deployment_suffix

  tls_enabled = var.tls_domain != ""

  # TLS config travels as plain instance metadata attributes (read via the
  # metadata server by launcher/src/tls.rs), NOT as tee-env-* launch-policy
  # overrides: the release image deliberately omits
  # tee.launch_policy.allow_env_override, so the operator cannot inject
  # environment into the audited workload. Same delivery channel as the
  # weights config below.
  tls_metadata = local.tls_enabled ? {
    tls-domain     = var.tls_domain
    acme-contact   = var.acme_contact
    acme-directory = var.acme_directory
  } : {}

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

  # ---- Embeddings-model delivery (issue #11) --------------------------------
  # The second (EmbeddingGemma) model rides the same envelope pipeline and KMS
  # key as the chat weights, under its own `embed-weights-*` attribute names so
  # the two are configured independently. It decrypts into the same /models
  # tmpfs the chat weights mount provides (so this block sets no tee-mount), and
  # reuses the shared decrypt grant — no extra IAM.
  embed_weights_enabled = var.embed_weights_object != null && var.embed_weights_object != ""
  embed_weights_metadata = local.embed_weights_enabled ? {
    embed-weights-bucket       = local.artifacts_bucket
    embed-weights-object       = var.embed_weights_object
    embed-weights-kms-key      = local.artifact_kms_key
    embed-weights-wip-audience = local.wip_audience
  } : {}

  # ---- Signed, encrypted harness delivery (issue #8) ------------------------
  # The wasm harness rides the *same* envelope pipeline and the same KMS key as
  # the weights, so it reuses local.artifact_kms_key / local.wip_audience and
  # needs no extra IAM (the decrypt grant below already covers it). It is small
  # and decrypted into guest memory, so there is no tmpfs mount.
  harness_enabled = var.harness_object != null && var.harness_object != ""
  harness_metadata = local.harness_enabled ? {
    harness-bucket       = local.artifacts_bucket
    harness-object       = var.harness_object
    harness-kms-key      = local.artifact_kms_key
    harness-wip-audience = local.wip_audience
  } : {}

  # All artifacts share the bucket-read and KMS-decrypt grants, so those exist
  # if *any* is delivered. With weights enabled (the usual case) this is
  # unchanged, so prod plans zero-diff.
  artifact_delivery_enabled = local.weights_enabled || local.embed_weights_enabled || local.harness_enabled

  # ---- Scale-from-zero (issue #45) ------------------------------------------
  # Prod only: a dev deployment takes an ephemeral IP that a stop would
  # discard, so the controller and the idle metadata are never wired for dev.
  scale_enabled = local.is_prod && var.scale_to_zero
  # Delivered to the CVM as instance metadata, same channel as TLS/weights
  # config (read via the metadata server, not env). controller-url arms the
  # launcher's idle timer; without it the launcher stays up.
  controller_metadata = local.scale_enabled ? {
    controller-url       = google_cloudfunctions2_function.controller[0].url
    idle-timeout-minutes = tostring(var.idle_timeout_minutes)
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
  count  = local.artifact_delivery_enabled ? 1 : 0
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
resource "google_kms_crypto_key_iam_member" "artifact_decrypter" {
  count         = local.artifact_delivery_enabled && var.image_digest != null ? 1 : 0
  crypto_key_id = local.artifact_kms_key
  role          = "roles/cloudkms.cryptoKeyDecrypter"
  member        = "principalSet://iam.googleapis.com/${local.wip_pool}/attribute.image_digest/${var.image_digest}"
}

# Renamed from weights_decrypter: the grant now gates on either artifact
# (weights or harness, see local.artifact_delivery_enabled). The moved block
# migrates existing state with zero diff — prod stays untouched on apply.
moved {
  from = google_kms_crypto_key_iam_member.weights_decrypter
  to   = google_kms_crypto_key_iam_member.artifact_decrypter
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
    google_kms_crypto_key_iam_member.artifact_decrypter,
  ]

  # Re-run the wait when the per-digest decrypt grant changes: a digest
  # rotation replaces the KMS IAM member while this resource would otherwise
  # already exist, and KMS IAM propagation takes minutes too. (The launcher
  # also retries delivery for ~5 minutes, covering the slow tail.)
  triggers = {
    artifact_decrypter_digest = local.artifact_delivery_enabled && var.image_digest != null ? var.image_digest : ""
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
    # The launcher binds either plain HTTP or HTTPS, never both (main.rs):
    # open only the port that is actually listening. 443 is fixed — the
    # TLS-ALPN-01 challenge validates on 443 only, and HTTPS_PORT is an
    # env-only dev/test knob that production never sets.
    ports = local.tls_enabled ? ["443"] : [tostring(var.http_port)]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["tee-example"]
}

# ---- Scale-from-zero controller (issue #45) --------------------------------
# A gen2 Cloud Function (scales to 0) that the frontend pokes to start the
# stopped CVM and the launcher pokes to stop it when idle. It lives in this
# per-deployment root because it operates on this deployment's instance; it is
# outside the audited TCB and holds no privacy trust (the frontend re-attests
# on every reconnect). See controller/ and docs/DESIGN.md.

resource "google_service_account" "controller" {
  count        = local.scale_enabled ? 1 : 0
  account_id   = "tee-example-controller"
  display_name = "TEE example scale-from-zero controller"
}

# Least privilege: exactly the compute verbs the controller needs to read
# status and flip the power switch — not the broad instanceAdmin role.
resource "google_project_iam_custom_role" "controller" {
  count       = local.scale_enabled ? 1 : 0
  role_id     = "teeExampleController"
  title       = "TEE example CVM start/stop"
  description = "Start, stop, and read status of the scale-from-zero CVM (issue #45)."
  permissions = [
    "compute.instances.get",
    "compute.instances.start",
    "compute.instances.stop",
    "compute.zoneOperations.get",
  ]
}

resource "google_project_iam_member" "controller_compute" {
  count   = local.scale_enabled ? 1 : 0
  project = var.project_id
  role    = google_project_iam_custom_role.controller[0].id
  member  = "serviceAccount:${google_service_account.controller[0].email}"
}

# Read-only on logs: the idle path counts "tls certificate issued" entries.
resource "google_project_iam_member" "controller_logging" {
  count   = local.scale_enabled ? 1 : 0
  project = var.project_id
  role    = "roles/logging.viewer"
  member  = "serviceAccount:${google_service_account.controller[0].email}"
}

# Source bucket for the function zip. force_destroy is safe: it only ever holds
# ephemeral, redeployable source archives, never state or user data.
resource "google_storage_bucket" "controller_source" {
  count                       = local.scale_enabled ? 1 : 0
  name                        = "${var.project_id}-tee-controller-src"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true
}

data "archive_file" "controller" {
  count       = local.scale_enabled ? 1 : 0
  type        = "zip"
  source_dir  = "${path.module}/../controller"
  output_path = "${path.module}/.controller.zip"
}

resource "google_storage_bucket_object" "controller_source" {
  count = local.scale_enabled ? 1 : 0
  # Hash in the name so a source change uploads a new object and redeploys.
  name   = "controller-${data.archive_file.controller[0].output_md5}.zip"
  bucket = google_storage_bucket.controller_source[0].name
  source = data.archive_file.controller[0].output_path
}

resource "google_cloudfunctions2_function" "controller" {
  count       = local.scale_enabled ? 1 : 0
  name        = "tee-example-controller"
  location    = var.region
  description = "Scale-from-zero wake/idle controller for the CVM (issue #45)"

  build_config {
    runtime     = "python312"
    entry_point = "controller"
    source {
      storage_source {
        bucket = google_storage_bucket.controller_source[0].name
        object = google_storage_bucket_object.controller_source[0].name
      }
    }
  }

  service_config {
    min_instance_count    = 0 # scale to zero: no cost when no one is waking it
    max_instance_count    = 2
    available_memory      = "256Mi"
    timeout_seconds       = 60
    service_account_email = google_service_account.controller[0].email
    environment_variables = {
      CVM_PROJECT      = var.project_id
      INSTANCE_NAME    = local.instance_name
      INSTANCE_ZONE    = var.zone
      MAX_WEEKLY_BOOTS = tostring(var.max_weekly_boots)
    }
  }

  depends_on = [
    google_project_iam_member.controller_compute,
    google_project_iam_member.controller_logging,
  ]
}

# The browser's /wake is unauthenticated, so allow public invocation. Worst
# case for an anonymous caller: start a stopped VM or ask to stop an idle one
# (budget-gated) — both are normal operation, and the VM grants no trust to
# whatever started it (re-attestation on reconnect).
resource "google_cloud_run_service_iam_member" "controller_public" {
  count    = local.scale_enabled ? 1 : 0
  location = var.region
  service  = google_cloudfunctions2_function.controller[0].name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_compute_instance" "cvm" {
  name             = local.instance_name
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
    local.tls_metadata,
    local.weights_metadata,
    local.embed_weights_metadata,
    local.harness_metadata,
    local.controller_metadata,
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

    # TLS needs the domain's A record to resolve to this VM, and only prod
    # gets the bootstrap static IP the record points at. A dev deployment
    # takes an ephemeral IP, so ACME validation could never succeed there.
    precondition {
      condition     = local.is_prod || !local.tls_enabled
      error_message = "tls_domain is prod-only: a dev deployment (deployment_suffix set) gets an ephemeral IP, so the domain's A record cannot reach it and ACME validation would always fail."
    }
  }
}

output "external_ip" {
  value = google_compute_instance.cvm.network_interface[0].access_config[0].nat_ip
}

output "image_reference" {
  value = local.image_reference
}

# Base URL of the scale-from-zero controller, or "" when disabled. Feed this to
# the frontend as VITE_CONTROLLER_ENDPOINT so the app can wake a stopped enclave.
output "controller_url" {
  description = "Scale-from-zero controller base URL (set as VITE_CONTROLLER_ENDPOINT); empty when scale_to_zero is off."
  value       = local.scale_enabled ? google_cloudfunctions2_function.controller[0].url : ""
}
