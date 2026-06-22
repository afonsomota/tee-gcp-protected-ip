variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "europe-west4"
}

variable "zone" {
  description = "GCP zone (must support N2D / SEV-SNP)"
  type        = string
  default     = "europe-west4-a"
}

variable "image_digest" {
  description = "Digest of the pushed launcher image (sha256:...). Optional: omit on destroy-only runs (not evaluated when the VM is being deleted)."
  type        = string
  default     = null

  validation {
    condition     = var.image_digest == null || can(regex("^sha256:[0-9a-f]{64}$", var.image_digest))
    error_message = "image_digest must look like sha256:<64 hex chars>."
  }
}

variable "repository_id" {
  description = "Artifact Registry repository ID (created by infra/bootstrap)"
  type        = string
  default     = "tee-example"
}

variable "machine_type" {
  description = "Confidential VM machine type (N2D for SEV-SNP)"
  type        = string
  default     = "n2d-standard-4"
}

variable "confidential_space_image_family" {
  description = "Confidential Space image family (use confidential-space-debug for the SSH-able debug image)"
  type        = string
  default     = "confidential-space"
}

variable "http_port" {
  description = "Port the launcher listens on"
  type        = number
  default     = 8080
}

variable "static_ip_name" {
  description = "Name of the static external IP reserved by infra/bootstrap"
  type        = string
  default     = "tee-example-cvm"
}

variable "weights_object" {
  description = <<-EOT
    GCS object name of the encrypted-weights manifest inside the artifacts
    bucket (e.g. "weights/model.gguf.manifest.json"), as printed by
    scripts/provision-weights.py. Put it in infra/terraform.tfvars (gitignored,
    auto-loaded) — make deploy only passes project_id and image_digest.
    null or "" disables artifact delivery: no weights metadata on the CVM and
    no KMS decrypt grant, so /chat stays inactive on release images.
  EOT
  type        = string
  default     = null
}

variable "harness_object" {
  description = <<-EOT
    GCS object name of the encrypted-harness manifest inside the artifacts
    bucket (e.g. "harness/harness.wasm.manifest.json"), as printed by
    scripts/provision-harness.py. Put it in infra/terraform.tfvars alongside
    weights_object. The harness rides the same KMS-gated pipeline as the
    weights (shared bucket, KMS key, and workload-identity audience), so no
    separate decrypt grant is needed.
    null or "" disables harness delivery: no harness metadata on the CVM, so
    /chat serves 503 (the launcher will not run unsigned/undelivered code).
  EOT
  type        = string
  default     = null
}

variable "embed_weights_object" {
  description = <<-EOT
    GCS object name of the encrypted embeddings-model manifest inside the
    artifacts bucket (e.g. "weights/embed.gguf.manifest.json"), as printed by
    scripts/provision-weights.py. The embeddings model (EmbeddingGemma, issue
    #11) rides the same KMS-gated pipeline as the chat weights — shared bucket,
    KMS key, and workload-identity audience — and decrypts into the same /models
    tmpfs, so it needs no separate decrypt grant or mount.
    Requires weights_object to be set (the chat weights provide the /models
    mount). null or "" disables the embeddings model: semantic search degrades
    to keyword search and the launcher omits the `embed` tool from its manifest.
  EOT
  type        = string
  default     = null
}

variable "weights_tmpfs_bytes" {
  description = <<-EOT
    Size of the in-memory tmpfs Confidential Space mounts at /models for the
    decrypted weights. Must fit the plaintext model(s) — both the chat model and,
    when embed_weights_object is set, the embeddings model — since both decrypt
    into /models. Counts against guest RAM (n2d-standard-4 has 16 GiB; bump to
    -8 / 32 GiB if two models are tight, per docs/DESIGN.md spike 3).
  EOT
  type        = number
  default     = 8589934592 # 8 GiB
}

variable "deployment_suffix" {
  description = <<-EOT
    Suffix for a per-branch dev deployment running alongside prod ("" = prod).
    Non-empty: resource names get "-<suffix>" appended, the CVM takes an
    ephemeral external IP instead of the bootstrap static one, and state must
    live in the Terraform workspace named after the suffix. Use `make
    dev-deploy`, which derives a valid suffix from the git branch.
  EOT
  type        = string
  default     = ""

  validation {
    # ≤ 23 chars keeps the service-account account_id
    # ("tee-ex-<suffix>", limit 30) and instance name within GCP limits.
    condition     = can(regex("^$|^[a-z][a-z0-9-]{0,21}[a-z0-9]$", var.deployment_suffix))
    error_message = "deployment_suffix must be \"\" (prod) or 2-23 chars of [a-z0-9-], starting with a letter and ending with a letter or digit."
  }
}

# ---- TLS / ACME (issue 004) ------------------------------------------------

variable "tls_domain" {
  description = <<-EOT
    Domain the enclave serves HTTPS for (e.g. api.example.com). Empty
    disables TLS (plain HTTP on http_port, as before). Requires the
    bootstrap root applied and an A record pointing the domain at its
    static IP (output `cvm_ip`).
  EOT
  type        = string
  default     = ""
}

variable "acme_contact" {
  description = "Contact email for the Let's Encrypt account (required when tls_domain is set)"
  type        = string
  default     = ""

  validation {
    condition     = var.tls_domain == "" || var.acme_contact != ""
    error_message = "acme_contact is required when tls_domain is set."
  }
}

variable "acme_directory" {
  description = "ACME directory: letsencrypt-staging (default, no rate-limit risk) or letsencrypt for real certs"
  type        = string
  default     = "letsencrypt-staging"

  validation {
    condition     = contains(["letsencrypt", "letsencrypt-staging"], var.acme_directory) || startswith(var.acme_directory, "https://")
    error_message = "acme_directory must be letsencrypt, letsencrypt-staging, or an https:// directory URL."
  }
}

# ---- Scale-from-zero (issue #45) -------------------------------------------

variable "scale_to_zero" {
  description = <<-EOT
    Deploy the always-on controller (Cloud Function) that stops the CVM when it
    goes idle and starts it on demand, so a stopped VM costs no compute. Prod
    only: a dev deployment takes an ephemeral IP, which a stop would discard, so
    the controller is never wired for dev regardless of this flag. Set false to
    keep prod always-on (a continuous demo).
  EOT
  type        = bool
  default     = true
}

variable "idle_timeout_minutes" {
  description = <<-EOT
    Minutes with no inbound request after which the launcher pokes the
    controller to stop the idle CVM. Delivered to the VM as instance metadata
    (idle-timeout-minutes), read at boot by launcher/src/idle.rs. Takes effect
    on the next start.
  EOT
  type        = number
  default     = 45

  validation {
    condition     = var.idle_timeout_minutes > 0
    error_message = "idle_timeout_minutes must be positive."
  }
}

variable "max_weekly_boots" {
  description = <<-EOT
    Cap on cold boots (≈ Let's Encrypt cert issuances) the controller will allow
    per rolling 7 days. At or above this the controller leaves the idle VM
    running rather than stopping it, so a restart can never breach the
    Let's Encrypt prod limit (5 certs / 7 days) and lock out TLS — the limit
    becomes a cost knob. Keep < 5 for headroom; higher only makes sense on
    Let's Encrypt staging. Delivered to the controller as env config.
  EOT
  type        = number
  default     = 4

  validation {
    condition     = var.max_weekly_boots > 0
    error_message = "max_weekly_boots must be positive."
  }
}

variable "frontend_origins" {
  description = <<-EOT
    Browser origins allowed to read the scale-from-zero controller's responses
    (CORS allowlist). The SPA is served cross-origin from GitHub Pages, so the
    controller must echo a permitted Origin or the browser blocks the /wake
    response. Delivered to the controller as the comma-separated ALLOWED_ORIGINS
    env var. Empty list ⇒ the controller falls back to `*` (open read) — fine
    for local/dev, but set the real Pages origin(s) for a public deployment.
    CORS is not an auth boundary here: the controller is unauthenticated either
    way and the privacy guarantee comes from re-attestation, not this front door.
  EOT
  type        = list(string)
  default     = ["https://journal.inner-apple.com"]
}
