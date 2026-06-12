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
