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
