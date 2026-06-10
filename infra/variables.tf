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
  description = "Digest of the pushed launcher image (sha256:...)"
  type        = string

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.image_digest))
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
  default     = "n2d-standard-2"
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

variable "https_port" {
  description = "HTTPS port the launcher serves TLS on"
  type        = number
  default     = 443
}
