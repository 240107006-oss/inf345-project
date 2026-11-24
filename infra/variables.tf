variable "image" {
  description = "Full container image reference pinned by commit SHA"
  type        = string
  default     = "ghcr.io/240107006-oss/inf345-project:1ef0a2c9bd8b1d1e95a773f45c9cc38bea4e6660"
}

variable "internal_port" {
  description = "The port my service listens on inside the container - the contract's PORT"
  type        = number
  default     = 8080
}

variable "host_port" {
  description = "The port on my laptop: http://localhost:<host_port>/healthz"
  type        = number
  default     = 8080
}

variable "restart_policy" {
  description = "What Docker does when my service exits: no, on-failure, always or unless-stopped"
  type        = string
  default     = "no"
}
