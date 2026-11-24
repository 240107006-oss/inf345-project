output "healthz_url" {
  description = "Open this after apply"
  value       = "http://localhost:${var.host_port}/healthz"
}

output "container_id" {
  description = "The container Terraform created - compare it with docker ps"
  value       = docker_container.app.id
}
