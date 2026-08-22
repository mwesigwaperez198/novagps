variable "aws_region" {
  type        = string
  description = "AWS region for NOVA infrastructure."
  default     = "us-east-1"
}

variable "project_name" {
  type        = string
  description = "Project prefix for resource names."
  default     = "nova-gps"
}

variable "environment" {
  type        = string
  description = "Environment name."
  default     = "prod"
}

variable "db_username" {
  type        = string
  description = "Postgres admin username."
  default     = "nova_admin"
}

variable "db_password" {
  type        = string
  description = "Postgres admin password. Use a secrets manager in real deployments."
  sensitive   = true
}

variable "db_instance_class" {
  type        = string
  description = "Managed Postgres instance size."
  default     = "db.t4g.medium"
}
