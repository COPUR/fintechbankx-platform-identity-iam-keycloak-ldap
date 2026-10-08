variable "aws_region" {
  type        = string
  description = "AWS region of the cell."
  default     = "me-central-1"
}

variable "environment" {
  type        = string
  description = "Deployment environment (dev, staging, prod)."

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging or prod."
  }
}

variable "vpc_id" {
  type        = string
  description = "VPC of the EKS cluster that runs Keycloak."
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Private subnets in at least two Availability Zones for Aurora."
}

variable "workload_security_group_ids" {
  type        = list(string)
  description = "Security groups of the EKS nodes or Keycloak pods allowed to reach PostgreSQL."
}

variable "aurora_engine_version" {
  type        = string
  description = "Aurora PostgreSQL engine version (Keycloak 26 supports PostgreSQL 13-17)."
  default     = "16.4"
}

variable "aurora_instance_count" {
  type        = number
  description = "Writer plus readers; 2 or more outside dev so a reader in another AZ can take over."
  default     = 2
}

variable "aurora_min_capacity" {
  type        = number
  description = "Serverless v2 minimum ACUs."
  default     = 0.5
}

variable "aurora_max_capacity" {
  type        = number
  description = "Serverless v2 maximum ACUs."
  default     = 8
}

variable "backup_retention_days" {
  type        = number
  description = "Automated backup retention (PITR window)."
  default     = 35
}

variable "deletion_protection" {
  type        = bool
  description = "Protect the Keycloak database from deletion."
  default     = true
}

variable "alarm_topic_arn" {
  type        = string
  description = "SNS topic for CloudWatch alarms; null disables notifications."
  default     = null
}

variable "create_openldap_secrets" {
  type        = bool
  description = "Create the OpenLDAP admin secret container (dev and staging only; prod federates to the corporate directory)."
  default     = true
}

variable "tags" {
  type        = map(string)
  description = "Additional tags (cost centre, data classification)."
  default     = {}
}
