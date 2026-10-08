output "keycloak_db_writer_endpoint" {
  description = "Aurora writer endpoint (overlay identity-environment.databaseHost)."
  value       = module.keycloak_db.endpoint
}

output "keycloak_db_reader_endpoint" {
  description = "Aurora reader endpoint."
  value       = module.keycloak_db.reader_endpoint
}

output "keycloak_db_name" {
  description = "Keycloak database name (overlay identity-environment.databaseName)."
  value       = local.database
}

output "keycloak_db_app_secret_name" {
  description = "Secrets Manager entry synced into Secret keycloak-db."
  value       = module.keycloak_db.app_secret_name
}

output "keycloak_db_master_secret_arn" {
  description = "RDS-managed admin credential, for the DBA bootstrap only."
  value       = module.keycloak_db.master_user_secret_arn
}

output "identity_secrets_kms_key_arn" {
  description = "KMS key of the identity secrets (External Secrets Operator needs kms:Decrypt)."
  value       = aws_kms_key.identity_secrets.arn
}

output "oidc_client_secret_names" {
  description = "Service id -> Secrets Manager name of its OIDC client credential."
  value       = { for k, s in aws_secretsmanager_secret.oidc_client : k => s.name }
}
