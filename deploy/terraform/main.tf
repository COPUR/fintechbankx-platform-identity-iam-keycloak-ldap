# AWS resources owned by svc-idn-keycloak-ldap (Identity Platform Squad):
# - Aurora PostgreSQL for Keycloak (db_idn_keycloak_ldap_<env>) through the
#   platform aurora-postgresql module.
# - Secrets Manager containers for Keycloak runtime credentials and for every
#   service's OIDC client credential (<env>/<service-slug>/oidc-client).
#   Terraform creates the containers only; values are written by
#   scripts/identity/publish-oidc-client-secrets.sh and the DBA bootstrap.
# - A KMS key for those secrets, tagged so External Secrets Operator may
#   decrypt it (platform contract addendum).
# Keycloak needs no IRSA role: it reads no AWS API; ESO syncs its secrets.

locals {
  service_id   = "svc-idn-keycloak-ldap"
  service_slug = "identity-keycloak"
  name         = "${var.environment}-${local.service_slug}"
  database     = "db_idn_keycloak_ldap_${var.environment}"

  # Client registry shared with the realm import (realm/service-clients.json).
  client_registry = jsondecode(file("${path.module}/../../realm/service-clients.json"))
  service_clients = merge(
    { for c in local.client_registry.clients : c.clientId => c },
    { for c in try(local.client_registry.ssoClients, []) : c.clientId => c },
  )

  tags = merge({
    Service            = local.service_id
    BoundedContext     = "identity_access_management"
    OwningSquad        = "identity-platform"
    Environment        = var.environment
    DataClassification = "restricted"
    ManagedBy          = "terraform"
  }, var.tags)
}

module "keycloak_db" {
  source = "git::https://github.com/COPUR/fintechbankx-platform-delivery-iac-terraform-modules.git//modules/aurora-postgresql?ref=main"

  name                       = local.name
  database_name              = local.database
  master_username            = "keycloak_admin"
  engine_version             = var.aurora_engine_version
  instance_count             = var.aurora_instance_count
  min_capacity               = var.aurora_min_capacity
  max_capacity               = var.aurora_max_capacity
  vpc_id                     = var.vpc_id
  subnet_ids                 = var.private_subnet_ids
  allowed_security_group_ids = var.workload_security_group_ids
  backup_retention_days      = var.backup_retention_days
  deletion_protection        = var.deletion_protection
  # Keycloak's JDBC pool uses a password credential (ExternalSecret keycloak-db).
  iam_database_authentication_enabled = false
  create_app_secret                   = true
  app_secret_name                     = "${var.environment}/${local.service_slug}/db-app"
  alarm_topic_arn                     = var.alarm_topic_arn
  # 9 Keycloak pods x poolMaxSize 40 at prod peak.
  connections_alarm_threshold = 360
  tags                        = local.tags
}

# --- Secrets ----------------------------------------------------------------

resource "aws_kms_key" "identity_secrets" {
  description             = "Encrypts identity secrets: Keycloak admin client, LDAP bind and service OIDC client credentials"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = merge(local.tags, { "fintechbankx.io/secrets" = "true" })
}

resource "aws_kms_alias" "identity_secrets" {
  name          = "alias/${local.name}-secrets"
  target_key_id = aws_kms_key.identity_secrets.key_id
}

# {"client_id", "client_secret"} of the master-realm admin client used by the
# realm import Job (Keycloak CR spec.bootstrapAdmin.service).
resource "aws_secretsmanager_secret" "bootstrap_admin_client" {
  name                    = "${var.environment}/${local.service_slug}/bootstrap-admin-client"
  description             = "Keycloak master-realm admin client for the realm import Job"
  kms_key_id              = aws_kms_key.identity_secrets.arn
  recovery_window_in_days = 7
}

# {"bind_credential"} of the read-only directory bind account.
resource "aws_secretsmanager_secret" "ldap_bind" {
  name                    = "${var.environment}/${local.service_slug}/ldap-bind"
  description             = "Read-only LDAP bind credential used by Keycloak user federation"
  kms_key_id              = aws_kms_key.identity_secrets.arn
  recovery_window_in_days = 7
}

# {"admin_credential", "config_credential"} for the dev/staging OpenLDAP.
resource "aws_secretsmanager_secret" "openldap_admin" {
  count                   = var.create_openldap_secrets ? 1 : 0
  name                    = "${var.environment}/identity-openldap/admin"
  description             = "OpenLDAP administrative credentials (dev/staging directory only)"
  kms_key_id              = aws_kms_key.identity_secrets.arn
  recovery_window_in_days = 7
}

# One container per service client; value {"client_id", "client_secret",
# "issuer_uri", "token_uri"} written by scripts/identity/publish-oidc-client-secrets.sh.
resource "aws_secretsmanager_secret" "oidc_client" {
  for_each = local.service_clients

  name                    = "${var.environment}/${each.value.serviceSlug}/oidc-client"
  description             = "OIDC client credential of ${each.key} in realm fintechbankx"
  kms_key_id              = aws_kms_key.identity_secrets.arn
  recovery_window_in_days = 7
  tags = {
    ServiceId             = each.key
    "fintechbankx.io/use" = "oidc-client"
  }
}
