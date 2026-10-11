# Migration Granularity Notes

- Repository: `fintechbankx-platform-identity-keycloak-ldap`
- Source monorepo: `enterprise-loan-management-system`
- Sync date: `2026-03-15`
- Sync branch: `chore/granular-source-sync-20260313`

## Applied Rules

- dir: `security/vault` -> `security/vault` (removed 2026-10-11: the monolith Vault seed connected to PostgreSQL with `sslmode=require`, below the platform's `verify-full` rule, and no manifest here deployed it; database credentials come from AWS Secrets Manager under `<env>/<slug>/...`)
- dir: `security/secrets` -> `security/secrets`
- file: `security/service-architecture/service-mesh-config.yaml` -> `security/service-architecture/service-mesh-config.yaml`
- dir: `k8s/envoy` -> `k8s/envoy`
- file: `docs/enterprisearchitecture/compliance-security/ENTERPRISE_ANONYMITY_SECURITY_STANDARD.md` -> `docs/ENTERPRISE_ANONYMITY_SECURITY_STANDARD.md`

## Notes

- This is an extraction seed for bounded-context split migration.
- Follow-up refactoring may be needed to remove residual cross-context coupling.
- Build artifacts and local machine files are excluded by policy.


## Deployable identity platform (2026-10-08, Proposed)

Sources read from `enterprise-loan-management-system` (branch `master`) and the enterprise-architecture repository:

- `docker-compose.yml` services `keycloak` (Keycloak 23, `start-dev`, realm import from `config/keycloak/realms`) and `ldap` (`osixia/openldap:1.5.0`, `dc=banking,dc=local`, TLS, read-only user) -> `deploy/kustomize/` (Keycloak 26.7.5 via the operator, production mode) and `deploy/kustomize/components/openldap/` (same image, pinned by digest, base DN `dc=fintechbankx,dc=internal`).
- `config/keycloak/realms` and `config/ldap/bootstrap` are referenced by the compose file but not committed in the monolith; the realm and the directory seed were written from the platform contract instead (`realm/`, `seed/50-fintechbankx-structure.ldif`).
- `docs/puml/service-mesh/keycloak-aaa-blueprint.md` -> client taxonomy, DPoP/PAR/FAPI policy, LDAP federation model, config-as-code gates (`scripts/ci/check-realm.mjs`). Deviation: one realm per environment (platform contract) instead of three realms.
- Service `SecurityConfiguration` (realm_access.roles -> `ROLE_*`) -> realm roles and scope mappings.

Name drift: this file and the strict-mTLS workflow used `fintechbankx-platform-identity-keycloak-ldap`; the repository is `fintechbankx-platform-identity-iam-keycloak-ldap`. The workflow now lists both names.
